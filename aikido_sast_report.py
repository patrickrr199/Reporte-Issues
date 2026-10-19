#!/usr/bin/env python3
"""
Reporte SAST estilo Fortify para UN repositorio de Aikido Security.

Endpoints (https://apidocs.aikido.dev/):
  GET /api/public/v1/issues/export?filter_code_repo_id=...   issues del repo
  GET /api/public/v1/issues/{id}                            how_to_fix y líneas por issue
  GET /api/public/v1/issues/groups/{id}                     título / descripción del grupo
  POST /api/oauth/token                                     (solo si usas client id/secret)

Autenticación (una de las dos):
  $env:AIKIDO_TOKEN="eyJ..."                                  token Bearer ya generado (dura 1 h)
  $env:AIKIDO_CLIENT_ID="..."; $env:AIKIDO_CLIENT_SECRET="..."  el script pide el token

Ejemplo:
  python aikido_sast_report.py --repo-id 3030745 --src-dir "..\\aikido-backend-demo" -o reporte_AK-REP-BACK.html

Solo librería estándar de Python 3.8+.
"""
import argparse
import base64
import datetime as dt
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

REGIONS = {
    "eu": "https://app.aikido.dev",
    "us": "https://app.us.aikido.dev",
    "au": "https://app.au.aikido.dev",
    "me": "https://app.me.aikido.dev",
}
SEVERITIES = ["critical", "high", "medium", "low"]
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
ENGINES = [("sast", "SAST"), ("iac", "IaC"), ("leaked_secret", "Secrets"), ("open_source", "SCA")]
KINGDOM = {
    "sast": "Security Features (código propio)",
    "iac": "Environment (infraestructura como código)",
    "leaked_secret": "Security Features (secretos)",
    "open_source": "Dependencias de terceros",
}
LANG = {"PY": "Python", "JS": "JavaScript", "TS": "TypeScript", "CS": "C#", "github_act": "GitHub Actions"}


# --------------------------------------------------------------------------- API
class Aikido:
    def __init__(self, region, token=None, client_id=None, client_secret=None):
        self.base = REGIONS[region]
        self.api = self.base + "/api/public/v1"
        self.token = token or self._oauth(client_id, client_secret)

    def _call(self, req, retries=4):
        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    return json.loads(r.read().decode("utf-8") or "null")
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < retries:
                    time.sleep(int(e.headers.get("Retry-After") or 2 ** (attempt + 1)))
                    continue
                body = e.read().decode("utf-8", "replace")[:400]
                if e.code == 401:
                    raise SystemExit("401 No autorizado: el token expiró o es inválido (los tokens de Aikido duran 1 hora).\n" + body)
                raise SystemExit(f"HTTP {e.code} en {req.full_url}\n{body}")
            except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
                if attempt == retries:
                    raise SystemExit(f"Error de conexión en {req.full_url}: {e}")
                time.sleep(2 ** attempt)

    def _oauth(self, cid, secret):
        basic = base64.b64encode(f"{cid}:{secret}".encode()).decode()
        req = urllib.request.Request(
            self.base + "/api/oauth/token",
            data=b"grant_type=client_credentials",
            headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
            method="POST")
        tok = (self._call(req) or {}).get("access_token")
        if not tok:
            raise SystemExit("No se obtuvo access_token con AIKIDO_CLIENT_ID / AIKIDO_CLIENT_SECRET.")
        return tok

    def get(self, path, params=None):
        q = "?" + urllib.parse.urlencode(params) if params else ""
        req = urllib.request.Request(self.api + path + q,
                                     headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"})
        return self._call(req)


def fetch(cli, repo_id, types, status):
    params = {"format": "json", "filter_code_repo_id": repo_id}
    if status != "all":
        params["filter_status"] = status
    log(f"Exportando issues del repo {repo_id} ...")
    issues = [i for i in cli.get("/issues/export", params) if i.get("type") in types]
    log(f"  {len(issues)} issues de tipo {', '.join(types)}")
    groups = {}
    for n, i in enumerate(issues, 1):
        log(f"  detalle {n}/{len(issues)}", end="\r")
        d = cli.get(f"/issues/{i['id']}") or {}
        for k in ("how_to_fix", "issue_type_metadata", "reachability_status", "ignore_reasons", "snooze_reason"):
            if d.get(k) not in (None, "", []):
                i[k] = d[k]
        gid = i.get("group_id")
        if gid and gid not in groups:
            groups[gid] = cli.get(f"/issues/groups/{gid}") or {}
    log("")
    return issues, groups


def log(msg, end="\n"):
    print(msg, file=sys.stderr, end=end, flush=True)


# ----------------------------------------------------------------------- helpers
def esc(x):
    return html.escape("" if x is None else str(x))


def day(x):
    return dt.datetime.fromtimestamp(int(x)).strftime("%Y-%m-%d") if x else None


def lines_of(i):
    md = (i.get("issue_type_metadata") or {}).get(i.get("type")) or {}
    s = i.get("start_line") or md.get("start_line")
    e = i.get("end_line") or md.get("end_line") or s
    return s, e


def category(i):
    return i.get("rule") or "Sin regla"


def is_audited(i):
    # Equivalente al "audited" de Fortify: el issue ya fue revisado / gestionado en Aikido.
    return i.get("status") in ("closed", "ignored", "snoozed")


def package_of(path):
    d = os.path.dirname(path or "").replace("\\", "/").strip("/")
    return d.replace("/", ".") if d else "(raíz)"


FUNC_RE = [
    re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("),                                   # Python
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\("),                # JS/TS
    re.compile(r"^\s*(?:public|private|protected|internal)[\w<>\[\],\s]*?\s(\w+)\s*\("), # C# / Java
]


def read_source(src_dirs, i, ctx=3):
    """Devuelve (líneas [(n, texto, resaltada)], método contenedor) leyendo el repo local."""
    f, (s, e) = i.get("affected_file"), lines_of(i)
    if not f or not s:
        return None, None
    for d in src_dirs:
        path = os.path.join(d, f.lstrip("/\\"))
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read().splitlines()
        s, e = int(s), int(e or s)
        lo, hi = max(1, s - ctx), min(len(content), e + ctx)
        func = None
        for n in range(min(s, len(content)), 0, -1):
            for rx in FUNC_RE:
                m = rx.match(content[n - 1])
                if m:
                    func = m.group(1)
                    break
            if func:
                break
        return [(n, content[n - 1], s <= n <= e) for n in range(lo, hi + 1)], func
    return None, None


def md(text):
    """Markdown mínimo (how_to_fix) a HTML seguro."""
    out, code = [], False
    for line in str(text or "").splitlines():
        if line.strip().startswith("```"):
            out.append("</pre>" if code else "<pre class='fix'>")
            code = not code
            continue
        if code:
            out.append(esc(line))
            continue
        l = esc(line)
        l = re.sub(r"`([^`]+)`", r"<code>\1</code>", l)
        l = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", l)
        l = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r'<a href="\2">\1</a>', l)
        out.append(l + "<br>")
    if code:
        out.append("</pre>")
    return "\n".join(out)


# ------------------------------------------------------------------------ render
CSS = """
*{box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;color:#111;margin:0;background:#fff;font-size:13px}
.page{max-width:1000px;margin:0 auto;padding:28px 32px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:22px;margin:34px 0 8px}
.meta{color:#555;margin-bottom:16px;line-height:1.5}.meta b{color:#111}
p.lead{margin:0 0 12px;line-height:1.4;font-size:14px}
table{border-collapse:collapse;width:100%}
.sum th{background:#0a9ad7;color:#fff;font-size:15px;text-align:left;padding:5px 8px}
.sum th.c{text-align:center}.sum td{padding:4px 8px}
.sum td.n{text-align:right;width:92px}.sum tr:nth-child(odd) td{background:#ececec}
.sum tr.tot td{font-weight:bold;border-top:2px solid #0a9ad7;background:#fff}
.h-critical{background:#e0201b!important;color:#111!important}.h-high{background:#f27a1a!important;color:#111!important}
.h-medium{background:#f6b26b!important;color:#111!important}.h-low{background:#f1d04f!important;color:#111!important}
.eng{margin:26px 0 10px}.eng h3{font-size:16px;text-decoration:underline;margin:0 0 6px}
.eng th{text-align:right;padding:3px 8px}.eng th:first-child{text-align:left}
.eng td{padding:2px 8px;text-align:right}.eng td:first-child{text-align:left;width:45%}
.eng tr.tot td{font-weight:bold}.eng table{border-bottom:2px solid #c8d8e0}
.issue{margin:10px 0 34px;page-break-inside:avoid}
.bar{display:flex;gap:2px}.bar .t{flex:1;background:#0a9ad7;color:#fff;font-weight:bold;font-size:15px;padding:4px 8px}
.bar .s{width:170px;text-align:center;font-weight:bold;font-size:15px;padding:4px 8px}
.pkg{background:#808080;color:#fff;font-weight:bold;padding:4px 8px;margin-top:2px;font-size:14px}
.loc{background:#c8c8c8;font-weight:bold;padding:4px 8px;margin-top:2px;font-size:14px}
.sec{background:#d0d0d0;font-weight:bold;padding:4px 8px;margin:12px 0 6px 6px;font-size:14px;width:96%}
.kv{padding-left:40px;line-height:1.5}
.code{border:1px solid #ddd;margin:8px 0 0 6px;font-family:Consolas,"Courier New",monospace;font-size:12px}
.code div{display:flex;white-space:pre-wrap}.code .ln{width:40px;flex:none;background:#eee;font-weight:bold;padding:2px 6px}
.code .tx{padding:2px 6px;flex:1;background:#f6f6f6}.code .hl .tx{background:#fff3c4}
.desc{padding-left:40px;line-height:1.45}pre.fix{background:#f5f5f5;border:1px solid #ddd;padding:6px;white-space:pre-wrap}
code{background:#f0f0f0;padding:0 3px}.muted{color:#777}
@media print{.page{padding:0;max-width:none}h2.brk{page-break-before:always}}
"""


def render(issues, groups, opts, repo_name):
    by_cat = defaultdict(list)
    for i in issues:
        by_cat[category(i)].append(i)
    cats = sorted(by_cat, key=str.lower)

    def cell(lst, sev):
        sel = [i for i in lst if i.get("severity") == sev]
        return f"{sum(map(is_audited, sel))} / {len(sel)}" if sel else "0"

    H = []
    a = H.append
    title = opts.title or f"Reporte SAST — {repo_name}"
    a(f"<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>{esc(title)}</title><style>{CSS}</style></head><body><div class='page'>")
    a(f"<h1>{esc(title)}</h1>")
    st = Counter(i.get("status") for i in issues)
    a(f"<div class='meta'>Repositorio: <b>{esc(repo_name)}</b> (id {esc(opts.repo_id)}) · Motor: <b>Aikido {esc(', '.join(opts.types).upper())}</b> · "
      f"Generado: <b>{dt.datetime.now():%Y-%m-%d %H:%M}</b><br>Issues: <b>{len(issues)}</b> — "
      + ", ".join(f"{k}: <b>{v}</b>" for k, v in sorted(st.items())) + "</div>")

    # ---- Issue Breakdown by Category (tabla principal)
    a("<h2>Desglose de issues por categoría Aikido</h2>")
    a("<p class='lead'>La siguiente tabla resume todos los issues agrupados verticalmente por categoría (regla de Aikido). "
      "Para cada categoría se muestra el número de issues por severidad Aikido, incluyendo cuántos están auditados "
      "(cerrados, ignorados o pospuestos en Aikido).</p>")
    a("<table class='sum'><tr><th rowspan='2'>Categoría</th><th class='c' colspan='4'>Severidad Aikido (auditados/total)</th>"
      "<th class='c' rowspan='2'>Total<br>Issues</th></tr><tr>")
    a("".join(f"<th class='c h-{s}'>{SEV_LABEL[s]}</th>" for s in SEVERITIES) + "</tr>")
    for c in cats:
        lst = by_cat[c]
        a(f"<tr><td>{esc(c)}</td>" + "".join(f"<td class='n'>{cell(lst, s)}</td>" for s in SEVERITIES)
          + f"<td class='n'>{sum(map(is_audited, lst))} / {len(lst)}</td></tr>")
    a("<tr class='tot'><td>Total</td>" + "".join(f"<td class='n'>{cell(issues, s)}</td>" for s in SEVERITIES)
      + f"<td class='n'>{sum(map(is_audited, issues))} / {len(issues)}</td></tr></table>")

    # ---- Detalle por categoría
    a("<h2 class='brk'>Detalle de issues</h2>")
    for c in cats:
        lst = sorted(by_cat[c], key=lambda i: (SEVERITIES.index(i.get("severity", "low")), i.get("affected_file") or "", lines_of(i)[0] or 0))
        a(f"<div class='eng'><h3>Engine Breakdown</h3><table><tr><th></th>"
          + "".join(f"<th>{l}</th>" for _, l in ENGINES) + "<th>Total</th></tr>")
        row = "".join(f"<td>{sum(1 for i in lst if i.get('type') == t)}</td>" for t, _ in ENGINES)
        a(f"<tr><td>{esc(c)}</td>{row}<td>{len(lst)}</td></tr><tr class='tot'><td>Total</td>{row}<td>{len(lst)}</td></tr></table></div>")
        for i in lst:
            render_issue(a, i, groups.get(i.get("group_id")) or {}, opts)
    a("<p class='muted' style='margin-top:40px'>Generado con aikido_sast_report.py a partir de la API pública de Aikido Security.</p>")
    a("</div></body></html>")
    return "\n".join(H)


def render_issue(a, i, g, opts):
    sev = i.get("severity", "low")
    f = i.get("affected_file") or ""
    s, e = lines_of(i)
    rule = category(i)
    snippet, func = read_source(opts.src_dir, i)
    a("<div class='issue'>")
    a(f"<div class='bar'><div class='t'>{esc(rule)}</div><div class='s h-{sev}'>{SEV_LABEL.get(sev, sev)}</div></div>")
    a(f"<div class='pkg'>Package: {esc(package_of(f))}</div>")
    a(f"<div class='loc'>{esc(i.get('code_repo_name'))}/{esc(f)}{', line ' + str(s) if s else ''} ({esc(rule)})</div>")

    a("<div class='sec'>Issue Details</div><div class='kv'>")
    rows = [
        ("Kingdom", KINGDOM.get(i.get("type"), i.get("type"))),
        ("Scan Engine", f"Aikido {dict(ENGINES).get(i.get('type'), i.get('type'))}"),
        ("Estado", i.get("status") + (" (" + "; ".join(r.get("reason") or r.get("kind") or "" if isinstance(r, dict) else str(r) for r in i["ignore_reasons"]) + ")" if i.get("ignore_reasons") else "")),
        ("Severity score", f"{i.get('severity_score')}/100"),
        ("CWE", ", ".join(i.get("cwe_classes") or [])),
        ("Lenguaje", LANG.get(i.get("programming_language"), i.get("programming_language"))),
        ("Rama", i.get("code_repo_branch_name")),
        ("Detectado", day(i.get("first_detected_at"))),
        ("SLA (remediar antes de)", day(i.get("sla_remediate_by"))),
        ("Issue ID", i.get("id")),
    ]
    for k, v in rows:
        if v:
            a(f"<b>{esc(k)}:</b> {esc(v)}<br>")
    a("</div>")

    a("<div class='sec'>Sink Details</div><div class='kv'>")
    if func:
        a(f"<b>Enclosing Method:</b> {esc(func)}()<br>")
    a(f"<b>File:</b> {esc(i.get('code_repo_name'))}/{esc(f)}{':' + str(s) if s else ''}"
      + (f" (líneas {s}-{e})" if e and s and e != s else "") + "<br></div>")
    if snippet:
        a("<div class='code'>")
        for n, t, hl in snippet:
            a(f"<div class='{'hl' if hl else ''}'><span class='ln'>{n}</span><span class='tx'>{esc(t) or ' '}</span></div>")
        a("</div>")
    elif opts.src_dir:
        a("<div class='kv muted'>(archivo no encontrado en --src-dir)</div>")

    fix = i.get("how_to_fix") or g.get("how_to_fix")
    if fix:
        a(f"<div class='sec'>Recomendación</div><div class='desc'>{md(fix)}</div>")
    a("</div>")


# -------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Reporte SAST estilo Fortify de un repositorio de Aikido")
    ap.add_argument("--repo-id", type=int, required=True, help="ID del repositorio en Aikido (ej. 3030745)")
    ap.add_argument("--types", default="sast", help="Tipos de issue separados por coma (default: sast)")
    ap.add_argument("--status", default="all", choices=["all", "open", "ignored", "snoozed", "closed"])
    ap.add_argument("--src-dir", action="append", default=[], help="Clon local del repo para mostrar el código (repetible)")
    ap.add_argument("--region", choices=REGIONS, default=os.getenv("AIKIDO_REGION", "eu"))
    ap.add_argument("--title")
    ap.add_argument("-o", "--output")
    ap.add_argument("--json-out", help="Guarda también los datos crudos en JSON")
    ap.add_argument("--from-json", help="Genera el reporte desde un JSON guardado con --json-out (sin llamar a la API)")
    opts = ap.parse_args()
    opts.types = [t.strip() for t in opts.types.split(",") if t.strip()]

    if opts.from_json:
        with open(opts.from_json, encoding="utf-8") as fh:
            data = json.load(fh)
        issues, groups = data["issues"], {int(k): v for k, v in data["groups"].items()}
    else:
        token = os.getenv("AIKIDO_TOKEN")
        cid, sec = os.getenv("AIKIDO_CLIENT_ID"), os.getenv("AIKIDO_CLIENT_SECRET")
        if not token and not (cid and sec):
            raise SystemExit("Define AIKIDO_TOKEN, o AIKIDO_CLIENT_ID y AIKIDO_CLIENT_SECRET.")
        cli = Aikido(opts.region, token, cid, sec)
        issues, groups = fetch(cli, opts.repo_id, opts.types, opts.status)

    repo_name = next((i["code_repo_name"] for i in issues if i.get("code_repo_name")), str(opts.repo_id))
    if opts.json_out:
        with open(opts.json_out, "w", encoding="utf-8") as fh:
            json.dump({"issues": issues, "groups": {str(k): v for k, v in groups.items()}}, fh, indent=2, ensure_ascii=False)
    out = opts.output or f"reporte_sast_{repo_name}.html"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render(issues, groups, opts, repo_name))
    log(f"Reporte generado: {os.path.abspath(out)}  ({len(issues)} issues)")


if __name__ == "__main__":
    main()
