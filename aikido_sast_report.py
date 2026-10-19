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

    def _build_validated_url(self, base_url: str, path: str, params=None) -> str:
        try:
            # Minimal path validation
            if "/../" in path or re.search(r"/%2e%2e/", path, re.IGNORECASE):
                raise ValueError("Invalid path")
            
            parsed = urllib.parse.urlparse(base_url)
            
            # Rebuild path from base path + validated user path
            parsed = parsed._replace(path=parsed.path + path)
            
            # Add query parameters
            if params:
                parsed = parsed._replace(query=urllib.parse.urlencode(params))
            
            return urllib.parse.urlunparse(parsed)
        except Exception:
            raise ValueError("Invalid URL")
    
    def get(self, path, params=None):
        url = self._build_validated_url(self.api, path, params)
        req = urllib.request.Request(url,
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
        base_real = os.path.realpath(d)
        target_real = os.path.realpath(path)
        if os.path.commonpath([base_real, target_real]) != base_real:
            raise Exception("Invalid file path")
        with open(target_real, encoding="utf-8", errors="replace") as fh:
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
:root{--bg:#f6f6fa;--card:#fff;--line:#e7e7f0;--ink:#16162a;--muted:#6b6b85;--brand:#6551f3;--brand-soft:#efedfe;
--critical:#d92d20;--high:#f26b1d;--medium:#f2b705;--low:#8a8fa3}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Inter,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
-webkit-print-color-adjust:exact;print-color-adjust:exact}
.top{background:#141428;color:#fff}
.top .in{max-width:1040px;margin:0 auto;padding:22px 24px;display:flex;align-items:center;gap:14px}
.logo{width:34px;height:34px;border-radius:9px;background:var(--brand);display:grid;place-items:center;font-weight:800;font-size:18px}
.top .brand{font-weight:700;font-size:15px;opacity:.9}.top .sub{font-size:12px;opacity:.6}
.page{max-width:1040px;margin:0 auto;padding:24px}
h1{font-size:24px;margin:0 0 4px;letter-spacing:-.01em}
.meta{color:var(--muted);font-size:13px;margin-bottom:20px}.meta b{color:var(--ink);font-weight:600}
h2{font-size:17px;margin:30px 0 12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.kpi{padding:14px 16px}.kpi .l{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:6px}
.kpi .v{font-size:28px;font-weight:700;margin-top:2px}.kpi .x{font-size:12px;color:var(--muted)}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.d-critical{background:var(--critical)}.d-high{background:var(--high)}.d-medium{background:var(--medium)}.d-low{background:var(--low)}
.lead{color:var(--muted);font-size:13px;margin:-4px 0 12px}
table{border-collapse:collapse;width:100%}
.sum{overflow:hidden}.sum th{font-size:12px;font-weight:600;color:var(--muted);text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);background:#fafafd}
.sum th.c,.sum td.n{text-align:center}.sum td{padding:10px 14px;border-bottom:1px solid var(--line)}
.sum tr:last-child td{border-bottom:0}.sum tr.tot td{font-weight:700;background:#fafafd}
.sum td.n{width:96px;color:var(--muted)}.sum td.n.has{color:var(--ink);font-weight:600}
.sum a{color:inherit;text-decoration:none}.sum a:hover{color:var(--brand)}
.badge{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;white-space:nowrap}
.b-critical{background:#fde7e5;color:var(--critical)}.b-high{background:#fdeee4;color:#c4520f}
.b-medium{background:#fdf5d8;color:#9a7300}.b-low{background:#eef0f4;color:#5b6075}
.chip{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:1px 8px;font-size:12px;color:var(--muted);background:#fff}
.st-open{color:var(--brand);border-color:#d6d0fd;background:var(--brand-soft)}
.cat{margin:34px 0 10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.cat h3{margin:0;font-size:16px}
.issue{margin:0 0 14px;page-break-inside:avoid;overflow:hidden}
.ih{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.ih .t{font-weight:600;flex:1;min-width:240px}.ih .f{font-family:Consolas,"SFMono-Regular",monospace;font-size:12.5px;color:var(--muted)}
.ib{display:grid;grid-template-columns:260px 1fr}
.side{padding:14px 16px;border-right:1px solid var(--line);font-size:13px}
.side div{display:flex;justify-content:space-between;gap:8px;padding:3px 0}.side span{color:var(--muted)}
.side b{font-weight:600;text-align:right}
.main{padding:14px 16px;min-width:0}
.lbl{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:0 0 6px}
.code{border-radius:8px;overflow:hidden;background:#141428;color:#e6e6f0;font:12.5px/1.55 Consolas,"SFMono-Regular",monospace;margin-bottom:14px}
.code .hd{background:#1f1f38;color:#a9a9c6;padding:6px 12px;font-size:12px}
.code .r{display:flex;white-space:pre-wrap}.code .ln{width:44px;flex:none;text-align:right;padding:0 10px;color:#6f6f92}
.code .tx{flex:1;padding-right:12px}.code .hl{background:rgba(242,107,29,.22)}.code .hl .ln{color:#fff;box-shadow:inset 3px 0 0 var(--high)}
.fix{background:var(--brand-soft);border-radius:8px;padding:10px 12px;font-size:13px}
.fix pre{background:#fff;border:1px solid var(--line);border-radius:6px;padding:8px;white-space:pre-wrap}
code{background:#ececf6;border-radius:4px;padding:0 4px;font-size:12.5px}
.muted{color:var(--muted)}.foot{color:var(--muted);font-size:12px;margin:40px 0 10px;text-align:center}
@media (max-width:760px){.kpis{grid-template-columns:repeat(2,1fr)}.ib{grid-template-columns:1fr}.side{border-right:0;border-bottom:1px solid var(--line)}
.sum{overflow-x:auto}.sum table{min-width:620px}}
@media print{body{background:#fff}.page{padding:0 8px}.cat{page-break-before:auto}}
"""


def render(issues, groups, opts, repo_name):
    by_cat = defaultdict(list)
    for i in issues:
        by_cat[category(i)].append(i)

    def worst(c):
        return min(SEVERITIES.index(i.get("severity", "low")) for i in by_cat[c])

    cats = sorted(by_cat, key=lambda c: (worst(c), c.lower()))
    anchor = {c: f"cat-{n}" for n, c in enumerate(cats, 1)}

    def cell(lst, sev):
        sel = [i for i in lst if i.get("severity") == sev]
        if not sel:
            return "<td class='n'>–</td>"
        return f"<td class='n has'>{sum(map(is_audited, sel))} / {len(sel)}</td>"

    H = []
    a = H.append
    title = opts.title or f"Reporte SAST — {repo_name}"
    a(f"<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>{esc(title)}</title><style>{CSS}</style></head><body>")
    a("<div class='top'><div class='in'><div class='logo'>A</div><div><div class='brand'>Aikido Security</div>"
      "<div class='sub'>Reporte de vulnerabilidades por repositorio</div></div></div></div><div class='page'>")
    a(f"<h1>{esc(title)}</h1>")
    a(f"<div class='meta'>Repositorio <b>{esc(repo_name)}</b> · ID <b>{esc(opts.repo_id)}</b> · Escáner <b>{esc(', '.join(opts.types).upper())}</b> · "
      f"Generado <b>{dt.datetime.now():%Y-%m-%d %H:%M}</b></div>")

    # ---- KPIs
    st = Counter(i.get("status") for i in issues)
    a("<div class='kpis'>")
    a(f"<div class='card kpi'><div class='l'>Total issues</div><div class='v'>{len(issues)}</div>"
      f"<div class='x'>{st.get('open', 0)} abiertos · {sum(map(is_audited, issues))} gestionados</div></div>")
    for s in SEVERITIES:
        sel = [i for i in issues if i.get("severity") == s]
        a(f"<div class='card kpi'><div class='l'><span class='dot d-{s}'></span>{SEV_LABEL[s]}</div><div class='v'>{len(sel)}</div>"
          f"<div class='x'>{sum(1 for i in sel if i.get('status') == 'open')} abiertos</div></div>")
    a("</div>")

    # ---- Tabla por categoría
    a("<h2>Issues por categoría</h2>")
    a("<p class='lead'>Cada celda muestra <b>gestionados / total</b> (gestionado = cerrado, ignorado o pospuesto en Aikido).</p>")
    a("<div class='card sum'><table><tr><th>Categoría</th>"
      + "".join(f"<th class='c'><span class='badge b-{s}'>{SEV_LABEL[s]}</span></th>" for s in SEVERITIES)
      + "<th class='c'>Total</th></tr>")
    for c in cats:
        lst = by_cat[c]
        a(f"<tr><td><a href='#{anchor[c]}'>{esc(c)}</a></td>" + "".join(cell(lst, s) for s in SEVERITIES)
          + f"<td class='n has'>{sum(map(is_audited, lst))} / {len(lst)}</td></tr>")
    a("<tr class='tot'><td>Total</td>" + "".join(cell(issues, s) for s in SEVERITIES)
      + f"<td class='n has'>{sum(map(is_audited, issues))} / {len(issues)}</td></tr></table></div>")

    # ---- Detalle
    a("<h2>Detalle de issues</h2>")
    for c in cats:
        lst = sorted(by_cat[c], key=lambda i: (SEVERITIES.index(i.get("severity", "low")), i.get("affected_file") or "", lines_of(i)[0] or 0))
        engines = Counter(dict(ENGINES).get(i.get("type"), i.get("type")) for i in lst)
        sev = SEVERITIES[worst(c)]
        a(f"<div class='cat' id='{anchor[c]}'><span class='badge b-{sev}'><span class='dot d-{sev}'></span>{SEV_LABEL[sev]}</span>"
          f"<h3>{esc(c)}</h3><span class='chip'>{len(lst)} issue{'s' if len(lst) != 1 else ''}</span>"
          + "".join(f"<span class='chip'>{esc(k)}: {v}</span>" for k, v in engines.items()) + "</div>")
        for i in lst:
            render_issue(a, i, groups.get(i.get("group_id")) or {}, opts)
    a("<div class='foot'>Generado con aikido_sast_report.py a partir de la API pública de Aikido Security.</div>")
    a("</div></body></html>")
    return "\n".join(H)


STATUS_LABEL = {"open": "Abierto", "closed": "Cerrado", "ignored": "Ignorado", "snoozed": "Pospuesto"}


def render_issue(a, i, g, opts):
    sev = i.get("severity", "low")
    f = i.get("affected_file") or ""
    s, e = lines_of(i)
    status = i.get("status") or ""
    snippet, func = read_source(opts.src_dir, i)
    a("<div class='card issue'>")
    a(f"<div class='ih'><span class='badge b-{sev}'><span class='dot d-{sev}'></span>{SEV_LABEL.get(sev, sev)} · {esc(i.get('severity_score'))}</span>"
      f"<span class='t'>{esc(category(i))}</span>"
      f"<span class='f'>{esc(f)}{':' + str(s) if s else ''}</span>"
      f"<span class='chip{' st-open' if status == 'open' else ''}'>{esc(STATUS_LABEL.get(status, status))}</span></div>")

    reasons = "; ".join(r.get("reason") or r.get("kind") or "" if isinstance(r, dict) else str(r) for r in i.get("ignore_reasons") or [])
    rows = [
        ("Tipo", KINGDOM.get(i.get("type"), i.get("type"))),
        ("Escáner", f"Aikido {dict(ENGINES).get(i.get('type'), i.get('type'))}"),
        ("CWE", ", ".join(i.get("cwe_classes") or [])),
        ("Lenguaje", LANG.get(i.get("programming_language"), i.get("programming_language"))),
        ("Rama", i.get("code_repo_branch_name")),
        ("Paquete", package_of(f)),
        ("Función", f"{func}()" if func else None),
        ("Detectado", day(i.get("first_detected_at"))),
        ("SLA", day(i.get("sla_remediate_by"))),
        ("Motivo", reasons),
        ("Issue ID", i.get("id")),
    ]
    a("<div class='ib'><div class='side'>")
    for k, v in rows:
        if v:
            a(f"<div><span>{esc(k)}</span><b>{esc(v)}</b></div>")
    a("</div><div class='main'>")

    a("<div class='lbl'>Código afectado</div>")
    if snippet:
        a(f"<div class='code'><div class='hd'>{esc(i.get('code_repo_name'))}/{esc(f)}"
          + (f" · líneas {s}-{e}" if e and s and e != s else (f" · línea {s}" if s else "")) + "</div>")
        for n, t, hl in snippet:
            a(f"<div class='r{' hl' if hl else ''}'><span class='ln'>{n}</span><span class='tx'>{esc(t) or ' '}</span></div>")
        a("</div>")
    else:
        a(f"<p class='muted'>{esc(i.get('code_repo_name'))}/{esc(f)}{':' + str(s) if s else ''}"
          + (" — archivo no encontrado en --src-dir" if opts.src_dir else "") + "</p>")

    fix = i.get("how_to_fix") or g.get("how_to_fix")
    if fix:
        a(f"<div class='lbl'>Cómo corregirlo</div><div class='fix'>{md(fix)}</div>")
    a("</div></div></div>")


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
