#!/usr/bin/env python3
"""
Reporte SCA (dependencias / librerías) de UN repositorio de Aikido Security, con el estilo de la vista
"Open Source" de Aikido: por archivo de dependencias, una fila por librería con su severidad, CVEs y la
versión a la que hay que actualizar.

Reutiliza el cliente de la API y los estilos de aikido_sast_report.py (debe estar en la misma carpeta).

Endpoints:
  GET /api/public/v1/issues/export?filter_code_repo_id=...&filter_issue_type=open_source
  GET /api/public/v1/issues/groups/{id}      (título y tiempo estimado de corrección)

Ejemplo:
  $env:AIKIDO_CLIENT_ID="..."; $env:AIKIDO_CLIENT_SECRET="..."
  python aikido_sca_report.py --repo-id 3030745
"""
import argparse
import datetime as dt
import json
import os
import re
from collections import Counter, defaultdict

from aikido_sast_report import CSS as BASE_CSS, REGIONS, SEVERITIES, SEV_LABEL, client_from_env, day, esc, log

STATUS_LABEL = {"open": "Abierto", "closed": "Cerrado", "ignored": "Ignorado", "snoozed": "Pospuesto"}
EXPLOIT = {"actively_exploited": "Explotada activamente", "poc_exists": "Existe PoC", "no_known_exploit": "Sin exploit conocido"}


# ----------------------------------------------------------------------- datos
def fetch(cli, repo_id, status, with_groups):
    params = {"format": "json", "filter_code_repo_id": repo_id, "filter_issue_type": "open_source"}
    if status != "all":
        params["filter_status"] = status
    log(f"Exportando issues SCA del repo {repo_id} ...")
    issues = [i for i in cli.get("/issues/export", params) if i.get("type") == "open_source"]
    log(f"  {len(issues)} vulnerabilidades")
    groups = {}
    if with_groups:
        gids = sorted({i["group_id"] for i in issues if i.get("group_id")})
        for n, gid in enumerate(gids, 1):
            log(f"  grupo {n}/{len(gids)}", end="\r")
            groups[gid] = cli.get(f"/issues/groups/{gid}") or {}
        log("")
    return issues, groups


def scope(issues, opts):
    """Deja solo lo del repo pedido, en la rama pedida y (por defecto) sin lo de la imagen de contenedor."""
    repo = [i for i in issues if i.get("code_repo_id") == opts.repo_id]
    if not opts.include_container:
        container = sum(1 for i in repo if i.get("container_repo_id"))
        repo = [i for i in repo if not i.get("container_repo_id")]
        if container:
            log(f"  {container} vulnerabilidades de la imagen de contenedor excluidas (usa --include-container para verlas)")
    branches = Counter(i.get("code_repo_branch_name") for i in repo)
    kept = [i for i in repo if i.get("code_repo_branch_name") == opts.branch]
    if repo and not kept:
        raise SystemExit(f"No hay vulnerabilidades en la rama '{opts.branch}' del repo {opts.repo_id}. "
                         f"Ramas encontradas: {', '.join(f'{b} ({n})' for b, n in branches.items())}")
    log(f"  {len(kept)} vulnerabilidades del repo {opts.repo_id} en la rama '{opts.branch}'")
    return kept


def vkey(v):
    """Clave ordenable para versiones tipo 1.26.17, 3.5.7-1~deb13u3, >3.11.4."""
    return tuple(int(x) for x in re.findall(r"\d+", str(v or "")))


def fixed_version(i):
    """Menor versión parcheada que sea mayor a la instalada (los avisos suelen listar una por rama)."""
    inst = vkey(i.get("installed_version"))
    cands = [p.strip().lstrip("<>=~^ ") for p in i.get("patched_versions") or [] if p and p.strip()]
    newer = [p for p in cands if vkey(p) > inst]
    return min(newer or cands, key=vkey) if cands else None


def manifest_of(i):
    # Aikido reporta rutas de la imagen a veces con y a veces sin "/" inicial: se normalizan para agruparlas.
    f = i.get("affected_file") or "(sin archivo)"
    rel = f.lstrip("/")
    return "/" + rel if rel.startswith(("usr/", "var/", "opt/", "lib/", "etc/")) else f


def origin_of(path):
    if path.endswith("/var/lib/dpkg/status") or path.startswith("/var/lib/"):
        return "Paquetes del sistema operativo (imagen Docker)"
    if path.startswith("/"):
        return "Librerías instaladas en la imagen Docker"
    return "Archivo de dependencias del repositorio"


def sev_rank(i):
    return (SEVERITIES.index(i.get("severity", "low")), -(i.get("severity_score") or 0))


def build(issues):
    """{manifest: [paquete, ...]} con cada paquete = dict(nombre, versión, vulns, severidad, fix...)."""
    tree = defaultdict(lambda: defaultdict(list))
    for i in issues:
        tree[manifest_of(i)][(i.get("affected_package") or "?").lower()].append(i)
    out = {}
    for mf, pkgs in tree.items():
        rows = []
        for vulns in pkgs.values():
            vulns.sort(key=sev_rank)
            fixes = [f for f in map(fixed_version, vulns) if f]
            rows.append({
                "name": vulns[0].get("affected_package"),
                "installed": sorted({v.get("installed_version") for v in vulns if v.get("installed_version")}, key=vkey),
                "vulns": vulns,
                "severity": vulns[0].get("severity", "low"),
                "score": vulns[0].get("severity_score") or 0,
                "upgrade": max(fixes, key=vkey) if fixes else None,
                "no_fix": sum(1 for v in vulns if not fixed_version(v)),
                "open": sum(1 for v in vulns if v.get("status") == "open"),
            })
        rows.sort(key=lambda r: (SEVERITIES.index(r["severity"]), -r["score"], r["name"].lower()))
        out[mf] = rows
    # Primero los archivos del repo (requirements.txt, package.json...), luego los de la imagen
    return dict(sorted(out.items(), key=lambda kv: (kv[0].startswith("/"), min(SEVERITIES.index(r["severity"]) for r in kv[1]), kv[0])))


# ---------------------------------------------------------------------- render
CSS = BASE_CSS + """
.mf{margin:28px 0 0}
.mfh{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:14px 16px;border-bottom:1px solid var(--line)}
.mfh .p{font-weight:700;font-family:Consolas,"SFMono-Regular",monospace;font-size:13.5px;word-break:break-all}
.mfh .sep{color:var(--line)}.mfh .o{color:var(--muted);font-size:12px;margin-left:auto}
.pk th{font-size:12px;font-weight:600;color:var(--muted);text-align:left;padding:10px 16px;border-bottom:1px solid var(--line);background:#fafafd}
.pk td{padding:12px 16px;border-bottom:1px solid var(--line);vertical-align:middle}
.pk tr:last-child td{border-bottom:0}
.pk td.sv{width:130px;text-align:center}.pk td.sv.s-critical{background:#fff4f3}
.pk .nm{font-weight:600}.pk .nm a{color:inherit;text-decoration:none}.pk .nm a:hover{color:var(--brand)}
.pk .ds{color:var(--muted);font-size:12.5px;max-width:330px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cve{font-size:13px;line-height:1.6}.cve div{white-space:nowrap}
.up{display:inline-flex;align-items:center;gap:6px;border:1px solid #f5c79f;color:#8a4a12;border-radius:999px;padding:2px 10px;font-size:12.5px;font-weight:600;white-space:nowrap}
.up.none{border-color:var(--line);color:var(--muted);font-weight:500}
.vd{margin:22px 0 10px;overflow:hidden;page-break-inside:avoid}
.vd .h{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line)}
.vd .h .n{font-weight:700;font-size:15px}.vd .h .m{color:var(--muted);font-size:12.5px}
.vt th{font-size:11.5px;font-weight:600;color:var(--muted);text-align:left;padding:8px 16px;background:#fafafd;border-bottom:1px solid var(--line)}
.vt td{padding:8px 16px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}.vt tr:last-child td{border-bottom:0}
.vt .t{color:var(--muted);font-size:12px}
@media (max-width:760px){.mf,.vd{overflow-x:auto}.pk,.vt{min-width:720px}}
"""


def sev_badge(s, score=None):
    return (f"<span class='badge b-{s}'><span class='dot d-{s}'></span>{SEV_LABEL.get(s, s)}"
            + (f" · {score}" if score is not None else "") + "</span>")


def status_chip(s):
    return f"<span class='chip{' st-open' if s == 'open' else ''}'>{esc(STATUS_LABEL.get(s, s))}</span>"


def render(tree, issues, groups, opts, repo_name, branch):
    H = []
    a = H.append
    title = opts.title or f"Reporte SCA — {repo_name}"
    a(f"<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>{esc(title)}</title><style>{CSS}</style></head><body>")
    a("<div class='top'><div class='in'><div class='logo'>A</div><div><div class='brand'>Aikido Security</div>"
      "<div class='sub'>Reporte de dependencias vulnerables (SCA)</div></div></div></div><div class='page'>")
    a(f"<h1>{esc(title)}</h1>")
    filt = "solo abiertas" if opts.status == "open" else ("todas" if opts.status == "all" else opts.status)
    a(f"<div class='meta'>Repositorio <b>{esc(repo_name)}</b> · ID <b>{esc(opts.repo_id)}</b> · Rama <b>{esc(branch or '—')}</b> · "
      f"Vulnerabilidades: <b>{esc(filt)}</b> · Generado <b>{dt.datetime.now():%Y-%m-%d %H:%M}</b></div>")

    # ---- KPIs
    pkgs = [p for rows in tree.values() for p in rows]
    a("<div class='kpis'>")
    a(f"<div class='card kpi'><div class='l'>Librerías vulnerables</div><div class='v'>{len(pkgs)}</div>"
      f"<div class='x'>{len(issues)} vulnerabilidades · {len(tree)} archivo{'s' if len(tree) != 1 else ''}</div></div>")
    for s in SEVERITIES:
        n = sum(1 for p in pkgs if p["severity"] == s)
        v = sum(1 for i in issues if i.get("severity") == s)
        a(f"<div class='card kpi'><div class='l'><span class='dot d-{s}'></span>{SEV_LABEL[s]}</div><div class='v'>{n}</div>"
          f"<div class='x'>librerías · {v} vulnerabilidades</div></div>")
    a("</div>")
    a("<p class='lead' style='margin-top:12px'>La severidad de cada librería es la de su vulnerabilidad más grave. "
      "<b>Actualizar a</b> es la versión mínima que corrige todas sus vulnerabilidades con parche disponible.</p>")

    # ---- Tablas por archivo de dependencias (vista principal)
    a("<h2>Librerías afectadas</h2>")
    for mf, rows in tree.items():
        a(f"<div class='card mf'><div class='mfh'><span class='p'>{esc(mf)}</span><span class='sep'>|</span>"
          f"<span>{esc(repo_name)}</span>" + (f"<span class='chip'>{esc(branch)}</span>" if branch else "")
          + f"<span class='o'>{esc(origin_of(mf))} · {len(rows)} librerías</span></div>")
        a("<table class='pk'><tr><th>Nombre</th><th style='text-align:center'>Severidad</th><th>CVE</th>"
          "<th>Actualizar a</th></tr>")
        for p in rows:
            n = len(p["vulns"])
            g = groups.get(p["vulns"][0].get("group_id")) or {}
            desc = (g.get("title") if n == 1 and g.get("title") and g.get("title") != p["name"] else None) \
                or f"Esta librería tiene {n} vulnerabilidad{'es' if n != 1 else ''}"
            ids = [v.get("cve_id") for v in p["vulns"] if v.get("cve_id")]
            inst = ", ".join(p["installed"]) or "?"
            up = (f"<span class='up'>⚠ {esc(inst)} → {esc(p['upgrade'])}</span>" if p["upgrade"]
                  else "<span class='up none'>Sin versión corregida</span>")
            a(f"<tr><td><div class='nm'><a href='#{anchor(mf, p)}'>{esc(p['name'])}</a></div><div class='ds'>{esc(desc)}</div></td>"
              f"<td class='sv s-{p['severity']}'>{sev_badge(p['severity'])}</td>"
              f"<td class='cve'>{''.join(f'<div>{esc(x)}</div>' for x in ids) or '—'}</td>"
              f"<td>{up}</td></tr>")
        a("</table></div>")

    # ---- Detalle por librería
    if not opts.no_detail:
        a("<h2 style='margin-top:40px'>Detalle de vulnerabilidades por librería</h2>")
        for mf, rows in tree.items():
            for p in rows:
                a(f"<div class='card vd' id='{anchor(mf, p)}'><div class='h'>{sev_badge(p['severity'])}"
                  f"<span class='n'>{esc(p['name'])}</span><span class='m'>{esc(', '.join(p['installed']) or '?')} · {esc(mf)}</span>"
                  + (f"<span class='up' style='margin-left:auto'>Actualizar a {esc(p['upgrade'])}</span>" if p["upgrade"] else "")
                  + "</div>")
                a("<table class='vt'><tr><th>CVE</th><th>Severidad</th><th>Corregida en</th><th>CWE</th>"
                  "<th>Explotabilidad</th><th>Estado</th><th>SLA</th></tr>")
                for v in p["vulns"]:
                    a(f"<tr><td><b>{esc(v.get('cve_id') or '—')}</b></td><td>{sev_badge(v.get('severity', 'low'), v.get('severity_score'))}</td>"
                      f"<td>{esc(fixed_version(v) or 'Sin parche')}</td>"
                      f"<td class='t'>{esc(', '.join(v.get('cwe_classes') or []) or '—')}</td>"
                      f"<td class='t'>{esc(EXPLOIT.get(v.get('exploitability'), v.get('exploitability') or '—'))}</td>"
                      f"<td>{status_chip(v.get('status'))}</td><td class='t'>{esc(day(v.get('sla_remediate_by')) or '—')}</td></tr>")
                a("</table></div>")

    a("<div class='foot'>Generado con aikido_sca_report.py a partir de la API pública de Aikido Security.</div>")
    a("</div></body></html>")
    return "\n".join(H)


def anchor(mf, p):
    return "pkg-" + re.sub(r"[^a-z0-9]+", "-", f"{mf}-{p['name']}".lower()).strip("-")


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="Reporte SCA (librerías vulnerables) de un repositorio de Aikido")
    ap.add_argument("--repo-id", type=int, required=True, help="ID del repositorio en Aikido (ej. 3030745)")
    ap.add_argument("--status", default="open", choices=["all", "open", "ignored", "snoozed", "closed"],
                    help="Estado de las vulnerabilidades (default: open, igual que la vista de Aikido)")
    ap.add_argument("--branch", default="main", help="Rama del repositorio (default: main)")
    ap.add_argument("--include-container", action="store_true",
                    help="Incluir también lo que Aikido detectó en la imagen de contenedor ligada al repo")
    ap.add_argument("--no-groups", action="store_true", help="No consultar /issues/groups (sin descripción corta de la librería)")
    ap.add_argument("--no-detail", action="store_true", help="Omitir la sección de detalle por librería")
    ap.add_argument("--region", choices=REGIONS, default=os.getenv("AIKIDO_REGION", "eu"))
    ap.add_argument("--title")
    ap.add_argument("-o", "--output")
    ap.add_argument("--json-out", help="Guarda también los datos crudos en JSON")
    ap.add_argument("--from-json", help="Genera el reporte desde un JSON guardado con --json-out (sin llamar a la API)")
    opts = ap.parse_args()

    if opts.from_json:
        with open(opts.from_json, encoding="utf-8") as fh:
            data = json.load(fh)
        issues = [i for i in data["issues"] if i.get("type") == "open_source"
                  and (opts.status == "all" or i.get("status") == opts.status)]
        groups = {int(k): v for k, v in (data.get("groups") or {}).items()}
    else:
        cli = client_from_env(opts.region)
        issues, groups = fetch(cli, opts.repo_id, opts.status, not opts.no_groups)

    issues = scope(issues, opts)
    repo_name = next((i["code_repo_name"] for i in issues if i.get("code_repo_name")), str(opts.repo_id))
    branch = opts.branch

    if opts.json_out:
        with open(opts.json_out, "w", encoding="utf-8") as fh:
            json.dump({"issues": issues, "groups": {str(k): v for k, v in groups.items()}}, fh, indent=2, ensure_ascii=False)
    tree = build(issues)
    out = opts.output or f"reporte_sca_{repo_name}.html"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render(tree, issues, groups, opts, repo_name, branch))
    log(f"Reporte generado: {os.path.abspath(out)}  ({sum(len(r) for r in tree.values())} librerías, {len(issues)} vulnerabilidades)")


if __name__ == "__main__":
    main()
