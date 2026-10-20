#!/usr/bin/env python3
"""
Reporte DAST de UN dominio de Aikido Security (escaneo de superficie / "Domains & APIs").

Se elige el dominio por su ID (--domain-id) o por su nombre (--domain). Todo sale de la API de Aikido.

Endpoints:
  GET /api/public/v1/domains                                         datos del dominio (tipo de escaneo, último escaneo)
  GET /api/public/v1/issues/export?filter_domain_id=...&filter_issue_type=surface_monitoring
  GET /api/public/v1/issues/{id}                                     URL afectada, evidencia, cómo corregirlo
  GET /api/public/v1/issues/groups/{id}                              título y tiempo estimado

Ejemplo:
  $env:AIKIDO_CLIENT_ID="..."; $env:AIKIDO_CLIENT_SECRET="..."
  python aikido_dast_report.py --domain-id 148121
  python aikido_dast_report.py --domain vulnlab-dast.onrender.com

Reutiliza el cliente de la API y los estilos de aikido_sast_report.py (debe estar en la misma carpeta).
"""
import argparse
import datetime as dt
import json
import os
import time
from collections import Counter, defaultdict

from aikido_sast_report import (CSS as BASE_CSS, REGIONS, SEVERITIES, SEV_LABEL, STATUS_LABEL, client_from_env, day, esc, log, md)

KIND = {"front_end": "Aplicación web (front-end)", "rest_api": "API REST", "graphql_api": "API GraphQL", "hosted": "Dominio alojado"}


# ----------------------------------------------------------------------- datos
def norm(d):
    d = (d or "").strip().lower()
    for p in ("https://", "http://"):
        d = d[len(p):] if d.startswith(p) else d
    return d.rstrip("/")


def list_domains(cli):
    out, page = [], 0
    while True:
        batch = cli.get("/domains", {"page": page, "per_page": 100}) or []
        out += batch
        if len(batch) < 100:
            return out
        page += 1


def resolve_domain(cli, domain_id, name):
    domains = list_domains(cli)
    if domain_id:
        found = [d for d in domains if d.get("id") == domain_id]
    else:
        found = [d for d in domains if norm(d.get("domain")) == norm(name)] \
            or [d for d in domains if norm(name) in norm(d.get("domain"))]
    if len(found) == 1:
        return found[0]
    listado = "\n".join(f"  {d.get('id')}  {d.get('domain')}  ({d.get('kind')})" for d in domains)
    if not found:
        if domain_id:  # puede existir aunque no esté activo; se sigue solo con el ID
            log(f"  aviso: el dominio {domain_id} no aparece en /domains; se continúa solo con el ID")
            return {"id": domain_id}
        raise SystemExit(f"No se encontró el dominio '{name}'. Dominios disponibles:\n{listado}")
    raise SystemExit(f"'{name}' coincide con varios dominios; usa --domain-id:\n"
                     + "\n".join(f"  {d.get('id')}  {d.get('domain')}" for d in found))


def fetch(cli, domain, types, status):
    params = {"format": "json", "filter_domain_id": domain["id"]}
    if len(types) == 1:
        params["filter_issue_type"] = types[0]
    if status != "all":
        params["filter_status"] = status
    log(f"Exportando issues DAST del dominio {domain['id']} ...")
    issues = [i for i in cli.get("/issues/export", params) or []
              if i.get("type") in types and i.get("domain_id") == domain["id"]]
    log(f"  {len(issues)} issues")
    groups = {}
    for n, i in enumerate(issues, 1):
        log(f"  detalle {n}/{len(issues)}", end="\r")
        d = cli.get(f"/issues/{i['id']}") or {}
        for k in ("how_to_fix", "issue_type_metadata", "ignore_reasons", "snooze_reason", "cve_id"):
            if d.get(k) not in (None, "", []):
                i[k] = d[k]
        gid = i.get("group_id")
        if gid and gid not in groups:
            groups[gid] = cli.get(f"/issues/groups/{gid}") or {}
    log("")
    return issues, groups


def meta(i):
    m = i.get("issue_type_metadata") or {}
    return m.get(i.get("type")) or m


def title_of(i, groups):
    g = groups.get(i.get("group_id")) or {}
    return i.get("rule") or g.get("title") or i.get("rule_id") or "Sin título"


def out_of_sla(i):
    return i.get("status") == "open" and i.get("sla_remediate_by") and int(i["sla_remediate_by"]) < time.time()


# ---------------------------------------------------------------------- render
CSS = BASE_CSS + """
.where{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;background:#fafafd;border:1px solid var(--line);border-radius:8px;
padding:10px 14px;margin-bottom:14px;font-size:13px}.where span{color:var(--muted)}
.where b{font-family:Consolas,"SFMono-Regular",monospace;font-weight:600;word-break:break-all}
.ev{background:#141428;color:#e6e6f0;border-radius:8px;padding:10px 12px;font:12.5px/1.55 Consolas,"SFMono-Regular",monospace;
white-space:pre-wrap;word-break:break-word;margin:0 0 14px}
.txt{font-size:13px;line-height:1.55;margin:0 0 14px}
.sla{border-color:#f5c79f;color:#c4520f;background:#fdeee4}
.dom{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0 0 18px}
.dom .card{padding:12px 14px}.dom .l{font-size:12px;color:var(--muted)}.dom .v{font-weight:600;word-break:break-all}
@media (max-width:760px){.dom{grid-template-columns:repeat(2,1fr)}}
"""


def sev_badge(s, score=None):
    return (f"<span class='badge b-{s}'><span class='dot d-{s}'></span>{SEV_LABEL.get(s, s)}"
            + (f" · {score}" if score is not None else "") + "</span>")


def render(domain, issues, groups, opts):
    name = domain.get("domain") or next((i.get("domain_name") for i in issues if i.get("domain_name")), str(domain["id"]))
    by_cat = defaultdict(list)
    for i in issues:
        by_cat[title_of(i, groups)].append(i)

    def worst(lst):
        return min(SEVERITIES.index(i.get("severity", "low")) for i in lst)

    cats = sorted(by_cat, key=lambda c: (worst(by_cat[c]), c.lower()))
    anchor = {c: f"cat-{n}" for n, c in enumerate(cats, 1)}

    def cell(lst, sev=None):
        sel = [i for i in lst if sev is None or i.get("severity") == sev]
        if not sel:
            return "<td class='n'>–</td>"
        op = sum(1 for i in sel if i.get("status") == "open")
        return f"<td class='n has'>{len(sel)}<small class='{'op' if op else ''}'>{op} abierto{'s' if op != 1 else ''}</small></td>"

    H = []
    a = H.append
    title = opts.title or f"Reporte DAST — {norm(name)}"
    a(f"<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>{esc(title)}</title><style>{CSS}</style></head><body>")
    a("<div class='top'><div class='in'><div class='logo'>A</div><div><div class='brand'>Aikido Security</div>"
      "<div class='sub'>Reporte de escaneo dinámico (DAST) por dominio</div></div></div></div><div class='page'>")
    a(f"<h1>{esc(title)}</h1>")
    a(f"<div class='meta'>Dominio <b>{esc(name)}</b> · ID <b>{esc(domain['id'])}</b> · "
      f"Generado <b>{dt.datetime.now():%Y-%m-%d %H:%M}</b></div>")

    # ---- Datos del dominio (GET /domains)
    lr = domain.get("linked_resource") or {}
    last = domain.get("last_scanned_at")
    info = [
        ("Tipo de escaneo", KIND.get(domain.get("kind"), domain.get("kind"))),
        ("Último escaneo", dt.datetime.fromtimestamp(int(last)).strftime("%Y-%m-%d %H:%M") if last else None),
        ("Autenticación configurada", {True: "Sí", False: "No"}.get(domain.get("is_auth_configured"))),
        ("Recurso vinculado", f"{'Repositorio' if lr.get('type') == 'code_repo' else 'Contenedor'} ID {lr['id']}" if lr.get("id") else None),
    ]
    if any(v for _, v in info):
        a("<div class='dom'>" + "".join(f"<div class='card'><div class='l'>{esc(k)}</div><div class='v'>{esc(v or '—')}</div></div>"
                                        for k, v in info) + "</div>")

    # ---- KPIs
    st = Counter(i.get("status") for i in issues)
    sla = sum(1 for i in issues if out_of_sla(i))
    a("<div class='kpis'>")
    a(f"<div class='card kpi'><div class='l'>Total issues</div><div class='v'>{len(issues)}</div>"
      f"<div class='x'>{st.get('open', 0)} abiertos · {sla} fuera de SLA</div></div>")
    for s in SEVERITIES:
        sel = [i for i in issues if i.get("severity") == s]
        a(f"<div class='card kpi'><div class='l'><span class='dot d-{s}'></span>{SEV_LABEL[s]}</div><div class='v'>{len(sel)}</div>"
          f"<div class='x'>{sum(1 for i in sel if i.get('status') == 'open')} abiertos</div></div>")
    a("</div>")

    # ---- Tabla por vulnerabilidad
    a("<h2>Issues por vulnerabilidad</h2>")
    a("<p class='lead'>Cada celda muestra el <b>número total de issues</b> y, debajo, cuántos siguen <b>abiertos</b>.</p>")
    a("<div class='card sum'><table><tr><th>Vulnerabilidad</th>"
      + "".join(f"<th class='c'><span class='badge b-{s}'>{SEV_LABEL[s]}</span></th>" for s in SEVERITIES)
      + "<th class='c'>Total</th></tr>")
    for c in cats:
        a(f"<tr><td><a href='#{anchor[c]}'>{esc(c)}</a></td>" + "".join(cell(by_cat[c], s) for s in SEVERITIES) + cell(by_cat[c]) + "</tr>")
    a("<tr class='tot'><td>Total</td>" + "".join(cell(issues, s) for s in SEVERITIES) + cell(issues) + "</tr></table></div>")

    # ---- Detalle
    a("<h2>Detalle de issues</h2>")
    for c in cats:
        lst = sorted(by_cat[c], key=lambda i: (SEVERITIES.index(i.get("severity", "low")), i.get("status") != "open", i.get("id")))
        sev = SEVERITIES[worst(lst)]
        a(f"<div class='cat' id='{anchor[c]}'>{sev_badge(sev)}<h3>{esc(c)}</h3>"
          f"<span class='chip'>{len(lst)} issue{'s' if len(lst) != 1 else ''}</span></div>")
        for i in lst:
            render_issue(a, i, groups.get(i.get("group_id")) or {}, name)
    a("<div class='foot'>Generado con aikido_dast_report.py a partir de la API pública de Aikido Security.</div>")
    a("</div></body></html>")
    return "\n".join(H)


def render_issue(a, i, g, domain_name):
    sev = i.get("severity", "low")
    m = meta(i)
    status = i.get("status") or ""
    url = m.get("domain_target_url") or domain_name
    a("<div class='card issue'>")
    a(f"<div class='ih'>{sev_badge(sev, i.get('severity_score'))}<span class='t'>{esc(title_of(i, {i.get('group_id'): g}))}</span>"
      f"<span class='f'>{esc(url)}</span>"
      + ("<span class='chip sla'>Fuera de SLA</span>" if out_of_sla(i) else "")
      + f"<span class='chip{' st-open' if status == 'open' else ''}'>{esc(STATUS_LABEL.get(status, status))}</span></div>")

    reasons = "; ".join(r.get("reason") or r.get("kind") or "" if isinstance(r, dict) else str(r) for r in i.get("ignore_reasons") or [])
    cve = i.get("cve_id") or m.get("cve_id")
    rows = [
        ("Escáner", "Aikido DAST"),
        ("Regla", i.get("rule_id")),
        ("CWE", ", ".join(i.get("cwe_classes") or [])),
        ("CVE", cve),
        ("Detectado", day(i.get("first_detected_at"))),
        ("SLA", day(i.get("sla_remediate_by"))),
        ("Tiempo estimado", f"{g['time_to_fix_minutes']} min" if g.get("time_to_fix_minutes") else None),
        ("Motivo", reasons),
        ("Issue ID", i.get("id")),
    ]
    a("<div class='ib'><div class='side'>")
    for k, v in rows:
        if v:
            a(f"<div><span>{esc(k)}</span><b>{esc(v)}</b></div>")
    a("</div><div class='main'>")

    # Dónde se encontró: solo lo que devuelve la API (dominio, URL probada, componente detectado)
    a("<div class='lbl'>Dónde se encontró</div><div class='where'>")
    a(f"<span>Dominio</span><b>{esc(i.get('domain_name') or domain_name)} (ID {esc(i.get('domain_id'))})</b>")
    a(f"<span>URL afectada</span><b>{esc(m['domain_target_url'])}</b>" if m.get("domain_target_url")
      else "<span>URL afectada</span><b class='muted'>Aikido no devolvió la URL exacta</b>")
    if m.get("package_name"):
        a(f"<span>Componente</span><b>{esc(m['package_name'])} {esc(m.get('package_version') or '')}</b>")
    if i.get("attack_surface"):
        a(f"<span>Superficie</span><b>{esc(i['attack_surface'])}</b>")
    a("</div>")

    # Descripción: la del grupo de Aikido y, si existe, la descripción de la evidencia del escaneo
    desc = [t for t in (g.get("description"), m.get("evidence_description")) if t and t != g.get("title")]
    a("<div class='lbl'>Descripción del issue</div>")
    a(f"<div class='txt'>{'<br>'.join(md(t) for t in desc)}</div>" if desc
      else "<div class='txt muted'>Aikido no devolvió una descripción para este issue.</div>")
    if m.get("evidence"):
        ev = m["evidence"] if isinstance(m["evidence"], str) else json.dumps(m["evidence"], indent=2, ensure_ascii=False)
        a(f"<div class='lbl'>Evidencia</div><pre class='ev'>{esc(ev)}</pre>")
    fix = i.get("how_to_fix") or g.get("how_to_fix")
    a("<div class='lbl'>Cómo solucionarlo</div>")
    a(f"<div class='fix'>{md(fix)}</div>" if fix
      else "<div class='txt muted'>Aikido no devolvió una recomendación para este issue.</div>")
    a("</div></div></div>")


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="Reporte DAST de un dominio de Aikido")
    who = ap.add_mutually_exclusive_group(required=True)
    who.add_argument("--domain-id", type=int, help="ID del dominio en Aikido (ej. 148121)")
    who.add_argument("--domain", help="Nombre del dominio (ej. vulnlab-dast.onrender.com)")
    ap.add_argument("--types", default="surface_monitoring",
                    help="Tipos de issue separados por coma (default: surface_monitoring = DAST)")
    ap.add_argument("--status", default="all", choices=["all", "open", "ignored", "snoozed", "closed"])
    ap.add_argument("--region", choices=REGIONS, default=os.getenv("AIKIDO_REGION", "eu"))
    ap.add_argument("--title")
    ap.add_argument("-o", "--output")
    ap.add_argument("--json-out", help="Guarda también los datos crudos en JSON")
    ap.add_argument("--from-json", help="Genera el reporte desde un JSON guardado con --json-out (sin llamar a la API)")
    opts = ap.parse_args()
    types = [t.strip() for t in opts.types.split(",") if t.strip()]

    if opts.from_json:
        with open(opts.from_json, encoding="utf-8") as fh:
            data = json.load(fh)
        domain = data.get("domain") or {"id": opts.domain_id}
        issues = [i for i in data["issues"] if i.get("type") in types and i.get("domain_id") == domain.get("id")
                  and (opts.status == "all" or i.get("status") == opts.status)]
        groups = {int(k): v for k, v in (data.get("groups") or {}).items()}
    else:
        cli = client_from_env(opts.region)
        domain = resolve_domain(cli, opts.domain_id, opts.domain)
        log(f"Dominio: {domain.get('domain', '?')} (ID {domain['id']})")
        issues, groups = fetch(cli, domain, types, opts.status)

    if opts.json_out:
        with open(opts.json_out, "w", encoding="utf-8") as fh:
            json.dump({"domain": domain, "issues": issues, "groups": {str(k): v for k, v in groups.items()}},
                      fh, indent=2, ensure_ascii=False)
    out = opts.output or f"reporte_dast_{domain['id']}.html"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render(domain, issues, groups, opts))
    log(f"Reporte generado: {os.path.abspath(out)}  ({len(issues)} issues)")


if __name__ == "__main__":
    main()
