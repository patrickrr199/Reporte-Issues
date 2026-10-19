# Reporte SAST estilo Fortify (Aikido, por repositorio)

`aikido_sast_report.py` genera un HTML (Ctrl+P → Guardar como PDF) con la estructura del reporte Fortify:

1. **Desglose por categoría** (regla Aikido) × Critical/High/Medium/Low en formato `auditados / total`
   (auditado = cerrado, ignorado o pospuesto en Aikido).
2. Por categoría: **Engine Breakdown** (SAST / IaC / Secrets / SCA).
3. Por issue: barra regla + severidad, **Package**, archivo y línea, **Issue Details**
   (Kingdom, Scan Engine, estado, score, CWE, lenguaje, SLA), **Sink Details** (método contenedor + código
   con la línea resaltada) y **Recomendación** (`how_to_fix` de Aikido).

La API de Aikido no devuelve el código fuente: el fragmento se lee del clon local indicado en `--src-dir`.

## Uso (PowerShell)

```powershell
# Opción A: token Bearer ya generado (expira a la hora)
$env:AIKIDO_TOKEN = "eyJ..."
# Opción B: credenciales del cliente REST (el script pide el token solo)
$env:AIKIDO_CLIENT_ID = "..."; $env:AIKIDO_CLIENT_SECRET = "..."

python aikido_sast_report.py --repo-id 3030745 --src-dir "..\aikido-backend-demo" --json-out datos_AK-REP-BACK.json
```

| Opción | Descripción |
|---|---|
| `--repo-id` | ID del repo en Aikido (obligatorio) |
| `--types` | Tipos de issue, por defecto `sast` (ej. `sast,iac`) |
| `--status` | `all` (defecto), `open`, `ignored`, `snoozed`, `closed` |
| `--src-dir` | Clon local del repo, para mostrar el código |
| `--json-out` / `--from-json` | Guardar los datos crudos / regenerar el HTML sin llamar a la API |
| `-o` | Archivo de salida (defecto `reporte_sast_<repo>.html`) |
| `--region` | `eu` (defecto), `us`, `au`, `me` |
