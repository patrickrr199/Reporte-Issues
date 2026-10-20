# Reportes de seguridad Aikido (SAST · SCA · DAST)

Scripts en Python que consultan la **API pública de Aikido Security** y generan reportes HTML listos para
imprimir a PDF (Ctrl+P → *Guardar como PDF*).

| Script | Reporte | Se elige por |
|---|---|---|
| `aikido_sast_report.py` | **SAST**: vulnerabilidades en el código propio, por regla, con archivo, líneas y cómo corregirlas | ID del repositorio + rama |
| `aikido_sca_report.py` | **SCA**: librerías vulnerables por archivo de dependencias, con todos sus CVE y la versión a la que actualizar | ID del repositorio + rama |
| `aikido_dast_report.py` | **DAST**: hallazgos del escaneo dinámico de un dominio, con URL afectada, evidencia y cómo solucionarlos | ID o nombre del dominio |

Todo el contenido sale de la API de Aikido: los scripts **no leen el código fuente** del repositorio ni se
conectan a ningún otro servicio.

> Para desplegarlo en un pipeline (Azure DevOps, GitHub Actions, GitLab CI) ver **[PIPELINE.md](PIPELINE.md)**.

---

## 1. Requisitos

| Requisito | Detalle |
|---|---|
| **Python 3.8 o superior** | Solo librería estándar: **no hay que instalar paquetes** (`pip install` no es necesario). Comprobar con `python --version`. |
| **PowerShell** | Windows PowerShell 5.1 o PowerShell 7 (`pwsh`). También funciona en bash/Linux cambiando la forma de definir las variables. |
| **Acceso a internet** | Salida HTTPS hacia `app.aikido.dev` (o la región de tu cuenta, ver `--region`). |
| **Cliente REST de Aikido** | *Aikido → Settings → Integrations → REST API → Add client*. Entrega un **client ID** (`AIK_CLIENT_...`) y un **client secret** (`AIK_SECRET_...`). |
| **Permisos (scopes) del cliente** | `issues:read` para los tres reportes, y además `domains:read` para DAST. |
| **Los tres `.py` juntos** | `aikido_sca_report.py` y `aikido_dast_report.py` reutilizan el cliente de la API y los estilos de `aikido_sast_report.py`; deben estar en la misma carpeta. |

### IDs que necesitas

| Dato | Dónde encontrarlo |
|---|---|
| ID del repositorio (SAST / SCA) | En Aikido, la URL del repositorio, o el campo `code_repo_id` de la API. Ej.: `3030745` (AK-REP-BACK). |
| Rama | La rama que escanea Aikido para ese repositorio (por defecto `main`). En Aikido **cada rama escaneada tiene su propio ID de repositorio**. |
| ID del dominio (DAST) | En Aikido, *Domains & APIs*, o el campo `domain_id` de la API. Ej.: `148109`. También se puede pasar el nombre con `--domain`. |

---

## 2. Variables de entorno

Los scripts leen las credenciales de variables de entorno. **Nunca se escriben en el código ni en archivos.**

| Variable | Obligatoria | Valor |
|---|---|---|
| `AIKIDO_CLIENT_ID` | Sí* | Client ID del cliente REST (`AIK_CLIENT_...`) |
| `AIKIDO_CLIENT_SECRET` | Sí* | Client secret del cliente REST (`AIK_SECRET_...`). Usar siempre el **último generado** |
| `AIKIDO_TOKEN` | No | Alternativa: un token de acceso ya generado (empieza con `eyJ...`, **vence en 1 hora**) |
| `AIKIDO_REGION` | No | `eu` (por defecto), `us`, `au` o `me`, según la región de tu cuenta Aikido |

\* Con `AIKIDO_CLIENT_ID` + `AIKIDO_CLIENT_SECRET` el script pide el token a Aikido en cada ejecución, así que
nunca vence. Es la opción recomendada. Si están definidas ambas formas, se usan el client ID y el secret.

> ⚠️ El client secret va en `AIKIDO_CLIENT_SECRET`, **no** en `AIKIDO_TOKEN`.

---

## 3. Probarlo en PowerShell, paso a paso

Todo en **una sola ventana** de PowerShell: las variables `$env:` solo existen en la ventana donde se
definen. Si la cierras o abres otra, hay que definirlas de nuevo.

**Paso 1. Abrir PowerShell en la carpeta de los scripts**

```powershell
cd "C:\ruta\a\script informes"
```

**Paso 2. Comprobar Python**

```powershell
python --version
```

Debe mostrar `Python 3.8` o superior.

**Paso 3. Definir las credenciales**

```powershell
$env:AIKIDO_CLIENT_ID = "AIK_CLIENT_xxxxxxxxxxxxxxxx"
$env:AIKIDO_CLIENT_SECRET = "AIK_SECRET_xxxxxxxxxxxxxxxx"
```

Solo si tu cuenta no es de la región EU:

```powershell
$env:AIKIDO_REGION = "us"
```

**Paso 4. Verificar las variables**

```powershell
Get-ChildItem Env:AIKIDO*
```

Deben aparecer `AIKIDO_CLIENT_ID` y `AIKIDO_CLIENT_SECRET`. Si aparece un `AIKIDO_TOKEN` viejo, quítalo:

```powershell
Remove-Item Env:AIKIDO_TOKEN
```

**Paso 5. Generar los reportes**

```powershell
# SAST del repositorio 3030745, rama main
python aikido_sast_report.py --repo-id 3030745 --branch main --json-out datos_sast_3030745.json -o reporte_sast_3030745.html

# SCA del repositorio 3030745, rama main
python aikido_sca_report.py --repo-id 3030745 --branch main --json-out datos_sca_3030745.json -o reporte_sca_3030745.html

# DAST del dominio 148109 (o por nombre: --domain vulnlab-dast.onrender.com)
python aikido_dast_report.py --domain-id 148109 --json-out datos_dast_148109.json -o reporte_dast_148109.html
```

Cada script muestra su progreso y termina con `Reporte generado: ...`.

**Paso 6. Abrir el reporte**

```powershell
start .\reporte_dast_148109.html
```

**Paso 7 (opcional). Limpiar las credenciales al terminar**

```powershell
Remove-Item Env:AIKIDO_CLIENT_ID, Env:AIKIDO_CLIENT_SECRET
```

### Opcional: guardar las credenciales en tu usuario de Windows

Para no repetir el paso 3 en cada ventana, en tu PC (no en el pipeline):

```powershell
setx AIKIDO_CLIENT_ID "AIK_CLIENT_xxxxxxxxxxxxxxxx"
setx AIKIDO_CLIENT_SECRET "AIK_SECRET_xxxxxxxxxxxxxxxx"
```

En Windows, los scripts también leen estas variables guardadas, incluso desde ventanas abiertas antes del
`setx`. Si una variable está definida con `$env:` en la ventana, esa tiene prioridad.

---

## 4. Opciones de cada script

### Comunes a los tres

| Opción | Descripción |
|---|---|
| `-o`, `--output` | Archivo HTML de salida |
| `--json-out` | Guarda también los datos crudos que devolvió la API (sirve como evidencia) |
| `--from-json` | Regenera el HTML desde un JSON guardado con `--json-out`, **sin llamar a la API** ni necesitar credenciales |
| `--status` | Filtra por estado: `all`, `open`, `ignored`, `snoozed`, `closed` |
| `--region` | `eu`, `us`, `au`, `me` (también por la variable `AIKIDO_REGION`) |
| `--title` | Título personalizado del reporte |

### `aikido_sast_report.py`

| Opción | Descripción |
|---|---|
| `--repo-id` | **Obligatorio.** ID del repositorio en Aikido |
| `--branch` | Rama (por defecto `main`). Si no hay datos en esa rama, el script lista las ramas que sí tienen |
| `--types` | Tipos de issue, por defecto `sast` (ej. `sast,iac`) |
| `--status` | Por defecto `all` |

### `aikido_sca_report.py`

| Opción | Descripción |
|---|---|
| `--repo-id` | **Obligatorio.** ID del repositorio en Aikido |
| `--branch` | Rama (por defecto `main`) |
| `--status` | Por defecto `open` (igual que la vista de Aikido) |
| `--include-container` | Incluye lo que Aikido detectó en la imagen de contenedor ligada al repo (por defecto se excluye) |
| `--no-groups` | No consulta los grupos de issues (más rápido, sin descripción corta) |
| `--no-detail` | Omite la sección de detalle por librería |

### `aikido_dast_report.py`

| Opción | Descripción |
|---|---|
| `--domain-id` / `--domain` | **Uno de los dos es obligatorio.** ID del dominio, o su nombre (con o sin `https://`). Si el nombre no existe, el script lista los dominios disponibles |
| `--types` | Tipos de issue, por defecto `surface_monitoring` (DAST) |
| `--status` | Por defecto `all` |

---

## 5. Cómo funciona

```
Variables de entorno (AIKIDO_CLIENT_ID / AIKIDO_CLIENT_SECRET)
        │
        ▼
POST /api/oauth/token ─────────────► token de acceso (1 h)
        │
        ▼
Consultas a la API (solo lectura)
  SAST: GET /issues/export?filter_code_repo_id=…   + GET /issues/{id} + GET /issues/groups/{id}
  SCA:  GET /issues/export?filter_code_repo_id=…&filter_issue_type=open_source + GET /issues/groups/{id}
  DAST: GET /domains  + GET /issues/export?filter_domain_id=…&filter_issue_type=surface_monitoring
        + GET /issues/{id} + GET /issues/groups/{id}
        │
        ▼
Filtrado en el script: repositorio/dominio pedido, rama, tipo de issue
        │
        ▼
reporte_*.html  (+ datos_*.json con --json-out)
```

**Qué incluye cada reporte**

- **SAST:** resumen por severidad, tabla por regla (total y abiertos) y, por issue: severidad y score, estado, CWE, lenguaje, rama, SLA, si es alcanzable, tiempo estimado, ubicación (repositorio, rama, archivo, líneas) y cómo corregirlo. La API no entrega el fragmento de código, solo archivo y líneas.
- **SCA:** resumen, una tabla por archivo de dependencias con librería, severidad, todos sus CVE y "Actualizar a" (versión mínima que corrige todo), y el detalle de cada CVE: versión que lo corrige, CWE, explotabilidad, estado y SLA.
- **DAST:** datos del dominio (tipo de escaneo, último escaneo, autenticación, recurso vinculado), resumen con issues fuera de SLA, tabla por vulnerabilidad y, por issue: dónde se encontró (dominio, URL afectada, componente), descripción, evidencia y cómo solucionarlo. Si Aikido no devuelve un dato, el reporte lo indica en vez de dejar el hueco.

---

## 6. Problemas comunes

| Mensaje | Causa | Solución |
|---|---|---|
| `Faltan credenciales de Aikido...` | La ventana no tiene `AIKIDO_CLIENT_ID` / `AIKIDO_CLIENT_SECRET` | Repetir el paso 3 **en la misma ventana** donde ejecutas el script |
| `401 ... invalid_client` | Client ID o secret incorrectos, o de clientes distintos | Usar el **último** secret generado y que sea del mismo cliente que el ID |
| `401 ... The tokens signature is invalid` | En `AIKIDO_TOKEN` hay algo que no es un token | `Remove-Item Env:AIKIDO_TOKEN` y usar client ID + secret |
| `403` | Al cliente le falta un permiso | Darle `issues:read` (y `domains:read` para DAST) |
| `No hay issues en la rama 'X'...` | El repositorio no tiene datos en esa rama | Usar una de las ramas que lista el mensaje en `--branch` |
| `No se encontró el dominio '...'` | El nombre no coincide | Usar uno de los dominios que lista el mensaje, o `--domain-id` |
| `start : ... cannot find the file` | El script falló antes y no creó el HTML | Revisar el error del paso 5 |
| `python` no se reconoce | Python no instalado o fuera del PATH | Instalar Python 3.8+ y marcar *Add to PATH* |

**Códigos de salida:** `0` si el reporte se generó; distinto de `0` si hubo un error (credenciales, red,
dominio o rama inexistente). Los scripts **no** fallan por encontrar vulnerabilidades.

---

## 7. Seguridad

- Las credenciales solo se leen de variables de entorno. No se guardan en el HTML, en el JSON ni en ningún archivo.
- El cliente REST solo necesita permisos de **lectura** (`issues:read`, `domains:read`).
- Si un secret quedó expuesto (en una terminal compartida, un chat o un log), regénéralo en Aikido.
- Los `reporte_*.html` y `datos_*.json` contienen información de vulnerabilidades: no los subas al repositorio (ya están en `.gitignore`) y compártelos solo con quien corresponda.
