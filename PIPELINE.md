# Despliegue en pipeline (CI/CD)

Guía para ejecutar los reportes de Aikido (SAST, SCA y DAST) como un paso del pipeline, normalmente
**después del deploy** de la aplicación. Para el uso local y las opciones de cada script, ver [README.md](README.md).

---

## 1. Resumen

```
 build ──► deploy ──► reportes Aikido ──► artefactos (HTML + JSON)
                         │
                         ├─ python aikido_sast_report.py --repo-id …  --branch …
                         ├─ python aikido_sca_report.py  --repo-id …  --branch …
                         └─ python aikido_dast_report.py --domain-id …
```

- El paso **solo llama a la API de Aikido**: no hace falta compilar ni descargar el código de la aplicación.
- Las credenciales llegan como **variables de entorno** (`$env:AIKIDO_CLIENT_ID`, `$env:AIKIDO_CLIENT_SECRET`),
  cargadas desde los **secretos** del pipeline.
- Los HTML y JSON se publican como **artefactos** del pipeline.

---

## 2. Requisitos del agente / runner

| Requisito | Detalle |
|---|---|
| Python 3.8+ | Solo librería estándar, sin `pip install`. En Azure DevOps/GitHub se asegura con un paso *Use Python* / `setup-python`. |
| PowerShell | `pwsh` (PowerShell 7, Linux/Windows) o Windows PowerShell 5.1 (agentes Windows). Los ejemplos funcionan en ambos. |
| Salida a internet | HTTPS hacia `app.aikido.dev` (o `app.us.aikido.dev`, `app.au.aikido.dev`, `app.me.aikido.dev`). Si el agente está detrás de un proxy o firewall, permitir ese dominio. |
| Archivos | Los tres `aikido_*_report.py` en la misma carpeta (pueden vivir en este repositorio o en uno de herramientas). |

---

## 3. Preparar las credenciales (una sola vez)

1. En Aikido: **Settings → Integrations → REST API → Add client**.
   - Permisos: `issues:read` (y `domains:read` si vas a usar el reporte DAST). Solo lectura.
   - Un cliente exclusivo para el pipeline, separado del que uses en tu PC.
2. Guarda el client ID y el client secret como **secretos** en tu herramienta de CI:

| Herramienta | Dónde |
|---|---|
| Azure DevOps | *Pipelines → Library → Variable group* (p. ej. `aikido-credentials`) con `AIKIDO_CLIENT_ID` y `AIKIDO_CLIENT_SECRET`, marcando el 🔒 *secret* en el secret. O variables secretas del pipeline. |
| GitHub Actions | *Settings → Secrets and variables → Actions → New repository secret*: `AIKIDO_CLIENT_ID`, `AIKIDO_CLIENT_SECRET`. |
| GitLab CI | *Settings → CI/CD → Variables*: `AIKIDO_CLIENT_ID`, `AIKIDO_CLIENT_SECRET` (*Masked* y, si aplica, *Protected*). |

> En Azure DevOps las variables **secretas no llegan solas** al entorno del script: hay que mapearlas en el
> bloque `env:` del paso, como en el ejemplo de abajo.

---

## 4. Parámetros del paso

| Parámetro | Ejemplo | Uso |
|---|---|---|
| ID del repositorio | `3030745` | SAST y SCA (`--repo-id`) |
| Rama | `main` | SAST y SCA (`--branch`). Debe ser la rama que escanea Aikido |
| ID del dominio | `148109` | DAST (`--domain-id`), o el nombre con `--domain` |
| Región | `eu` | Variable `AIKIDO_REGION` si la cuenta no es EU |

Conviene dejarlos como variables del pipeline (no secretas) para reutilizar el mismo YAML en varios proyectos.

---

## 5. Azure DevOps

```yaml
# azure-pipelines.yml (fragmento): etapa que corre después del deploy
variables:
  - group: aikido-credentials          # AIKIDO_CLIENT_ID y AIKIDO_CLIENT_SECRET (secreto)
  - name: AIKIDO_REPO_ID
    value: 3030745
  - name: AIKIDO_BRANCH
    value: main
  - name: AIKIDO_DOMAIN_ID
    value: 148109

stages:
  # - stage: Build ...
  # - stage: Deploy ...

  - stage: AikidoReports
    displayName: Reportes de seguridad Aikido
    dependsOn: Deploy
    condition: succeeded('Deploy')
    jobs:
      - job: Reports
        pool:
          vmImage: ubuntu-latest          # o windows-latest
        steps:
          - checkout: self                # solo para obtener los scripts

          - task: UsePythonVersion@0
            inputs:
              versionSpec: "3.12"

          - task: PowerShell@2
            displayName: Generar reportes SAST, SCA y DAST
            continueOnError: true         # un fallo del reporte no revierte el deploy
            env:
              AIKIDO_CLIENT_ID: $(AIKIDO_CLIENT_ID)
              AIKIDO_CLIENT_SECRET: $(AIKIDO_CLIENT_SECRET)
            inputs:
              targetType: inline
              pwsh: true
              workingDirectory: $(Build.SourcesDirectory)   # carpeta donde están los .py
              script: |
                $out = "$(Build.ArtifactStagingDirectory)/aikido"
                New-Item -ItemType Directory -Force $out | Out-Null
                $fallos = 0

                python aikido_sast_report.py --repo-id $(AIKIDO_REPO_ID) --branch $(AIKIDO_BRANCH) `
                  -o "$out/reporte_sast.html" --json-out "$out/datos_sast.json"
                if ($LASTEXITCODE -ne 0) { $fallos++ }

                python aikido_sca_report.py --repo-id $(AIKIDO_REPO_ID) --branch $(AIKIDO_BRANCH) `
                  -o "$out/reporte_sca.html" --json-out "$out/datos_sca.json"
                if ($LASTEXITCODE -ne 0) { $fallos++ }

                python aikido_dast_report.py --domain-id $(AIKIDO_DOMAIN_ID) `
                  -o "$out/reporte_dast.html" --json-out "$out/datos_dast.json"
                if ($LASTEXITCODE -ne 0) { $fallos++ }

                if ($fallos -gt 0) { Write-Error "$fallos reporte(s) no se generaron"; exit 1 }

          - task: PublishPipelineArtifact@1
            displayName: Publicar reportes
            condition: always()
            inputs:
              targetPath: $(Build.ArtifactStagingDirectory)/aikido
              artifact: reportes-aikido
```

---

## 6. GitHub Actions

```yaml
# .github/workflows/deploy.yml (fragmento)
env:
  AIKIDO_REPO_ID: "3030745"
  AIKIDO_BRANCH: main
  AIKIDO_DOMAIN_ID: "148109"

jobs:
  # build: ...
  # deploy: ...

  aikido-reports:
    needs: deploy
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Generar reportes SAST, SCA y DAST
        shell: pwsh
        continue-on-error: true
        env:
          AIKIDO_CLIENT_ID: ${{ secrets.AIKIDO_CLIENT_ID }}
          AIKIDO_CLIENT_SECRET: ${{ secrets.AIKIDO_CLIENT_SECRET }}
        run: |
          New-Item -ItemType Directory -Force aikido | Out-Null
          $fallos = 0
          python aikido_sast_report.py --repo-id $env:AIKIDO_REPO_ID --branch $env:AIKIDO_BRANCH -o aikido/reporte_sast.html --json-out aikido/datos_sast.json
          if ($LASTEXITCODE -ne 0) { $fallos++ }
          python aikido_sca_report.py --repo-id $env:AIKIDO_REPO_ID --branch $env:AIKIDO_BRANCH -o aikido/reporte_sca.html --json-out aikido/datos_sca.json
          if ($LASTEXITCODE -ne 0) { $fallos++ }
          python aikido_dast_report.py --domain-id $env:AIKIDO_DOMAIN_ID -o aikido/reporte_dast.html --json-out aikido/datos_dast.json
          if ($LASTEXITCODE -ne 0) { $fallos++ }
          if ($fallos -gt 0) { Write-Error "$fallos reporte(s) no se generaron"; exit 1 }

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: reportes-aikido
          path: aikido/
          retention-days: 30
```

---

## 7. GitLab CI

```yaml
# .gitlab-ci.yml (fragmento)
aikido_reports:
  stage: post-deploy
  image: mcr.microsoft.com/powershell:latest
  needs: [deploy]
  allow_failure: true
  variables:
    AIKIDO_REPO_ID: "3030745"
    AIKIDO_BRANCH: main
    AIKIDO_DOMAIN_ID: "148109"
  before_script:
    - apt-get update -qq && apt-get install -y -qq python3 > /dev/null
  script:
    - pwsh -Command '
        New-Item -ItemType Directory -Force aikido | Out-Null;
        python3 aikido_sast_report.py --repo-id $env:AIKIDO_REPO_ID --branch $env:AIKIDO_BRANCH -o aikido/reporte_sast.html --json-out aikido/datos_sast.json;
        python3 aikido_sca_report.py --repo-id $env:AIKIDO_REPO_ID --branch $env:AIKIDO_BRANCH -o aikido/reporte_sca.html --json-out aikido/datos_sca.json;
        python3 aikido_dast_report.py --domain-id $env:AIKIDO_DOMAIN_ID -o aikido/reporte_dast.html --json-out aikido/datos_dast.json'
  artifacts:
    when: always
    paths: [aikido/]
    expire_in: 30 days
```

`AIKIDO_CLIENT_ID` y `AIKIDO_CLIENT_SECRET` llegan como variables de entorno desde *Settings → CI/CD → Variables*.

---

## 8. Validar la integración

1. **Probar las credenciales** con un paso mínimo antes de armar todo el pipeline:
   ```powershell
   python aikido_dast_report.py --domain-id 148109 -o prueba.html
   ```
   Debe terminar con `Reporte generado`. Si sale `401`, revisa el secreto (ver tabla de problemas en el README).
2. **Revisar el log del paso:** cada script muestra cuántos issues encontró, en qué rama o dominio, y si excluyó algo.
3. **Descargar el artefacto** `reportes-aikido` y abrir los HTML.

---

## 9. Consideraciones

| Tema | Recomendación |
|---|---|
| **Momento del escaneo** | Aikido escanea de forma asíncrona. Si el paso corre justo después del deploy, el reporte refleja **el último escaneo de Aikido**, que puede ser anterior al commit desplegado. Para DAST, el dominio se escanea con la app ya desplegada. |
| **¿Bloquear el pipeline?** | Los scripts devuelven error solo si no pudieron generar el reporte (credenciales, red, ID inexistente), **no** por encontrar vulnerabilidades. Al ir después del deploy se recomienda `continueOnError` / `continue-on-error` / `allow_failure` para que un fallo del reporte no marque el deploy como fallido. |
| **Ramas** | En Aikido cada rama escaneada es un repositorio con su propio ID. Usa el `--repo-id` de la rama desplegada y la misma rama en `--branch`. |
| **Secretos** | Nunca en el YAML ni en el código. Un cliente REST solo para el pipeline, de solo lectura. Rotar el secret si aparece en un log. |
| **Artefactos** | Contienen información de vulnerabilidades: limitar quién puede descargarlos y fijar un tiempo de retención. |
| **Límite de peticiones** | Si Aikido responde `429`, el script espera y reintenta solo. |
| **Región** | Si la cuenta no es EU, agregar `AIKIDO_REGION: us` (o `au`, `me`) al `env:` del paso. |
