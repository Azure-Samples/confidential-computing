# Automotive Machine Vision (Confidential ACI + CCE)

This sample deploys a Flask-based video redaction app to Azure Container Instances (Confidential SKU), protected by a Confidential Compute Enforcement (CCE) policy and remote attestation gate.

## What the app does

1. Serves the web app over HTTPS.
2. Requires attestation validation before upload/processing can proceed.
3. Accepts `.mp4` uploads and processes video inside the confidential container.
4. Blurs sensitive content in processed output:
   - Faces (cascade detection)
   - License plates (direct plate detection plus vehicle-guided inference and temporal stabilization)
5. Shows processing status with per-worker progress and a final playback view.
6. Exposes live plate-tracking tuning controls in the UI (`holdFrames`, `matchIou`) and applies them without redeploy.

## Live app screenshot

Updated screenshot captured from the running app:

![Automotive machine vision app](docs/app-screengrab.png)

An additional copy is kept at `AutomotiveVisionApp.png` for convenience.

## Current redaction behavior

- Blurs only faces and license plates.
- Uses a lead-vehicle-first strategy to reduce false-positive plate blur regions.
- Keeps plate blur stable across short detector dropouts via temporal hold logic.
- Uses red-glare-aware carryover to avoid losing blur under brake-light glare.

## Project files

- `app.py`: Flask API, detection/redaction pipeline, job orchestration, settings APIs.
- `templates/index.html`: web UI for attestation, upload, progress, playback, and plate-tracking settings.
- `Deploy-AutomotiveMachineVision.ps1`: build/deploy script for ACR + confidential ACI deployment.
- `deployment-template.json`: ACI deployment template with CCE policy integration.
- `deployment-params.json`: deployment parameters for the template.
- `Dockerfile`, `nginx.conf`, `supervisord.conf`: runtime container stack.
- `docs/app-screengrab.png`: screenshot embedded in this README.

## Prerequisites

- Azure CLI (`az`)
- Azure CLI `confcom` extension
- PowerShell 7+
- Docker Desktop (required for CCE policy generation)

```powershell
az extension add --name confcom --upgrade
az confcom --version
```

## Build and deploy

```powershell
Set-Location automotive-machine-vision

# Build and push image to ACR
.\Deploy-AutomotiveMachineVision.ps1 -Build

# Deploy confidential ACI with CCE policy generation
.\Deploy-AutomotiveMachineVision.ps1 -Deploy
```

To use a real certificate (including Let's Encrypt), pass your PEM files at deploy time:

```powershell
.\Deploy-AutomotiveMachineVision.ps1 -Deploy \
   -ImageTag amv-20260602-<suffix> \
   -TlsCertPath "C:\path\to\fullchain.pem" \
   -TlsKeyPath "C:\path\to\privkey.pem"
```

For Let's Encrypt specifically, use Certbot output files:

- `fullchain.pem` for `-TlsCertPath`
- `privkey.pem` for `-TlsKeyPath`

### Generate Let's Encrypt artifacts

This repo includes a helper that runs Certbot in Docker and writes local PEM artifacts under `certs/live/<domain>/`:

```powershell
Set-Location automotive-machine-vision

# DNS challenge (manual TXT record entry)
.\Get-LetsEncryptCertificate.ps1 -Domain "your.domain.com" -Email "you@example.com" -Challenge dns-manual

# Optional: HTTP challenge (requires inbound port 80 to this machine)
.\Get-LetsEncryptCertificate.ps1 -Domain "your.domain.com" -Email "you@example.com" -Challenge http-standalone
```

Then deploy using generated files:

```powershell
.\Deploy-AutomotiveMachineVision.ps1 -Deploy \
   -TlsCertPath ".\certs\live\your.domain.com\fullchain.pem" \
   -TlsKeyPath ".\certs\live\your.domain.com\privkey.pem"
```

For deterministic deployments, use an explicit image tag:

```powershell
.\Deploy-AutomotiveMachineVision.ps1 -Build -ImageTag amv-20260602-<suffix>
.\Deploy-AutomotiveMachineVision.ps1 -Deploy -ImageTag amv-20260602-<suffix>
```

## Attestation and policy highlights

- CCE policy generation enforces approved image measurement and non-interactive execution (`--disable-stdio`).
- The UI shows decoded claim values and explanations for attestation evidence before enabling upload.

## Security notes

- The container supports CA-issued certificates (including Let's Encrypt) via `-TlsCertPath` and `-TlsKeyPath`.
- If no certificate is provided, the container falls back to a self-signed certificate for demo/testing.
- Video processing is server-side within the confidential container boundary.
