# Automotive Machine Vision (Confidential ACI + CCE)

This sample deploys a web app to **Azure Container Instances (Confidential SKU)** and applies a **Confidential Compute Enforcement (CCE)** policy so the workload:

- Runs only from the approved container image
- Blocks interactive access (`--disable-stdio`)
- Requires remote attestation before sensitive upload/processing actions proceed

## What this sample does

1. Presents a web app over **HTTPS/TLS**
2. Requires **attestation check** before upload is enabled
3. Shows attestation claims and claim explanations to the user
4. Lets the user explicitly **Proceed** or **Abort**
5. Accepts `.mp4` upload only after proceed confirmation
6. Processes video **inside the container**:
   - Blurs faces
   - Blurs detected license plate regions
   - Adds overlay labels for detected vehicle-like objects (car/truck/cycle/motorcycle) with confidence
7. Updates processing status every 5 seconds
8. Provides playback controls (play/pause, rewind, fast-forward, timeline slider, timestamps)

## Folder layout

- `app.py` - Flask API + machine vision processing
- `templates/index.html` - web UI (attestation, upload, progress, playback)
- `Dockerfile` - combined app + SKR binary + TLS reverse proxy
- `nginx.conf` - HTTPS termination and proxy to Flask
- `supervisord.conf` - process manager for SKR, Flask, NGINX
- `deployment-template-original.json` - confidential ACI ARM template with CCE policy placeholder
- `Deploy-AutomotiveMachineVision.ps1` - build/deploy/cleanup script
- `sample-video-local/` - local-only place for sample videos (gitignored)

## Prerequisites

- Azure CLI (`az`) with `confcom` extension
- PowerShell 7+
- Docker Desktop (required by `az confcom acipolicygen`)

```powershell
az extension add --name confcom --upgrade
az confcom --version
```

## Build and deploy

```powershell
cd automotive-machine-vision

# Build image in ACR
.\Deploy-AutomotiveMachineVision.ps1 -Build

# Deploy confidential container and generate CCE policy
.\Deploy-AutomotiveMachineVision.ps1 -Deploy
```

The deploy step runs:

```powershell
az confcom acipolicygen -a deployment-template.json --parameters deployment-params.json --disable-stdio
```

This policy generation step is what enforces:

- **Approved image measurement** (container policy bound to image layers)
- **No interactive shell/exec** (stdio disabled)

## Attestation claims shown in UI

The app decodes token claims returned by MAA and displays each claim with an explanation. Typical claims include:

- `x-ms-attestation-type`: hardware attestation technology indicator
- `x-ms-compliance-status`: compliance state from attestation flow
- `x-ms-sevsnpvm-is-debuggable`: debug mode status
- `x-ms-policy-hash`: hash of policy measurement
- `x-ms-runtime`: runtime evidence details

## Local sample video handling

Use the provided YouTube link only as a source reference and keep any downloaded sample in:

```text
automotive-machine-vision/sample-video-local/
```

This folder is intentionally gitignored and should never be committed.

## Security notes

- TLS certificate in the container is self-signed for demonstration.
- For production, use a CA-issued certificate and stronger identity/network controls.
- Processing logic executes on the server side inside the ACI confidential container.
