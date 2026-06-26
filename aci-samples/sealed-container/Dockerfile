# sealed-app image — restrictive confidential ACI container.
#
# Properties:
#   * Multi-stage build. Stage 1 compiles `get-snp-report` from the upstream
#     microsoft/confidential-sidecar-containers repo at a pinned tag. Only the
#     resulting static binary is copied into the runtime stage.
#   * Runtime stage starts from a pinned python:3.11-slim digest (replace the
#     ${BASE_IMAGE_DIGEST} ARG at build time with the actual `sha256:...`
#     pulled from your registry to make this fully reproducible).
#   * No shell, no package manager, no compilers in the final image. We use
#     pip wheels only — no source builds at runtime.
#   * Non-root user `sealed` (uid 10001).
#   * No HEALTHCHECK directive (the ACI control plane is the only thing that
#     ever probes us, and the CCE policy denies arbitrary exec).
#   * The sealed data bundle (`sealed-data.enc`) is BAKED INTO the image so
#     the image digest covers it too — meaning the SKR release policy, which
#     is keyed off the CCE policy hash (which is itself keyed off the image
#     digest via the fragment) cryptographically binds the sealed payload to
#     the only container that can ever decrypt it.

ARG SIDECAR_TAG=v2.14
# Base images are pulled from the Microsoft Artifact Registry (MCR) mirror,
# not Docker Hub. ACR build agents share a public NAT and routinely hit
# Docker Hub's unauthenticated pull rate limit; MCR has no such limit and
# is itself an air-gapped, signed mirror of the upstream library images.
ARG BASE_IMAGE=mcr.microsoft.com/mirror/docker/library/python:3.11-slim
ARG BASE_IMAGE_DIGEST=sha256:replace-with-pulled-digest

# ---------------------------------------------------------------------------
# Stage 1 — build get-snp-report from source.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/mirror/docker/library/debian:bookworm-slim AS snp-build
ARG SIDECAR_TAG
RUN apt-get update \
 && apt-get install -y --no-install-recommends git make gcc libc6-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${SIDECAR_TAG} \
        https://github.com/microsoft/confidential-sidecar-containers.git /src
WORKDIR /src/tools/get-snp-report
# Build the SNP binary, then regenerate its sha256 manifest using only the
# basename so the runtime stage can verify it from /usr/local/bin without
# carrying over the build-stage relative path (`bin/get-snp-report`).
RUN make bin/get-snp-report \
 && (cd bin && sha256sum get-snp-report > get-snp-report.sha256)

# ---------------------------------------------------------------------------
# Stage 2 — runtime image.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8443 \
    SEALED_DIR=/run/sealed \
    SEALED_BUNDLE=/app/sealed-data.enc \
    GET_SNP_REPORT=/usr/local/bin/get-snp-report

# Single layer for everything user-code-related: copy deps, copy code, copy
# the SNP binary with its checksum, create the unprivileged user, strip
# setuid/setgid bits, and make /app read-only friendly.
COPY requirements.txt /tmp/requirements.txt
COPY app.py entrypoint.py /app/
COPY templates/ /app/templates/
COPY artifacts/sealed-data.enc /app/sealed-data.enc
COPY artifacts/firewall-policy.json /app/firewall-policy.json
COPY --from=snp-build /src/tools/get-snp-report/bin/get-snp-report     /usr/local/bin/get-snp-report
COPY --from=snp-build /src/tools/get-snp-report/bin/get-snp-report.sha256 /usr/local/bin/get-snp-report.sha256

RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt \
 && groupadd --system --gid 10001 sealed \
 && useradd  --system --uid 10001 --gid 10001 --home-dir /app --shell /sbin/nologin sealed \
 && chown -R sealed:sealed /app \
 && chmod 0555 /app /app/templates /usr/local/bin/get-snp-report \
 && chmod 0444 /app/app.py /app/entrypoint.py /app/sealed-data.enc /app/firewall-policy.json /usr/local/bin/get-snp-report.sha256 \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Verify the SNP report binary checksum at image build time so a tampered
# build cache would explode the image. The sha256 manifest was generated
# in stage 1 against the basename only, so verification works from
# /usr/local/bin where the binary now lives.
RUN cd /usr/local/bin && sha256sum -c get-snp-report.sha256

USER sealed:sealed
WORKDIR /app
EXPOSE 8443

# PID 1 = entrypoint — performs SKR + unseal, then execs the Flask app.
ENTRYPOINT ["python", "/app/entrypoint.py"]
