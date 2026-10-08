FROM python:3.12-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libcurl4-openssl-dev libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN python -m pip wheel --wheel-dir /wheels '.[textual]' 'certbot==5.8.0' 'certbot-httpreq==0.0.24' 'acme-http-connector==0.2.1' 'auton==1.2.1' 'autond==1.2.1'

FROM python:3.12-slim-bookworm
ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="CertLord" \
      org.opencontainers.image.description="TLS certificate lifecycle automation with ACME, Vault storage and Auton deployment." \
      org.opencontainers.image.source="https://github.com/decryptus/certlord" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.licenses="GPL-3.0-or-later"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libcurl4 libmagic1 openssh-client && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 certlord && useradd --uid 10001 --gid certlord --create-home certlord
COPY --from=build /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels certlord certbot certbot-httpreq acme-http-connector auton autond textual && rm -rf /wheels \
    && mkdir -p /var/lib/certlord /var/lib/auton && chown certlord:certlord /var/lib/certlord /var/lib/auton
COPY docker/ /opt/certlord-docker/
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /var/lib/certlord
EXPOSE 8666
STOPSIGNAL SIGTERM
CMD ["certlord", "-f", "-c", "/etc/certlord/certlord.yml", "-p", "/var/lib/certlord/certlord.pid", "--logfile", "/var/lib/certlord/certlord.log"]
