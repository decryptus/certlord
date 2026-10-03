FROM debian:12 AS service
ENV container=docker
RUN apt-get update -qq && apt-get install -y --no-install-recommends systemd systemd-sysv dbus redis-server ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package/ /package/
RUN apt-get update -qq && apt-get install -y --no-install-recommends /package/certlord_*.deb && rm -rf /var/lib/apt/lists/*
COPY vault /usr/local/bin/vault
COPY vault-fixture.service /etc/systemd/system/vault-fixture.service
COPY systemd_acceptance.py /fixture/systemd_acceptance.py
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

FROM service AS lifecycle
RUN /opt/venvs/certlord/bin/python -m pip install autond==1.2.1
COPY tools/ /fixture/tools/
COPY lifecycle.py network_faults.py systemd_process.py auton-routes.yml /fixture/
COPY source/etc/ /fixture/source/etc/
COPY auton-routes.yml /fixture/source/tests/integration/auton-routes.yml
