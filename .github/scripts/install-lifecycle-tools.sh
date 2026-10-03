#!/usr/bin/env bash
# Disposable Linux amd64 integration tools; no installation into the host PATH.
set -euo pipefail
fixture_dir="${1:?Usage: install-lifecycle-tools.sh DIRECTORY}"
mkdir -p "$fixture_dir"
cd "$fixture_dir"
for binary in pebble pebble-challtestsrv; do
    curl --fail --silent --show-error --location --retry 2 --max-time 120 \
        "https://github.com/letsencrypt/pebble/releases/download/v2.10.1/${binary}-linux-amd64.tar.gz" \
        --output "$binary.tar.gz"
done
curl --fail --silent --show-error --location --retry 2 --max-time 120 \
    https://releases.hashicorp.com/vault/1.20.4/vault_1.20.4_linux_amd64.zip --output vault.zip
sha256sum --check <<'SUMS'
4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed  pebble.tar.gz
e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92  pebble-challtestsrv.tar.gz
fc5fb5d01d192f1216b139fb5c6af17e3af742aaeffc289fd861920ec55f2c9c  vault.zip
SUMS
for binary in pebble pebble-challtestsrv; do
    tar --no-same-owner -xzf "$binary.tar.gz"
    cp "$binary-linux-amd64/linux/amd64/$binary" "$binary"
    chmod +x "$binary"
done
unzip -q vault.zip vault
