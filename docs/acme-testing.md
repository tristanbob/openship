# Testing alternate ACME CAs locally

A throwaway ACME CA that **requires EAB**, so the alternate-CA path can be
exercised without touching a real CA's rate limits or issuing a public
certificate. Everything runs in Docker and nothing needs public DNS.

The pieces: [Pebble](https://github.com/letsencrypt/pebble) as the CA,
`pebble-challtestsrv` as a DNS server that resolves every name to loopback so
HTTP-01 can validate, and real certbot as the client.

## Start the CA

```bash
# DNS only — certbot (not challtestsrv) serves the HTTP-01 challenge.
docker run -d --name challtestsrv --network host \
  ghcr.io/letsencrypt/pebble-challtestsrv:latest \
  -dnsserver ":8053" -defaultIPv4 127.0.0.1 -http01 "" -https01 "" -tlsalpn01 "" -doh ""

# Pebble's own image ships an EAB-required config with three known kid/HMAC pairs.
docker run -d --name pebble-eab --network host \
  ghcr.io/letsencrypt/pebble:latest \
  -config /test/config/pebble-config-external-account-bindings.json \
  -dnsserver 127.0.0.1:8053
```

Pebble serves its directory at `https://localhost:14000/dir` behind a private
root, so extract that root for `OPENSHIP_ACME_CA_BUNDLE` / `REQUESTS_CA_BUNDLE`:

```bash
cid=$(docker create ghcr.io/letsencrypt/pebble:latest)
docker cp "$cid:/test/certs/pebble.minica.pem" .
docker rm "$cid"
```

The config's first credential pair is `kid-1` /
`zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W`.

> On Docker Desktop / WSL2, `--network host` is the Docker VM's network, not the
> WSL2 host's — the containers reach each other, but a process on the host can't
> reach `:8053` directly. That's fine; only Pebble needs that DNS server. Use the
> published `:14000` for anything running outside Docker.

## Verify the config-time check

```bash
PEBBLE_DIRECTORY=https://localhost:14000/dir \
PEBBLE_CA_BUNDLE=$PWD/pebble.minica.pem \
  bun run --cwd apps/api test test/lib/acme-ca-pebble.smoke.test.ts
```

Skipped unless `PEBBLE_DIRECTORY` is set. It covers what a self-written fake
HTTP server cannot — real ACME protocol compliance. It exists because a real CA
caught a bug the unit tests could not: Pebble rejects any request without a
`User-Agent` (RFC 8555 §6.1) with `400 malformed`, which made the check report
"HTTP 400" against every conforming CA.

## Verify issuance and renewal

```bash
printf 'eab-kid = kid-1\neab-hmac-key = zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W\n' > eab.ini
chmod 600 eab.ini

docker run --rm --network host \
  -v "$PWD/eab.ini:/eab/eab.ini:ro" -v "$PWD/pebble.minica.pem:/root.pem:ro" \
  -v "$PWD/le:/etc/letsencrypt" \
  --entrypoint env certbot/certbot:latest \
  REQUESTS_CA_BUNDLE=/root.pem certbot --config /eab/eab.ini certonly \
  --standalone --http-01-port 5002 --cert-name acme-e2e.test -d acme-e2e.test \
  --server https://localhost:14000/dir \
  --key-type ecdsa --elliptic-curve secp384r1 \
  --email ops@example.test --agree-tos --non-interactive
```

The argv mirrors what `NginxProvider.provisionCert` composes, so this checks the
EAB file format, `--server`, and the key-type mapping together. Renewal drops
both `--server` and the EAB config — EAB is consumed at account registration, so
by renewal time the account already exists:

```bash
docker run --rm --network host \
  -v "$PWD/pebble.minica.pem:/root.pem:ro" -v "$PWD/le:/etc/letsencrypt" \
  --entrypoint env certbot/certbot:latest \
  REQUESTS_CA_BUNDLE=/root.pem certbot renew --cert-name acme-e2e.test \
  --key-type ecdsa --elliptic-curve secp384r1 --force-renewal --non-interactive
```

Two things worth asserting by hand afterwards. The issued key really is the one
that was asked for:

```bash
docker run --rm -v "$PWD/le:/le:ro" --entrypoint openssl certbot/certbot:latest \
  x509 -in /le/live/acme-e2e.test/fullchain.pem -noout -issuer -text | grep -E "issuer=|NIST CURVE"
```

And the lineage records the issuing directory, which is what
`renewCert` reads to decide between renewing and reissuing after a CA switch:

```bash
grep '^server' le/renewal/acme-e2e.test.conf
```

## Clean up

```bash
docker rm -f pebble-eab challtestsrv
```
