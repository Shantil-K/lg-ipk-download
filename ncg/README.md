# NCG-protected apps: offline decryption tooling

Some LG Content Store apps ship their payload files (`index.html`, `*.js`, ...)
encrypted with **NCG** (LG's content protection, format version 2). The
encrypted files carry a 1KB `NCGFILE_HEADER` and only decrypt on a TV that holds
a matching license in its device-bound license store, so a downloaded IPK does
not work in Developer Mode as-is.

This tooling decrypts the payload **offline** and repacks the IPK so the app
can be installed with `ares-install` and run from the home screen.

## Quick start

Once, per app content id (needs a live TV + one LG request; see
[ro-protocol.md](../docs/ro-protocol.md)):

```bash
# TV-native: build the addon once, then one command per app. The exchange runs
# on the TV in a single node process against the TV's own libncg_agent.so
# (headers never leave the TV), and the CEK is cached locally.
ncg/build.sh
node ncg/fetch-cek.js --app-id com.example.foo --ipk com.example.foo_1.2.3.ipk
```

The exchange looks the app's license up in the TV's current store region; if
the app only exists in another region's store, add `--country <cc>` (e.g.
`--country CN`) to the `fetch-cek.js` line.

The RO response is plain XML or DH-encrypted depending on the app; `<cek>`
is 44 base64 chars -> 32 bytes, and the driver prints it in its JSON line
(or it is recovered from the TV library log `/var/log/ncgdrm-*.log`).

If you already have a CEK value, cache it without any exchange:

```bash
node ncg/ncg-decrypt.js cache add \
  --app-id com.example.foo --sid 50000001 \
  --cid 00112233445566778899AABBCCDDEEFF \
  --cek-b64 '<base64 from the RO response>' \
  --source 'one live exchange 2026-10-30' --date 2026-10-30
```

After that, everything is offline:

```bash
# Decrypt every NCG file in the IPK and write a new, installable IPK.
# The output is verified before the command reports success: valid ar/tar
# structure, zero NCG files left, and every member that was not replaced is
# byte-identical to the input.
node ncg/ncg-decrypt.js decrypt-ipk \
  com.example.foo_1.2.3.ipk --out /tmp/com.example.foo_1.2.3_dec.ipk \
  --app-id com.example.foo

# Install from your computer (Developer Mode) and do NOT launch it from
# the store
ares-install /tmp/com.example.foo_1.2.3_dec.ipk --device tv
```

`decrypt-file` handles a single NCG file:

```bash
node ncg/ncg-decrypt.js decrypt-file index.html.ncg --out index.html
# key/iv come from the cache by cid; --key/--iv hex override the cache
```

## Notes

- Verified end to end (2026-10-30) on three NCG-protected store apps: one
  with a plain-XML RO response (4 NCG files) and two with DH-encrypted
  responses (11 and 254 NCG files); the app ids in the examples above are
  placeholders.
- The CEK is deterministic per (Right Session ID, content id): the same request
  always yields the same `<cek>`. One exchange is enough per app build; the
  cache exists so repeated work never touches the TV or LG.
- Keep RO exchanges rare. Repeated right-object requests from one device risk
  the account/device being blocked by LG; prefer the CEK cache so no further
  requests are made.
- Decrypted IPKs are ordinary webOS packages. Installing them in Developer Mode
  and using the app on your own TV is intended use here; do not redistribute
  decrypted packages or CEKs.
