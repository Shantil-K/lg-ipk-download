# LG IPK Download

A command-line tool that downloads the latest official IPK for any LG Content
Store app, in any store region, without installing the app on your TV first.
NCG-protected apps are decrypted automatically after download.

**More webOS tools:** [IPTV Player](https://github.com/lennylxx/webos-iptv-player) · [DevMode Forever](https://github.com/lennylxx/lg-devmode-forever) · [GeoLock Bypass](https://github.com/lennylxx/lg-geolock-bypass)

> [!NOTE]
> The CLI runs on your computer. It temporarily runs a small helper on the TV,
> because the private palmbus, device-bound SDX authentication, and the
> short-lived signed package URL are only available there. Sensitive headers and
> signed URL parameters never leave the TV.

> [!TIP]
> You don't need to change your TV's region to download apps from another
> country's store: `--country` takes care of it. If you already changed
> regions and got stuck, use
> [lg-geolock-bypass](https://github.com/lennylxx/lg-geolock-bypass).

## Requirements

- An LG webOS TV with Developer Mode and SSH enabled
- Node.js on your computer
- `ares-setup-device` from the webOS CLI
- `expect`, `ssh`, and `scp`
- macOS, Linux, or Windows WSL2

Configure the TV with `ares-setup-device` first, then verify it is listed:

```bash
ares-setup-device --list
```

## Quick start

```bash
cd lg-ipk-download

./bin/lg-ipk-download.js \
  --device tv \
  --output /tmp/com.palmdts.devmode.ipk \
  com.palmdts.devmode
```

The positional argument can be either:

```bash
# Internal Content Store app ID
./bin/lg-ipk-download.js com.palmdts.devmode

# Numeric ID from the LG Apps website (US by default)
./bin/lg-ipk-download.js 232503

# Select another store country for both website lookup and TV requests
./bin/lg-ipk-download.js --country DE 232503
```

See [Country codes](#country-codes).

Example output:

```text
Downloaded com.palmdts.devmode 2.1.4
Output:  /tmp/com.palmdts.devmode.ipk
Size:    6435718 bytes
SHA-256: 610d87c5a3b5a569130dbf7ea515f7395afc4589cd0fb397c3144af93390e5d4
```

If `--output` is omitted, the IPK is saved to the current directory as:

```text
<app-id>_<store-version>.ipk
```

## Search

Search the TV's app store by keyword or internal ID without downloading or
installing anything:

```bash
./bin/lg-ipk-download.js search "Developer Mode"
./bin/lg-ipk-download.js search "Developer Mode" --country DE
```

Results include each matching app's name and internal ID. Searches require
a connected TV and use its current store region unless `--country` is specified.
Search runs on LG's servers and may include related apps.

## Options

```text
-o, --output <path>       Local output path
-d, --device <name>       ares-setup-device profile name
    --country <code>      Store country/region (e.g. US, DE, CN)
    --api-version <ver>   SDP API version (default: 10.0.0)
    --timeout <seconds>   Download timeout (default: 180)
    --keep-remote         Keep the downloaded file on the TV
    --force               Replace an existing output file
    --no-decrypt          Skip the automatic NCG decryption after download
    --fetch-cek           If no CEK is cached, run one live RO exchange to
                          obtain it and retry the decryption
    --json                Print the final result as JSON
-h, --help                Show this help
```

Machine-readable example:

```bash
./bin/lg-ipk-download.js --json com.palmdts.devmode
```

## Country codes

Use `--country` with a case-insensitive two-letter code for downloads or searches.
Regional site mappings are automatic and do not change TV
settings. Without this option, website lookups default to US and TV requests
use the TV's current store region.

The table lists regions in LG's public store selector. Other two-letter codes
are accepted, but store and app availability depend on the region and TV model.

| Code | Country/region | Code | Country/region | Code | Country/region |
|------|----------------|------|----------------|------|----------------|
| `AE` | United Arab Emirates | `FR` | France | `PE` | Peru |
| `AR` | Argentina | `GB` | United Kingdom | `PH` | Philippines |
| `AT` | Austria | `HK` | Hong Kong | `PT` | Portugal |
| `AU` | Australia | `ID` | Indonesia | `RU` | Russia |
| `BR` | Brazil | `IL` | Israel | `SG` | Singapore |
| `CA` | Canada | `IN` | India | `TH` | Thailand |
| `CL` | Chile | `IT` | Italy | `TR` | Turkey |
| `CN` | China | `JP` | Japan | `TW` | Taiwan |
| `CO` | Colombia | `KR` | South Korea | `UA` | Ukraine |
| `DE` | Germany | `KZ` | Kazakhstan | `US` | United States |
| `EC` | Ecuador | `MX` | Mexico | `VN` | Vietnam |
| `ES` | Spain | `MY` | Malaysia | `ZA` | South Africa |

## NCG-protected apps

Some store apps ship their payload files (`index.html`, `*.js`, ...) encrypted
with LG's **NCG** content protection. Those IPKs do not work in Developer Mode
as-is. This repository includes offline tooling to decrypt them and repack the
IPK so it installs with `ares-install`.

The download command decrypts automatically: once a CEK for the app is cached,
every download also writes a decrypted, installable copy next to the original
(`<name>.ipk` -> `<name>_dec.ipk`). Without a cached CEK the encrypted IPK is
kept and the tool prints how to obtain one. `--no-decrypt` skips the step.

With `--fetch-cek`, a missing CEK is obtained during the download itself: one
live RO exchange (the same call `ncg/fetch-cek.js` makes) runs on your TV,
the CEK is cached, and the decryption is retried. Each exchange is a real
request to LG's service — keep it rare. The exchange looks the app's license
up in the TV's current store region; if the app only exists in another
region's store, pass `--country <code>` (the download command forwards its own
`--country` to the exchange).

```bash
# one-time: cache the app's CEK. One command (TV-native exchange: the TV's own
# libncg_agent.so in a single node process, SDX headers never leave the TV):
#   ncg/build.sh          # once, needs docker
#   node ncg/fetch-cek.js --app-id com.example.foo --ipk com.example.foo_1.2.3.ipk
node ncg/ncg-decrypt.js cache add \
  --app-id com.example.foo --sid 50000001 \
  --cid 00112233445566778899AABBCCDDEEFF \
  --cek-b64 '<from the RO response>' --date 2026-10-30

# then every download is decrypted automatically:
./bin/lg-ipk-download.js --device tv com.example.foo
# -> com.example.foo_1.2.3.ipk and com.example.foo_1.2.3_dec.ipk

# or decrypt manually / later, e.g. right after the CEK gets cached:
node ncg/ncg-decrypt.js decrypt-ipk \
  com.example.foo_1.2.3.ipk --out /tmp/com.example.foo_1.2.3_dec.ipk \
  --app-id com.example.foo

# install from your computer (do not launch the app from the store)
ares-install /tmp/com.example.foo_1.2.3_dec.ipk --device tv
```

The CEK is deterministic per app build and cached under `cache/ncg/`
(gitignored), so repeated work needs no TV or LG access. Keep right object
exchanges rare — frequent requests risk the device being blocked. Details:
[ncg/README.md](ncg/README.md), the RO protocol
([ro-protocol.md](docs/ro-protocol.md)), and the NCG format and payload
algorithm ([ncg-format.md](docs/ncg-format.md)).

### Supported webOS versions

The TV-side toolchain (the N-API addon from `ncg/ncg_native.c` and
`tv/ro-exchange.js`) needs the TV's Node.js to ship Node-API. Every
"verified" row below was tested in QEMU-user against a real TV firmware
rootfs, running the TV's own `libncg_agent` (no LG server access required).
Note that LG's firmware updates bump the TV's Node.js within a marketing
generation — one 2023 model ran node 12.22.2 in its 03.31.82 build, 16.19.1
in 23.25.55, and 16.20.2 in 33.31.75 — so the table lists the Node.js range
actually seen per generation.

| webOS | Year | TV Node.js | Status |
|-------|------|------------|--------|
| 4.x and earlier | 2015–2019 | 0.10 / 0.12 | ❌ Not supported — predates Node-API |
| 5.0 | 2020 | 8.12.0 | ✅ Verified (2020 UP8000 firmware 03.53.45) |
| 6.0 | 2021 | 12.22.2 – 16.20.2 | ✅ Verified across a 2021 model's firmware lifecycle: 03.31.82 (12.22.2), 23.25.55 (16.19.1), 33.31.75 (16.20.2) |
| 22 | 2022 | 12.21.0 / 12.22.2 | ✅ Verified (13.30.85, node v12.22.2; an earlier build of the generation ships 12.21.0) |
| 23 | 2023 | 12.22.2 / 16.19.1 | ✅ Verified (23.25.55, node v16.19.1; the generation's 12.22.2 build is the same Node.js verified for webOS 22) |
| 24 | 2024 | 16.19.1 | ✅ Verified (2024 C4 firmware 03.11.20, webOS TV 9.1.0, node v16.19.1) |
| 25 | 2025 | 16.20.2 | ✅ Verified (33.31.61 and 33.31.75 firmwares, plus a live RO exchange on a webOS 25 TV) |
| 26 | 2026 | 20.12.2 | ✅ Verified (43.21.62 firmware) |

The offline half (`ncg/ncg-decrypt.js`) runs on the Node.js of your computer
and has no webOS version dependency.

## How it works

### On the computer

1. If given a numeric store ID, look up the app name and category through
   the LG Apps `retrieveAppInfo.ajax` endpoint.
2. Read the selected TV connection from `ares-setup-device`.
3. Push `tv/download-ipk.js` to a unique path under `/tmp`.
4. Run the helper over SSH.
5. Pull the completed IPK with SCP.
6. Check the file size against the size reported by LG, and compute the SHA-256.
7. If the IPK contains NCG-encrypted files and a CEK for the app is cached,
   decrypt them and write `<name>_dec.ipk` next to the original
   (skipped with `--no-decrypt`; without a cached CEK the encrypted IPK is
   kept and a hint is printed, unless `--fetch-cek` runs one live RO
   exchange and retries).
8. Remove the temporary helper from the TV. The TV copy of the IPK is also
   removed unless `--keep-remote` is used.

### On the TV

1. Open an anonymous private palmbus handle:

   ```js
   new palmbus.Handle('', false)
   ```

   This anonymous private-bus access pattern comes from
   [lennylxx/lg-geolock-bypass](https://github.com/lennylxx/lg-geolock-bypass).

2. For an LG Apps numeric ID, query the TV's `/app/list` catalog and map the
   website name and category to the TV's internal app ID. Ambiguous matches are
   rejected rather than guessed.

3. Call:

   ```text
   luna://com.webos.service.sdx/getHttpHeaderForServiceRequest
   ```

   This returns the device-bound Content Store request headers and the regional
   SDP host.

4. Query the app detail endpoint:

   ```text
   /apps/<api-version>/app/app?app_id=<internal-app-id>
   ```

5. Optionally call:

   ```text
   luna://com.webos.applicationManager/getAppInfo
   ```

   If the app is installed, this returns its current version and `binId`.
   Otherwise, the helper uses `bin_id=0&version=0`.

6. Request A.001 install metadata without actually installing the app:

   ```text
   /apps/<api-version>/app/install
       ?id=<internal-app-id>
       &bin_id=<installed-bin-id-or-0>
       &version=<installed-version-or-0>
   ```

7. Validate that the returned package URL uses HTTPS, then stream the package
   directly to a temporary file on the TV.

The install metadata response contains the current package version, the
expected packed size, and a short-lived signed GFTS URL. The helper keeps
that URL in memory only.

## Temporary directories

The helper uses the first writable location from this list:

1. `/tmp/lg-ipk-download`
2. `/media/developer/temp/lg-ipk-download`

The second location is for platforms such as webOS 26, where `/tmp` may not
be writable from the Developer Mode environment.

The tool deliberately avoids `/media/internal` and downloadmanager, because
IPKs saved there stay in `/media/internal` and keep taking up storage on your
TV. `/tmp`, on the other hand, is cleared on every reboot. After a successful
SCP, the IPK is removed from the TV unless `--keep-remote` is specified.

## Security

- SDX authentication headers never leave the helper process on the TV.
- Authorization values, device identifiers, cookies, and session tokens are
  never printed.
- Signed URL query parameters are never printed or persisted.
- The computer receives only non-sensitive package metadata and the IPK.
- Downloaded IPKs are excluded from git via `.gitignore`.
- If the download fails on the TV, the partial file is removed.
- If SCP fails after the TV download completes, the file is kept on the TV
  and its path there is printed so you can copy it manually.

## Limitations

- Numeric IDs from the website are not the same as the TV's internal app IDs.
  The tool maps them using the regional website metadata and the TV catalog.
  If more than one app is an equally good match, pass the internal app ID
  instead.
- Which apps are available, and which package is returned, depend on the
  selected TV's model, region, firmware, and Content Store account state.
- The default API version, `10.0.0`, was verified on an OLED77C5PUA running
  webOS 10.3.1 (firmware 33.31.69).
- Use `--api-version` when targeting a different SDP API generation.
- LG may change private services, authentication requirements, or SDP response
  formats in future firmware.
