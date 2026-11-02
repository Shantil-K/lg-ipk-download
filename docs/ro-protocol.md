# Obtaining the CEK: applicense and the Right Object (RO) protocol

The payload key (CEK) for an NCG-protected app is issued by LG's Right Object
service. This document describes the full chain that was used to obtain it, with
the parts that can and cannot be done offline.

Verified 2026-10-30 on an LG TV (webOS 25, US region, HE_DTV_W25G) for a
CN-store app.

## 1. Find the license endpoints (TV-side, passive)

For an app that has content protection, the store's license metadata is served
by the SDP "applicense" endpoint (TV-side passive request: no app launch, no
state change):

```text
GET https://cn.nextlgsdp.com/apps/10.0.0/applicense/applicenseurl
    ?app_id=com.example.foo&dev_usb_flag=0&version=1.2.3
```

with the TV's SDX request headers. Response:

```json
{"secureURL": {
   "RightObjectURL": "http://kr.security.lgtvsdp.com/license_manager.asp",
   "RightSessionID": "50000001"
}}
```

Notes from the field:

- The host depends on the store region. The driver queries the TV's current
  region (the SDX `HOST`) unless `--country <cc>` selects another one
  (`<cc>.nextlgsdp.com` with `X-Device-Country: <cc>`; CN also sets
  `X-Device-Country-Group: CN`, `X-Device-Language: zh-CN`,
  `X-Device-Locale: zh-CN`). The example app above only exists in the CN
  store: from a US-region TV the US endpoint answers `A.018.01` (app not
  found), so it is exchanged with `--country CN` — which works without
  changing any TV setting.
- `RightSessionID` (the "sid") is stable per app build; `RightObjectURL` is the
  RO exchange endpoint.

## 2. SDX authentication (what the headers are, and why they can't be forged)

Every SDP request carries device-bound headers obtained on the TV:

```text
luna://com.webos.service.sdx/getHttpHeaderForServiceRequest
```

The two that gate access are `Authorization` and `X-Authentication`:
HS256-signed JWTs (`iss=aic.tv.wiselg.com`, ~2h validity, the payload contains
an encrypted device MAC) signed with a per-device secret ("Model Secret Key")
that lives in the TV's SESTORE (`/mnt/lg/cmn_data`, AES + HMAC, not present in
the firmware image). Signing also requires the TV's
`luna com.webos.service.sm/crypto/doDigitalSign`.

Consequences:

- The headers cannot be forged offline; a live TV is needed to mint them.
- They expire after ~2h, so a single RO exchange should be planned with a
  freshly fetched header set.
- The headers and the CEK they unlock are different things: the CEK itself is
  per (sid, cid) and deterministic (below), so once captured it needs no
  headers at all.

## 3. The RO exchange (one-shot)

The TV's `libncg_agent.so` performs the exchange, driven with the TV's
headers through the N-API addon: `ncg/ncg_native.c` binds the library from
node, and `tv/ro-exchange.js` runs the whole exchange in one node process on
the TV (below).

The library call sequence:

1. `NCG_Init(agent, deviceid, "webostv", secret_dir)` where `deviceid` is the
   TV's eth0 MAC in colon-lowercase form (e.g. `00:11:22:33:44:55`); the library
   derives its internal device id from it.
2. `NCG_MakeRORequestMsgWithSSID(agent, rsid, msg, &len)` builds the
   form-urlencoded request body.
3. `POST http://kr.security.lgtvsdp.com/license_manager.asp` (plain HTTP) with
   the SDX headers.
4. `NCG_SaveROResponseMsg(agent, response)` parses the license.

### TV-native execution

`ncg/build.sh` cross-compiles the N-API addon `dist/ncg_native.node`.
It is built with the older glibc 2.31 toolchain (`Dockerfile`) on
purpose: its `dlopen`/`dlsym`/`dlclose` references then bind to their original
`GLIBC_2.4` versions, safe on the TV's glibc 2.33 (newer toolchains re-version
them to `GLIBC_2.34`). `ncg/fetch-cek.js` runs the whole exchange from
the host:

1. Pick one NCG file from the encrypted IPK (host side, node one-liner).
2. Push the driver (`tv/ro-exchange.js`), the addon, and the NCG file to
   `/tmp/ncgrow` on the TV.
3. On the TV, one node process does everything: SDX headers from the SDX service
   (held in memory, never written to disk), `RightSessionID`/`RightObjectURL`
   from the applicense endpoint of the selected store region (`--country`, or
   the TV's current region; unless `--sid`/`--ro-url` are given), then
   `addon.init(so, MAC, secret_dir)` -> `makeRequest(sid)` -> HTTP POST to the
   RO URL with the SDX headers -> `save(response)` (rc `0xF0000422` is the
   expected result for online licenses) -> `cekList()` for the 32-byte CEK.
   Node does the networking (native DNS), so there is no static-glibc caveat.
4. `--verify-file` proves the CEK end to end: the driver opens the pushed NCG
   file through `NCG_OpenAndVerifyFile` and compares the CEK the library
   resolves for that file against the license CEK.
5. The driver prints one JSON line (`ok`, `sid`, `cek`, `verified`); the host
   caches the CEK with `lg-ipk cache add`. If the driver died
   before printing, the CEK is recovered from the TV library log
   `/var/log/ncgdrm-*.log` instead.
6. Clean up `/tmp/ncgrow` (wiped on reboot anyway).

Properties: the request leaves from the TV's own IP (the most normal pattern
from LG's perspective), the signed headers never leave the TV's node process,
and no build machine is needed after the one-time artifact build. Caveat: the
library runs unsandboxed on the device — with `<verificationmethod>online` it
refuses to persist the license, so its writes stay in the scratch dir — but
treat the run as a real-device operation and do it deliberately.

The `.so` itself is a TV firmware file; the driver runs against the TV's live
copy by default. Re-fetch a copy when the TV's firmware generation changes.

The response comes in two shapes, depending on the app (both observed 2026-10-30
from the same device):

**Plain XML** (e.g. `com.example.foo`): the license is in the response body
directly:

```xml
<response result='1'>
  ...
  <ncgro>
    <content>
      <cid>00112233445566778899AABBCCDDEEFF</cid>
      <cek>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</cek>
    </content>
    <permission>
      ...
      <verificationmethod>online</verificationmethod>
    </permission>
  </ncgro>
  ...
</response>
```

**DH-encrypted** (e.g. `com.example.bar`, `com.example.baz`): the license is
sealed with the per-run Diffie-Hellman session the library set up in
`NCG_Init` / `ncg_generate_key`:

```xml
<response result='0' message=''>
  <responsedata>B=1A1097...;license=jaO6HZ...;hmac=4YKZ62...=</responsedata>
</response>
```

The library decrypts `license` and checks `hmac` inside `NCG_SaveROResponseMsg`;
the parsed XML (including `<cid>`/`<cek>`) is then written to the library log
`/var/log/ncgdrm-<yyyymmdd>.log`. With this shape the `<cek>` is NOT in the
printed raw response — extract it from that log (see "Capturing for the cache").
The client DH private key is in-memory only, so an encrypted response cannot be
replayed offline.

Field semantics (from the firmware's `_ncg_ParseCIDLicense` /
`NCG_GetCEKForce`):

- `<cid>`: the content id, byte-identical to the `<cid>` in each NCG file's 1KB
  header. One per protected file group.
- `<cek>`: **32 bytes** of base64 (44 chars). This single field is split by the
  firmware into the AES-128 key (first 16 bytes) and the CTR IV (last 16 bytes)
  for the payload algorithm — see [ncg-format.md](ncg-format.md).
- `<verificationmethod>online</verificationmethod>`: the license is not meant to
  be persisted to the TV's license DB. Accordingly `NCG_SaveROResponseMsg`
  returns `0xF0000422` (-268434398) instead of 0; the in-memory license is still
  valid and the files decrypt fine. This is expected behavior, not an error.

### Is the response encrypted?

For `com.example.foo` it was not: two exchanges with independent
Diffie-Hellman sessions returned byte-identical `<cek>` values in plain XML.
For `com.example.bar` and `com.example.baz` (2026-10-30) the response uses
the DH-encrypted `responsedata` wrapper; the `<cek>` values extracted from the
library log matched the cids in the NCG file headers, and the offline decryption
produced clean plaintext for every file. The determinism claim (below) was
established on the plain-XML app and holds for both wrapper types by
construction (the CEK is issued per (sid, cid), not per session).
The request is form-urlencoded in all cases.

### Determinism

The same (sid, cid, device) always yields the same `<cek>`. Therefore one
exchange captures everything permanently; the CEK is then cached locally
(`~/.cache/lg-ipk-download/ncg/`, overridden with `NCG_CACHE_DIR`) and neither
the TV nor LG is needed again.

## 4. Capturing for the cache

The node driver prints one JSON line, and `cek.b64` in it is the full 32-byte
CEK (key || iv) read back from the in-memory license **after**
`NCG_SaveROResponseMsg` — so it covers both response shapes (plain XML and
DH-encrypted) and does not depend on the library log. If the driver dies before
printing, the parsed XML is still in the library log; the orchestrator
(`ro-exchange.js`) greps it in place on the TV.

The per-file open path (`NCG_OpenAndVerifyFile`) takes the 6-argument form used
by the firmware's own `libsm_appdrm.so` (rc 0 = ok, the file handle returned
through the 6th argument, which the library writes unconditionally at entry — a
call missing that argument writes to stack garbage). The open + handle-CEK read
runs clean with this convention (verified 2026-10-31, RC=0).

Store the captured value:

```bash
lg-ipk cache add \
  --app-id com.example.foo --sid 50000001 \
  --cid 00112233445566778899AABBCCDDEEFF \
  --cek-b64 '<value>' --source 'one live exchange 2026-10-30' --date 2026-10-30
```

## 5. What a fresh app build changes

- A new app version usually means a new content id (`<cid>` per file) and
  possibly a new sid — the CEK must be captured once per new (sid, cid).
- If the app is re-signed/protected differently, re-verify the payload algorithm
  against the firmware of the TV generation in use; the 512-byte scatter table
  and the key/IV layout have been stable across the generations examined so far.
