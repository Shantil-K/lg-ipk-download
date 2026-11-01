# NCG v2 file format and payload algorithm

Reverse-engineered from the TV firmware's `libncg_agent.so.2.0.0` (disassembly)
and validated against real decrypted output. All statements below were verified
on a NCG-protected store app package (webOS 25 firmware library, file
`libncg_agent.so.2.0.0`, `.text` at file offset 0x5210, `.rodata` at 0x166a4,
VA == file offset).

## File layout

```text
offset  size   field
0x000   14     magic "NCGFILE_HEADER"
0x00E   2      version, u16 LE (== 2)
0x010   4      bodySize, u32 LE (== 512 in all observed packages)
0x000-  ...    rest of the 1KB header
0x200   512    NUL-terminated XML license block; contains <cid>
0x400   ...    payload (starts at 512 + bodySize)
```

The payload length is `file_size - (512 + bodySize)`. The `<cid>` in the header
XML is the content id the payload was encrypted under; every NCG file in a
package shares one cid.

## Key material

The RO response's `<cek>` field decodes from base64 to exactly 32 bytes
(44 base64 chars). The firmware splits that one field:

```text
cek     = base64decode(<cek>)      # 32 bytes
aes_key = cek[0:16]                # raw, standard AES-128 key, no transform
ctr_iv  = cek[16:32]               # raw 128-bit CTR start counter
```

`NCG_GetCEKForce` (lib offset ~0xbab8) copies `license+35..51` to the handle's
key slot and `license+51..67` to its IV slot; `_ncg_ParseCIDLicense` (0x5dc4)
base64-decodes the single `<cek>` XML field into `license+35..67`. There is no
other key material in the file or in the firmware constants: the IV is
per-license server data, which is why no offline derivation from the file
header / cid / sid can work.

(A 4-byte word-swap of the key appears in the library's RO *HMAC* path; it does
**not** apply to the payload AES. The payload uses the raw key — verified
empirically, see below.)

## Payload algorithm

All blocks are 512 bytes. For a file with cid `C` define

```text
seed = sum(ord(c) for c in C) % 16          # == 7 for the observed cid
T    = SCATTER_TABLE[32*seed : 32*seed+32]  # 32 bytes, each in 0..15
```

where `SCATTER_TABLE` is the 512-byte table at firmware file offset
0x17660. It is embedded in `ncg/ncg-decrypt.js`.

For each full 512-byte block `B` (byte offset `i*512`):

```text
for k in 0..31:
    p_k = 16*k + T[k]
keys[k] = B[p_k]                              # 32 "stored key" bytes
B[0:480] ^= (keys repeated 15 times)          # body, 480 bytes
keys     = AES128_CTR(keys, aes_key, ctr_iv)  # 32 bytes of keystream
for k in 0..31:
    B[p_k] = keys[k]                          # restore the scatter positions
B[480:512] is stored in the clear and untouched
```

The final partial block (length < 512) is **pure AES-128-CTR** with the same
key/iv.

CTR counter semantics: the firmware re-seeds the counter from the handle's IV
field on **every** block and on the tail (`_ncg_DecryptBlock` at 0x6a10 copies
`handle+1036..1052` as the counter before each `NED_AES_encrypt` call).
There is no counter continuity across blocks: every 512-byte block and the
tail all use keystream starting at counter = `ctr_iv`.

Interpretation: the 32 scatter positions of each block store the block's "key
bytes" (the previous state of the keystream mix), and the plaintext at those
same positions is recovered by XORing them with the 32-byte CTR keystream. The
remaining 480 body bytes are XORed with those key bytes directly — which is why
the body decrypts correctly even with a wrong IV (only the 32 scatter positions
per block depend on the key/iv at all).

## Seed

The decrypter uses `seed = sum(ord(c) for c in cid) % 16`. This was empirically
verified (all 32 scatter positions of every block across all 4 files decrypt to
the real file content with seed 7). The firmware computes the seed from the
license record's cid bytes in `_ncg_OpenNCGHeader` (0x7668, sum at 0x77bc-0x77de
with a sign that makes the two formulas coincide for the observed cid). If a
future app's files ever disagree with `sum(cid) % 16`, brute-forcing the 16
candidate seeds is trivial: the algorithm's structure makes the right one
unambiguous (scatter positions must look like the surrounding file content).

## Handle layout (reference)

`NCG_OpenAndVerifyFile` (6-arg form: rc 0 = ok, the handle delivered through the
6th argument — see [ro-protocol.md](ro-protocol.md)) is a ~1.1KB structure:

```text
+1020 (0x3fc)  16B  AES-128 key   (license+35..51)
+1036 (0x40c)  16B  CTR IV        (license+51..67)
+1052 (0x424)  ...  flags
+1056 (0x428)  4B   seed
+1064 (0x430)  8B   content size
+1088 (0x440)  8B   read offset / block counter
```

`_ncg_GetContents` (0x6b34) routes reads through
`_ncg_DecryptBlock(handle+1020, buf, len, seed)`; `len < 512` takes the pure-CTR
tail path.

## Verification record

1. **Table**: firmware file offset 0x17660, 512 bytes.
2. **Scatter test**: with `key = cek[0:16]`, `iv = cek[16:32]`, all 32*64 = 2048
   scatter positions across the first 64 blocks of `index.html` decrypt to
   printable HTML (2048/2048). Every other (key, iv) candidate scores at or near
   random (~300-1000/2048).
3. **Full files**: all 4 NCG files of the verified package decrypt to clean
   plaintext — `index.html` starts with `<!doctype html>` and ends with
   `</html>`; the three JS files are valid webpack chunk scripts; zero
   unexpected control bytes in any of the 241KB of output.
4. **Cross-check with the library**: the RO-exchange driver dumps the key/IV the
   firmware resolves from the live license (handle+1020/+1036); they match the
   cached `key_hex`/`iv_hex`, and the library's own decrypted output matches
   `ncg-decrypt.js` byte-for-byte.

## Installing the decrypted IPK

The decrypted IPK is a standard webOS package (outer container: standard `ar`
archive — `debian-binary/`, `control.tar.gz/`, `data.tar.gz/` — with LG's
trailing-slash member-name quirk). Repack only touches the four NCG members
inside `data.tar.gz`; everything else (control metadata, icons, `.sign/`,
`usr/palm/packages/`) is preserved. Install with `ares-install`; the app then
reads ordinary plaintext files and runs without a license.
