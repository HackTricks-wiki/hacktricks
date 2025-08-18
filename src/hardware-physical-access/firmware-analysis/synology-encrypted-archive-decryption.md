# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Overview

Several Synology devices (DSM/BSM NAS, BeeStation, …) distribute their firmware and application packages in **encrypted PAT / SPK archives**.  Those archives can be decrypted *offline* with nothing but the public download files thanks to hard-coded keys embedded inside the official extraction libraries.

This page documents, step-by-step, how the encrypted format works and how to fully recover the clear-text **TAR** that sits inside each package.  The procedure is based on Synacktiv research performed during Pwn2Own Ireland 2024 and implemented in the open-source tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  The format is exactly the same for both `*.pat` (system update) and `*.spk` (application) archives – they only differ in the pair of hard-coded keys that are selected.

---

## 1. Grab the archive

The firmware/application update can normally be downloaded from Synology’s public portal:

```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```

## 2. Dump the PAT structure (optional)

`*.pat` images are themselves a **cpio bundle** that embeds several files (boot loader, kernel, rootfs, packages…).  The free utility [`patology`](https://github.com/sud0woodo/patology) is convenient to inspect that wrapper:

```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```

For `*.spk` you can directly jump to step 3.

## 3. Extract the Synology extraction libraries

The real decryption logic lives in:

* `/usr/syno/sbin/synoarchive`               → main CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → calls the wrapper from DSM UI
* `libsynocodesign.so`                       → **contains the cryptographic implementation**

Both binaries are present in the system rootfs (`hda1.tgz`) **and** in the compressed init-rd (`rd.bin`).  If you only have the PAT you can get them this way:

```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```

## 4. Recover the hard-coded keys (`get_keys`)

Inside `libsynocodesign.so` the function `get_keys(int keytype)` simply returns two 128-bit global variables for the requested archive family:

```c
case 0:            // PAT (system)
case 10:
case 11:
  signature_key = qword_23A40;
  master_key    = qword_23A68;
  break;

case 3:            // SPK (applications)
  signature_key = qword_23AE0;
  master_key    = qword_23B08;
  break;
```

* **signature_key** → Ed25519 public key used to verify the archive header.
* **master_key**    → Root key used to derive the per-archive encryption key.

You only have to dump those two constants once for each DSM major version.

## 5. Header structure & signature verification

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` performs the following:

1. Read magic (3 bytes) `0xBFBAAD` **or** `0xADBEEF`.
2. Read little-endian 32-bit `header_len`.
3. Read `header_len` bytes + the next **0x40-byte Ed25519 signature**.
4. Iterate over all embedded public keys until `crypto_sign_verify_detached()` succeeds.
5. Decode the header with **MessagePack**, yielding:

```python
[
  data: bytes,
  entries: [ [size: int, sha256: bytes], … ],
  archive_description: bytes,
  serial_number: [bytes],
  not_valid_before: int
]
```

`entries` later allows libarchive to integrity-check each file as it is decrypted.

## 6. Derive the per-archive sub-key

From the `data` blob contained in the MessagePack header:

* `subkey_id`  = little-endian `uint64` at offset 0x10
* `ctx`        = 7 bytes at offset 0x18

The 32-byte **stream key** is obtained with libsodium:

```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```

## 7. Synology’s custom **libarchive** backend

Synology bundles a patched libarchive that registers a fake "tar" format whenever the magic is `0xADBEEF`:

```c
register_format(
   "tar", spk_bid, spk_options,
   spk_read_header, spk_read_data, spk_read_data_skip,
   NULL, spk_cleanup, NULL, NULL);
```

### spk_read_header()

```
- Read 0x200 bytes
- nonce  = buf[0:0x18]
- cipher = buf[0x18:0x18+0x193]
- crypto_secretstream_xchacha20poly1305_init_pull(state, nonce, kdf_subkey)
- crypto_secretstream_xchacha20poly1305_pull(state, tar_hdr, …, cipher, 0x193)
```

The decrypted `tar_hdr` is a **classical POSIX TAR header**.

### spk_read_data()

```
while (remaining > 0):
    chunk_len = min(0x400000, remaining) + 0x11   # +tag
    buf   = archive_read_ahead(chunk_len)
    crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
    remaining -= chunk_len - 0x11
```

Each **0x18-byte nonce** is prepended to the encrypted chunk.

Once all entries are processed libarchive produces a perfectly valid **`.tar`** that can be unpacked with any standard tool.

## 8. Decrypt everything with synodecrypt

```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```

`synodecrypt` automatically detects PAT/SPK, loads the correct keys and applies the full chain described above.

## 9. Common pitfalls

* Do **not** swap `signature_key` and `master_key` – they serve different purposes.
* The **nonce** comes *before* the ciphertext for every block (header and data).
* The maximum encrypted chunk size is **0x400000 + 0x11** (libsodium tag).
* Archives created for one DSM generation may switch to different hard-coded keys in the next release.

## 10. Additional tooling

* [`patology`](https://github.com/sud0woodo/patology) – parse/dump PAT archives.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – decrypt PAT/SPK/others.
* [`libsodium`](https://github.com/jedisct1/libsodium) – reference implementation of XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – header serialisation.

## References

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}