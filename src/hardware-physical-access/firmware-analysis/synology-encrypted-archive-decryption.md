# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Overview

Vifaa vingi vya Synology (DSM/BSM NAS, BeeStation, …) vinatoa firmware na pakiti za programu katika **archive za PAT / SPK zilizofichwa**. Archive hizo zinaweza kufichuliwa *offline* kwa kutumia tu faili za kupakua za umma kutokana na funguo zilizowekwa ndani ya maktaba rasmi za uondoaji.

Ukurasa huu unandika, hatua kwa hatua, jinsi muundo wa kufichwa unavyofanya kazi na jinsi ya kurejesha kabisa **TAR** ya wazi ambayo iko ndani ya kila pakiti. Utaratibu huu unategemea utafiti wa Synacktiv uliofanywa wakati wa Pwn2Own Ireland 2024 na kutekelezwa katika zana ya chanzo wazi [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  Muundo ni sawa kabisa kwa `*.pat` (sasisho la mfumo) na `*.spk` (programu) archive – zinatofautiana tu katika jozi ya funguo zilizowekwa.

---

## 1. Grab the archive

Sasisho la firmware/programu kwa kawaida linaweza kupakuliwa kutoka kwenye portal ya umma ya Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump the PAT structure (optional)

`*.pat` images ni **cpio bundle** ambayo inajumuisha faili kadhaa (boot loader, kernel, rootfs, packages…). Zana ya bure [`patology`](https://github.com/sud0woodo/patology) ni rahisi kutumia kukagua wrapper hiyo:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Kwa `*.spk` unaweza kuruka moja kwa moja hadi hatua ya 3.

## 3. Toa maktaba za uchimbaji za Synology

Mantiki halisi ya ufichuzi iko katika:

* `/usr/syno/sbin/synoarchive`               → kifunguo kikuu cha CLI
* `/usr/lib/libsynopkg.so.1`                 → inaita kifunguo kutoka kwa UI ya DSM
* `libsynocodesign.so`                       → **ina utekelezaji wa kificho**

Binafsi zote zipo katika mfumo wa rootfs (`hda1.tgz`) **na** katika init-rd iliyoshinikizwa (`rd.bin`). Ikiwa una PAT pekee unaweza kuzipata kwa njia hii:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Recover the hard-coded keys (`get_keys`)

Ndani ya `libsynocodesign.so` kazi `get_keys(int keytype)` inarudisha tu mabadiliko mawili ya kimataifa ya 128-bit kwa familia ya archive iliyotolewa:
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
* **signature_key** → Ed25519 public key inayotumika kuthibitisha kichwa cha archive.
* **master_key**    → Funguo ya mzizi inayotumika kupata funguo za usimbaji za kila archive.

Unahitaji tu kutoa hizo constants mbili mara moja kwa kila toleo kuu la DSM.

## 5. Muundo wa kichwa & uthibitishaji wa saini

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` inatekeleza yafuatayo:

1. Soma magic (bytes 3) `0xBFBAAD` **au** `0xADBEEF`.
2. Soma little-endian 32-bit `header_len`.
3. Soma bytes `header_len` + saini ya **0x40-byte Ed25519** inayofuata.
4. Pitia funguo zote za umma zilizojumuishwa hadi `crypto_sign_verify_detached()` ifanikiwe.
5. Fanya decode kichwa kwa **MessagePack**, ikitoa:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` baadaye inaruhusu libarchive kukagua uhalali wa kila faili kadri inavyotolewa.

## 6. Pata funguo ndogo ya kila archive

Kutoka kwenye `data` blob iliyo ndani ya kichwa cha MessagePack:

* `subkey_id`  = little-endian `uint64` kwenye offset 0x10
* `ctx`        = bytes 7 kwenye offset 0x18

Funguo la **stream key** la byte 32 linapatikana kwa kutumia libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology’s custom **libarchive** backend

Synology inajumuisha libarchive iliyorekebishwa ambayo inasajili muundo wa "tar" wa uwongo kila wakati uchawi ni `0xADBEEF`:
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
The decrypted `tar_hdr` ni **kichwa cha POSIX TAR cha kawaida**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Kila **0x18-byte nonce** inaongezwa kabla ya kipande kilichosimbwa.

Mara baada ya kuandaa kila kipengee, libarchive inazalisha **`.tar`** halali ambayo inaweza kufunguliwa na chombo chochote cha kawaida.

## 8. Futa kila kitu kwa kutumia synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` inatambua moja kwa moja PAT/SPK, inaload funguo sahihi na inatumia mnyororo kamili ulioelezwa hapo juu.

## 9. Mtego wa kawaida

* Usibadilishe `signature_key` na `master_key` – zina huduma tofauti.
* **Nonce** inakuja *kabla* ya ciphertext kwa kila block (kichwa na data).
* Ukubwa wa juu wa kipande kilichosimbwa ni **0x400000 + 0x11** (libsodium tag).
* Hifadhi zilizoundwa kwa kizazi kimoja cha DSM zinaweza kubadilisha funguo tofauti zilizowekwa kwa nguvu katika toleo linalofuata.

## 10. Zana za ziada

* [`patology`](https://github.com/sud0woodo/patology) – parse/dump PAT archives.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – decrypt PAT/SPK/others.
* [`libsodium`](https://github.com/jedisct1/libsodium) – reference implementation of XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – header serialisation.

## Marejeleo

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
