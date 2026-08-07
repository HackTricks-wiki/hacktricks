# Uondoaji wa Usimbaji wa PAT/SPK Encrypted Archive za Synology

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Vifaa kadhaa vya Synology (DSM/BSM NAS, BeeStation, …) husambaza firmware na application packages zake katika **encrypted PAT / SPK archives**. Archives hizo zinaweza kusimbuliwa *offline* bila chochote zaidi ya public download files, kutokana na hard-coded keys zilizowekwa ndani ya official extraction libraries.

Ukurasa huu unaeleza, hatua kwa hatua, jinsi format iliyosimbwa inavyofanya kazi na jinsi ya kurejesha kikamilifu **TAR** iliyo katika kila package. Utaratibu huu unatokana na utafiti wa Synacktiv uliofanywa wakati wa Pwn2Own Ireland 2024 na kutekelezwa katika open-source tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Format ni ileile kabisa kwa `*.pat` (system update) na `*.spk` (application) archives – zinatofautiana tu katika jozi ya hard-coded keys zinazochaguliwa.

---

## 1. Pakua archive

Firmware/application update kwa kawaida inaweza kupakuliwa kutoka public portal ya Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump muundo wa PAT (hiari)

`*.pat` images ni **cpio bundle** zenyewe inayobeba faili kadhaa (boot loader, kernel, rootfs, packages…). Zana ya bure [`patology`](https://github.com/sud0woodo/patology) inafaa kukagua wrapper hiyo:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Kwa `*.spk` unaweza kuruka moja kwa moja hadi hatua ya 3.

## 3. Extract maktaba za Synology

Mantiki halisi ya decryption iko katika:

* `/usr/syno/sbin/synoarchive`               → main CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → huita wrapper kutoka DSM UI
* `libsynocodesign.so`                       → **ina cryptographic implementation**

Binaries zote mbili zinapatikana kwenye system rootfs (`hda1.tgz`) **na** kwenye init-rd iliyobanwa (`rd.bin`). Ikiwa una PAT pekee, unaweza kuzipata hivi:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Rejesha funguo za hard-coded (`get_keys`)

Ndani ya `libsynocodesign.so`, function ya `get_keys(int keytype)` hurejesha variables mbili za global za biti 128 kwa familia ya archive iliyoombwa:<sup>[[1]](#references)</sup>
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
* **signature_key** → Ed25519 public key inayotumika kuthibitisha archive header.
* **master_key**    → Root key inayotumika kutengeneza encryption key ya kila archive.

Unahitaji kudump hizo constants mbili mara moja tu kwa kila DSM major version.

## 5. Muundo wa header na uthibitishaji wa signature

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` hufanya yafuatayo:<sup>[[1]](#references)</sup>

1. Soma magic (bytes 3) `0xBFBAAD` **au** `0xADBEEF`.
2. Soma `header_len` ya bits 32 katika little-endian.
3. Soma bytes `header_len` + **signature ya Ed25519 yenye ukubwa wa bytes 0x40** inayofuata.
4. Pitia public keys zote zilizopachikwa hadi `crypto_sign_verify_detached()` ifanikiwe.
5. Decode header kwa **MessagePack**, ukipata:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` baadaye huruhusu libarchive kukagua integrity ya kila faili linapodecryptiwa.

## 6. Derive the per-archive sub-key

Kutoka kwenye `data` blob iliyo ndani ya MessagePack header:

* `subkey_id`  = little-endian `uint64` kwenye offset 0x10
* `ctx`        = baiti 7 kwenye offset 0x18

**stream key** ya baiti 32 hupatikana kwa kutumia libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. **libarchive** backend maalum ya Synology

Synology inajumuisha libarchive iliyorekebishwa ambayo husajili format bandia ya "tar" wakati wowote magic inapokuwa `0xADBEEF`:<sup>[[1]](#references)</sup>
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
`tar_hdr` iliyofutwa usimbaji fiche ni **TAR header ya kawaida ya POSIX**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Kila **0x18-byte nonce** huongezwa mwanzoni mwa kipande kilichosimbwa kwa encryption.

Baada ya entries zote kuchakatwa, libarchive hutengeneza **`.tar`** halali kabisa ambayo inaweza kufunguliwa kwa tool yoyote ya kawaida.

## 8. Decrypt kila kitu kwa synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` hutambua kiotomatiki PAT/SPK, hupakia keys sahihi na kutumia chain kamili iliyoelezwa hapo juu.<sup>[[2]](#references)</sup>

## 9. Mitego ya kawaida

* **Usibadilishe** `signature_key` na `master_key` – hutumika kwa madhumuni tofauti.
* **Nonce** huja *kabla* ya ciphertext kwa kila block (header na data).
* Ukubwa wa juu wa encrypted chunk ni **0x400000 + 0x11** (libsodium tag).
* Archives zilizoundwa kwa kizazi kimoja cha DSM zinaweza kubadilisha na kutumia hard-coded keys tofauti katika release inayofuata.

## 10. Zana za ziada

* [`patology`](https://github.com/sud0woodo/patology) – parse/dump PAT archives.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – decrypt PAT/SPK/others.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – reference implementation ya XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – header serialisation.

## Marejeo

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
