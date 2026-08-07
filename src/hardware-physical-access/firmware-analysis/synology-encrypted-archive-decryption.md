# Synology PAT/SPK-geënkripteerde argiefdekripsie

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Verskeie Synology-toestelle (DSM/BSM NAS, BeeStation, …) versprei hul firmware- en toepassingspakkette in **geënkripteerde PAT / SPK-argiewe**. Hierdie argiewe kan *offline* gedekripteer word met niks meer as die publieke aflaailêers nie, danksy hard-coded sleutels wat binne die amptelike ekstraksiebiblioteke ingebed is.

Hierdie bladsy dokumenteer stap vir stap hoe die geënkripteerde formaat werk en hoe om die duidelike **TAR** wat binne elke pakket sit, volledig te herwin. Die prosedure is gebaseer op Synacktiv-navorsing wat tydens Pwn2Own Ireland 2024 uitgevoer is, en geïmplementeer in die open-source tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Die formaat is presies dieselfde vir beide `*.pat`- (stelselopdatering) en `*.spk`- (toepassing) argiewe – hulle verskil slegs in die paar hard-coded sleutels wat gekies word.

---

## 1. Kry die argief

Die firmware-/toepassingsopdatering kan gewoonlik vanaf Synology se openbare portaal afgelaai word:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump die PAT-struktuur (opsioneel)

`*.pat`-images is self ’n **cpio bundle** wat verskeie files insluit (boot loader, kernel, rootfs, packages…). Die gratis utility [`patology`](https://github.com/sud0woodo/patology) is gerieflik om daardie wrapper te inspekteer:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Vir `*.spk` kan jy direk na stap 3 spring.

## 3. Onttrek die Synology extraction libraries

Die werklike decryption logic is in:

* `/usr/syno/sbin/synoarchive`               → main CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → roep die wrapper vanaf die DSM UI
* `libsynocodesign.so`                       → **bevat die cryptographic implementation**

Albei binaries is in die system rootfs (`hda1.tgz`) **en** in die compressed init-rd (`rd.bin`).  As jy slegs die PAT het, kan jy hulle op hierdie manier kry:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Herwin die hard-coded keys (`get_keys`)

Binne `libsynocodesign.so` gee die funksie `get_keys(int keytype)` eenvoudig twee 128-bis globale veranderlikes terug vir die aangevraagde argief-familie:<sup>[[1]](#references)</sup>
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
* **signature_key** → Ed25519 publieke sleutel wat gebruik word om die argiefkop te verifieer.
* **master_key**    → Wortelsleutel wat gebruik word om die enkripsiesleutel per argief af te lei.

Jy hoef slegs daardie twee konstantes een keer vir elke DSM-hoofweergawe te dump.

## 5. Kopstruktuur en handtekeningverifikasie

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` voer die volgende uit:<sup>[[1]](#references)</sup>

1. Lees magic (3 grepe) `0xBFBAAD` **of** `0xADBEEF`.
2. Lees little-endian 32-bis `header_len`.
3. Lees `header_len` grepe + die volgende **0x40-greep Ed25519-handtekening**.
4. Itereer deur al die ingebedde publieke sleutels totdat `crypto_sign_verify_detached()` slaag.
5. Decodeer die kop met **MessagePack**, wat die volgende oplewer:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` stel libarchive later in staat om elke lêer te integriteitkontroleer soos dit gedekripteer word.

## 6. Lei die sub-sleutel per argief af

Uit die `data`-blob wat in die MessagePack-header vervat is:

* `subkey_id`  = little-endian `uint64` by offset 0x10
* `ctx`        = 7 grepe by offset 0x18

Die 32-grepe **stream key** word met libsodium verkry:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology se pasgemaakte **libarchive**-backend

Synology bundel ’n gelapte libarchive wat ’n vals "tar"-formaat registreer wanneer die magic `0xADBEEF` is:<sup>[[1]](#references)</sup>
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
Die gedekripteerde `tar_hdr` is ’n **klassieke POSIX TAR-header**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Elke **0x18-byte nonce** word voor die encrypted chunk geplaas.

Sodra alle inskrywings verwerk is, produseer libarchive ’n volledig geldige **`.tar`** wat met enige standaardtool uitgepak kan word.

## Decrypt alles met synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` bespeur PAT/SPK outomaties, laai die korrekte sleutels en pas die volledige ketting hierbo beskryf toe.<sup>[[2]](#references)</sup>

## 9. Algemene slaggate

* Moet **nie** `signature_key` en `master_key` omruil nie – hulle dien verskillende doeleindes.
* Die **nonce** kom vir elke blok (kop en data) *voor* die ciphertext.
* Die maksimum grootte van 'n geënkripteerde chunk is **0x400000 + 0x11** (libsodium-tag).
* Argiewe wat vir een DSM-generasie geskep is, kan in die volgende release na ander hard-coded keys oorskakel.

## 10. Addisionele tooling

* [`patology`](https://github.com/sud0woodo/patology) – ontleed/dump PAT-argiewe.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – dekripteer PAT/SPK/ander formate.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – verwysingsimplementering van XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – serialisering van kopdata.

## Verwysings

- [1] [Onttrekking van Synology-geënkripteerde argiewe – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt op GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology op GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
