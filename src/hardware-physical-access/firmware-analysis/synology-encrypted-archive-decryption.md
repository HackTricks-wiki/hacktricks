# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Verskeie Synology toestelle (DSM/BSM NAS, BeeStation, …) versprei hul firmware en toepassingspakkette in **geënkripteerde PAT / SPK argiewe**. Daardie argiewe kan *aflyn* gedekripteer word met niks anders as die publieke aflaaifiles nie, danksy hard-gecodeerde sleutels wat in die amptelike ekstraksiebiblioteke ingebed is.

Hierdie bladsy dokumenteer, stap-vir-stap, hoe die geënkripteerde formaat werk en hoe om die duidelike teks **TAR** wat binne elke pakket sit, volledig te herstel. Die prosedure is gebaseer op Synacktiv navorsing wat tydens Pwn2Own Ierland 2024 uitgevoer is en geïmplementeer is in die oopbron hulpmiddel [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  Die formaat is presies dieselfde vir beide `*.pat` (stelseldatumn) en `*.spk` (toepassing) argiewe – hulle verskil net in die paar hard-gecodeerde sleutels wat gekies word.

---

## 1. Grijp die argief

Die firmware/toepassing opdatering kan normaalweg van Synology se publieke portaal afgelaai word:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump die PAT-struktuur (opsioneel)

`*.pat` beelde is self 'n **cpio bundel** wat verskeie lêers (boot loader, kernel, rootfs, pakkette…) insluit. Die gratis nut `patology` is gerieflik om daardie omhulsel te ondersoek:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Vir `*.spk` kan jy direk na stap 3 spring.

## 3. Onttrek die Synology onttrekkingsbiblioteke

Die werklike ontsleutelinglogika is in:

* `/usr/syno/sbin/synoarchive`               → hoof CLI-wrapper
* `/usr/lib/libsynopkg.so.1`                 → roep die wrapper vanaf DSM UI aan
* `libsynocodesign.so`                       → **bevat die kriptografiese implementering**

Albei binêre is teenwoordig in die stelsels rootfs (`hda1.tgz`) **en** in die gecomprimeerde init-rd (`rd.bin`).  As jy net die PAT het, kan jy hulle op hierdie manier kry:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Herwin die hard-gecodeerde sleutels (`get_keys`)

Binne `libsynocodesign.so` keer die funksie `get_keys(int keytype)` eenvoudig twee 128-bit globale veranderlikes terug vir die versoekte argieffamilie:
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
* **master_key**    → Wortelsleutel wat gebruik word om die per-argief versleuteling sleutel af te lei.

Jy moet slegs daardie twee konstantes een keer vir elke DSM hoofweergawe dump.

## 5. Kopstruktuur & handtekeningverifikasie

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` voer die volgende uit:

1. Lees magic (3 bytes) `0xBFBAAD` **of** `0xADBEEF`.
2. Lees little-endian 32-bit `header_len`.
3. Lees `header_len` bytes + die volgende **0x40-byte Ed25519 handtekening**.
4. Herhaal oor al die ingebedde publieke sleutels totdat `crypto_sign_verify_detached()` slaag.
5. Dekodeer die kop met **MessagePack**, wat oplewer:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` laat later libarchive toe om die integriteit van elke lêer te kontroleer soos dit gedekript word.

## 6. Ontleed die per-archive sub-sleutel

Van die `data` blob wat in die MessagePack kop is:

* `subkey_id`  = little-endian `uint64` by offset 0x10
* `ctx`        = 7 bytes by offset 0x18

Die 32-byte **stream key** word verkry met libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology se pasgemaakte **libarchive** agtergrond

Synology bundel 'n gepatchte libarchive wat 'n vals "tar" formaat registreer wanneer die magie `0xADBEEF` is:
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
Die ontsleutelde `tar_hdr` is 'n **klassieke POSIX TAR kop**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Elke **0x18-byte nonce** word aan die begin van die versleutelde stuk gevoeg.

Sodra alle inskrywings verwerk is, produseer libarchive 'n volmaak geldige **`.tar`** wat met enige standaard hulpmiddel ontpak kan word.

## 8. Decrypt alles met synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` detecteer outomaties PAT/SPK, laai die korrekte sleutels en pas die volle ketting hierbo beskryf toe.

## 9. Algemene valstrikke

* Moet **nie** `signature_key` en `master_key` ruil nie – hulle dien verskillende doeleindes.
* Die **nonce** kom *voor* die geslote teks vir elke blok (kop en data).
* Die maksimum versleutelde stukgrootte is **0x400000 + 0x11** (libsodium etiket).
* Argiewe wat vir een DSM-generasie geskep is, mag in die volgende weergawe na verskillende hard-gecodeerde sleutels oorgaan.

## 10. Bykomende gereedskap

* [`patology`](https://github.com/sud0woodo/patology) – ontleed/dump PAT-argiewe.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – ontsleutel PAT/SPK/ander.
* [`libsodium`](https://github.com/jedisct1/libsodium) – verwysingsimplementering van XChaCha20-Poly1305 geheimstroom.
* [`msgpack`](https://msgpack.org/) – kopserialisering.

## Verwysings

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
