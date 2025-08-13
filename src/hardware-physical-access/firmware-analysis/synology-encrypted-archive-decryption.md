# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Nekoliko Synology uređaja (DSM/BSM NAS, BeeStation, …) distribuira svoj firmware i aplikacione pakete u **kriptovanim PAT / SPK arhivama**. Te arhive se mogu dekriptovati *offline* samo uz javne preuzete datoteke zahvaljujući hard-kodiranim ključevima ugrađenim unutar zvaničnih biblioteka za ekstrakciju.

Ova stranica dokumentuje, korak po korak, kako kriptovani format funkcioniše i kako potpuno povratiti čisti tekst **TAR** koji se nalazi unutar svakog paketa. Procedura se zasniva na istraživanju Synacktiv-a sprovedenom tokom Pwn2Own Irska 2024 i implementirana je u open-source alatu [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  Format je potpuno isti za `*.pat` (ažuriranje sistema) i `*.spk` (aplikacija) arhive – jedino se razlikuju u paru hard-kodiranih ključeva koji se biraju.

---

## 1. Preuzmite arhivu

Ažuriranje firmware/aplikacije se obično može preuzeti sa javnog portala Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Ispusti PAT strukturu (opciono)

`*.pat` slike su same **cpio paket** koji sadrži nekoliko datoteka (boot loader, kernel, rootfs, paketi…). Besplatni alat [`patology`](https://github.com/sud0woodo/patology) je zgodan za pregledavanje tog omota:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Za `*.spk` možete direktno preći na korak 3.

## 3. Izdvojite Synology biblioteke za ekstrakciju

Prava logika dekripcije se nalazi u:

* `/usr/syno/sbin/synoarchive`               → glavni CLI omotač
* `/usr/lib/libsynopkg.so.1`                 → poziva omotač iz DSM UI
* `libsynocodesign.so`                       → **sadrži kriptografsku implementaciju**

Oba binarna fajla su prisutna u sistemskom rootfs (`hda1.tgz`) **i** u komprimovanom init-rd (`rd.bin`). Ako imate samo PAT, možete ih dobiti na ovaj način:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Povratak hard-kodiranih ključeva (`get_keys`)

Unutar `libsynocodesign.so` funkcija `get_keys(int keytype)` jednostavno vraća dve 128-bitne globalne promenljive za traženu porodicu arhiva:
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
* **signature_key** → Ed25519 javni ključ koji se koristi za verifikaciju zaglavlja arhive.
* **master_key**    → Glavni ključ koji se koristi za derivaciju ključa za enkripciju po arhivi.

Morate da izbacite ta dva konstanta samo jednom za svaku glavnu verziju DSM-a.

## 5. Struktura zaglavlja i verifikacija potpisa

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` izvršava sledeće:

1. Pročitajte magiju (3 bajta) `0xBFBAAD` **ili** `0xADBEEF`.
2. Pročitajte little-endian 32-bitni `header_len`.
3. Pročitajte `header_len` bajtova + sledeći **0x40-bajtni Ed25519 potpis**.
4. Iterirajte kroz sve ugrađene javne ključeve dok `crypto_sign_verify_detached()` ne uspe.
5. Dekodirajte zaglavlje sa **MessagePack**, što daje:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` kasnije omogućava libarchive da proveri integritet svake datoteke dok se dekriptuje.

## 6. Izvedi podključ po arhivi

Iz `data` blob-a sadržanog u MessagePack header-u:

* `subkey_id`  = little-endian `uint64` na offsetu 0x10
* `ctx`        = 7 bajtova na offsetu 0x18

32-bajtni **stream key** se dobija pomoću libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology-ov prilagođeni **libarchive** backend

Synology uključuje ispravljen libarchive koji registruje lažni "tar" format kada je magija `0xADBEEF`:
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
Dešifrovani `tar_hdr` je **klasična POSIX TAR glava**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Svaki **0x18-byte nonce** se dodaje ispred enkriptovanog dela.

Kada su svi unosi obrađeni, libarchive proizvodi savršeno validan **`.tar`** koji se može raspakovati sa bilo kojim standardnim alatom.

## 8. Dešifrujte sve sa synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` automatski detektuje PAT/SPK, učitava ispravne ključeve i primenjuje celu lanac opisan iznad.

## 9. Uobičajene zamke

* Ne **menjajte** `signature_key` i `master_key` – oni imaju različite svrhe.
* **Nonce** dolazi *pre* šifrovanog teksta za svaki blok (zaglavlje i podaci).
* Maksimalna veličina šifrovanog dela je **0x400000 + 0x11** (libsodium oznaka).
* Arhive kreirane za jednu generaciju DSM-a mogu preći na različite hard-kodirane ključeve u sledećem izdanju.

## 10. Dodatni alati

* [`patology`](https://github.com/sud0woodo/patology) – parsiranje/dump PAT arhiva.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – dešifrovanje PAT/SPK/drugo.
* [`libsodium`](https://github.com/jedisct1/libsodium) – referentna implementacija XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – serijalizacija zaglavlja.

## Reference

- [Ekstrakcija šifrovanih arhiva Synology – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt na GitHub-u](https://github.com/synacktiv/synodecrypt)
- [patology na GitHub-u](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
