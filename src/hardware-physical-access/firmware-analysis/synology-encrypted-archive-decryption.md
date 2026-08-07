# Decryption of Synology PAT/SPK Encrypted Archives

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Nekoliko Synology uređaja (DSM/BSM NAS, BeeStation, …) distribuira svoj firmware i pakete aplikacija u **šifrovanim PAT / SPK arhivama**. Te arhive mogu da se dešifruju *offline*, koristeći samo javno dostupne datoteke za preuzimanje, zahvaljujući hardkodovanim ključevima ugrađenim u zvanične biblioteke za ekstrakciju.

Ova stranica dokumentuje, korak po korak, kako šifrovani format funkcioniše i kako u potpunosti povratiti clear-text **TAR** koji se nalazi unutar svakog paketa. Procedura je zasnovana na istraživanju kompanije Synacktiv sprovedenom tokom takmičenja Pwn2Own Ireland 2024 i implementirana u open-source alatu [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️ Format je potpuno isti za `*.pat` (ažuriranje sistema) i `*.spk` (aplikacija) arhive – razlikuju se samo po paru hardkodovanih ključeva koji se biraju.

---

## 1. Preuzimanje arhive

Ažuriranje firmware-a/aplikacije se obično može preuzeti sa Synology javnog portala:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Ispis PAT strukture (opciono)

`*.pat` images su same po sebi **cpio bundle** koji sadrži nekoliko datoteka (boot loader, kernel, rootfs, packages…). Besplatni utility [`patology`](https://github.com/sud0woodo/patology) je praktičan za ispitivanje tog omotača:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Za `*.spk` možete direktno preći na korak 3.

## 3. Ekstrakcija Synology biblioteka za ekstrakciju

Prava logika dešifrovanja nalazi se u:

* `/usr/syno/sbin/synoarchive`               → glavni CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → poziva wrapper iz DSM UI-ja
* `libsynocodesign.so`                       → **sadrži kriptografsku implementaciju**

Obe binarne datoteke prisutne su u sistemskom rootfs-u (`hda1.tgz`) **i** u kompresovanom init-rd-u (`rd.bin`).  Ako imate samo PAT, možete ih dobiti na sledeći način:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Preuzimanje hard-coded ključeva (`get_keys`)

U biblioteci `libsynocodesign.so`, funkcija `get_keys(int keytype)` jednostavno vraća dve 128-bitne globalne promenljive za zahtevanu familiju arhiva:<sup>[[1]](#references)</sup>
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
* **signature_key** → Ed25519 public key koji se koristi za verifikaciju zaglavlja arhive.
* **master_key**    → Root key koji se koristi za izvođenje encryption key-a za pojedinačnu arhivu.

Te dve konstante morate dump-ovati samo jednom za svaku glavnu DSM verziju.

## 5. Struktura zaglavlja i verifikacija potpisa

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` izvršava sledeće:<sup>[[1]](#references)</sup>

1. Čita magic (3 bajta) `0xBFBAAD` **ili** `0xADBEEF`.
2. Čita little-endian 32-bitni `header_len`.
3. Čita `header_len` bajtova + naredni **0x40-bajtni Ed25519 potpis**.
4. Iterira kroz sve ugrađene javne ključeve dok `crypto_sign_verify_detached()` ne uspe.
5. Dekodira zaglavlje pomoću **MessagePack**, čime dobija:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` kasnije omogućava libarchive-u da proveri integritet svake datoteke tokom dešifrovanja.

## 6. Izvođenje podključa po arhivi

Iz `data` blob-a sadržanog u MessagePack zaglavlju:

* `subkey_id`  = little-endian `uint64` na offset-u 0x10
* `ctx`        = 7 bajtova na offset-u 0x18

32-bajtni **stream key** dobija se pomoću libsodium-a:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology-ov prilagođeni **libarchive** backend

Synology uključuje izmenjeni libarchive koji registruje lažni format "tar" kad god je magic `0xADBEEF`:<sup>[[1]](#references)</sup>
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
Dešifrovani `tar_hdr` je **klasično POSIX TAR zaglavlje**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Svaki **0x18-byte nonce** nalazi se ispred enkriptovanog segmenta.

Nakon obrade svih stavki, libarchive proizvodi potpuno validan **`.tar`** koji se može raspakovati bilo kojim standardnim alatom.

## 8. Dešifrujte sve pomoću synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` automatski detektuje PAT/SPK, učitava odgovarajuće ključeve i primenjuje ceo lanac opisan iznad.<sup>[[2]](#references)</sup>

## 9. Uobičajene greške

* **Nemojte** zameniti `signature_key` i `master_key` – imaju različite namene.
* **Nonce** se nalazi *pre* ciphertext-a za svaki blok (zaglavlje i podaci).
* Maksimalna veličina šifrovanog chunk-a je **0x400000 + 0x11** (libsodium tag).
* Arhive kreirane za jednu DSM generaciju mogu u sledećem izdanju preći na druge hard-coded ključeve.

## 10. Dodatni alati

* [`patology`](https://github.com/sud0woodo/patology) – parsiranje i dump PAT arhiva.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – dešifrovanje PAT/SPK/drugih formata.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – referentna implementacija XChaCha20-Poly1305 secretstream-a.
* [`msgpack`](https://msgpack.org/) – serijalizacija zaglavlja.

## Reference

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
