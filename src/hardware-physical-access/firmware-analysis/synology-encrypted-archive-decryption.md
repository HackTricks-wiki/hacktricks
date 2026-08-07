# Deszyfrowanie zaszyfrowanych archiwów PAT/SPK Synology

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Kilka urządzeń Synology (DSM/BSM NAS, BeeStation, …) dystrybuuje swoje firmware i pakiety aplikacji w **zaszyfrowanych archiwach PAT / SPK**. Archiwa te można odszyfrować *offline*, korzystając wyłącznie z publicznie dostępnych plików do pobrania, ponieważ oficjalne biblioteki ekstrakcyjne zawierają hard-coded keys.

Ta strona szczegółowo, krok po kroku, opisuje działanie zaszyfrowanego formatu oraz sposób pełnego odzyskania jawnego **TAR** znajdującego się wewnątrz każdego pakietu. Procedura bazuje na badaniach Synacktiv przeprowadzonych podczas Pwn2Own Ireland 2024 i zaimplementowanych w open-source tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Format jest dokładnie taki sam dla archiwów `*.pat` (system update) i `*.spk` (application) – różnią się wyłącznie parą wybranych hard-coded keys.

---

## 1. Pobierz archiwum

Firmware/application update można zazwyczaj pobrać z publicznego portalu Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Zrzut struktury PAT (opcjonalnie)

Obrazy `*.pat` są same w sobie **pakietem cpio**, który zawiera kilka plików (boot loader, kernel, rootfs, pakiety…). Do wygodnego sprawdzania tej otoczki można użyć darmowego narzędzia [`patology`](https://github.com/sud0woodo/patology):<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Dla `*.spk` możesz od razu przejść do kroku 3.

## 3. Wyodrębnij biblioteki deszyfrujące Synology

Rzeczywista logika deszyfrowania znajduje się w:

* `/usr/syno/sbin/synoarchive`               → główny wrapper CLI
* `/usr/lib/libsynopkg.so.1`                 → wywołuje wrapper z interfejsu DSM
* `libsynocodesign.so`                       → **zawiera implementację kryptograficzną**

Oba pliki binarne znajdują się w systemowym rootfs (`hda1.tgz`) **oraz** w skompresowanym init-rd (`rd.bin`). Jeśli masz tylko PAT, możesz je uzyskać w następujący sposób:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Odzyskiwanie kluczy zakodowanych na stałe (`get_keys`)

Wewnątrz `libsynocodesign.so` funkcja `get_keys(int keytype)` po prostu zwraca dwie globalne zmienne 128-bitowe dla żądanej rodziny archiwów:<sup>[[1]](#references)</sup>
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
* **signature_key** → publiczny klucz Ed25519 używany do weryfikacji nagłówka archiwum.
* **master_key**    → klucz główny używany do wyprowadzenia klucza szyfrowania danego archiwum.

Musisz wykonać dump tych dwóch stałych tylko raz dla każdej głównej wersji DSM.

## 5. Struktura nagłówka i weryfikacja podpisu

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` wykonuje następujące czynności:<sup>[[1]](#references)</sup>

1. Odczytuje magic (3 bajty) `0xBFBAAD` **lub** `0xADBEEF`.
2. Odczytuje 32-bitowe `header_len` w formacie little-endian.
3. Odczytuje `header_len` bajtów oraz następny **64-bajtowy podpis Ed25519**.
4. Iteruje po wszystkich osadzonych kluczach publicznych, aż `crypto_sign_verify_detached()` zakończy się powodzeniem.
5. Dekoduje nagłówek za pomocą **MessagePack**, uzyskując:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` pozwala później bibliotece libarchive sprawdzać integralność każdego pliku podczas jego odszyfrowywania.

## 6. Wyprowadzenie sub-key dla archiwum

Z bloku `data` zawartego w nagłówku MessagePack:

* `subkey_id`  = little-endian `uint64` pod offsetem 0x10
* `ctx`        = 7 bajtów pod offsetem 0x18

32-bajtowy **stream key** jest uzyskiwany za pomocą libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Niestandardowy backend **libarchive** firmy Synology

Synology dołącza zmodyfikowaną wersję libarchive, która rejestruje fikcyjny format „tar”, gdy magic ma wartość `0xADBEEF`:<sup>[[1]](#references)</sup>
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
Odszyfrowany `tar_hdr` to **klasyczny nagłówek POSIX TAR**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Każdy **0x18-bajtowy nonce** jest dodawany przed zaszyfrowanym chunkem.

Po przetworzeniu wszystkich wpisów libarchive tworzy w pełni poprawny plik **`.tar`**, który można rozpakować dowolnym standardowym narzędziem.

## 8. Odszyfruj wszystko za pomocą synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` automatycznie wykrywa PAT/SPK, ładuje właściwe klucze i stosuje pełny opisany powyżej łańcuch.<sup>[[2]](#references)</sup>

## 9. Typowe pułapki

* **Nie** zamieniaj `signature_key` i `master_key` – służą do różnych celów.
* **Nonce** znajduje się *przed* ciphertextem dla każdego bloku (nagłówka i danych).
* Maksymalny rozmiar zaszyfrowanego fragmentu to **0x400000 + 0x11** (tag libsodium).
* Archiwa utworzone dla jednej generacji DSM mogą w następnym wydaniu przełączać się na inne hard-coded keys.

## 10. Dodatkowe narzędzia

* [`patology`](https://github.com/sud0woodo/patology) – analizowanie/zrzucanie archiwów PAT.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – odszyfrowywanie PAT/SPK/innych.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – implementacja referencyjna secretstream XChaCha20-Poly1305.
* [`msgpack`](https://msgpack.org/) – serializacja nagłówka.

## Referencje

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
