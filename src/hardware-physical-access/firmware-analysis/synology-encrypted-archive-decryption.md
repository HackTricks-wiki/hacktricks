# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Overview

Kilka urządzeń Synology (DSM/BSM NAS, BeeStation, …) dystrybuuje swoje oprogramowanie i pakiety aplikacji w **zaszyfrowanych archiwach PAT / SPK**. Te archiwa można odszyfrować *offline* przy użyciu jedynie publicznych plików do pobrania, dzięki wbudowanym w oficjalne biblioteki ekstrakcji kluczom zakodowanym na stałe.

Ta strona dokumentuje, krok po kroku, jak działa zaszyfrowany format i jak w pełni odzyskać tekst jawny **TAR**, który znajduje się w każdym pakiecie. Procedura opiera się na badaniach Synacktiv przeprowadzonych podczas Pwn2Own Ireland 2024 i została zaimplementowana w narzędziu open-source [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  Format jest dokładnie taki sam dla archiwów `*.pat` (aktualizacja systemu) i `*.spk` (aplikacja) – różnią się tylko parą kluczy zakodowanych na stałe, które są wybierane.

---

## 1. Grab the archive

Aktualizację oprogramowania/aplikacji można zazwyczaj pobrać z publicznego portalu Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Zrzut struktury PAT (opcjonalnie)

`*.pat` obrazy są same w sobie **pakietem cpio**, który zawiera kilka plików (boot loader, kernel, rootfs, pakiety…). Darmowe narzędzie [`patology`](https://github.com/sud0woodo/patology) jest wygodne do inspekcji tego opakowania:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Dla `*.spk` możesz bezpośrednio przejść do kroku 3.

## 3. Wyodrębnij biblioteki wyodrębniania Synology

Prawdziwa logika deszyfrowania znajduje się w:

* `/usr/syno/sbin/synoarchive`               → główny wrapper CLI
* `/usr/lib/libsynopkg.so.1`                 → wywołuje wrapper z interfejsu DSM
* `libsynocodesign.so`                       → **zawiera implementację kryptograficzną**

Oba pliki binarne są obecne w systemowym rootfs (`hda1.tgz`) **i** w skompresowanym init-rd (`rd.bin`). Jeśli masz tylko PAT, możesz je uzyskać w ten sposób:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Odzyskiwanie twardo zakodowanych kluczy (`get_keys`)

Wewnątrz `libsynocodesign.so` funkcja `get_keys(int keytype)` po prostu zwraca dwie 128-bitowe zmienne globalne dla żądanej rodziny archiwów:
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
* **signature_key** → Klucz publiczny Ed25519 używany do weryfikacji nagłówka archiwum.
* **master_key**    → Klucz główny używany do wyprowadzenia klucza szyfrowania dla archiwum.

Musisz zrzucić te dwa stałe tylko raz dla każdej głównej wersji DSM.

## 5. Struktura nagłówka i weryfikacja podpisu

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` wykonuje następujące czynności:

1. Odczytaj magiczne (3 bajty) `0xBFBAAD` **lub** `0xADBEEF`.
2. Odczytaj 32-bitowy `header_len` w formacie little-endian.
3. Odczytaj `header_len` bajtów + następny **0x40-bajtowy podpis Ed25519**.
4. Iteruj przez wszystkie osadzone klucze publiczne, aż `crypto_sign_verify_detached()` zakończy się sukcesem.
5. Zdekoduj nagłówek za pomocą **MessagePack**, co daje:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` później pozwala libarchive na sprawdzenie integralności każdego pliku w miarę jego deszyfrowania.

## 6. Wyprowadź podklucz dla archiwum

Z obiektu `data` zawartego w nagłówku MessagePack:

* `subkey_id`  = little-endian `uint64` w przesunięciu 0x10
* `ctx`        = 7 bajtów w przesunięciu 0x18

32-bajtowy **klucz strumieniowy** uzyskuje się za pomocą libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Własny backend **libarchive** Synology

Synology dołącza poprawioną wersję libarchive, która rejestruje fałszywy format "tar", gdy magiczne liczby to `0xADBEEF`:
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
Zdechifrowany `tar_hdr` to **klasyczny nagłówek TAR POSIX**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Każdy **0x18-bajtowy nonce** jest dodawany na początku zaszyfrowanego fragmentu.

Gdy wszystkie wpisy zostaną przetworzone, libarchive generuje całkowicie poprawny **`.tar`**, który można rozpakować za pomocą dowolnego standardowego narzędzia.

## 8. Odszyfruj wszystko za pomocą synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` automatycznie wykrywa PAT/SPK, ładuje odpowiednie klucze i stosuje pełny łańcuch opisany powyżej.

## 9. Typowe pułapki

* Nie zamieniaj `signature_key` i `master_key` – pełnią różne funkcje.
* **Nonce** występuje *przed* szyfrogramem dla każdego bloku (nagłówek i dane).
* Maksymalny rozmiar zaszyfrowanego kawałka to **0x400000 + 0x11** (tag libsodium).
* Archiwa utworzone dla jednej generacji DSM mogą przejść na różne zakodowane klucze w następnej wersji.

## 10. Dodatkowe narzędzia

* [`patology`](https://github.com/sud0woodo/patology) – analiza/zrzut archiwów PAT.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – deszyfrowanie PAT/SPK/innych.
* [`libsodium`](https://github.com/jedisct1/libsodium) – referencyjna implementacja XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – serializacja nagłówków.

## Odniesienia

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
