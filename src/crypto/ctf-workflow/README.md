# Przepływ pracy Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Lista kontrolna triage

1. Zidentyfikuj, co masz: encoding vs encryption vs hash vs signature vs MAC.
2. Określ, co jest kontrolowane: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Sklasyfikuj: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Zastosuj najprawdopodobniejsze kontrole najpierw: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Przejdź do zaawansowanych metod tylko jeśli to konieczne: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Zasoby online i narzędzia

Są przydatne, gdy zadanie polega na identyfikacji i zdejmowaniu warstw, lub gdy potrzebujesz szybkiego potwierdzenia hipotezy.

### Wyszukiwanie hashy

- Przeszukaj hash w Google (zaskakująco skuteczne).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Pomocniki do identyfikacji

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Platformy do ćwiczeń / odniesienia

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Zautomatyzowane dekodowanie

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technika

Wiele zadań crypto CTF to warstwowe transformacje: base encoding + simple substitution + compression. Celem jest zidentyfikować warstwy i bezpiecznie je zdjąć.

### Encodings: spróbuj wielu bases

Jeśli podejrzewasz warstwowe kodowanie (base64 → base32 → …), spróbuj:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Typowe wskazówki:

- Base64: `A-Za-z0-9+/=` (padding `=` jest częsty)
- Base32: `A-Z2-7=` (często dużo paddingu `=`)
- Ascii85/Base85: gęsta interpunkcja; czasem opakowane w `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

Często pojawia się jako grupy po 5 bitów lub 5 liter:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runy

Runy to często alfabety substytucyjne; wyszukaj "futhark cipher" i spróbuj tabel mapowań.

## Kompresja w wyzwaniach

### Technika

Kompresja pojawia się często jako dodatkowa warstwa (zlib/deflate/gzip/xz/zstd), czasem zagnieżdżona. Jeśli wynik niemal się parsuje, ale wygląda jak śmieci, podejrzewaj kompresję.

### Szybka identyfikacja

- `file <blob>`
- Szukaj magicznych bajtów:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, które często są najszybszą ścieżką, kiedy blob wygląda na skompresowany, ale `zlib` zawodzi.

### Przydatne narzędzia CLI
```bash
python3 - <<'PY'
import sys, zlib
data = sys.stdin.buffer.read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## Typowe konstrukcje kryptograficzne w CTF

### Technika

Pojawiają się często, ponieważ są realistycznymi błędami developerów albo popularnymi bibliotekami używanymi nieprawidłowo. Celem zazwyczaj jest rozpoznanie i zastosowanie znanego schematu ekstrakcji lub rekonstrukcji.

### Fernet

Typowa wskazówka: dwa ciągi Base64 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Jeśli widzisz wiele udziałów i wspomniany jest próg `t`, prawdopodobnie chodzi o Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs czasami podają wyniki `openssl enc` (nagłówek często zaczyna się od `Salted__`).

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Ogólny zestaw narzędzi

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Zalecana lokalna konfiguracja

Praktyczny stos dla CTF:

- Python + `pycryptodome` do prymitywów symetrycznych i szybkiego prototypowania
- SageMath do arytmetyki modularnej, CRT, lattices oraz pracy z RSA/ECC
- Z3 do zadań opartych na ograniczeniach (gdy crypto sprowadza się do ograniczeń)

Sugerowane pakiety Pythona:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
