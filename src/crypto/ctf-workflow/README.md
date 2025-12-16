# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Lista kontrolna triage

1. Zidentyfikuj, co masz: encoding vs encryption vs hash vs signature vs MAC.
2. Określ, co jest kontrolowane: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Sklasyfikuj: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Najpierw wykonaj kontrole o najwyższym prawdopodobieństwie: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Przejdź do zaawansowanych metod tylko jeśli to konieczne: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Zasoby online i narzędzia

Te narzędzia są przydatne, gdy zadanie polega na identyfikacji i zdejmowaniu warstw, albo gdy potrzebujesz szybkiego potwierdzenia hipotezy.

### Hash lookups

- Wyszukaj hash w Google (zaskakująco skuteczne).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Identification helpers

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technique

Wiele zadań crypto w CTF to warstwowe transformacje: base encoding + simple substitution + compression. Celem jest zidentyfikowanie warstw i bezpieczne ich zdejmowanie.

### Encodings: try many bases

Jeśli podejrzewasz warstwowe kodowanie (base64 → base32 → …), spróbuj:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Typowe wskazówki:

- Base64: `A-Za-z0-9+/=` (padding `=` jest częsty)
- Base32: `A-Z2-7=` (często dużo paddingu `=`)
- Ascii85/Base85: gęste znaki interpunkcyjne; czasem otoczone `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

### Bacon cipher

Often appears as groups of 5 bits or 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runy

Runy to często alfabety podstawieniowe — wyszukaj "futhark cipher" i spróbuj użyć tabel mapowań.

## Kompresja w zadaniach

### Technika

Kompresja pojawia się często jako dodatkowa warstwa (zlib/deflate/gzip/xz/zstd), czasem zagnieżdżona. Jeśli wynik prawie parsuje, ale wygląda jak śmieci, podejrzewaj kompresję.

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

CyberChef ma **Raw Deflate/Raw Inflate**, które często są najszybszą drogą, gdy blob wygląda na skompresowany, ale `zlib` zawodzi.

### Przydatne CLI
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

Pojawiają się często, ponieważ są to realistyczne błędy programistów lub popularne biblioteki używane niepoprawnie. Celem zwykle jest rozpoznanie i zastosowanie znanego procesu ekstrakcji lub rekonstrukcji.

### Fernet

Typical hint: two Base64 strings (token + key).

- Dekoder/notatki: https://asecuritysite.com/encryption/ferdecode
- W Pythonie: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Jeśli widzisz wiele udziałów i wspomniany jest próg `t`, prawdopodobnie jest to Shamir.

- Rekonstruktor online (przydatny w CTF): http://christian.gen.co/secrets/

### Solone formaty OpenSSL

CTFs czasami podają wyniki `openssl enc` (nagłówek często zaczyna się od `Salted__`).

Narzędzia do bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Ogólny zestaw narzędzi

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Zalecana lokalna konfiguracja

Praktyczny stos CTF:

- Python + `pycryptodome` do prymitywów symetrycznych i szybkiego prototypowania
- SageMath do arytmetyki modularnej, CRT, lattices oraz pracy z RSA/ECC
- Z3 do zadań opartych na ograniczeniach (gdy kryptografia sprowadza się do ograniczeń)

Sugerowane pakiety dla Pythona:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
