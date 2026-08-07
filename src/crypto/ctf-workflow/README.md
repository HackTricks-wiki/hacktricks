# Workflow Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Lista kontrolna triage

1. Zidentyfikuj, co posiadasz: encoding vs encryption vs hash vs signature vs MAC.
2. Ustal, co jest kontrolowane: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), częściowy leak.
3. Sklasyfikuj: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Najpierw zastosuj kontrole o najwyższym prawdopodobieństwie: dekodowanie warstw, known-plaintext XOR, ponowne użycie nonce, niewłaściwe użycie trybu, zachowanie oracle.
5. Sięgaj po zaawansowane metody tylko wtedy, gdy jest to konieczne: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Zasoby online i utilities

Są przydatne, gdy zadanie polega na identyfikacji i zdejmowaniu warstw lub gdy potrzebujesz szybkiego potwierdzenia hipotezy.

### Wyszukiwanie hashy

- Wygoogluj hash (zaskakująco skuteczne).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Narzędzia pomocnicze do identyfikacji

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (playground dla cipherów/encodingów): https://www.dcode.fr/tools-list
- Boxentriq (solvery substitution): https://www.boxentriq.com/code-breaking

### Platformy do ćwiczeń / references

- CryptoHack (praktyczne challenges z crypto): https://cryptohack.org/
- Cryptopals (klasyczne współczesne pułapki crypto): https://cryptopals.com/

### Automatyczne dekodowanie

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (próbuje wielu bases/encodingów): https://github.com/dhondta/python-codext

## Encodings i classical ciphers

### Technique

Wiele zadań crypto w CTF to transformacje warstwowe: base encoding + prosta substitution + compression. Celem jest identyfikacja warstw i bezpieczne ich zdejmowanie.

### Encodings: wypróbuj wiele bases

Jeśli podejrzewasz warstwowy encoding (base64 → base32 → …), wypróbuj:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Typowe oznaki:

- Base64: `A-Za-z0-9+/=` (padding `=` jest częsty)
- Base32: `A-Z2-7=` (często dużo paddingu `=`)
- Ascii85/Base85: gęsta interpunkcja; czasem opakowany w `<~ ~>`

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

Często pojawia się jako grupy 5 bitów lub 5 liter:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runy

Runy są często alfabetami podstawieniowymi; wyszukaj „futhark cipher” i spróbuj użyć tabel mapowania.

## Kompresja w challenges

### Technika

Kompresja pojawia się bardzo często jako dodatkowa warstwa (zlib/deflate/gzip/xz/zstd), czasami zagnieżdżona. Jeśli wynik prawie daje się sparsować, ale wygląda jak śmieci, podejrzewaj kompresję.

### Szybka identyfikacja

- `file <blob>`
- Szukaj magic bytes:
- gzip: `1f 8b`
- zlib: często `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ma **Raw Deflate/Raw Inflate**, co często jest najszybszym rozwiązaniem, gdy blob wygląda na skompresowany, ale `zlib` zawodzi.

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
## Typowe konstrukcje kryptograficzne CTF

### Technika

Pojawiają się często, ponieważ wynikają z realistycznych błędów deweloperów lub nieprawidłowego użycia popularnych bibliotek. Celem jest zazwyczaj rozpoznanie problemu i zastosowanie znanego workflow ekstrakcji lub rekonstrukcji.

### Fernet

Typowa wskazówka: dwa ciągi Base64 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- W Pythonie: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Jeśli widzisz wiele shares i wspomniano o threshold `t`, prawdopodobnie chodzi o Shamir.

- Online reconstructor (przydatny w CTF-ach): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF-y czasami dostarczają wyniki `openssl enc` (nagłówek często zaczyna się od `Salted__`).

Narzędzia pomocne przy bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Ogólny zestaw narzędzi

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Zalecana konfiguracja lokalna

Praktyczny stack CTF:

- Python + `pycryptodome` do prymitywów symetrycznych i szybkiego prototypowania
- SageMath do arytmetyki modularnej, CRT, lattice oraz pracy z RSA/ECC
- Z3 do challenges opartych na constraints (gdy crypto sprowadza się do constraints)

Sugerowane pakiety Pythona:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
