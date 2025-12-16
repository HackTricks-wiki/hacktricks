# Workflow za Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Kontrolna lista za trijažu

1. Identifikujte šta imate: encoding vs encryption vs hash vs signature vs MAC.
2. Odredite šta je pod kontrolom: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Klasifikujte: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Primetite najverovatnije provere prvo: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Pređite na napredne metode samo kada je potrebno: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resursi & alati

Ovo je korisno kada je zadatak identifikacija i uklanjanje slojeva, ili kada vam treba brza potvrda hipoteze.

### Hash lookups

- Pretražite hash na Google-u (iznenađujuće efikasno).
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

Mnogi CTF crypto zadaci su slojevite transformacije: base encoding + simple substitution + compression. Cilj je identifikovati slojeve i bezbedno ih ukloniti.

### Encodings: try many bases

Ako sumnjate na slojevito kodiranje (base64 → base32 → …), probajte:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Uobičajeni pokazatelji:

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: dense punctuation; sometimes wrapped in `<~ ~>`

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

Često se pojavljuje kao grupe od 5 bitova ili 5 slova:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Rune

Rune su često substitution alphabets; search for "futhark cipher" i probajte mapping tables.

## Kompresija u izazovima

### Tehnika

Kompresija se često pojavljuje kao dodatni sloj (zlib/deflate/gzip/xz/zstd), ponekad ugnježdena. Ako se izlaz skoro parsira ali izgleda kao smeće, sumnjajte na kompresiju.

### Brza identifikacija

- `file <blob>`
- Tražite magic bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ima **Raw Deflate/Raw Inflate**, što je često najbrži put kada blob izgleda kompresovano ali `zlib` zakaže.

### Korisni CLI
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
## Uobičajene CTF kripto konstrukcije

### Tehnika

Ovo se često pojavljuje zato što su to realistične greške programera ili uobičajene biblioteke korišćene na pogrešan način. Cilj je obično prepoznavanje i primena poznatog postupka za izdvajanje ili rekonstrukciju.

### Fernet

Tipičan nagoveštaj: dve Base64 stringa (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- U Pythonu: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ako vidite više shares i pomenut je prag `t`, verovatno je u pitanju Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF-ovi ponekad daju izlaze `openssl enc` (header često počinje sa `Salted__`).

Alati za bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Opšti skup alata

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Preporučeno lokalno okruženje

Praktični CTF stack:

- Python + `pycryptodome` za simetrične primitive i brzo prototipiziranje
- SageMath za modularnu aritmetiku, CRT, rešetke i rad sa RSA/ECC
- Z3 za izazove zasnovane na ograničenjima (kad se kripto svodi na ograničenja)

Preporučeni Python paketi:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
