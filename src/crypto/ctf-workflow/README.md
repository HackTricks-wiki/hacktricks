# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Checklist za trijažu

1. Utvrdite šta imate: encoding naspram encryption, hash, signature ili MAC.
2. Utvrdite šta je pod vašom kontrolom: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), delimični leak.
3. Klasifikujte: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Prvo primenite provere sa najvećom verovatnoćom uspeha: decode slojeva, known-plaintext XOR, ponovna upotreba nonce-a, pogrešna upotreba mode-a, ponašanje oracle-a.
5. Pređite na napredne metode samo kada je potrebno: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

Ovo je korisno kada je zadatak identifikacija i uklanjanje slojeva ili kada vam je potrebna brza potvrda hipoteze.

### Hash lookups

- Google-ujte hash (iznenađujuće je efikasno).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Pomagala za identifikaciju

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (playground za ciphers/encodings): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (praktični crypto izazovi): https://cryptohack.org/
- Cryptopals (klasične slabosti moderne kriptografije): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (isprobava mnoge baze/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technique

Mnogi CTF crypto zadaci koriste transformacije u slojevima: base encoding + simple substitution + compression. Cilj je identifikovati slojeve i bezbedno ih ukloniti.

### Encodings: isprobajte mnoge baze

Ako sumnjate na layered encoding (base64 → base32 → …), probajte:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Uobičajeni indikatori:

- Base64: `A-Za-z0-9+/=` (padding `=` je uobičajen)
- Base32: `A-Z2-7=` (često ima mnogo `=` padding-a)
- Ascii85/Base85: gusta interpunkcija; ponekad je obavijeno oznakama `<~ ~>`

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
### Runes

Runes su često supstitucioni alfabeti; pretražite "futhark cipher" i isprobajte tabele za mapiranje.

## Kompresija u izazovima

### Tehnika

Kompresija se stalno pojavljuje kao dodatni sloj (zlib/deflate/gzip/xz/zstd), ponekad ugnježden. Ako se izlaz gotovo parsira, ali izgleda kao besmislice, posumnjajte na kompresiju.

### Brza identifikacija

- `file <blob>`
- Potražite magic bytes:
- gzip: `1f 8b`
- zlib: često `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ima **Raw Deflate/Raw Inflate**, što je često najbrži način kada blob izgleda kompresovano, ali `zlib` ne uspe.

### Koristan CLI
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
## Uobičajene CTF crypto konstrukcije

### Technique

Ove tehnike se često pojavljuju zato što predstavljaju realne greške developera ili nepravilno korišćene uobičajene biblioteke. Cilj je obično prepoznavanje i primena poznatog workflow-a za ekstrakciju ili rekonstrukciju.

### Fernet

Tipičan hint: dva Base64 stringa (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- U Python-u: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ako vidite više share-ova i pominje se prag `t`, verovatno je u pitanju Shamir.

- Online reconstructor (koristan za CTF-ove): http://christian.gen.co/secrets/

### OpenSSL salted formati

CTF-ovi ponekad daju izlaze komande `openssl enc` (header često počinje sa `Salted__`).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Opšti toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Preporučeno lokalno okruženje

Praktičan CTF stack:

- Python + `pycryptodome` za simetrične primitive i brzo prototipisanje
- SageMath za modularnu aritmetiku, CRT, lattice algoritme i RSA/ECC rad
- Z3 za izazove zasnovane na constraint-ima (kada se crypto svodi na constraint-e)

Predloženi Python paketi:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
