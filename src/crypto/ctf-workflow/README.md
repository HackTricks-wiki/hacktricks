# Tok rada za Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Kontrolna lista za triage

1. Identifikuj šta imaš: encoding vs encryption vs hash vs signature vs MAC.
2. Odredi šta je pod kontrolom: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Klasifikuj: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Primeni provere sa najvećom verovatnoćom prvo: decode slojeve, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Pređi na napredne metode samo kada je potrebno: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resursi i alati

Ovo je korisno kada je zadatak identifikacija i uklanjanje slojeva, ili kada ti treba brza potvrda hipoteze.

### Pretraga hash-ova

- Pretraži hash na Google-u (iznenađujuće efikasno).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Alati za identifikaciju

- CyberChef (magija, dekodiranje, konverzija): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Platforme za vežbu / reference

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automatsko dekodiranje

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Enkodiranja & klasične šifre

### Tehnika

Mnogi CTF crypto zadaci su slojevite transformacije: base encoding + simple substitution + compression. Cilj je identifikovati slojeve i bezbedno ih ukloniti.

### Enkodiranja: probaj više base sistema

Ako sumnjaš na slojevito enkodiranje (base64 → base32 → …), pokušaj:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Česti indikatori:

- Base64: `A-Za-z0-9+/=` (padding `=` je čest)
- Base32: `A-Z2-7=` (često puno `=` padding-a)
- Ascii85/Base85: gusta interpunkcija; ponekad obavijeno u `<~ ~>`

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

Rune su često zamenski alfabeti; potraži "futhark cipher" i isprobaj tabele mapiranja.

## Kompresija u izazovima

### Tehnika

Kompresija se često javlja kao dodatni sloj (zlib/deflate/gzip/xz/zstd), ponekad ugnježdeno. Ako se izlaz skoro parsira ali izgleda kao smeće, sumnjaj na kompresiju.

### Brza identifikacija

- `file <blob>`
- Traži magic bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

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

Ove se često pojavljuju zato što su to realistične greške developera ili često pogrešno korišćene biblioteke. Cilj je obično prepoznavanje i primena poznatog postupka za ekstrakciju ili rekonstrukciju.

### Fernet

Tipičan nagoveštaj: dva Base64 stringa (token + key).

- Dekoder/beleške: https://asecuritysite.com/encryption/ferdecode
- U Pythonu: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ako vidite više delova (shares) i pominje se prag `t`, verovatno je u pitanju Shamir.

- Online reconstructor (koristan za CTF-ove): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF-ovi ponekad daju `openssl enc` izlaze (zaglavlje često počinje sa `Salted__`).

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Opšti set alata

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Preporučeno lokalno okruženje

Praktičan CTF stack:

- Python + `pycryptodome` za simetrične primitive i brzo prototipiranje
- SageMath za modularnu aritmetiku, CRT, rešetke (lattices) i rad sa RSA/ECC
- Z3 za izazove zasnovane na ograničenjima (kada se kriptografija svodi na ograničenja)

Predloženi Python paketi:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
