# Crypto CTF Werkvloei

{{#include ../../banners/hacktricks-training.md}}

## Triage kontrolelys

1. Identifiseer wat jy het: encoding vs encryption vs hash vs signature vs MAC.
2. Bepaal wat beheer word: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Klassifiseer: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Pas die hoogste-waarskynlikheidskontroles eerste toe: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Skaleer op na gevorderde metodes slegs wanneer nodig: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Aanlyn hulpbronne en nutsprogramme

Hierdie is nuttig wanneer die taak identifikasie en die afskil van lae behels, of wanneer jy vinnige bevestiging van 'n hipotese nodig het.

### Hash opsoeke

- Google die hash (verrassend effektief).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Identifikasie-hulpmiddels

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Oefenplatforms / verwysings

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Outomatiese dekodering

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings en klassieke sifers

### Tegniek

Baie CTF crypto-take is gelaagde transformaties: base encoding + simple substitution + compression. Die doel is om lae te identifiseer en dit veilig af te skil.

### Encodings: probeer verskeie basisse

As jy verdagting het van gelaagde encoding (base64 → base32 → …), probeer:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Algemene tekens:

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: dense punctuation; sometimes wrapped in `<~ ~>`

### Substitusie / monoalfabeties

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

Verskyn dikwels as groepe van 5 bits of 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes word dikwels substitusie-alfabette; soek na "futhark cipher" en probeer mapping tables.

## Kompressie in uitdagings

### Tegniek

Kompressie verskyn gereeld as 'n ekstra laag (zlib/deflate/gzip/xz/zstd), soms geneste. As die uitvoer amper ontleed kan word maar na rommel lyk, vermoed kompressie.

### Vinnige identifikasie

- `file <blob>`
- Soek na magic bytes:
- gzip: `1f 8b`
- zlib: dikwels `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef het **Raw Deflate/Raw Inflate**, wat dikwels die vinnigste pad is wanneer die blob na gecomprimeerd lyk maar `zlib` faal.

### Nuttige CLI
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
## Algemene CTF crypto konstruksies

### Tegniek

Hierdie kom dikwels voor omdat dit realistiese ontwikkelaarfoute of algemene biblioteke is wat verkeerd gebruik word. Die doel is gewoonlik herkenning en die toepas van 'n bekende ekstraksie- of rekonstruksie-werkvloeistroom.

### Fernet

Tipiese wenk: twee Base64-stringe (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

As jy verskeie shares sien en 'n drempel `t` genoem word, is dit waarskynlik Shamir.

- Online reconstructor (handig vir CTFs): http://christian.gen.co/secrets/

### OpenSSL gesoute formate

CTFs gee soms `openssl enc`-uitsette (header begin dikwels met `Salted__`).

Bruteforce-hulpmiddels:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Algemene toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Aanbevole plaaslike opstelling

Praktiese CTF-stapel:

- Python + `pycryptodome` vir symmetriese primitives en vinnige prototipering
- SageMath vir modulaire rekenkunde, CRT, lattices en RSA/ECC-werk
- Z3 vir beperking-gebaseerde uitdagings (wanneer die crypto tot beperkings reduseer)

Voorgestelde Python-pakkette:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
