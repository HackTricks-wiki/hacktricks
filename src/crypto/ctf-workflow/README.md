# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage-kontrolelys

1. Identifiseer wat jy het: encoding teenoor encryption teenoor hash teenoor signature teenoor MAC.
2. Bepaal wat beheer word: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), gedeeltelike leakage.
3. Klassifiseer: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Pas eers die kontroles met die hoogste waarskynlikheid toe: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Eskaleer slegs wanneer nodig na gevorderde metodes: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

Dit is nuttig wanneer die taak identification en layer peeling behels, of wanneer jy vinnig 'n hypothesis moet bevestig.

### Hash lookups

- Google die hash (verbasend effektief).
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

Baie CTF crypto-take is gelaagde transforms: base encoding + eenvoudige substitution + compression. Die doel is om layers te identifiseer en dit veilig af te skil.

### Encodings: try many bases

As jy layered encoding vermoed (base64 → base32 → …), probeer:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Common tells:

- Base64: `A-Za-z0-9+/=` (padding `=` is algemeen)
- Base32: `A-Z2-7=` (dikwels baie `=` padding)
- Ascii85/Base85: dense punctuation; soms omvou in `<~ ~>`

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

Kom dikwels voor as groepe van 5 bits of 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes is dikwels substitusie-alfabette; soek na "futhark cipher" en probeer karteringstabelle.

## Kompressie in challenges

### Tegniek

Kompressie kom voortdurend voor as ’n ekstra laag (zlib/deflate/gzip/xz/zstd), soms genestel. As die uitvoer amper parse, maar soos gemors lyk, vermoed kompressie.

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

CyberChef het **Raw Deflate/Raw Inflate**, wat dikwels die vinnigste pad is wanneer die blob soos kompressie lyk, maar `zlib` faal.

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
## Algemene CTF-crypto-konstrukte

### Tegniek

Hierdie kom gereeld voor omdat hulle realistiese ontwikkelaarsfoute of algemene libraries is wat verkeerd gebruik word. Die doel is gewoonlik herkenning en die toepassing van ’n bekende extraction- of reconstruction-workflow.

### Fernet

Tipiese hint: twee Base64-strings (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

As jy meerdere shares sien en ’n threshold `t` genoem word, is dit waarskynlik Shamir.

- Online reconstructor (handig vir CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs verskaf soms `openssl enc`-uitsette (die header begin dikwels met `Salted__`).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Algemene toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Aanbevole plaaslike setup

Praktiese CTF-stack:

- Python + `pycryptodome` vir symmetric primitives en vinnige prototyping
- SageMath vir modular arithmetic, CRT, lattices en RSA/ECC-werk
- Z3 vir constraint-based challenges (wanneer die crypto tot constraints gereduseer word)

Voorgestelde Python-packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
