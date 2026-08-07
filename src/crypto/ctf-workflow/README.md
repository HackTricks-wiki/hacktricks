# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Orodha ya ukaguzi wa Triage

1. Tambua ulicho nacho: encoding dhidi ya encryption dhidi ya hash dhidi ya signature dhidi ya MAC.
2. Tambua kinachodhibitiwa: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Ainisha: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Anza na ukaguzi wenye uwezekano mkubwa zaidi: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Tumia advanced methods pale tu inapohitajika: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Rasilimali za mtandaoni na utilities

Hizi ni muhimu wakati kazi ni kutambua na kuondoa layers, au unapohitaji uthibitisho wa haraka wa hypothesis.

### Hash lookups

- Google hash hiyo (inafaa kwa kiwango cha kushangaza).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Vifaa vya kusaidia utambuzi

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (uwanja wa majaribio wa ciphers/encodings): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (inajaribu bases/encodings nyingi): https://github.com/dhondta/python-codext

## Encodings na classical ciphers

### Technique

Kazi nyingi za crypto za CTF ni layered transforms: base encoding + simple substitution + compression. Lengo ni kutambua layers na kuziondoa kwa usalama.

### Encodings: jaribu bases nyingi

Ikiwa unashuku layered encoding (base64 → base32 → …), jaribu:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Dalili za kawaida:

- Base64: `A-Za-z0-9+/=` (padding `=` ni ya kawaida)
- Base32: `A-Z2-7=` (mara nyingi huwa na `=` padding nyingi)
- Ascii85/Base85: punctuation nyingi iliyosongamana; wakati mwingine hufungwa ndani ya `<~ ~>`

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

Mara nyingi huonekana kama makundi ya bits 5 au herufi 5:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes mara nyingi ni substitution alphabets; tafuta "futhark cipher" na ujaribu mapping tables.

## Compression in challenges

### Technique

Compression hujitokeza mara kwa mara kama layer ya ziada (zlib/deflate/gzip/xz/zstd), wakati mwingine ikiwa nested. Ikiwa output inakaribia ku-parse lakini inaonekana kama garbage, shuku compression.

### Quick identification

- `file <blob>`
- Tafuta magic bytes:
- gzip: `1f 8b`
- zlib: mara nyingi `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ina **Raw Deflate/Raw Inflate**, ambayo mara nyingi ndiyo njia ya haraka zaidi wakati blob inaonekana kuwa compressed lakini `zlib` inashindwa.

### Useful CLI
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
## Miundo ya kawaida ya crypto ya CTF

### Technique

Hii huonekana mara kwa mara kwa sababu ni makosa halisi ya developers au matumizi yasiyo sahihi ya libraries za kawaida. Lengo kwa kawaida ni kutambua tatizo na kutumia extraction au reconstruction workflow inayojulikana.

### Fernet

Kidokezo cha kawaida: strings mbili za Base64 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- Katika Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ukiona shares nyingi na threshold `t` imetajwa, kuna uwezekano mkubwa ni Shamir.

- Online reconstructor (inafaa kwa CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs wakati mwingine hutoa outputs za `openssl enc` (header mara nyingi huanza na `Salted__`).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Recommended local setup

CTF stack ya matumizi ya vitendo:

- Python + `pycryptodome` kwa symmetric primitives na fast prototyping
- SageMath kwa modular arithmetic, CRT, lattices, na RSA/ECC work
- Z3 kwa challenges zinazotegemea constraints (wakati crypto inapopunguzwa kuwa constraints)

Python packages zinazopendekezwa:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
