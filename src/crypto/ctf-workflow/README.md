# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Orodha ya ukaguzi (Triage)

1. Tambua unachonacho: encoding vs encryption vs hash vs signature vs MAC.
2. Tambua ni nini kinadhibitiwa: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Panga: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Anzisha ukaguzi wenye uwezekano mkubwa kwanza: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Hamisha kwenye mbinu za juu tu unapohitajika: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

Hizi zinakuwa muhimu unapoweka utambuzi na kutoa tabaka, au unapohitaji uthibitisho wa haraka wa nadharia.

### Hash lookups

- Google the hash (surprisingly effective).
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

Mara nyingi kazi za Crypto CTF zinakuwa transforms zenye tabaka: base encoding + simple substitution + compression. Lengo ni kutambua tabaka na kuzifungua kwa usalama.

### Encodings: try many bases

Ikiwa unadhani kuna layered encoding (base64 → base32 → …), jaribu:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Vidokezo vya kawaida:

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

Often appears as groups of 5 bits or 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes mara nyingi ni substitution alphabets; tafuta "futhark cipher" na jaribu mapping tables.

## Compression katika changamoto

### Mbinu

Compression inaonekana mara kwa mara kama tabaka la ziada (zlib/deflate/gzip/xz/zstd), wakati mwingine imewekwa ndani. Ikiwa matokeo yanaonekana karibu kusomwa lakini yanaonekana kama taka, shuku compression.

### Utambuzi wa haraka

- `file <blob>`
- Tafuta magic bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ina **Raw Deflate/Raw Inflate**, ambayo mara nyingi ni njia ya haraka zaidi wakati blob inaonekana imefinywa lakini `zlib` inashindwa.

### CLI Zinazofaa
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
## Miundo ya kawaida ya crypto za CTF

### Mbinu

Hizi zinaonekana mara kwa mara kwa sababu ni makosa ya kweli ya developer au libraries zinazotumiwa vibaya. Lengo mara nyingi ni kutambua na kutumia workflow inayojulikana ya uchimbaji au ujenzi upya.

### Fernet

Dalili ya kawaida: kamba mbili za Base64 (token + key).

- Decoder/maelezo: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ikiwa unaona sehemu nyingi na kizingiti `t` kimetajwa, kuna uwezekano ni Shamir.

- Mjenzi wa mtandaoni (mzuri kwa CTFs): http://christian.gen.co/secrets/

### Miundo ya OpenSSL zilizo na Salted

CTFs zinaweza kuonyesha outputs za `openssl enc` (kichwa mara nyingi huanza na `Salted__`).

Vifaa vya kusaidia kwa bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Seti ya zana za jumla

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Mpangilio wa ndani unaopendekezwa

Stack ya vitendo ya CTF:

- Python + `pycryptodome` kwa primitives za symmetric na prototyping ya haraka
- SageMath kwa arithmetic ya moduli, CRT, lattices, na kazi za RSA/ECC
- Z3 kwa changamoto zinazotegemea vikwazo (wakati crypto inapotatuliwa kama vikwazo)

Vifurushi vya Python vinavyopendekezwa:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
