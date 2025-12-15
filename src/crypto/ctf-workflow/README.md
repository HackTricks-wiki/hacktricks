# Mtiririko wa Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Orodha ya ukaguzi (Triage)

1. Tambua unachonacho: encoding vs encryption vs hash vs signature vs MAC.
2. Amua kinachodhibitiwa: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Chambua: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Tumia kwanza ukaguzi wenye uwezekano mkubwa: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Pandisha hadi mbinu za juu tu wakati zinahitajika: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Rasilimali za mtandaoni & zana

Hizi ni muhimu wakati kazi ni utambuzi na kuondoa tabaka, au unahitaji uthibitisho wa haraka wa nadharia.

### Hash lookups

- Tafuta hash kwenye Google (inatokea kuwa yenye ufanisi).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Vifaa vya utambuzi

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Majukwaa ya mazoezi / marejeo

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Mbinu

Mara nyingi kazi za crypto za CTF ni mfululizo wa transforms: base encoding + simple substitution + compression. Lengo ni kutambua tabaka na kuziondoa kwa usalama.

### Encodings: jaribu base nyingi

Ukishuku kuwepo kwa layered encoding (base64 → base32 → …), jaribu:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Dalili za kawaida:

- Base64: `A-Za-z0-9+/=` (padding `=` ni ya kawaida)
- Base32: `A-Z2-7=` (mara nyingi kuna padding nyingi `=`)
- Ascii85/Base85: dense punctuation; sometimes wrapped in `<~ ~>`

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

Mara nyingi huonekana kama makundi ya 5 bits au herufi 5:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes mara nyingi ni alfabeti za ubadilishanaji; tafuta "futhark cipher" na jaribu meza za ramani.

## Ukandishaji katika challenges

### Mbinu

Ukandishaji hujitokeza mara kwa mara kama tabaka la ziada (zlib/deflate/gzip/xz/zstd), wakati mwingine limewekwa ndani ya lingine. Ikiwa matokeo karibu yafasiriwa lakini yanaonekana kama taka, shuku ukandishaji.

### Utambuzi wa Haraka

- `file <blob>`
- Tafuta magic bytes:
- gzip: `1f 8b`
- zlib: mara nyingi `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ina **Raw Deflate/Raw Inflate**, ambayo mara nyingi ndiyo njia ya haraka wakati blob inaonekana imekandishwa lakini `zlib` inashindwa.

### CLI muhimu
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

Hizi zinaonekana mara kwa mara kwa sababu ni makosa halisi ya waendelezaji au maktaba zinazotumiwa vibaya. Lengo kawaida ni kutambua na kutumia mtiririko wa kazi uliotambulika wa uchimbaji au ujenzi upya.

### Fernet

Dalili ya kawaida: two Base64 strings (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- Katika Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ikiwa unaona sehemu nyingi na kizingiti `t` kimeelezwa, huenda ni Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs mara nyingine hutoa matokeo ya `openssl enc` (kichwa mara nyingi huanza na `Salted__`).

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Seti ya zana za jumla

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Usanidi wa ndani uliopendekezwa

Stack ya CTF ya vitendo:

- Python + `pycryptodome` kwa symmetric primitives na prototyping ya haraka
- SageMath kwa arithmetic ya modul, CRT, lattices, na kazi za RSA/ECC
- Z3 kwa changamoto zinazoegemea vizingiti (mara crypto inapopungua kuwa vizingiti)

Vifurushi vya Python vilivyopendekezwa:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
