# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage checklist

1. Identify what you have: encoding vs encryption vs hash vs signature vs MAC.
2. Determine what is controlled: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classify: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Apply the highest-probability checks first: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Escalate to advanced methods only when required: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

These are useful when the task is identification and layer peeling, or when you need quick confirmation of a hypothesis.

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

Many CTF crypto tasks are layered transforms: base encoding + simple substitution + compression. The goal is to identify layers and peel them safely.

### Encodings: try many bases

If you suspect layered encoding (base64 → base32 → …), try:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Common tells:

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

Runes are frequently substitution alphabets; search for "futhark cipher" and try mapping tables.

## Compression in challenges

### Technique

Compression shows up constantly as an extra layer (zlib/deflate/gzip/xz/zstd), sometimes nested. If output almost parses but looks like garbage, suspect compression.

### Quick identification

- `file <blob>`
- Look for magic bytes:
  - gzip: `1f 8b`
  - zlib: often `78 01/9c/da`
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

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

## Common CTF crypto constructs

### Technique

These appear frequently because they are realistic developer mistakes or common libraries used incorrectly. The goal is usually recognition and applying a known extraction or reconstruction workflow.

### Fernet

Typical hint: two Base64 strings (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

If you see multiple shares and a threshold `t` is mentioned, it is likely Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs sometimes give `openssl enc` outputs (header often begins with `Salted__`).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Recommended local setup

Practical CTF stack:

- Python + `pycryptodome` for symmetric primitives and fast prototyping
- SageMath for modular arithmetic, CRT, lattices, and RSA/ECC work
- Z3 for constraint-based challenges (when the crypto reduces to constraints)

Suggested Python packages:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}
