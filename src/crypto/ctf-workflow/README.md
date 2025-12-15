# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage-Checkliste

1. Identifiziere, was du hast: encoding vs encryption vs hash vs signature vs MAC.
2. Bestimme, was kontrolliert wird: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Kategorisiere: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Wende zuerst die wahrscheinlichsten Checks an: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Eskaliere auf fortgeschrittene Methoden nur bei Bedarf: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online-Ressourcen & Utilities

Diese sind nützlich, wenn die Aufgabe in der Identifikation und dem Entfernen von Schichten besteht, oder wenn du eine Hypothese schnell bestätigen möchtest.

### Hash-Lookups

- Google den hash (überraschend effektiv).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Identification-Hilfen

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Übungsplattformen / Referenzen

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automatisiertes Decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technik

Viele CTF-Crypto-Aufgaben bestehen aus geschichteten transforms: base encoding + simple substitution + compression. Das Ziel ist, die Schichten zu identifizieren und sicher zu entfernen.

### Encodings: try many bases

Wenn du layered encoding vermutest (base64 → base32 → …), versuche:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Typische Hinweise:

- Base64: `A-Za-z0-9+/=` (Padding `=` ist häufig)
- Base32: `A-Z2-7=` (oft viel `=` Padding)
- Ascii85/Base85: dichte Interpunktion; manchmal in `<~ ~>` eingeschlossen

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

Erscheint oft als Gruppen von 5 Bits oder 5 Buchstaben:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runen

Runen sind häufig Substitutionsalphabete; suche nach "futhark cipher" und probiere Zuordnungstabellen.

## Kompression in challenges

### Technik

Kompression tritt ständig als zusätzliche Schicht auf (zlib/deflate/gzip/xz/zstd), manchmal verschachtelt. Wenn die Ausgabe fast parsbar ist, aber wie Müll aussieht, dann vermute Kompression.

### Schnelle Identifikation

- `file <blob>`
- Suche nach Magic-Bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef bietet **Raw Deflate/Raw Inflate**, was oft der schnellste Weg ist, wenn der Blob komprimiert aussieht, aber `zlib` fehlschlägt.

### Nützliche CLI
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
## Häufige CTF-Krypto-Konstrukte

### Technik

Diese treten häufig auf, weil es realistische Entwicklerfehler oder gängige Bibliotheken sind, die falsch verwendet wurden. Das Ziel ist normalerweise, sie zu erkennen und einen bekannten Extraktions- oder Rekonstruktions-Workflow anzuwenden.

### Fernet

Typical hint: two Base64 strings (token + key).

- Decoder/Notizen: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

If you see multiple shares and a threshold `t` is mentioned, it is likely Shamir.

- Online-Rekonstruktor (praktisch für CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs sometimes give `openssl enc` outputs (header often begins with `Salted__`).

Bruteforce-Hilfen:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Allgemeines Toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Empfohlenes lokales Setup

Praktischer CTF-Stack:

- Python + `pycryptodome` für symmetrische Primitive und schnelles Prototyping
- SageMath für modulare Arithmetik, CRT, Gitter und RSA/ECC-Arbeit
- Z3 für constraint-basierte Challenges (wenn die Krypto auf Constraints reduziert wird)

Vorgeschlagene Python-Pakete:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
