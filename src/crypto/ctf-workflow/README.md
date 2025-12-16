# Crypto-CTF-Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage-Checkliste

1. Identifiziere, was du hast: encoding vs encryption vs hash vs signature vs MAC.
2. Bestimme, was kontrolliert wird: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Klassifiziere: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Führe zuerst die wahrscheinlichsten Prüfungen durch: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Steige nur bei Bedarf auf fortgeschrittene Methoden um: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online-Ressourcen & Hilfsmittel

Diese sind nützlich, wenn die Aufgabe in Identifikation und Schichtentfernung (layer peeling) besteht oder wenn du eine Hypothese schnell bestätigen möchtest.

### Hash lookups

- Google den Hash (überraschend effektiv).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Identification helpers

- CyberChef (Magic, decodieren, konvertieren): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings Spielwiese): https://www.dcode.fr/tools-list
- Boxentriq (Substitutions-Löser): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (praktische Crypto-Challenges): https://cryptohack.org/
- Cryptopals (klassische moderne Crypto-Fallen): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (probiert viele bases/encodings): https://github.com/dhondta/python-codext

## Encodings & klassische Chiffren

### Technique

Viele CTF-Crypto-Aufgaben sind geschichtete Transformationen: base encoding + simple substitution + compression. Ziel ist, die Schichten zu identifizieren und sie sicher zu entfernen.

### Encodings: try many bases

Wenn du geschichtete Encodings vermutest (base64 → base32 → …), probiere:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Gängige Hinweise:

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

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

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

Kompression tritt ständig als zusätzliche Schicht auf (zlib/deflate/gzip/xz/zstd), manchmal verschachtelt. Wenn die Ausgabe sich fast parsen lässt, aber wie Müll aussieht, vermute Kompression.

### Schnelle Erkennung

- `file <blob>`
- Auf Magic-Bytes prüfen:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

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

Diese treten häufig auf, weil es sich um realistische Entwicklerfehler oder um falsch verwendete verbreitete Bibliotheken handelt. Das Ziel ist meist die Erkennung und das Anwenden eines bekannten Extraktions- oder Rekonstruktionsworkflows.

### Fernet

Typical hint: two Base64 strings (token + key).

- Decoder/Anmerkungen: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Wenn du mehrere shares siehst und ein Schwellwert `t` erwähnt wird, handelt es sich wahrscheinlich um Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL-Salted-Formate

CTFs liefern manchmal `openssl enc`-Ausgaben (Header beginnt oft mit `Salted__`).

Bruteforce-Hilfen:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Allgemeines Toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Empfohlenes lokales Setup

Praktischer CTF-Stack:

- Python + `pycryptodome` für symmetrische Primitive und schnelles Prototyping
- SageMath für modulare Arithmetik, CRT, Gitter sowie RSA/ECC-Arbeiten
- Z3 für constraint-basierte Aufgaben (wenn die Krypto auf Constraints reduziert wird)

Empfohlene Python-Pakete:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
