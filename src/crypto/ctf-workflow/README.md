# Crypto-CTF-Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage-Checkliste

1. Identifiziere, was du hast: Encoding vs. Verschlüsselung vs. Hash vs. Signatur vs. MAC.
2. Bestimme, was kontrolliert wird: Plaintext/Ciphertext, IV/Nonce, Key, Oracle (Padding/Fehler/Timing), partielle Leaks.
3. Klassifiziere: symmetrisch (AES/CTR/GCM), Public-Key (RSA/ECC), Hash/MAC (SHA/MD5/HMAC), klassisch (Vigenere/XOR).
4. Wende zuerst die Prüfungen mit der höchsten Wahrscheinlichkeit an: Decode-Schichten, Known-Plaintext-XOR, Nonce-Wiederverwendung, fehlerhafte Mode-Nutzung, Oracle-Verhalten.
5. Wechsle nur bei Bedarf zu fortgeschrittenen Methoden: Lattices (LLL/Coppersmith), SMT/Z3, Side-Channels.

## Online-Ressourcen & Utilities

Diese sind nützlich, wenn es um die Identifikation und das Entfernen von Schichten geht oder wenn du eine Hypothese schnell bestätigen musst.

### Hash-Lookups

- Google den Hash (überraschend effektiv).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Hilfsmittel zur Identifikation

- CyberChef (Magic, Decode, Convert): https://gchq.github.io/CyberChef/
- dCode (Spielplatz für Ciphers/Encodings): https://www.dcode.fr/tools-list
- Boxentriq (Solver für Substitutionen): https://www.boxentriq.com/code-breaking

### Übungsplattformen / Referenzen

- CryptoHack (praktische Crypto-Challenges): https://cryptohack.org/
- Cryptopals (klassische Fallen moderner Crypto): https://cryptopals.com/

### Automatisiertes Decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (probiert viele Bases/Encodings aus): https://github.com/dhondta/python-codext

## Encodings & klassische Ciphers

### Technique

Viele Crypto-Aufgaben in CTFs bestehen aus geschichteten Transformationen: Base-Encoding + einfache Substitution + Kompression. Das Ziel ist, die Schichten zu identifizieren und sicher nacheinander zu entfernen.

### Encodings: viele Bases ausprobieren

Wenn du ein geschichtetes Encoding vermutest (base64 → base32 → …), probiere:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Typische Hinweise:

- Base64: `A-Za-z0-9+/=` (Padding `=` ist häufig)
- Base32: `A-Z2-7=` (oft viel `=`-Padding)
- Ascii85/Base85: dichte Interpunktion; manchmal in `<~ ~>` eingeschlossen

### Substitution / monoalphabetisch

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

### Bacon cipher

Erscheint häufig als Gruppen aus 5 Bits oder 5 Buchstaben:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runen

Runen sind häufig Substitutionsalphabete; suche nach "futhark cipher" und probiere Zuordnungstabellen aus.

## Komprimierung in Challenges

### Technik

Komprimierung taucht ständig als zusätzliche Schicht auf (zlib/deflate/gzip/xz/zstd), manchmal verschachtelt. Wenn die Ausgabe fast geparst werden kann, aber wie Datenmüll aussieht, solltest du Komprimierung vermuten.

### Schnelle Identifizierung

- `file <blob>`
- Suche nach Magic Bytes:
- gzip: `1f 8b`
- zlib: häufig `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef verfügt über **Raw Deflate/Raw Inflate**, was oft der schnellste Weg ist, wenn der Blob komprimiert aussieht, aber `zlib` fehlschlägt.

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
## Gängige CTF-Krypto-Konstrukte

### Technik

Diese treten häufig auf, weil sie realistische Fehler von Entwicklern oder häufig verwendete, aber falsch eingesetzte Bibliotheken darstellen. Das Ziel ist normalerweise, sie zu erkennen und einen bekannten Extraktions- oder Rekonstruktionsworkflow anzuwenden.

### Fernet

Typischer Hinweis: zwei Base64-Strings (Token + Key).

- Decoder/Notizen: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Wenn mehrere Shares vorhanden sind und ein Threshold `t` erwähnt wird, handelt es sich wahrscheinlich um Shamir.

- Online-Rekonstruktionstool (praktisch für CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs enthalten manchmal Ausgaben von `openssl enc` (der Header beginnt häufig mit `Salted__`).

Bruteforce-Hilfsprogramme:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Allgemeines Toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Empfohlenes lokales Setup

Praktischer CTF-Stack:

- Python + `pycryptodome` für symmetrische Primitives und schnelles Prototyping
- SageMath für modulare Arithmetik, CRT, Lattices und RSA/ECC-Arbeiten
- Z3 für constraint-basierte Challenges (wenn sich die Kryptografie auf Constraints reduzieren lässt)

Empfohlene Python-Pakete:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
