# Flusso di lavoro Crypto per CTF

{{#include ../../banners/hacktricks-training.md}}

## Checklist di triage

1. Identify what you have: encoding vs encryption vs hash vs signature vs MAC.
2. Determine what is controlled: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classify: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Apply the highest-probability checks first: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Escalate to advanced methods only when required: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Risorse online & utility

Queste sono utili quando il task è identificazione e rimozione degli strati, o quando hai bisogno di una conferma rapida di un'ipotesi.

### Hash lookups

- Google the hash (surprisingly effective).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

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

Many CTF crypto tasks are layered transforms: base encoding + simple substitution + compression. L'obiettivo è identificare gli strati e rimuoverli in sicurezza.

### Encodings: try many bases

If you suspect layered encoding (base64 → base32 → …), try:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicatori comuni:

- Base64: `A-Za-z0-9+/=` (il padding `=` è comune)
- Base32: `A-Z2-7=` (spesso molti `=` di padding)
- Ascii85/Base85: punteggiatura densa; a volte racchiuso in `<~ ~>`

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

Spesso appare come gruppi di 5 bit o 5 lettere:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Rune

Le rune sono spesso alfabeti di sostituzione; cerca "futhark cipher" e prova tabelle di mappatura.

## Compressione nelle sfide

### Tecnica

La compressione compare frequentemente come un livello aggiuntivo (zlib/deflate/gzip/xz/zstd), talvolta annidata. Se l'output quasi viene interpretato ma sembra spazzatura, sospetta che sia compresso.

### Identificazione rapida

- `file <blob>`
- Cerca byte magici:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

### CLI utile
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
## Costrutti crypto comuni nei CTF

### Tecnica

Appaiono spesso perché sono errori realistici di sviluppatori o librerie comuni usate in modo errato. L'obiettivo è solitamente il riconoscimento e l'applicazione di un workflow noto di estrazione o ricostruzione.

### Fernet

Indicazione tipica: due stringhe Base64 (token + key).

- Decoder/note: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se vedi più shares e viene menzionata una soglia `t`, probabilmente si tratta di Shamir.

- Ricostruttore online (utile per i CTF): http://christian.gen.co/secrets/

### Formati salted OpenSSL

I CTF a volte forniscono output di `openssl enc` (l'header spesso inizia con `Salted__`).

Strumenti per bruteforce:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Strumenti generali

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configurazione locale consigliata

Stack pratico per CTF:

- Python + `pycryptodome` per primitive simmetriche e prototipazione rapida
- SageMath per aritmetica modulare, CRT, lattice e lavoro su RSA/ECC
- Z3 per challenge basati su vincoli (quando la crypto si riduce a vincoli)

Pacchetti Python suggeriti:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
