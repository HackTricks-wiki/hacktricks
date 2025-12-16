# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage checklist

1. Identifica cosa hai: encoding vs encryption vs hash vs signature vs MAC.
2. Determina cosa è controllato: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classifica: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Applica prima i check con probabilità più alta: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Passa a metodi avanzati solo quando necessario: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

Queste risorse sono utili quando il task è identificazione e layer peeling, o quando ti serve una rapida conferma di un'ipotesi.

### Hash lookups

- Cerca l'hash su Google (sorprendentemente efficace).
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

Molti task di crypto in CTF sono trasformazioni a strati: base encoding + simple substitution + compression. L'obiettivo è identificare gli strati e sbucciarli in sicurezza.

### Encodings: try many bases

Se sospetti encoding a strati (base64 → base32 → …), prova:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Segnali comuni:

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

Solitamente appare come gruppi di 5 bit o 5 lettere:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Codice Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Rune

Rune sono frequentemente alfabeti di sostituzione; cerca "futhark cipher" e prova tabelle di mapping.

## Compressione nelle sfide

### Tecnica

La compressione compare frequentemente come un ulteriore livello (zlib/deflate/gzip/xz/zstd), a volte annidata. Se l'output quasi si interpreta ma appare illeggibile, sospetta una compressione.

### Identificazione rapida

- `file <blob>`
- Cerca i magic bytes:
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
## Costrutti crittografici comuni nei CTF

### Tecnica

Questi appaiono frequentemente perché sono errori realistici di sviluppatori o librerie comuni usate in modo errato. L'obiettivo è di solito il riconoscimento e l'applicazione di un workflow noto di estrazione o ricostruzione.

### Fernet

Indicazione tipica: due stringhe Base64 (token + key).

- Decoder/appunti: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se vedi più shares e viene menzionata una soglia `t`, è probabile che si tratti di Shamir.

- Ricostruttore online (comodo per i CTF): http://christian.gen.co/secrets/

### OpenSSL salted formats

I CTF a volte forniscono output di `openssl enc` (l'header spesso inizia con `Salted__`).

Aiuti per bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configurazione locale consigliata

Stack pratico per CTF:

- Python + `pycryptodome` per primitive simmetriche e prototipazione rapida
- SageMath per aritmetica modulare, CRT, reticoli e lavoro su RSA/ECC
- Z3 per challenge basate su vincoli (quando la crittografia si riduce a vincoli)

Pacchetti Python suggeriti:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
