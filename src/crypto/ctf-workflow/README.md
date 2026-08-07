# Workflow CTF per la crittografia

{{#include ../../banners/hacktricks-training.md}}

## Checklist di triage

1. Identifica cosa hai: encoding vs encryption vs hash vs signature vs MAC.
2. Determina cosa è controllato: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classifica: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Applica prima i controlli con la probabilità più alta: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Passa ai metodi avanzati solo quando necessario: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Risorse online e utility

Sono utili quando il task consiste nell'identificazione e nel peeling dei layer, oppure quando hai bisogno di una rapida conferma di un'ipotesi.

### Ricerca degli hash

- Cerca l'hash su Google (sorprendentemente efficace).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Strumenti di supporto all'identificazione

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (playground per ciphers/encodings): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Piattaforme per esercitarsi / riferimenti

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Decoding automatizzato

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (prova molte basi/encodings): https://github.com/dhondta/python-codext

## Encodings e ciphers classici

### Tecnica

Molti task di crypto nei CTF sono trasformazioni a più layer: base encoding + simple substitution + compression. L'obiettivo è identificare i layer e rimuoverli in sicurezza.

### Encodings: prova molte basi

Se sospetti un encoding a più layer (base64 → base32 → …), prova:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicatori comuni:

- Base64: `A-Za-z0-9+/=` (il padding `=` è comune)
- Base32: `A-Z2-7=` (spesso presenta molto padding `=`)
- Ascii85/Base85: punteggiatura densa; talvolta racchiuso in `<~ ~>`

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

Compare spesso come gruppi di 5 bit o 5 lettere:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Le Runes sono frequentemente alfabeti di sostituzione; cerca "futhark cipher" e prova le tabelle di mapping.

## Compressione nelle challenge

### Tecnica

La compressione compare costantemente come layer aggiuntivo (zlib/deflate/gzip/xz/zstd), a volte annidato. Se l'output viene quasi analizzato correttamente ma sembra spazzatura, sospetta la compressione.

### Identificazione rapida

- `file <blob>`
- Cerca i magic bytes:
- gzip: `1f 8b`
- zlib: spesso `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef dispone di **Raw Deflate/Raw Inflate**, che spesso è il percorso più rapido quando il blob sembra compresso ma `zlib` fallisce.

### CLI utili
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
## Costrutti comuni di crypto nei CTF

### Tecnica

Questi compaiono frequentemente perché sono errori realistici degli sviluppatori o librerie comuni utilizzate in modo errato. L'obiettivo è solitamente riconoscerli e applicare un workflow noto di estrazione o ricostruzione.

### Fernet

Indizio tipico: due stringhe Base64 (token + key).

- Decoder/note: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se vengono visualizzate più share e viene menzionata una soglia `t`, è probabilmente Shamir.

- Ricostruttore online (utile per i CTF): http://christian.gen.co/secrets/

### Formati salted di OpenSSL

A volte i CTF forniscono output di `openssl enc` (l'header inizia spesso con `Salted__`).

Helper per il bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Set di strumenti generale

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Setup locale consigliato

Stack pratico per i CTF:

- Python + `pycryptodome` per primitive simmetriche e prototipazione rapida
- SageMath per aritmetica modulare, CRT, reticoli e attività con RSA/ECC
- Z3 per challenge basate su vincoli (quando la crypto si riduce a vincoli)

Pacchetti Python suggeriti:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
