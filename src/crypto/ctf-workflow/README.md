# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Lista de verificación de triage

1. Identifica qué tienes: encoding vs encryption vs hash vs signature vs MAC.
2. Determina qué está controlado: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Clasificar: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Aplica primero las comprobaciones de mayor probabilidad: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Escala a métodos avanzados solo cuando sea necesario: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos y utilidades en línea

Estos son útiles cuando la tarea es identificación y pelado de capas, o cuando necesitas una confirmación rápida de una hipótesis.

### Búsqueda de hashes

- Busca el hash en Google (sorprendentemente efectivo).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Ayudantes de identificación

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Plataformas de práctica / referencias

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Decodificación automática

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Codificaciones y cifrados clásicos

### Técnica

Muchas tareas crypto de CTF son transformaciones por capas: base encoding + simple substitution + compression. El objetivo es identificar las capas y pelarlas de forma segura.

### Codificaciones: prueba muchas bases

Si sospechas codificación por capas (base64 → base32 → …), prueba:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores comunes:

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: dense punctuation; sometimes wrapped in `<~ ~>`

### Sustitución / monoalfabética

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

Aparece a menudo como grupos de 5 bits o 5 letras:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runas

Las runas suelen ser alfabetos de sustitución; busca "futhark cipher" y prueba tablas de mapeo.

## Compression in challenges

### Técnica

La compresión aparece con frecuencia como una capa adicional (zlib/deflate/gzip/xz/zstd), a veces anidada. Si la salida casi se parsea pero parece basura, sospecha compresión.

### Identificación rápida

- `file <blob>`
- Busca bytes mágicos:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

### Herramientas CLI útiles
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
## Construcciones criptográficas comunes en CTF

### Técnica

Estas aparecen frecuentemente porque son errores realistas de desarrolladores o bibliotecas comunes usadas incorrectamente. El objetivo suele ser el reconocimiento y la aplicación de un flujo de trabajo conocido de extracción o reconstrucción.

### Fernet

Pista típica: dos cadenas Base64 (token + key).

- Decodificador/notas: https://asecuritysite.com/encryption/ferdecode
- En Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si ves múltiples shares y se menciona un umbral `t`, probablemente sea Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

Los CTFs a veces dan salidas de `openssl enc` (el encabezado a menudo comienza con `Salted__`).

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Conjunto de herramientas general

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configuración local recomendada

Stack práctico para CTF:

- Python + `pycryptodome` para primitivas simétricas y prototipado rápido
- SageMath para aritmética modular, CRT, lattices, y trabajo con RSA/ECC
- Z3 para desafíos basados en constraints (cuando la crypto se reduce a constraints)

Paquetes de Python sugeridos:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
