# Flujo de trabajo de Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Lista de comprobación de triage

1. Identifica lo que tienes: encoding frente a encryption, hash, signature o MAC.
2. Determina qué está controlado: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), filtración parcial.
3. Clasifica: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Aplica primero las comprobaciones con mayor probabilidad de éxito: decodificar capas, known-plaintext XOR, reutilización de nonce, uso incorrecto del modo, comportamiento del oracle.
5. Recurre a métodos avanzados solo cuando sea necesario: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos online y utilidades

Son útiles cuando la tarea consiste en identificar y retirar capas, o cuando necesitas confirmar rápidamente una hipótesis.

### Búsquedas de hashes

- Busca el hash en Google (sorprendentemente efectivo).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Ayudas para la identificación

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (entorno de pruebas de ciphers/encodings): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Plataformas de práctica / referencias

- CryptoHack (desafíos prácticos de crypto): https://cryptohack.org/
- Cryptopals (errores clásicos de la crypto moderna): https://cryptopals.com/

### Decodificación automatizada

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (prueba muchas bases/encodings): https://github.com/dhondta/python-codext

## Encodings y ciphers clásicos

### Técnica

Muchas tareas de crypto en CTF son transformaciones en capas: base encoding + simple substitution + compresión. El objetivo es identificar las capas y retirarlas de forma segura.

### Encodings: prueba muchas bases

Si sospechas que hay encoding en capas (base64 → base32 → …), prueba:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores habituales:

- Base64: `A-Za-z0-9+/=` (el padding `=` es común)
- Base32: `A-Z2-7=` (a menudo incluye mucho padding `=`)
- Ascii85/Base85: puntuación densa; a veces aparece entre `<~ ~>`

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

A menudo aparece como grupos de 5 bits o 5 letras:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runas

Las runas son frecuentemente alfabetos de sustitución; busca "futhark cipher" y prueba tablas de mapeo.

## Compresión en challenges

### Técnica

La compresión aparece constantemente como una capa adicional (zlib/deflate/gzip/xz/zstd), a veces anidada. Si la salida casi se puede analizar, pero parece basura, sospecha de la compresión.

### Identificación rápida

- `file <blob>`
- Busca bytes mágicos:
- gzip: `1f 8b`
- zlib: a menudo `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef tiene **Raw Deflate/Raw Inflate**, que suele ser la forma más rápida cuando el blob parece comprimido, pero `zlib` falla.

### CLI útiles
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
## Constructos criptográficos comunes de CTF

### Técnica

Estos aparecen con frecuencia porque son errores realistas de desarrolladores o bibliotecas comunes utilizadas incorrectamente. El objetivo suele ser reconocerlos y aplicar un flujo de trabajo conocido de extracción o reconstrucción.

### Fernet

Pista típica: dos cadenas Base64 (token + clave).

- Decodificador/notas: https://asecuritysite.com/encryption/ferdecode
- En Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si ves varios shares y se menciona un umbral `t`, probablemente sea Shamir.

- Recontructor online (práctico para CTFs): http://christian.gen.co/secrets/

### Formatos con salt de OpenSSL

En ocasiones, los CTFs proporcionan salidas de `openssl enc` (el encabezado suele comenzar con `Salted__`).

Ayudantes de Bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Conjunto general de herramientas

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configuración local recomendada

Stack práctico para CTFs:

- Python + `pycryptodome` para primitivas simétricas y prototipado rápido
- SageMath para aritmética modular, CRT, retículos y trabajo con RSA/ECC
- Z3 para desafíos basados en restricciones (cuando la criptografía se reduce a restricciones)

Paquetes de Python sugeridos:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
