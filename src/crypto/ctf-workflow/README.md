# Flujo de trabajo Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Lista de verificación de triaje

1. Identifica qué tienes: encoding vs encryption vs hash vs signature vs MAC.
2. Determina qué está controlado: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Clasifica: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Aplica primero las comprobaciones de mayor probabilidad: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Escala a métodos avanzados sólo cuando sea necesario: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos en línea & utilidades

Estos son útiles cuando la tarea es identificación y pelado de capas, o cuando necesitas confirmación rápida de una hipótesis.

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

Muchas tareas de crypto en CTF son transformaciones por capas: base encoding + simple substitution + compression. El objetivo es identificar las capas y pelarlas de forma segura.

### Encodings: try many bases

Si sospechas codificaciones en capas (base64 → base32 → …), prueba:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores comunes:

- Base64: `A-Za-z0-9+/=` (el padding `=` es común)
- Base32: `A-Z2-7=` (a menudo mucho padding `=`)
- Ascii85/Base85: puntuación densa; a veces envuelto en `<~ ~>`

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

Runas suelen ser alfabetos de sustitución; busca "futhark cipher" y prueba tablas de mapeo.

## Compresión en retos

### Técnica

La compresión aparece constantemente como una capa extra (zlib/deflate/gzip/xz/zstd), a veces anidada. Si la salida casi se puede interpretar pero parece basura, sospecha compresión.

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

CyberChef tiene **Raw Deflate/Raw Inflate**, que a menudo es la vía más rápida cuando el blob parece comprimido pero `zlib` falla.

### CLI útil
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

Aparecen con frecuencia porque son errores realistas de desarrolladores o librerías comunes usadas incorrectamente. El objetivo suele ser reconocerlos y aplicar un flujo de trabajo conocido de extracción o reconstrucción.

### Fernet

Pista típica: dos cadenas Base64 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si ves múltiples shares y se menciona un umbral `t`, es probable que sea Shamir.

- Online reconstructor (útil para CTFs): http://christian.gen.co/secrets/

### Formatos salted de OpenSSL

A veces los CTFs dan salidas de `openssl enc` (el header a menudo comienza con `Salted__`).

Herramientas para bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Conjunto de herramientas general

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configuración local recomendada

Pila práctica para CTF:

- Python + `pycryptodome` para primitivas simétricas y prototipado rápido
- SageMath para aritmética modular, CRT, retículos y trabajo con RSA/ECC
- Z3 para desafíos basados en restricciones (cuando la criptografía se reduce a restricciones)

Paquetes Python sugeridos:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
