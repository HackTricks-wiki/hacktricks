# Flujo de trabajo de Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Lista de comprobación de triage

1. Identifica qué tienes: encoding vs encryption vs hash vs signature vs MAC.
2. Determina qué está controlado: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Clasifica: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Aplica primero las comprobaciones con mayor probabilidad: decode de capas, known-plaintext XOR, reutilización de nonce, uso incorrecto del modo, comportamiento del oracle.
5. Escala a métodos avanzados solo cuando sea necesario: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos online y utilities

Son útiles cuando la tarea consiste en identificar y eliminar capas, o cuando necesitas confirmar rápidamente una hipótesis.

### Consultas de hashes

- Busca un hash de challenge cuando se sepa que es sintético/público.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Búsqueda en hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

No envíes hashes de passwords reales ni material confidencial de challenges a servicios de lookup de terceros. Prefiere un ataque offline con wordlist/rules cuando la divulgación, los términos de servicio o las reglas de la competición sean motivo de preocupación.

### Helpers de identificación

- CyberChef (Magic, decoding y conversion).<sup>[[7]](#references)</sup>
- dCode (playground de cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (solvers de substitution).<sup>[[9]](#references)</sup>

### Plataformas de práctica / referencias

- CryptoHack (challenges prácticos de cryptography).<sup>[[10]](#references)</sup>
- Cryptopals (errores clásicos de modern-cryptography).<sup>[[11]](#references)</sup>

### Decoding automatizado

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (prueba muchas bases/encodings).<sup>[[13]](#references)</sup>

## Encodings y classical ciphers

### Técnica

Muchas tareas de crypto en CTF son transforms en capas: base encoding + simple substitution + compression. El objetivo es identificar las capas y eliminarlas de forma segura.

### Encodings: prueba muchas bases

Si sospechas de un encoding en capas (base64 → base32 → …), prueba:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores comunes:

- Base64: `A-Za-z0-9+/=` (el padding `=` es común)
- Base32: `A-Z2-7=` (a menudo incluye mucho padding `=`)
- Ascii85/Base85: puntuación densa; a veces está envuelto en `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

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
### Runes

Las runas suelen ser alfabetos de sustitución; busca "futhark cipher" y prueba con tablas de mapeo.

## Compresión en challenges

### Técnica

La compresión aparece constantemente como una capa adicional (zlib/deflate/gzip/xz/zstd), a veces anidada. Si la salida casi se puede analizar, pero parece basura, sospecha de la compresión.

### Identificación rápida

- `file <blob>`
- Busca bytes mágicos:
- gzip: `1f 8b`
- zlib: comúnmente `78 01`, `78 5e`, `78 9c` o `78 da` (el segundo byte depende de los flags de compresión)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef tiene **Raw Deflate/Raw Inflate**, que suele ser la forma más rápida cuando el blob parece comprimido, pero `zlib` falla.

### CLI útiles
```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## Constructos comunes de crypto en CTF

### Técnica

Estos aparecen con frecuencia porque son errores realistas de desarrolladores o bibliotecas comunes utilizadas incorrectamente. El objetivo suele ser reconocerlos y aplicar un workflow conocido de extracción o reconstrucción.

### Fernet

Pista típica: dos cadenas Base64 (token + key).

- Decoder/notas: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- En Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si ves varios shares y se menciona un threshold `t`, probablemente sea Shamir.

- Online reconstructor (solo para shares de CTF no sensibles).<sup>[[19]](#references)</sup>

### Formatos salted de OpenSSL

A veces los CTF proporcionan salidas de `openssl enc` (el encabezado suele comenzar con `Salted__`).

Ayudantes de bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Toolset general

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Setup local recomendado

Stack práctico para CTF:

- Python más `pycryptodome` para primitives simétricas y prototipado rápido.<sup>[[25]](#references)</sup>
- SageMath para aritmética modular, CRT, lattices y trabajo con RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 para challenges basados en constraints (cuando la crypto se reduce a constraints).<sup>[[27]](#references)</sup>

Paquetes de Python sugeridos:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [búsqueda de hashes](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Kit de herramientas para hashes](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [herramientas de dCode](https://www.dcode.fr/tools-list)
- [9] [herramientas de descifrado de códigos de Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Descifrador automático de cifrado César](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Cifrado Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Solucionador de Vigenère de Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Decodificador Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Recontructor de secreto compartido de Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Documentación de PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
