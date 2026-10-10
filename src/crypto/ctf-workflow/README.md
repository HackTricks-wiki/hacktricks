# Flujo de trabajo de CTF de criptografía

{{#include ../../banners/hacktricks-training.md}}

## Lista de verificación de triage

1. Identifica qué tienes: codificación, cifrado, hash, firma o MAC.
2. Determina qué puedes controlar: texto plano/cifrado, IV/nonce, clave, oracle (relleno/error/tiempo), filtración parcial.
3. Clasifica: simétrica (AES/CTR/GCM), clave pública (RSA/ECC), hash/MAC (SHA/MD5/HMAC), clásica (Vigenère/XOR).
4. Prueba primero las comprobaciones con mayor probabilidad de éxito: decodificar capas, XOR con texto conocido, reutilización de nonce, uso incorrecto de modos, comportamiento del oracle.
5. Recurre a métodos avanzados solo cuando sea necesario: retículas (LLL/Coppersmith), SMT/Z3, canales laterales.

## Recursos y utilidades en línea

Son útiles para identificar y eliminar capas, o cuando necesitas confirmar rápidamente una hipótesis.

### Búsquedas de hashes

- Busca el hash del desafío si se sabe que es sintético/público.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Búsqueda de hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

No envíes hashes de contraseñas reales ni material confidencial de desafíos a servicios de búsqueda de terceros. Si te preocupan la divulgación, los términos del servicio o las reglas de la competencia, prefiere un ataque offline con wordlist/reglas.

### Herramientas de identificación

- CyberChef (Magic, decodificación y conversión).<sup>[[7]](#references)</sup>
- dCode (entorno para cifrados/codificaciones).<sup>[[8]](#references)</sup>
- Boxentriq (solucionadores de sustitución).<sup>[[9]](#references)</sup>

### Plataformas de práctica / referencias

- CryptoHack (desafíos prácticos de criptografía).<sup>[[10]](#references)</sup>
- Cryptopals (errores clásicos de la criptografía moderna).<sup>[[11]](#references)</sup>

### Decodificación automatizada

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (prueba muchas bases/codificaciones).<sup>[[13]](#references)</sup>

## Codificaciones y cifrados clásicos

### Técnica

Muchos desafíos de criptografía CTF usan transformaciones en capas: codificación base + sustitución simple + compresión. El objetivo es identificar las capas y eliminarlas de forma segura.

### Codificaciones: prueba varias bases

Si sospechas que hay codificación en capas (base64 → base32 → …), prueba:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores comunes:

- Base64: `A-Za-z0-9+/=` (el relleno `=` es habitual)
- Base32: `A-Z2-7=` (a menudo tiene mucho relleno `=`)
- Ascii85/Base85: puntuación densa; a veces está entre `<~ ~>`

### Sustitución / monoalfabética

- Solucionador de criptogramas de Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Descifrador automático de cifrado Caesar de Nayuki.<sup>[[15]](#references)</sup>
- Herramienta Atbash de Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Herramienta Vigenère de dCode.<sup>[[8]](#references)</sup>
- Solucionador Vigenère de Guballa.<sup>[[17]](#references)</sup>

### Cifrado Bacon

A menudo aparece en grupos de 5 bits o 5 letras:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runas

Las runas suelen ser alfabetos de sustitución; busca "futhark cipher" y prueba tablas de correspondencia.

## Compresión en challenges

### Técnica

La compresión aparece constantemente como una capa adicional (zlib/deflate/gzip/xz/zstd), a veces anidada. Si la salida casi se puede analizar, pero parece basura, sospecha que hay compresión.

### Identificación rápida

- `file <blob>`
- Busca bytes mágicos:
  - gzip: `1f 8b`
  - zlib: normalmente `78 01`, `78 5e`, `78 9c` o `78 da` (el segundo byte depende de las opciones de compresión)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### DEFLATE sin procesar

CyberChef tiene **Raw Deflate/Raw Inflate**, que suele ser la forma más rápida cuando el blob parece comprimido, pero `zlib` falla.

### CLI útil

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

## Construcciones criptográficas comunes en CTF

### Técnica

Aparecen con frecuencia porque reflejan errores realistas de desarrolladores o el uso incorrecto de bibliotecas comunes. El objetivo suele ser reconocerlos y aplicar un flujo de trabajo conocido de extracción o reconstrucción.

### Fernet

Pista típica: dos cadenas Base64 (token + clave).

- Decodificador/notas: decodificador Fernet de Asecuritysite.<sup>[[18]](#references)</sup>
- En Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si ves varias shares y se menciona un umbral `t`, probablemente se trate de Shamir.

- Recontructor en línea (solo para shares de CTF no sensibles).<sup>[[19]](#references)</sup>

### Formatos salted de OpenSSL

A veces los CTF proporcionan salidas de `openssl enc` (el encabezado suele comenzar con `Salted__`).

Herramientas auxiliares de fuerza bruta:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Conjunto general de herramientas

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configuración local recomendada

Stack práctico para CTF:

- Python más `pycryptodome` para primitivas simétricas y prototipado rápido.<sup>[[25]](#references)</sup>
- SageMath para aritmética modular, CRT, retículos y trabajo con RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 para desafíos basados en restricciones (cuando la criptografía se reduce a restricciones).<sup>[[27]](#references)</sup>

Paquetes de Python recomendados:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [búsqueda de hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [herramientas de dCode](https://www.dcode.fr/tools-list)
- [9] [herramientas de descifrado de códigos de Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Descifrador automático de cifrado César](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - cifrado Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Solucionador de cifrado Vigenère de Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - decodificador Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Recontructor de Shamir secret-sharing](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [documentación de PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
