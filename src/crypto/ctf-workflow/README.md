# Flujo de trabajo de Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Lista de verificación para el triaje

1. Identifica qué tienes: codificación, cifrado, hash, firma o MAC.
2. Determina qué está bajo control: texto plano/cifrado, IV/nonce, clave, oracle (padding/error/temporización), filtración parcial.
3. Clasifica: simétrico (AES/CTR/GCM), clave pública (RSA/ECC), hash/MAC (SHA/MD5/HMAC), clásico (Vigenere/XOR).
4. Aplica primero las comprobaciones con mayor probabilidad de éxito: decodificar capas, XOR con texto plano conocido, reutilización de nonce, uso incorrecto del modo, comportamiento del oracle.
5. Recurre a métodos avanzados solo cuando sea necesario: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos y utilidades en línea

Son útiles cuando la tarea consiste en identificar y eliminar capas, o cuando necesitas confirmar rápidamente una hipótesis.

### Búsquedas de hashes

- Busca el hash de un desafío si se sabe que es sintético/público.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Búsqueda en hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

No envíes hashes de contraseñas reales ni material confidencial de desafíos a servicios de búsqueda de terceros. Si te preocupa la divulgación, los términos del servicio o las reglas de la competición, es preferible realizar un ataque offline con wordlists y reglas.

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

Para código fuente en lenguajes esotéricos y el estado de intérpretes personalizados, consulta [Crypto CTF Misc](../ctf-misc/).

## Codificaciones y cifrados clásicos

### Técnica

Muchas tareas de criptografía en CTF usan transformaciones en capas: codificación base + sustitución simple + compresión. El objetivo es identificar las capas y eliminarlas de forma segura.

### Codificaciones: prueba muchas bases

Si sospechas que hay codificaciones en capas (base64 → base32 → …), prueba:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores comunes:

- Base64: `A-Za-z0-9+/=` (el padding `=` es común)
- Base32: `A-Z2-7=` (a menudo con mucho padding `=`)
- Ascii85/Base85: puntuación densa; a veces delimitada por `<~ ~>`

### Sustitución / monoalfabética

- Solucionador de criptogramas de Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Recuperación con known-plaintext de nombres de archivo Base32 sustituidos

Cuando un nombre de archivo ofuscado solo usa `a-z2-7`, se expande hasta aproximadamente `ceil(8 * byte_length / 5)` caracteres después de quitar un sufijo fijo, y el mismo texto plano produce la misma salida en distintos archivos, prueba **Base32 sin padding seguida de una sustitución fija de símbolos**. Estas pistas no son una prueba por sí solas. Reúne nombres de archivo predecibles y sus textos cifrados, conserva las mayúsculas y minúsculas, codifica cada texto plano en Base32 y alinea los símbolos posición por posición. Cada símbolo de texto plano repetido debe corresponder al mismo símbolo de texto cifrado, y la correspondencia inversa también debe ser única. En un caso de ransomware, `ntuser.ini` y `NTUSER.DAT` proporcionaron esos pares; esto permitió recuperar nombres de archivo, **no el contenido de los archivos ni las claves de cifrado**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Si un objetivo contiene símbolos sin mapear, obtén más pares conocidos o permuta solo las asignaciones de símbolos Base32 que no se hayan usado. Restablece el relleno hasta alcanzar un límite de ocho caracteres, rechaza Base32 no válido y nombres decodificados no imprimibles; luego vuelve a codificar los candidatos restantes y compara el **texto cifrado original completo**. Los bloques de texto cifrado repetidos pueden aportar más pistas: en el caso anterior, `3gpng2wv` se correspondía con Base32 `gaydambq`, que se decodifica como cinco ceros ASCII. Un candidato imprimible por sí solo no constituye una prueba única.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Descifrador automático de cifrados Caesar de Nayuki.<sup>[[15]](#references)</sup>
- Herramienta Atbash de Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Herramienta Vigenère de dCode.<sup>[[8]](#references)</sup>
- Solucionador Vigenère de Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

A menudo aparece en grupos de 5 bits o 5 letras:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Las runas suelen ser alfabetos de sustitución; busca «futhark cipher» y prueba tablas de correspondencias.

## Compresión en desafíos

### Técnica

La compresión aparece constantemente como una capa adicional (zlib/deflate/gzip/xz/zstd), a veces anidada. Si la salida casi se puede analizar, pero parece basura, sospecha que hay compresión.

### Identificación rápida

- `file <blob>`
- Busca bytes mágicos:
  - gzip: `1f 8b`
  - zlib: comúnmente `78 01`, `78 5e`, `78 9c` o `78 da` (el segundo byte depende de las opciones de compresión)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### DEFLATE sin procesar

CyberChef tiene **Raw Deflate/Raw Inflate**, que suele ser la vía más rápida cuando el blob parece comprimido, pero `zlib` falla.

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

## Construcciones criptográficas comunes de CTF

### Técnica

Aparecen con frecuencia porque son errores realistas de desarrolladores o bibliotecas comunes usadas incorrectamente. El objetivo suele ser reconocerlos y aplicar un flujo de trabajo conocido de extracción o reconstrucción.

### Fernet

Indicio típico: dos cadenas Base64 (token + clave).

- Decodificador/notas: decodificador Fernet de Asecuritysite.<sup>[[18]](#references)</sup>
- En Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si ves varias shares y se menciona un umbral `t`, probablemente sea Shamir.

- Recontructor en línea (solo para shares de CTF no sensibles).<sup>[[19]](#references)</sup>

### Formatos OpenSSL con salt

A veces los CTF proporcionan salidas de `openssl enc` (el encabezado suele comenzar con `Salted__`).

Herramientas auxiliares de fuerza bruta:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Conjunto general de herramientas

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configuración local recomendada

Conjunto práctico para CTF:

- Python más `pycryptodome` para primitivas simétricas y prototipado rápido.<sup>[[25]](#references)</sup>
- SageMath para aritmética modular, CRT, retículas y trabajo con RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 para desafíos basados en restricciones (cuando la criptografía se reduce a restricciones).<sup>[[27]](#references)</sup>

Paquetes de Python sugeridos:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```



## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [Búsqueda de hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [Herramientas de dCode](https://www.dcode.fr/tools-list)
- [9] [Herramientas de descifrado de códigos de Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Descifrador automático del cifrado César](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Cifrado Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Solucionador de Vigenère de Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Decodificador Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Recontructor de compartición de secretos de Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Documentación de PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Cómo romper esquemas de cifrado de la forma fácil](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
