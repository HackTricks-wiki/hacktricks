# Crypto simétrica

{{#include ../../banners/hacktricks-training.md}}

## Qué buscar en CTFs

- **Uso incorrecto del modo**: patrones de ECB, maleabilidad de CBC, reutilización de nonce en CTR/GCM.
- **Padding oracles**: errores/tiempos diferentes para padding incorrecto.
- **Confusión con MAC**: usar CBC-MAC con mensajes de longitud variable o cometer errores de MAC-then-encrypt.
- **XOR por todas partes**: los stream ciphers y las construcciones personalizadas a menudo se reducen a XOR con un keystream.

## Modos AES y uso incorrecto

NIST especifica los modos de confidencialidad ECB, CBC y CTR en SP 800-38A, y el cifrado autenticado GCM en SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB filtra patrones: bloques de plaintext iguales → bloques de ciphertext iguales. Esto permite:

- Cut-and-paste / reordenación de bloques
- Eliminación de bloques (si el formato sigue siendo válido)

Si puedes controlar el plaintext y observar el ciphertext (o las cookies), intenta crear bloques repetidos (por ejemplo, muchas `A`) y busca repeticiones.

### CBC: Cipher Block Chaining

- CBC es **maleable**: cambiar bits en `C[i-1]` cambia bits predecibles en `P[i]`, mientras que también corrompe `P[i-1]`. Modificar el IV apunta al primer bloque de plaintext sin corromper un bloque de plaintext anterior.
- Si el sistema expone si el padding es válido o inválido, podrías tener un **padding oracle**.

### CTR

CTR convierte AES en un stream cipher: `C = P XOR keystream`.

Si se reutiliza un nonce/IV con la misma key:

- `C1 XOR C2 = P1 XOR P2` (reutilización clásica del keystream)
- Con plaintext conocido, puedes recuperar el keystream y descifrar otros.

**Patrones de explotación de reutilización de nonce/IV**

- Recupera el keystream donde el plaintext sea conocido o predecible:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Aplica los bytes del keystream recuperado para descifrar cualquier otro ciphertext producido con la misma key+IV en los mismos offsets.
- Los datos muy estructurados (por ejemplo, certificados ASN.1/X.509, file headers, JSON/CBOR) proporcionan grandes regiones de plaintext conocido. A menudo puedes hacer XOR entre el ciphertext del certificado y el cuerpo predecible del certificado para derivar el keystream y, después, descifrar otros secretos cifrados bajo el IV reutilizado. Consulta también [TLS & Certificates](../tls-and-certificates/README.md) para conocer las estructuras típicas de los certificados.<sup>[[1]](#references)</sup>
- Cuando varios secretos con el **mismo formato/tamaño serializado** se cifran bajo la misma key+IV, la alineación de campos filtra información incluso sin conocer completamente el plaintext. Ejemplo: las claves RSA PKCS#8 del mismo tamaño de modulus colocan los factores primos en offsets coincidentes (~99,6 % de alineación para 2048-bit). Hacer XOR entre dos ciphertexts bajo el keystream reutilizado aísla `p ⊕ p'` / `q ⊕ q'`, que se puede recuperar por fuerza bruta en segundos.<sup>[[1]](#references)</sup>
- Los IV predeterminados en las libraries (por ejemplo, una constante `000...01`) son un footgun crítico: cada cifrado repite el mismo keystream, convirtiendo CTR en un one-time pad reutilizado.<sup>[[1]](#references)</sup>

**Maleabilidad de CTR**

- CTR proporciona únicamente confidencialidad: cambiar bits en el ciphertext cambia determinísticamente los mismos bits en el plaintext. Sin un authentication tag, los attackers pueden manipular los datos (por ejemplo, modificar keys, flags o mensajes) sin ser detectados.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) y aplica la verificación del tag para detectar cambios de bits.

### GCM

GCM también falla gravemente cuando se reutiliza el nonce. Si se usa la misma key+nonce más de una vez, normalmente se obtiene:

- Reutilización del keystream para el cifrado (como en CTR), lo que permite recuperar el plaintext cuando se conoce cualquier plaintext.
- Pérdida de las garantías de integridad. Dependiendo de lo que se exponga (varios pares de mensaje/tag bajo el mismo nonce), los attackers podrían falsificar tags.

Guía operativa:

- Trata la "reutilización de nonce" en AEAD como una vulnerabilidad crítica.
- Los AEAD resistentes al uso incorrecto, como AES-GCM-SIV, reducen las consecuencias de la reutilización del nonce. Los callers deben seguir proporcionando nonces únicos, tal como requiere la interfaz de la construcción; la reutilización accidental tiene consecuencias limitadas en comparación con GCM ordinario.<sup>[[3]](#references)[[4]](#references)</sup>
- Si tienes varios ciphertexts bajo el mismo nonce, empieza comprobando relaciones del tipo `C1 XOR C2 = P1 XOR P2`.

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) para realizar experimentos rápidos.<sup>[[8]](#references)</sup>
- El paquete [PyCryptodome](https://www.pycryptodome.org/) de Python para hacer scripting.<sup>[[9]](#references)</sup>

## Patrones de explotación de ECB

ECB (Electronic Code Book) cifra cada bloque de forma independiente:

- bloques de plaintext iguales → bloques de ciphertext iguales
- esto filtra la estructura y permite ataques de estilo cut-and-paste

![Diagrama de bloques del descifrado en modo ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea de detección: patrón de token/cookie

Si inicias sesión varias veces y **siempre obtienes la misma cookie**, el ciphertext puede ser determinista (ECB o IV fijo).

Si creas dos usuarios con layouts de plaintext prácticamente idénticos (por ejemplo, caracteres repetidos largos) y observas bloques de ciphertext repetidos en los mismos offsets, ECB es el principal sospechoso.

### Patrones de explotación

#### Eliminar bloques completos

Si el formato del token es algo como `<username>|<password>` y el límite del bloque está alineado, a veces puedes crear un usuario de forma que el bloque `admin` quede alineado y, después, eliminar los bloques anteriores para obtener un token válido para `admin`.

#### Mover bloques

Si el backend tolera padding/espacios adicionales (`admin` frente a `admin    `), puedes:

- Alinear un bloque que contenga `admin   `
- Intercambiar/reutilizar ese bloque de ciphertext en otro token

## Padding Oracle

### Qué es

En modo CBC, si el servidor revela (directa o indirectamente) si el plaintext descifrado tiene un **padding PKCS#7 válido**, normalmente puedes:<sup>[[7]](#references)</sup>

- Descifrar el ciphertext sin la key
- Construir un ciphertext que descifre a un plaintext elegido cuando puedes enviar bloques precedentes o IVs manipulados y la aplicación acepta el mensaje resultante con padding válido

El oracle puede ser:

- Un mensaje de error específico
- Un status HTTP / tamaño de respuesta diferente
- Una diferencia de tiempo

### Explotación práctica

PadBuster es el tool clásico:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Ejemplo:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Why it works

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. By modifying bytes in `C[i-1]` and watching whether the padding is valid, you can recover `P[i]` byte-by-byte.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. If you can modify ciphertext blocks and the application uses the decrypted plaintext as structured data (e.g., `role=user`), you can flip specific bits to change selected plaintext bytes at a chosen position in the next block.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

This is not a break of confidentiality by itself, but it is a common privilege-escalation primitive when integrity is missing.

## CBC-MAC

CBC-MAC is secure only under specific conditions (notably **fixed-length messages** and correct domain separation). AES-CMAC is a standardized construction that safely handles variable-length inputs.<sup>[[5]](#references)</sup>

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

If you can obtain tags for chosen messages, you can often craft a tag for a concatenation (or related construction) without knowing the key, by exploiting how CBC chains blocks.

This frequently appears in CTF cookies/tokens that MAC username or role with CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

If you know any plaintext segment at position `i`, you can recover keystream bytes and decrypt other ciphertexts at those positions.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is a legacy stream cipher; encrypt/decrypt are the same XOR operation. Its known biases make it unsuitable for new systems, and TLS explicitly prohibits its cipher suites.<sup>[[6]](#references)</sup>

If you can get RC4 encryption of known plaintext under the same key, you can recover the keystream and decrypt other messages of the same length/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Descuido frente a artesanía en criptografía](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Recomendación para modos de operación de cifrado por bloques](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Recomendación para Galois/Counter Mode (GCM) y GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: cifrado autenticado resistente al uso indebido de nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - El algoritmo AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Prohibición de conjuntos de cifrado RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Pruebas para Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Documentación de PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
