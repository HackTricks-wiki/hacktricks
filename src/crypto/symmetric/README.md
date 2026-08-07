# Criptografía simétrica

{{#include ../../banners/hacktricks-training.md}}

## Qué buscar en CTFs

- **Uso incorrecto del modo**: patrones de ECB, maleabilidad de CBC, reutilización de nonce en CTR/GCM.
- **Padding oracles**: errores/tiempos diferentes para un padding incorrecto.
- **Confusión con MAC**: uso de CBC-MAC con mensajes de longitud variable o errores de MAC-then-encrypt.
- **XOR por todas partes**: los stream ciphers y las construcciones personalizadas suelen reducirse a XOR con un keystream.

## Modos de AES y uso incorrecto

### ECB: Electronic Codebook

ECB hace leak de patrones: bloques de plaintext iguales → bloques de ciphertext iguales. Esto permite:

- Cut-and-paste / reordenación de bloques
- Eliminación de bloques (si el formato sigue siendo válido)

Si puedes controlar el plaintext y observar el ciphertext (o cookies), intenta crear bloques repetidos (por ejemplo, muchas `A`) y busca repeticiones.

### CBC: Cipher Block Chaining

- CBC es **maleable**: cambiar bits en `C[i-1]` cambia bits predecibles en `P[i]`.
- Si el sistema expone un padding válido frente a uno inválido, puedes tener un **padding oracle**.

### CTR

CTR convierte AES en un stream cipher: `C = P XOR keystream`.

Si se reutiliza un nonce/IV con la misma key:

- `C1 XOR C2 = P1 XOR P2` (reutilización clásica del keystream)
- Con plaintext conocido, puedes recuperar el keystream y descifrar otros mensajes.

**Patrones de explotación de reutilización de nonce/IV**

- Recupera el keystream donde el plaintext sea conocido o se pueda adivinar:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Aplica los bytes recuperados del keystream para descifrar cualquier otro ciphertext producido con la misma key+IV en los mismos offsets.
- Los datos muy estructurados (por ejemplo, certificados ASN.1/X.509, cabeceras de archivos, JSON/CBOR) proporcionan grandes regiones de known-plaintext. A menudo puedes hacer XOR entre el ciphertext del certificado y el cuerpo predecible del certificado para obtener el keystream y después descifrar otros secretos cifrados bajo el IV reutilizado. Consulta también [TLS & Certificates](../tls-and-certificates/README.md) para conocer las estructuras típicas de los certificados.<sup>[[1]](#references)</sup>
- Cuando múltiples secretos con el **mismo formato/tamaño serializado** se cifran bajo la misma key+IV, la alineación de campos hace leak incluso sin disponer del known-plaintext completo. Ejemplo: las keys RSA PKCS#8 del mismo tamaño de modulus colocan los factores primos en offsets coincidentes (aproximadamente un 99,6 % de alineación para 2048 bits). Hacer XOR entre dos ciphertexts bajo el keystream reutilizado aísla `p ⊕ p'` / `q ⊕ q'`, que puede recuperarse mediante brute force en segundos.<sup>[[1]](#references)</sup>
- Los IV predeterminados en las libraries (por ejemplo, la constante `000...01`) son un footgun crítico: cada cifrado repite el mismo keystream, convirtiendo CTR en un one-time pad reutilizado.<sup>[[1]](#references)</sup>

**Maleabilidad de CTR**

- CTR solo proporciona confidencialidad: cambiar bits en el ciphertext cambia de forma determinista los mismos bits en el plaintext. Sin un authentication tag, los atacantes pueden manipular los datos (por ejemplo, modificar keys, flags o mensajes) sin ser detectados.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) y aplica la verificación del tag para detectar bit-flips.

### GCM

GCM también falla gravemente cuando se reutiliza el nonce. Si se usa la misma key+nonce más de una vez, normalmente se obtiene:

- Reutilización del keystream para el cifrado (como en CTR), lo que permite recuperar el plaintext cuando se conoce algún plaintext.
- Pérdida de las garantías de integridad. Dependiendo de lo que se exponga (múltiples pares message/tag bajo el mismo nonce), los atacantes podrían falsificar tags.

Guía operativa:

- Trata la "reutilización del nonce" en AEAD como una vulnerabilidad crítica.
- Los AEAD resistentes al uso incorrecto (por ejemplo, GCM-SIV) reducen las consecuencias del uso incorrecto del nonce, pero siguen requiriendo nonces/IVs únicos.
- Si tienes múltiples ciphertexts bajo el mismo nonce, empieza comprobando relaciones del tipo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef para experimentos rápidos: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` para scripting

## Patrones de explotación de ECB

ECB (Electronic Code Book) cifra cada bloque de forma independiente:

- bloques de plaintext iguales → bloques de ciphertext iguales
- esto hace leak de la estructura y permite ataques del tipo cut-and-paste

![Diagrama de bloques del descifrado en modo ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea de detección: patrón de token/cookie

Si inicias sesión varias veces y **siempre recibes la misma cookie**, el ciphertext puede ser determinista (ECB o IV fijo).

Si creas dos usuarios con layouts de plaintext prácticamente idénticos (por ejemplo, con muchos caracteres repetidos) y observas bloques de ciphertext repetidos en los mismos offsets, ECB es el principal sospechoso.

### Patrones de explotación

#### Eliminación de bloques completos

Si el formato del token es algo como `<username>|<password>` y los límites de bloque están alineados, a veces puedes crear un usuario de forma que el bloque `admin` quede alineado y después eliminar los bloques precedentes para obtener un token válido para `admin`.

#### Movimiento de bloques

Si el backend tolera padding/espacios adicionales (`admin` frente a `admin    `), puedes:

- Alinear un bloque que contenga `admin   `
- Intercambiar/reutilizar ese bloque de ciphertext en otro token

## Padding Oracle

### Qué es

En modo CBC, si el servidor revela (directa o indirectamente) si el plaintext descifrado tiene un **padding PKCS#7 válido**, a menudo puedes:

- Descifrar ciphertext sin la key
- Cifrar plaintext elegido (forjar ciphertext)

El oracle puede ser:

- Un mensaje de error específico
- Un status HTTP / tamaño de respuesta diferente
- Una diferencia de tiempo

### Explotación práctica

PadBuster es la tool clásica:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Ejemplo:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notas:

- El tamaño de bloque suele ser `16` para AES.
- `-encoding 0` significa Base64.
- Usa `-error` si el oracle es una cadena específica.

### Por qué funciona

El descifrado CBC calcula `P[i] = D(C[i]) XOR C[i-1]`. Al modificar bytes en `C[i-1]` y observar si el padding es válido, puedes recuperar `P[i]` byte a byte.

## Bit-flipping en CBC

Incluso sin un padding oracle, CBC es maleable. Si puedes modificar bloques de ciphertext y la aplicación usa el plaintext descifrado como datos estructurados (por ejemplo, `role=user`), puedes cambiar bits específicos para modificar bytes de plaintext seleccionados en una posición concreta del bloque siguiente.

Patrón típico de CTF:

- Token = `IV || C1 || C2 || ...`
- Controlas bytes en `C[i]`
- Apuntas a bytes de plaintext en `P[i+1]` porque `P[i+1] = D(C[i+1]) XOR C[i]`

Esto no rompe la confidencialidad por sí mismo, pero es un primitive común de escalada de privilegios cuando falta integridad.

## CBC-MAC

CBC-MAC solo es seguro bajo condiciones específicas (principalmente, **mensajes de longitud fija** y una separación de dominios correcta).

### Patrón clásico de forgery con longitud variable

CBC-MAC normalmente se calcula así:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si puedes obtener tags para mensajes elegidos, a menudo puedes crear un tag para una concatenación (o una construcción relacionada) sin conocer la key, explotando la forma en que CBC encadena los bloques.

Esto aparece con frecuencia en cookies/tokens de CTF que aplican CBC-MAC al username o al role.

### Alternativas más seguras

- Usa HMAC (SHA-256/512)
- Usa CMAC (AES-CMAC) correctamente
- Incluye la longitud del mensaje / separación de dominios

## Cifrados de flujo: XOR y RC4

### El modelo mental

La mayoría de las situaciones con stream ciphers se reducen a:

`ciphertext = plaintext XOR keystream`

Por lo tanto:

- Si conoces el plaintext, recuperas el keystream.
- Si el keystream se reutiliza (misma key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Cifrado basado en XOR

Si conoces cualquier segmento de plaintext en la posición `i`, puedes recuperar los bytes del keystream y descifrar otros ciphertexts en esas posiciones.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 es un stream cipher; cifrar y descifrar son la misma operación.

Si puedes obtener el cifrado RC4 de un plaintext conocido usando la misma key, puedes recuperar el keystream y descifrar otros mensajes con la misma longitud/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Referencias

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
