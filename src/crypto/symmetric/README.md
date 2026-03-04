# Criptografía simétrica

{{#include ../../banners/hacktricks-training.md}}

## Qué buscar en CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: different errors/timings for bad padding.
- **MAC confusion**: using CBC-MAC with variable-length messages, or MAC-then-encrypt mistakes.
- **XOR en todas partes**: stream ciphers and custom constructions often reduce to XOR with a keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB revela patrones: bloques iguales de texto plano → bloques iguales de texto cifrado. Esto permite:

- Cut-and-paste / reordenamiento de bloques
- Eliminación de bloques (si el formato sigue siendo válido)

Si puedes controlar el texto plano y observar el texto cifrado (o cookies), intenta crear bloques repetidos (p. ej., muchos `A`s) y busca repeticiones.

### CBC: Cipher Block Chaining

- CBC es **malleable**: cambiar bits en `C[i-1]` cambia bits predecibles en `P[i]`.
- Si el sistema revela padding válido vs padding inválido, puedes tener un **padding oracle**.

### CTR

CTR convierte AES en un cifrado de flujo: `C = P XOR keystream`.

Si un nonce/IV se reutiliza con la misma clave:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Con texto plano conocido, puedes recuperar el keystream y descifrar otros.

**Patrones de explotación por reutilización de nonce/IV**

- Recuperar el keystream donde el texto plano sea conocido/adivinable:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Aplica los bytes de keystream recuperados para descifrar cualquier otro texto cifrado producido con la misma clave+IV en los mismos offsets.
- Datos altamente estructurados (p. ej., ASN.1/X.509 certificates, file headers, JSON/CBOR) proporcionan grandes regiones de texto plano conocido. A menudo puedes XORear el ciphertext del certificado con el cuerpo predecible del certificado para derivar el keystream, y luego descifrar otros secretos cifrados bajo el IV reutilizado. See also [TLS & Certificates](../tls-and-certificates/README.md) for typical certificate layouts.
- Cuando múltiples secretos del **mismo formato/size serializado** se cifran bajo la misma clave+IV, la alineación de campos filtra información incluso sin texto plano completo conocido. Ejemplo: claves PKCS#8 RSA del mismo tamaño de módulo colocan los factores primos en offsets coincidentes (~99.6% de alineamiento para 2048-bit). XORear dos ciphertexts bajo el keystream reutilizado aísla `p ⊕ p'` / `q ⊕ q'`, que puede recuperarse por fuerza bruta en segundos.
- Los IV por defecto en librerías (p. ej., constante `000...01`) son una trampa crítica: cada encriptación repite el mismo keystream, convirtiendo CTR en una one-time pad reutilizada.

**CTR malleability**

- CTR proporciona solo confidencialidad: cambiar bits en el ciphertext cambia determinísticamente los mismos bits en el texto plano. Sin una etiqueta de autenticación, los atacantes pueden manipular datos (p. ej., modificar claves, flags o mensajes) sin ser detectados.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) y exige la verificación de la etiqueta para detectar cambios de bits.

### GCM

GCM también se rompe gravemente con la reutilización de nonce. Si la misma clave+nonce se usa más de una vez, normalmente obtienes:

- Reutilización del keystream para encriptación (como CTR), permitiendo la recuperación de texto plano cuando cualquier texto plano es conocido.
- Pérdida de garantías de integridad. Dependiendo de lo que se exponga (múltiples pares mensaje/tag bajo el mismo nonce), los atacantes pueden ser capaces de falsificar tags.

Guía operativa:

- Trata la "reutilización de nonce" en AEAD como una vulnerabilidad crítica.
- AEADs resistentes al maluso (p. ej., GCM-SIV) reducen las consecuencias de reutilizar nonces pero aún requieren nonces/IVs únicos.
- Si tienes múltiples ciphertexts bajo el mismo nonce, empieza comprobando relaciones del tipo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef para experimentos rápidos: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` para scripting

## Patrones de explotación de ECB

ECB (Electronic Code Book) cifra cada bloque de forma independiente:

- bloques iguales de texto plano → bloques iguales de texto cifrado
- esto revela estructura y permite ataques estilo cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea para detección: patrón de token/cookie

Si inicias sesión varias veces y **siempre obtienes la misma cookie**, el ciphertext puede ser determinista (ECB o IV fijo).

Si creas dos usuarios con layouts de texto plano mayormente idénticos (p. ej., caracteres repetidos largos) y ves bloques de ciphertext repetidos en los mismos offsets, ECB es un sospechoso principal.

### Patrones de explotación

#### Eliminación de bloques enteros

Si el formato del token es algo como `<username>|<password>` y la frontera de bloque se alinea, a veces puedes crear un usuario de modo que el bloque `admin` aparezca alineado, luego eliminar los bloques previos para obtener un token válido para `admin`.

#### Mover bloques

Si el backend tolera padding/espacios extra (`admin` vs `admin    `), puedes:

- Alinear un bloque que contenga `admin   `
- Intercambiar/reutilizar ese bloque de ciphertext en otro token

## Padding Oracle

### Qué es

En modo CBC, si el servidor revela (directa o indirectamente) si el texto plano descifrado tiene **padding PKCS#7 válido**, a menudo puedes:

- Descifrar texto cifrado sin la clave
- Encriptar texto plano elegido (forjar texto cifrado)

El oracle puede ser:

- Un mensaje de error específico
- Un status HTTP diferente / tamaño de respuesta distinto
- Una diferencia de tiempo

### Explotación práctica

PadBuster es la herramienta clásica:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notas:

- El tamaño de bloque suele ser `16` para AES.
- `-encoding 0` significa Base64.
- Usa `-error` si el oracle es una cadena específica.

### Por qué funciona

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Modificando bytes en `C[i-1]` y observando si el padding es válido, puedes recuperar `P[i]` byte a byte.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. Si puedes modificar bloques de ciphertext y la aplicación usa el plaintext descifrado como datos estructurados (p. ej., `role=user`), puedes voltear bits específicos para cambiar bytes seleccionados del plaintext en una posición elegida en el siguiente bloque.

Patrón típico en CTF:

- Token = `IV || C1 || C2 || ...`
- Controlas bytes en `C[i]`
- Apuntas a bytes de plaintext en `P[i+1]` porque `P[i+1] = D(C[i+1]) XOR C[i]`

Esto no es una ruptura de confidencialidad por sí sola, pero es un primitivo común de escalada de privilegios cuando falta integridad.

## CBC-MAC

CBC-MAC es seguro solo bajo condiciones específicas (en particular **mensajes de longitud fija** y separación de dominio correcta).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si puedes obtener tags para mensajes elegidos, a menudo puedes crear un tag para una concatenación (o construcción relacionada) sin conocer la clave, explotando cómo CBC encadena los bloques.

Esto aparece frecuentemente en cookies/tokens de CTF que aplican un MAC a username o role con CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### Modelo mental

La mayoría de situaciones con stream ciphers se reducen a:

`ciphertext = plaintext XOR keystream`

Así que:

- Si conoces plaintext, recuperas keystream.
- Si el keystream se reutiliza (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Si conoces cualquier segmento de plaintext en la posición `i`, puedes recuperar bytes del keystream y descifrar otros ciphertexts en esas posiciones.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 es un stream cipher; encrypt/decrypt son la misma operación.

Si puedes obtener RC4 encryption de plaintext conocido bajo la misma clave, puedes recuperar el keystream y descifrar otros mensajes de la misma longitud/desplazamiento.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Referencias

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
