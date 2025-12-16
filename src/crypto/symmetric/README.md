# Criptografía simétrica

{{#include ../../banners/hacktricks-training.md}}

## Qué buscar en CTFs

- **Mal uso de modos**: patrones ECB, malleability de CBC, reutilización de nonce en CTR/GCM.
- **Padding oracles**: diferentes errores/timings para padding inválido.
- **MAC confusion**: uso de CBC-MAC con mensajes de longitud variable, o errores de MAC-then-encrypt.
- **XOR por todas partes**: stream ciphers y construcciones custom a menudo se reducen a XOR con un keystream.

## Modos AES y mal uso

### ECB: Electronic Codebook

ECB leaks patterns: bloques de plaintext iguales → bloques de ciphertext iguales. Esto permite:

- Cut-and-paste / reordenamiento de bloques
- Eliminación de bloques (si el formato permanece válido)

Si puedes controlar el plaintext y observar el ciphertext (o cookies), intenta crear bloques repetidos (p. ej., muchos `A`s) y busca repeticiones.

### CBC: Cipher Block Chaining

- CBC is **malleable**: cambiar bits en `C[i-1]` cambia bits predecibles en `P[i]`.
- Si el sistema expone padding válido vs padding inválido, puede que tengas un **padding oracle**.

### CTR

CTR convierte AES en un stream cipher: `C = P XOR keystream`.

Si un nonce/IV se reutiliza con la misma clave:

- `C1 XOR C2 = P1 XOR P2` (reutilización clásica del keystream)
- Con plaintext conocido, puedes recuperar el keystream y descifrar otros.

### GCM

GCM también falla gravemente bajo reutilización de nonce. Si la misma key+nonce se usa más de una vez, típicamente obtienes:

- Reutilización del keystream para cifrado (como CTR), permitiendo la recuperación de plaintext cuando cualquier plaintext es conocido.
- Pérdida de garantías de integridad. Dependiendo de lo expuesto (múltiples pares message/tag bajo el mismo nonce), los atacantes pueden ser capaces de forjar tags.

Operational guidance:

- Trata la reutilización de nonce en AEAD como una vulnerabilidad crítica.
- Si tienes múltiples ciphertexts bajo el mismo nonce, empieza comprobando relaciones del estilo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef para experimentos rápidos: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` para scripting

## Patrones de explotación de ECB

ECB (Electronic Code Book) cifra cada bloque de forma independiente:

- bloques de plaintext iguales → bloques de ciphertext iguales
- esto leaks la estructura y permite ataques estilo cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea de detección: patrón token/cookie

Si inicias sesión varias veces y **siempre obtienes la misma cookie**, el ciphertext puede ser determinista (ECB o IV fijo).

Si creas dos usuarios con formatos de plaintext mayormente idénticos (p. ej., caracteres repetidos largos) y ves bloques de ciphertext repetidos en los mismos offsets, ECB es un sospechoso principal.

### Patrones de explotación

#### Eliminación de bloques enteros

Si el formato del token es algo como `<username>|<password>` y el límite de bloque se alinea, a veces puedes crear un usuario de modo que el bloque `admin` aparezca alineado, luego eliminar bloques anteriores para obtener un token válido para `admin`.

#### Mover bloques

Si el backend tolera padding/espacios extra (`admin` vs `admin    `), puedes:

- Alinear un bloque que contenga `admin   `
- Intercambiar/reutilizar ese bloque de ciphertext en otro token

## Padding Oracle

### Qué es

En modo CBC, si el servidor revela (directa o indirectamente) si el plaintext descifrado tiene **padding PKCS#7 válido**, a menudo puedes:

- Descifrar ciphertext sin la clave
- Encriptar plaintext elegido (forjar ciphertext)

El oracle puede ser:

- Un mensaje de error específico
- Un status HTTP diferente / tamaño de respuesta
- Una diferencia de timing

### Explotación práctica

PadBuster es la herramienta clásica:

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

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Al modificar bytes en `C[i-1]` y observar si el padding es válido, puedes recuperar `P[i]` byte a byte.

## Bit-flipping en CBC

Even without a padding oracle, CBC is malleable. Si puedes modificar bloques de ciphertext y la aplicación usa el plaintext descifrado como datos estructurados (p. ej., `role=user`), puedes invertir bits específicos para cambiar bytes seleccionados del plaintext en una posición elegida del siguiente bloque.

Patrón típico en CTF:

- Token = `IV || C1 || C2 || ...`
- Controlas bytes en `C[i]`
- Apuntas a bytes del plaintext en `P[i+1]` porque `P[i+1] = D(C[i+1]) XOR C[i]`

Esto no rompe la confidencialidad por sí solo, pero es una técnica común de escalada de privilegios cuando falta integridad.

## CBC-MAC

CBC-MAC es seguro solo bajo condiciones específicas (notablemente **mensajes de longitud fija** y separación de dominios correcta).

### Patrón clásico de falsificación de longitud variable

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si puedes obtener tags para mensajes elegidos, a menudo puedes crear un tag para una concatenación (o construcción relacionada) sin conocer la clave, explotando cómo CBC encadena los bloques.

Esto aparece frecuentemente en cookies/tokens de CTF que usan CBC-MAC para proteger el username o role.

### Alternativas más seguras

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Cifradores de flujo: XOR y RC4

### Modelo mental

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Si conoces cualquier segmento de plaintext en la posición `i`, puedes recuperar bytes del keystream y descifrar otros ciphertexts en esas posiciones.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 es un cifrador de flujo; encriptar/descifrar es la misma operación.

Si puedes obtener RC4 encryption of known plaintext under the same key, puedes recuperar el keystream y descifrar otros mensajes de la misma longitud/desplazamiento.

Análisis de referencia (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
