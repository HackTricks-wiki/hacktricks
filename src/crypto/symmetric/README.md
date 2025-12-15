# Criptografía simétrica

{{#include ../../banners/hacktricks-training.md}}

## Qué buscar en CTFs

- **Uso incorrecto de modos**: patrones ECB, maleabilidad CBC, reutilización de nonce en CTR/GCM.
- **Padding oracles**: errores diferentes/variaciones en tiempos para padding inválido.
- **MAC confusion**: usar CBC-MAC con mensajes de longitud variable, o errores de MAC-then-encrypt.
- **XOR everywhere**: stream ciphers y construcciones personalizadas a menudo se reducen a XOR con un keystream.

## Modos AES y uso incorrecto

### ECB: Electronic Codebook

ECB leaks patterns: bloques de texto plano iguales → bloques de texto cifrado iguales. Esto permite:

- Cut-and-paste / reordenamiento de bloques
- Eliminación de bloques (si el formato sigue siendo válido)

Si puedes controlar el plaintext y observar el ciphertext (o cookies), intenta crear bloques repetidos (p.ej., muchos `A`) y busca repeticiones.

### CBC: Cipher Block Chaining

- CBC es **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Si el sistema expone padding válido vs padding inválido, puede que tengas un **padding oracle**.

### CTR

CTR convierte AES en un stream cipher: `C = P XOR keystream`.

Si se reutiliza un nonce/IV con la misma key:

- `C1 XOR C2 = P1 XOR P2` (reuse clásico de keystream)
- Con plaintext conocido, puedes recuperar el keystream y descifrar otros mensajes.

### GCM

GCM también falla gravemente con la reutilización de nonce. Si la misma key+nonce se usa más de una vez, típicamente obtienes:

- Reutilización de keystream para cifrado (como CTR), permitiendo la recuperación de plaintext cuando cualquier plaintext es conocido.
- Pérdida de garantías de integridad. Dependiendo de lo que se exponga (múltiples pares message/tag bajo el mismo nonce), un atacante puede ser capaz de forjar tags.

Guía operativa:

- Trata "nonce reuse" en AEAD como una vulnerabilidad crítica.
- Si tienes múltiples ciphertexts bajo el mismo nonce, comienza comprobando relaciones del tipo `C1 XOR C2 = P1 XOR P2`.

### Herramientas

- CyberChef para experimentos rápidos: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` para scripting

## Patrones de explotación de ECB

ECB (Electronic Code Book) cifra cada bloque independientemente:

- bloques de texto plano iguales → bloques de texto cifrado iguales
- esto filtra la estructura y permite ataques tipo cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea de detección: patrón de token/cookie

Si inicias sesión varias veces y **siempre obtienes la misma cookie**, el ciphertext puede ser determinista (ECB o IV fijo).

Si creas dos usuarios con disposiciones de texto plano mayormente idénticas (p.ej., muchos caracteres repetidos) y ves bloques de ciphertext repetidos en las mismas posiciones, ECB es un sospechoso principal.

### Patrones de explotación

#### Eliminación de bloques completos

Si el formato del token es algo como `<username>|<password>` y la frontera de bloque coincide, a veces puedes crear un usuario de forma que el bloque `admin` quede alineado, luego eliminar los bloques previos para obtener un token válido para `admin`.

#### Mover bloques

Si el backend tolera padding/espacios extra (`admin` vs `admin    `), puedes:

- Alinear un bloque que contenga `admin   `
- Intercambiar/reusar ese bloque de ciphertext en otro token

## Padding Oracle

### Qué es

En CBC mode, si el servidor revela (directa o indirectamente) si el plaintext descifrado tiene **valid PKCS#7 padding**, a menudo puedes:

- Decrypt ciphertext without the key
- Encrypt chosen plaintext (forge ciphertext)

El oracle puede ser:

- Un mensaje de error específico
- Un HTTP status / tamaño de respuesta diferente
- Una diferencia de timing

### Explotación práctica

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notas:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Por qué funciona

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Al modificar bytes en `C[i-1]` y observar si el padding es válido, puedes recuperar `P[i]` byte a byte.

## Bit-flipping en CBC

Even without a padding oracle, CBC is malleable. Si puedes modificar bloques de ciphertext y la aplicación usa el plaintext descifrado como datos estructurados (p. ej., `role=user`), puedes voltear bits específicos para cambiar bytes seleccionados del plaintext en una posición elegida del siguiente bloque.

Patrón típico en CTF:

- Token = `IV || C1 || C2 || ...`
- Controlas bytes en `C[i]`
- Apuntas a bytes de plaintext en `P[i+1]` porque `P[i+1] = D(C[i+1]) XOR C[i]`

Esto no rompe la confidencialidad por sí solo, pero es una primitiva común de escalamiento de privilegios cuando falta integridad.

## CBC-MAC

CBC-MAC es seguro solo bajo condiciones específicas (notablemente **mensajes de longitud fija** y separación de dominio correcta).

### Patrón clásico de falsificación de longitud variable

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si puedes obtener tags para mensajes elegidos, a menudo puedes crear un tag para una concatenación (o construcción relacionada) sin conocer la key, explotando cómo CBC encadena los bloques.

Esto aparece frecuentemente en cookies/tokens de CTF que hacen MAC a username o role con CBC-MAC.

### Alternativas más seguras

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Cifradores de flujo: XOR y RC4

### El modelo mental

La mayoría de situaciones con stream cipher se reducen a:

`ciphertext = plaintext XOR keystream`

Entonces:

- Si conoces plaintext, recuperas keystream.
- Si el keystream se reutiliza (misma key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Encriptación basada en XOR

Si conoces cualquier segmento de plaintext en la posición `i`, puedes recuperar bytes del keystream y descifrar otros ciphertexts en esas posiciones.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 es un stream cipher; encrypt/decrypt son la misma operación.

Si puedes obtener RC4 encryption de plaintext conocido bajo la misma key, puedes recuperar el keystream y descifrar otros mensajes de la misma length/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
