# Criptografía simétrica

{{#include ../../banners/hacktricks-training.md}}

## Qué buscar en CTFs

- **Uso incorrecto de modos**: patrones ECB, maleabilidad de CBC, reutilización de nonce en CTR/GCM.
- **Padding oracles**: errores o tiempos distintos cuando el padding no es válido.
- **Confusión de MAC**: uso de CBC-MAC con mensajes de longitud variable o errores de MAC-then-encrypt.
- **XOR por todas partes**: los cifrados de flujo y las construcciones personalizadas suelen reducirse a un XOR con un keystream.

## Modos AES y uso incorrecto

NIST especifica los modos de confidencialidad ECB, CBC y CTR en SP 800-38A, y el cifrado autenticado GCM en SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB filtra patrones: bloques de texto plano iguales → bloques de texto cifrado iguales. Esto permite:

- Cortar y pegar / reordenar bloques
- Eliminar bloques (si el formato sigue siendo válido)

Si puedes controlar el texto plano y observar el texto cifrado (o las cookies), intenta generar bloques repetidos (por ejemplo, muchas `A`) y busca repeticiones.

### CBC: Cipher Block Chaining

- CBC es **maleable**: invertir bits en `C[i-1]` invierte bits predecibles en `P[i]`, pero también corrompe `P[i-1]`. Modificar el IV permite alterar el primer bloque de texto plano sin corromper un bloque anterior.
- Si el sistema revela si el padding es válido o no, puede que tengas un **padding oracle**.

### CTR

CTR convierte AES en un cifrado de flujo: `C = P XOR keystream`.

Si se reutiliza un nonce/IV con la misma clave:

- `C1 XOR C2 = P1 XOR P2` (reutilización clásica del keystream)
- Si conoces el texto plano, puedes recuperar el keystream y descifrar otros mensajes.

**Patrones de explotación de la reutilización de nonce/IV**

- Recuperar el keystream allí donde el texto plano se conoce o se puede adivinar:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Aplica los bytes del keystream recuperado para descifrar cualquier otro ciphertext generado con la misma key+IV en los mismos offsets.
- Los datos altamente estructurados (p. ej., certificados ASN.1/X.509, cabeceras de archivos, JSON/CBOR) proporcionan grandes regiones de texto plano conocido. A menudo puedes aplicar XOR al ciphertext del certificado con el cuerpo predecible del certificado para derivar el keystream y, luego, descifrar otros secretos cifrados con el IV reutilizado. Consulta también [TLS & Certificates](../tls-and-certificates/README.md) para ver estructuras típicas de certificados.<sup>[[1]](#references)</sup>
- Cuando se cifran varios secretos con el **mismo formato/tamaño serializado** usando la misma key+IV, la alineación de campos filtra información incluso sin texto plano conocido completo. Por ejemplo, las claves RSA PKCS#8 del mismo tamaño de módulo colocan los factores primos en offsets coincidentes (alineación de ~99,6 % para 2048 bits). Aplicar XOR a dos ciphertexts bajo el keystream reutilizado aísla `p ⊕ p'` / `q ⊕ q'`, que pueden recuperarse mediante fuerza bruta en segundos.<sup>[[1]](#references)</sup>
- Los IV predeterminados en las bibliotecas (p. ej., una constante `000...01`) son un riesgo crítico: cada cifrado repite el mismo keystream, convirtiendo CTR en un one-time pad reutilizado.<sup>[[1]](#references)</sup>

**Maleabilidad de CTR**

- CTR solo proporciona confidencialidad: invertir bits en el ciphertext invierte de forma determinista los mismos bits en el plaintext. Sin una etiqueta de autenticación, los atacantes pueden modificar datos (p. ej., alterar claves, flags o mensajes) sin ser detectados.
- Usa AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) y exige la verificación de la etiqueta para detectar cambios de bits.

### GCM

GCM también se ve gravemente comprometido al reutilizar el nonce. Si se usa la misma key+nonce más de una vez, normalmente se obtiene lo siguiente:

- Reutilización del keystream para el cifrado (como en CTR), lo que permite recuperar el plaintext cuando se conoce cualquier parte de este.
- Pérdida de las garantías de integridad. Según lo que se exponga (varios pares de mensaje/etiqueta con el mismo nonce), los atacantes podrían falsificar etiquetas.

Recomendaciones operativas:

- Trata la «reutilización del nonce» en AEAD como una vulnerabilidad crítica.
- Los AEAD resistentes al uso indebido, como AES-GCM-SIV, reducen las consecuencias de reutilizar el nonce. Aun así, quienes los usan deben proporcionar nonces únicos, tal como exige la interfaz de la construcción; la reutilización accidental tiene consecuencias acotadas en comparación con GCM convencional.<sup>[[3]](#references)[[4]](#references)</sup>
- Si tienes varios ciphertexts con el mismo nonce, empieza comprobando relaciones del tipo `C1 XOR C2 = P1 XOR P2`.

### Herramientas

- [CyberChef](https://gchq.github.io/CyberChef/) para pruebas rápidas.<sup>[[8]](#references)</sup>
- El paquete [PyCryptodome](https://www.pycryptodome.org/) de Python para crear scripts.<sup>[[9]](#references)</sup>

## Patrones de explotación de ECB

ECB (Electronic Code Book) cifra cada bloque de forma independiente:

- bloques de plaintext iguales → ciphertexts iguales
- esto filtra la estructura y permite ataques de tipo cut-and-paste

![Diagrama de bloques de descifrado en modo ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idea para detectar: patrón de token/cookie

Si inicias sesión varias veces y **siempre obtienes la misma cookie**, el ciphertext podría ser determinista (ECB o IV fijo).

Si creas dos usuarios con diseños de plaintext casi idénticos (p. ej., largas secuencias de caracteres repetidos) y observas bloques de ciphertext repetidos en los mismos offsets, ECB es un sospechoso principal.

### Patrones de explotación

#### Eliminar bloques completos

Si el formato del token es algo como `<username>|<password>` y los límites de bloque están alineados, a veces puedes crear un usuario para que el bloque `admin` quede alineado y, luego, eliminar los bloques anteriores para obtener un token válido para `admin`.

#### Mover bloques

Si el backend admite padding/espacios adicionales (`admin` frente a `admin    `), puedes:

- Alinear un bloque que contenga `admin   `
- Intercambiar/reutilizar ese bloque de ciphertext en otro token

## Padding Oracle

### Qué es

En modo CBC, si el servidor revela (directa o indirectamente) si el plaintext descifrado tiene un **padding PKCS#7 válido**, a menudo puedes:<sup>[[7]](#references)</sup>

- Descifrar ciphertext sin la clave
- Construir un ciphertext que se descifre como el plaintext elegido, si puedes enviar bloques anteriores o IVs manipulados y la aplicación acepta el mensaje resultante con padding válido

El oracle puede ser:

- Un mensaje de error específico
- Un código de estado HTTP / tamaño de respuesta diferente
- Una diferencia de tiempo

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
- Usa `-error` si el oracle devuelve una cadena específica.

### Por qué funciona

El descifrado CBC calcula `P[i] = D(C[i]) XOR C[i-1]`. Al modificar bytes en `C[i-1]` y observar si el padding es válido, puedes recuperar `P[i]` byte a byte.

## Bit-flipping en CBC

Incluso sin un padding oracle, CBC es maleable. Si puedes modificar bloques de ciphertext y la aplicación usa el plaintext descifrado como datos estructurados (p. ej., `role=user`), puedes cambiar bits específicos para modificar bytes concretos del plaintext en una posición elegida del siguiente bloque.

Patrón típico de CTF:

- Token = `IV || C1 || C2 || ...`
- Controlas bytes en `C[i]`
- Apuntas a bytes del plaintext en `P[i+1]` porque `P[i+1] = D(C[i+1]) XOR C[i]`

Esto no rompe la confidencialidad por sí solo, pero es una primitiva común para escalar privilegios cuando falta integridad.

## CBC-MAC

CBC-MAC solo es seguro bajo condiciones específicas (en particular, **mensajes de longitud fija** y una separación de dominios correcta). AES-CMAC es una construcción estandarizada que maneja de forma segura entradas de longitud variable.<sup>[[5]](#references)</sup>

### Patrón clásico de falsificación con longitud variable

CBC-MAC suele calcularse así:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si puedes obtener tags para mensajes elegidos, a menudo puedes crear un tag para una concatenación (o una construcción relacionada) sin conocer la clave, aprovechando cómo CBC encadena los bloques.

Esto aparece con frecuencia en cookies/tokens de CTF que aplican MAC al nombre de usuario o al rol con CBC-MAC.

### Alternativas más seguras

- Usa HMAC (SHA-256/512)
- Usa CMAC (AES-CMAC) correctamente
- Incluye la longitud del mensaje / separación de dominios

## Cifrados de flujo: XOR y RC4

### El modelo mental

La mayoría de las situaciones con cifrados de flujo se reducen a:

`ciphertext = plaintext XOR keystream`

Así que:

- Si conoces el plaintext, recuperas el keystream.
- Si se reutiliza el keystream (misma clave+nonce), `C1 XOR C2 = P1 XOR P2`.

### Cifrado basado en XOR

Si conoces cualquier segmento de plaintext en la posición `i`, puedes recuperar bytes del keystream y descifrar otros ciphertexts en esas posiciones.

Herramientas automáticas:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 es un cifrado de flujo obsoleto; cifrar y descifrar son la misma operación XOR. Sus sesgos conocidos lo hacen inadecuado para sistemas nuevos, y TLS prohíbe explícitamente sus conjuntos de cifrado.<sup>[[6]](#references)</sup>

Si puedes obtener el cifrado RC4 de un plaintext conocido con la misma clave, puedes recuperar el keystream y descifrar otros mensajes de la misma longitud/posición.

Writeup de referencia (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Descuidos frente a artesanía en criptografía](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Recomendación para modos de operación de cifrados de bloque](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Recomendación para Galois/Counter Mode (GCM) y GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: cifrado autenticado resistente al uso indebido de nonces](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - El algoritmo AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Prohibición de los conjuntos de cifrado RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Pruebas para detectar Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Documentación de PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
