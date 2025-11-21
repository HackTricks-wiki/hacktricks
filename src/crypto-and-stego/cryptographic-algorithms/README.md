# Algoritmos Criptográficos/Compresión

{{#include ../../banners/hacktricks-training.md}}

## Identificando Algoritmos

Si terminas en un código **using shift rights and lefts, xors and several arithmetic operations** es muy probable que sea la implementación de un **algoritmo criptográfico**. Aquí se van a mostrar algunas formas de **identificar el algoritmo que se usa sin necesidad de revertir cada paso**.

### API functions

**CryptDeriveKey**

Si esta función se usa, puedes encontrar qué **algorithm is being used** comprobando el valor del segundo parámetro:

![](<../../images/image (156).png>)

Consulta aquí la tabla de posibles algoritmos y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprimen y descomprimen un buffer de datos dado.

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Inicia el hashing de un stream de datos. Si esta función se usa, puedes encontrar qué **algorithm is being used** comprobando el valor del segundo parámetro:

![](<../../images/image (549).png>)

\
Consulta aquí la tabla de posibles algoritmos y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

A veces es muy fácil identificar un algoritmo gracias a que necesita usar un valor especial y único.

![](<../../images/image (833).png>)

Si buscas la primera constante en Google esto es lo que obtienes:

![](<../../images/image (529).png>)

Por lo tanto, puedes asumir que la función decompilada es un **sha256 calculator.**\
Puedes buscar cualquiera de las otras constantes y obtendrás (probablemente) el mismo resultado.

### data info

Si el código no tiene ninguna constante significativa puede que esté **cargando información desde la sección .data**.\
Puedes acceder a esos datos, **agrupar el primer dword** y buscarlo en Google como hicimos en la sección anterior:

![](<../../images/image (531).png>)

En este caso, si buscas **0xA56363C6** puedes encontrar que está relacionado con las **tablas del algoritmo AES**.

## RC4 **(Criptografía simétrica)**

### Characteristics

Está compuesto por 3 partes principales:

- **Initialization stage/**: Crea una **tabla de valores desde 0x00 a 0xFF** (256 bytes en total, 0x100). Esta tabla comúnmente se llama **Substitution Box** (o SBox).
- **Scrambling stage**: Hará un **loop through the table** creado antes (loop de 0x100 iteraciones, otra vez) modificando cada valor con bytes **semi-random**. Para crear estos bytes semi-random se usa la **key** de RC4. Las RC4 **keys** pueden tener **entre 1 y 256 bytes de longitud**, sin embargo normalmente se recomienda que sean más de 5 bytes. Comúnmente, las RC4 keys son de 16 bytes de longitud.
- **XOR stage**: Finalmente, el plain-text o cyphertext se **XORed con los valores creados antes**. La función para encriptar y desencriptar es la misma. Para esto, se hará un **loop through the created 256 bytes** tantas veces como sea necesario. Esto usualmente se reconoce en un código decompilado con un **%256 (mod 256)**.

> [!TIP]
> **Para identificar un RC4 en un disassembly/decompiled code puedes buscar 2 loops de tamaño 0x100 (con el uso de una key) y luego un XOR del input data con los 256 valores creados antes en los 2 loops, probablemente usando un %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Fíjate en el número 256 usado como contador y cómo se escribe un 0 en cada posición de los 256 chars)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Criptografía simétrica)**

### **Characteristics**

- Uso de **substitution boxes and lookup tables**
- Es posible **distinguir AES gracias al uso de valores específicos en lookup tables** (constantes). _Ten en cuenta que la **constant** puede estar **almacenada** en el binario **o creada**_ _**dinámicamente**._
- La **encryption key** debe ser **divisible** por **16** (usualmente 32B) y normalmente se usa un **IV** de 16B.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Criptografía simétrica)**

### Characteristics

- Es raro encontrar malware que lo use pero hay ejemplos (Ursnif)
- Es sencillo determinar si un algoritmo es Serpent o no basándose en su longitud (función extremadamente larga)

### Identifying

En la imagen siguiente fíjate cómo la constante **0x9E3779B9** es usada (nota que esta constante también la usan otros algoritmos cripto como **TEA** -Tiny Encryption Algorithm).\
También observa el **tamaño del loop** (**132**) y el **número de operaciones XOR** en las instrucciones del **disassembly** y en el ejemplo de **código**:

![](<../../images/image (547).png>)

Como se mencionó antes, este código puede visualizarse dentro de cualquier decompilador como una **función muy larga** ya que **no hay jumps** dentro de ella. El código decompilado puede parecerse a lo siguiente:

![](<../../images/image (513).png>)

Por lo tanto, es posible identificar este algoritmo comprobando el **magic number** y los **XORs iniciales**, viendo una **función muy larga** y **comparando** algunas **instrucciones** de la función larga **con una implementación** (como el shift left by 7 y el rotate left by 22).

## RSA **(Criptografía asimétrica)**

### Characteristics

- Más complejo que los algoritmos simétricos
- ¡No hay constantes! (implementaciones custom son difíciles de determinar)
- KANAL (a crypto analyzer) falla en mostrar pistas sobre RSA ya que depende de constantes.

### Identifying by comparisons

![](<../../images/image (1113).png>)

- En la línea 11 (izquierda) hay un `+7) >> 3` que es lo mismo que en la línea 35 (derecha): `+7) / 8`
- La línea 12 (izquierda) está comprobando si `modulus_len < 0x040` y en la línea 36 (derecha) está comprobando si `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Characteristics

- 3 funciones: Init, Update, Final
- Funciones de inicialización similares

### Identify

**Init**

Puedes identificar ambos comprobando las constantes. Ten en cuenta que sha_init tiene 1 constante que MD5 no tiene:

![](<../../images/image (406).png>)

**MD5 Transform**

Fíjate en el uso de más constantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Más pequeño y más eficiente ya que su función es encontrar cambios accidentales en los datos
- Usa lookup tables (por lo que puedes identificar constantes)

### Identify

Comprueba las **lookup table constants**:

![](<../../images/image (508).png>)

Un algoritmo de hash CRC se ve así:

![](<../../images/image (391).png>)

## APLib (Compresión)

### Characteristics

- No tiene constantes reconocibles
- Puedes intentar escribir el algoritmo en python y buscar cosas similares en línea

### Identify

El grafo es bastante grande:

![](<../../images/image (207) (2) (1).png>)

Comprueba **3 comparisons para reconocerlo**:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 requires HashEdDSA verifiers to split a signature `sig = R || s` and reject any scalar with `s \geq n`, where `n` is the group order. The `elliptic` JS library skipped that bound check, so any attacker that knows a valid pair `(msg, R || s)` can forge alternate signatures `s' = s + k·n` and keep re-encoding `sig' = R || s'`.
- The verification routines only consume `s mod n`, therefore all `s'` congruent to `s` are accepted even though they are different byte strings. Systems treating signatures as canonical tokens (blockchain consensus, replay caches, DB keys, etc.) can be desynchronized because strict implementations will reject `s'`.
- When auditing other HashEdDSA code, ensure the parser validates both the point `R` and the scalar length; try appending multiples of `n` to a known-good `s` to confirm the verifier fails closed.

### ECDSA truncation vs. leading-zero hashes

- ECDSA verifiers must use only the leftmost `log2(n)` bits of the message hash `H`. In `elliptic`, the truncation helper computed `delta = (BN(msg).byteLength()*8) - bitlen(n)`; the `BN` constructor drops leading zero octets, so any hash that begins with ≥4 zero bytes on curves like secp192r1 (192-bit order) appeared to be only 224 bits instead of 256.
- The verifier right-shifted by 32 bits instead of 64, producing an `E` that does not match the value used by the signer. Valid signatures on those hashes therefore fail with probability ≈`2^-32` for SHA-256 inputs.
- Feed both the “all good” vector and leading-zero variants (e.g., Wycheproof `ecdsa_secp192r1_sha256_test.json` case `tc296`) to a target implementation; if the verifier disagrees with the signer, you found an exploitable truncation bug.

### Exercising Wycheproof vectors against libraries
- Wycheproof ships JSON test sets that encode malformed points, malleable scalars, unusual hashes and other corner cases. Building a harness around `elliptic` (or any crypto library) is straightforward: load the JSON, deserialize each test case, and assert that the implementation matches the expected `result` flag.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Las fallas deben ser triadas para distinguir violaciones de la spec de falsos positivos. Para los dos bugs anteriores, los casos fallidos de Wycheproof señalaron de inmediato la falta de comprobaciones de rango de scalar (EdDSA) y un truncamiento de hash incorrecto (ECDSA).
- Integra el harness en CI para que las regresiones en scalar parsing, hash handling, o la validez de coordenadas activen pruebas tan pronto como se introduzcan. Esto es especialmente útil para lenguajes de alto nivel (JS, Python, Go) donde las conversiones sutiles de bignum son fáciles de equivocarse.

## Referencias

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
