# Algoritmos Criptográficos/Compresión

{{#include ../../banners/hacktricks-training.md}}

## Identificando Algoritmos

If you ends in a code **using shift rights and lefts, xors and several arithmetic operations** it's highly possible that it's the implementation of a **cryptographic algorithm**. Aquí se mostrarán algunas formas de **identificar el algoritmo que se está usando sin necesidad de revertir cada paso**.

### Funciones API

**CryptDeriveKey**

If this function is used, you can find which **algorithm is being used** checking the value of the second parameter:

![](<../../images/image (156).png>)

Check here the table of possible algorithms and their assigned values: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime y descomprime un buffer de datos dado.

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Inicia el hashing de un stream de datos. If this function is used, you can find which **algorithm is being used** checking the value of the second parameter:

![](<../../images/image (549).png>)

\
Check here the table of possible algorithms and their assigned values: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes en el código

A veces es muy fácil identificar un algoritmo gracias a que necesita usar un valor especial y único.

![](<../../images/image (833).png>)

If you search for the first constant in Google this is what you get:

![](<../../images/image (529).png>)

Therefore, you can assume that the decompiled function is a **sha256 calculator.**\
Puedes buscar cualquiera de las otras constantes y probablemente obtendrás el mismo resultado.

### Información de datos

If the code doesn't have any significant constant it may be **loading information from the .data section**.\
Puedes acceder a esos datos, **agrupar el primer dword** y buscarlo en Google como hicimos en la sección anterior:

![](<../../images/image (531).png>)

En este caso, si buscas **0xA56363C6** puedes encontrar que está relacionado con las **tablas del algoritmo AES**.

## RC4 **(Criptografía Simétrica)**

### Características

Está compuesto por 3 partes principales:

- **Initialization stage/**: Crea una **tabla de valores desde 0x00 hasta 0xFF** (256 bytes en total, 0x100). Esta tabla comúnmente se llama **Substitution Box** (o SBox).
- **Scrambling stage**: Recorre la **tabla creada antes** (bucle de 0x100 iteraciones, de nuevo) modificando cada valor con bytes **semi-aleatorios**. Para crear estos bytes semi-aleatorios se usa la **key** de RC4. Las RC4 **keys** pueden tener **entre 1 y 256 bytes de longitud**, sin embargo normalmente se recomienda que sean mayores a 5 bytes. Comúnmente, las RC4 keys tienen 16 bytes de longitud.
- **XOR stage**: Finalmente, el plain-text o cyphertext se **XORea con los valores creados antes**. La función para encriptar y desencriptar es la misma. Para ello se realiza un **bucle sobre los 256 bytes creados** tantas veces como sea necesario. Esto suele reconocerse en un código decompilado por un **%256 (mod 256)**.

> [!TIP]
> **Para identificar un RC4 en un disassembly/decompiled code puedes comprobar 2 bucles de tamaño 0x100 (con el uso de una key) y luego un XOR de los datos de entrada con los 256 valores creados antes en los 2 bucles, probablemente usando un %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Fíjate en el número 256 usado como contador y cómo se escribe un 0 en cada posición de los 256 chars)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Criptografía Simétrica)**

### **Características**

- Uso de cajas de sustitución y tablas de búsqueda (substitution boxes and lookup tables)
- Es posible **distinguir AES gracias al uso de valores específicos en tablas de búsqueda** (constantes). _Nota que la **constante** puede estar **almacenada** en el binario **o creada**_ _**dinámicamente**._
- La **encryption key** debe ser **divisible** por **16** (usualmente 32B) y normalmente se usa un **IV** de 16B.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Criptografía Simétrica)**

### Características

- Es raro encontrar malware que lo use, pero hay ejemplos (Ursnif)
- Fácil de determinar si un algoritmo es Serpent o no basándose en su longitud (función extremadamente larga)

### Identificación

En la imagen siguiente observa cómo se usa la constante **0x9E3779B9** (nota que esta constante también es usada por otros algoritmos como **TEA** - Tiny Encryption Algorithm).\
Fíjate también en el **tamaño del bucle** (**132**) y en el **número de operaciones XOR** en las instrucciones del **disassembly** y en el **ejemplo de código**:

![](<../../images/image (547).png>)

Como se mencionó antes, este código puede visualizarse en cualquier decompiler como una **función muy larga** ya que **no hay saltos** dentro de ella. El código decompilado puede verse así:

![](<../../images/image (513).png>)

Por lo tanto, es posible identificar este algoritmo comprobando el **número mágico** y los **XORs iniciales**, viendo una **función muy larga** y **comparando** algunas **instrucciones** de la función larga **con una implementación** (como el shift left por 7 y el rotate left por 22).

## RSA **(Criptografía Asimétrica)**

### Características

- Más complejo que los algoritmos simétricos
- ¡No hay constantes! (implementaciones custom son difíciles de identificar)
- KANAL (un crypto analyzer) no suele mostrar pistas sobre RSA ya que se basa en constantes.

### Identificación por comparaciones

![](<../../images/image (1113).png>)

- En la línea 11 (izquierda) hay un `+7) >> 3` que es lo mismo que en la línea 35 (derecha): `+7) / 8`
- La línea 12 (izquierda) comprueba si `modulus_len < 0x040` y en la línea 36 (derecha) comprueba si `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Características

- 3 funciones: Init, Update, Final
- Funciones de inicialización similares

### Identificar

**Init**

Puedes identificar ambos comprobando las constantes. Ten en cuenta que sha_init tiene 1 constante que MD5 no tiene:

![](<../../images/image (406).png>)

**MD5 Transform**

Fíjate en el uso de más constantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Más pequeño y más eficiente ya que su función es detectar cambios accidentales en los datos
- Usa tablas de búsqueda (por lo que puedes identificar constantes)

### Identificar

Comprueba las **constantes de las lookup tables**:

![](<../../images/image (508).png>)

Un algoritmo de hash CRC se ve así:

![](<../../images/image (391).png>)

## APLib (Compresión)

### Características

- No tiene constantes reconocibles
- Puedes intentar implementar el algoritmo en python y buscar cosas similares en línea

### Identificar

El grafo es bastante grande:

![](<../../images/image (207) (2) (1).png>)

Revisa **3 comparaciones para reconocerlo**:

![](<../../images/image (430).png>)

## Errores en implementaciones de firmas de curva elíptica

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 requiere que los verificadores de HashEdDSA separen una firma `sig = R || s` y rechacen cualquier escalar con `s \geq n`, donde `n` es el orden del grupo. La librería `elliptic` en JS omitió esa comprobación de límite, por lo que cualquier atacante que conozca un par válido `(msg, R || s)` puede forjar firmas alternativas `s' = s + k·n` y seguir re-codificando `sig' = R || s'`.
- Las rutinas de verificación solo consumen `s mod n`, por lo tanto todos los `s'` congruentes con `s` son aceptados aunque sean diferentes secuencias de bytes. Sistemas que tratan las firmas como tokens canónicos (blockchain consensus, replay caches, DB keys, etc.) pueden desincronizarse porque implementaciones estrictas rechazarán `s'`.
- Al auditar otro código HashEdDSA, asegúrate de que el parser valide tanto el punto `R` como la longitud del escalar; intenta añadir múltiplos de `n` a un `s` conocido-bueno para confirmar que el verificador falla cerrado.

### ECDSA truncation vs. leading-zero hashes

- Los verificadores ECDSA deben usar solo los bits más a la izquierda `log2(n)` del hash del mensaje `H`. En `elliptic`, el helper de truncamiento calculaba `delta = (BN(msg).byteLength()*8) - bitlen(n)`; el constructor `BN` elimina octetos iniciales cero, por lo que cualquier hash que comience con ≥4 bytes cero en curvas como secp192r1 (orden de 192 bits) parecía tener solo 224 bits en lugar de 256.
- El verificador desplazó a la derecha por 32 bits en lugar de 64, produciendo una `E` que no coincide con el valor usado por el firmante. Por tanto, firmas válidas sobre esos hashes fallan con probabilidad ≈`2^-32` para entradas SHA-256.
- Alimenta tanto el vector “todo bien” como variantes con ceros a la izquierda (por ejemplo, Wycheproof `ecdsa_secp192r1_sha256_test.json` caso `tc296`) a una implementación objetivo; si el verificador difiere del firmante, has encontrado un bug de truncamiento explotable.

### Ejercitando vectores Wycheproof contra librerías
- Wycheproof incluye conjuntos de pruebas en JSON que codifican puntos malformados, escalares maleables, hashes inusuales y otros casos límite. Construir un harness alrededor de `elliptic` (o cualquier crypto library) es sencillo: carga el JSON, deserializa cada caso de prueba y asegura que la implementación coincida con la flag `result` esperada.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Las fallas deben clasificarse para distinguir violaciones de la especificación de falsos positivos. Para los dos bugs anteriores, los casos fallidos de Wycheproof indicaron de inmediato comprobaciones faltantes del rango de escalares (EdDSA) y un truncamiento incorrecto del hash (ECDSA).
- Integra el harness en CI para que las regresiones en el parseo de escalares, el manejo de hash o la validez de coordenadas activen tests en cuanto se introduzcan. Esto es especialmente útil para lenguajes de alto nivel (JS, Python, Go) donde las conversiones sutiles de bignum son fáciles de equivocar.

## Referencias

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
