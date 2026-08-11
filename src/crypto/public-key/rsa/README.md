# Ataques RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triage rápido

Recopila:

- `n`, `e`, `c` (y cualquier ciphertext adicional)
- Cualquier relación entre mensajes (¿mismo plaintext? ¿modulus compartido? ¿plaintext estructurado?)
- Cualquier leak (parte de `p/q`, bits de `d`, `dp/dq`, padding conocido)

Después prueba:

- Comprobación de factorización (Factordb / `sage: factor(n)` para valores relativamente pequeños)
- Patrones de exponente bajo (`e=3`, broadcast)
- Common modulus / repeated primes
- Métodos de lattice (Coppersmith/LLL) cuando algo es casi conocido

## Ataques RSA comunes

### Common modulus

Si dos ciphertexts `c1, c2` cifran el **mismo mensaje** bajo el **mismo modulus** `n`, pero con exponentes diferentes `e1, e2` (y `gcd(e1,e2)=1`), puedes recuperar `m` usando el algoritmo euclídeo extendido:

`m = c1^a * c2^b mod n` donde `a*e1 + b*e2 = 1`.

Esquema del procedimiento:

1. Calcula `(a, b) = xgcd(e1, e2)` para que `a*e1 + b*e2 = 1`
2. Si `a < 0`, interpreta `c1^a` como `inv(c1)^{-a} mod n` (igual para `b`)
3. Multiplica y reduce módulo `n`

### Shared primes across moduli

Si tienes varios RSA moduli del mismo challenge, comprueba si comparten un primo:

- `gcd(n1, n2) != 1` implica un fallo catastrófico en la generación de claves.

Esto aparece con frecuencia en CTFs como "generamos muchas claves rápidamente" o "mala aleatoriedad".

### Sparse / short-sleeve moduli

Algunos generadores de enteros grandes defectuosos filtran directamente estructura en el modulus público: cada limb contiene solo un pequeño subcampo aleatorio y el resto de los bits son `0`. En la práctica, esto aparece como **bloques de ceros espaciados regularmente** a lo largo de `n`, normalmente alineados con limbs de 32 o 128 bits.<sup>[[1]](#references)</sup>

Comprobaciones rápidas:

- Muestra `n` en hexadecimal y busca ventanas de ceros repetidas con un stride fijo.
- Divide de nuevo `n` en limbs (`2^32`, `2^64`, `2^128`) e inspecciona si cada limb es inusualmente pequeño.
- Audita claves públicas SSH/TLS con herramientas como **badkeys** cuando sospeches de una generación débil de host keys.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Esto es más grave que un sesgo estadístico: si ambos factores privados `p` y `q` tienen short sleeves, el modulus puede resultar **fácil de factorizar**.<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

Para un width de limb sospechoso `w`, escribe el modulus en base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Como la evaluación es multiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Si los factores también tienen coeficientes de limb dispersos, entonces:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Esquema del ataque:

1. Adivina el width del limb `w`.
2. Convierte el modulus público `n` en `f_n(x)` usando la base `2^w`.
3. Factoriza `f_n(x)` sobre los enteros.
4. Evalúa de nuevo los factores candidatos en `B = 2^w`.
5. Verifica qué candidatos multiplican hasta obtener `n`.

Esto **no rompe el RSA normal**. Solo funciona cuando los factores primos tienen coeficientes de limb muy pequeños y altamente estructurados.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Los bytes dispersos no siempre están alineados en el extremo inferior de cada limb. Si la conversión directa en base `2^w` produce coeficientes grandes, busca shifts `i,j` tales que `2^i p` y `2^j q` se vuelvan dispersos en esa base de limbs. El polinomio del producto aún puede derivarse del modulus público, factorizarse y recombinarse en los factores enteros originales.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Un patrón peligroso consiste en calcular el número de **limbs de 32 bits**, reservar solo esa cantidad de **bytes** y copiarlos en el array de limbs:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Esto da a cada limb de 32 bits solo **8 bits de entropía**, además de un bit superior forzado en el último limb. Los primos RSA resultantes a menudo pueden reconocerse y factorizarse únicamente a partir de la clave pública.<sup>[[1]](#references)</sup>

### Modo de fallo relacionado de DSA

Si la misma rutina defectuosa de big-integer se reutiliza para generar el exponente privado de DSA, la clave pública `y = g^x` puede leakear un espacio de búsqueda para `x` **drásticamente reducido y estructurado**. Una vez conocido el patrón de los limbs, los ataques de logaritmo discreto, como **baby-step giant-step**, pueden volverse prácticos contra los parámetros públicos.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Si el mismo plaintext se envía a múltiples destinatarios con un `e` pequeño (a menudo `e=3`) y sin padding adecuado, puedes recuperar `m` mediante CRT y una raíz entera.

Condición técnica:

Si tienes `e` ciphertexts del mismo mensaje bajo módulos `n_i` coprimos por pares:

- Usa CRT para recuperar `M = m^e` sobre el producto `N = Π n_i`
- Si `m^e < N`, entonces `M` es la potencia entera verdadera, y `m = integer_root(M, e)`

### Wiener attack: exponente privado pequeño

Si `d` es demasiado pequeño, las fracciones continuas pueden recuperarlo a partir de `e/n`.

### Errores del RSA de libro de texto

Si ves:

- Sin OAEP/PSS, exponenciación modular sin formato
- Encriptación determinista

entonces los ataques algebraicos y el abuso de oráculos se vuelven mucho más probables.

### Herramientas

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, raíces, CF): https://www.sagemath.org/

## Patrones de mensajes relacionados

Si ves dos ciphertexts bajo el mismo módulo con mensajes relacionados algebraicamente (por ejemplo, `m2 = a*m1 + b`), busca ataques de "related-message", como Franklin–Reiter. Normalmente requieren:

- mismo módulo `n`
- mismo exponente `e`
- relación conocida entre los plaintexts

En la práctica, esto suele resolverse con Sage configurando polinomios módulo `n` y calculando un GCD.

## Retículas / Coppersmith

Recurre a esto cuando tengas bits parciales, un plaintext estructurado o relaciones cercanas que hagan que el valor desconocido sea pequeño.

Los métodos de retículas (LLL/Coppersmith) aparecen siempre que tienes información parcial:

- Plaintext parcialmente conocido (mensaje estructurado con una cola desconocida)
- `p`/`q` parcialmente conocidos (bits superiores leaked)
- Diferencias desconocidas pequeñas entre valores relacionados

### Qué reconocer

Pistas típicas en los challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Herramientas

En la práctica usarás Sage para LLL y una plantilla conocida para la instancia específica.

Buenos puntos de partida:

- Plantillas de criptografía CTF para Sage: https://github.com/defund/coppersmith
- Una referencia tipo survey: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factorización de claves RSA "short-sleeve" con polinomios](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [Herramienta independiente de badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
