# Ataques contra RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triaje rápido

Recopila:

- `n`, `e`, `c` (y cualquier ciphertext adicional)
- Cualquier relación entre mensajes (¿mismo plaintext? ¿módulo compartido? ¿plaintext estructurado?)
- Cualquier leak (`p/q` parcial, bits de `d`, `dp/dq`, padding conocido)

Después prueba:

- Comprobación de factorización (Factordb / `sage: factor(n)` para valores pequeños)
- Patrones de exponente bajo (`e=3`, broadcast)
- Módulo común / primos repetidos
- Métodos de lattice (Coppersmith/LLL) cuando se conoce casi todo

## Ataques comunes contra RSA

### Módulo común

Si dos ciphertexts `c1, c2` cifran el **mismo mensaje** bajo el **mismo módulo** `n`, pero con exponentes diferentes `e1, e2` (y `gcd(e1,e2)=1`), puedes recuperar `m` usando el algoritmo de Euclides extendido:

`m = c1^a * c2^b mod n` donde `a*e1 + b*e2 = 1`.

Esquema del ejemplo:

1. Calcula `(a, b) = xgcd(e1, e2)` para que `a*e1 + b*e2 = 1`
2. Si `a < 0`, interpreta `c1^a` como `inv(c1)^{-a} mod n` (igual para `b`)
3. Multiplica y reduce módulo `n`

### Primos compartidos entre módulos

Si tienes varios módulos RSA del mismo challenge, comprueba si comparten un primo:

- `gcd(n1, n2) != 1` implica un fallo catastrófico en la generación de claves.

Esto aparece con frecuencia en CTFs como "generamos muchas claves rápidamente" o "mala aleatoriedad".

### Módulos sparse / short-sleeve

Algunos generadores de enteros grandes defectuosos filtran directamente una estructura en el módulo público: cada limb contiene solo un pequeño subcampo aleatorio y el resto de los bits son `0`. En la práctica, esto aparece como **bloques de ceros espaciados regularmente** a lo largo de `n`, normalmente alineados con limbs de 32 o 128 bits.<sup>[[1]](#references)</sup>

Comprobaciones rápidas:

- Muestra `n` en hexadecimal y busca ventanas de ceros repetidas con un stride fijo.
- Vuelve a dividir `n` en limbs (`2^32`, `2^64`, `2^128`) e inspecciona si cada limb es inusualmente pequeño.
- Audita claves públicas SSH/TLS con herramientas como **badkeys** cuando sospeches de una generación débil de host keys.<sup>[[2]](#references)[[3]](#references)</sup>

Esto es más grave que un sesgo estadístico: si ambos factores privados `p` y `q` tienen short-sleeves, el módulo puede resultar **fácil de factorizar**.<sup>[[1]](#references)</sup>

### Factorización polinómica de claves RSA estructuradas

Para un ancho de limb sospechado `w`, escribe el módulo en base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Como la evaluación es multiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Si los factores también tienen coeficientes de limb sparse, entonces:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Esquema del ataque:

1. Adivina el ancho del limb `w`.
2. Convierte el módulo público `n` en `f_n(x)` usando la base `2^w`.
3. Factoriza `f_n(x)` sobre los enteros.
4. Evalúa los factores candidatos de nuevo en `B = 2^w`.
5. Verifica qué candidatos multiplican hasta dar `n`.

Esto **no rompe RSA normal**. Solo funciona cuando los factores primos tienen coeficientes de limb muy pequeños y altamente estructurados.<sup>[[1]](#references)</sup>

### Filtración de limbs desplazados

Los bytes sparse no siempre están alineados en el extremo inferior de cada limb. Si la conversión directa en base `2^w` produce coeficientes grandes, busca desplazamientos `i,j` tales que `2^i p` y `2^j q` se vuelvan sparse en esa base de limbs. El polinomio del producto todavía puede derivarse a partir del módulo público, factorizarse y recombinarse en los factores enteros originales.<sup>[[1]](#references)</sup>

### Indicador de una implementación defectuosa: bug del RNG de byte a limb

Un patrón peligroso consiste en calcular el número de **limbs de 32 bits**, asignar únicamente esa cantidad de **bytes** y copiarlos en el array de limbs:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Esto da a cada limb de 32 bits solo **8 bits de entropía**, además de un bit superior forzado en el último limb. Los primos RSA resultantes a menudo pueden reconocerse y factorizarse únicamente a partir de la clave pública.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Si la misma rutina defectuosa de big-integer se reutiliza para generar el exponente privado de DSA, la clave pública `y = g^x` puede filtrar un espacio de búsqueda **drásticamente reducido y estructurado** para `x`. Una vez conocido el patrón de los limbs, los ataques de discrete-log, como **baby-step giant-step**, pueden resultar prácticos contra los parámetros públicos.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Si el mismo plaintext se envía a múltiples destinatarios con un `e` pequeño (a menudo `e=3`) y sin un padding adecuado, puedes recuperar `m` mediante CRT y una raíz entera.

Condición técnica:

Si tienes `e` ciphertexts del mismo mensaje bajo moduli `n_i` pairwise-coprime:

- Usa CRT para recuperar `M = m^e` sobre el producto `N = Π n_i`
- Si `m^e < N`, entonces `M` es la potencia entera verdadera, y `m = integer_root(M, e)`

### Wiener attack: small private exponent

Si `d` es demasiado pequeño, las fracciones continuas pueden recuperarlo a partir de `e/n`.

### Textbook RSA pitfalls

Si ves:

- Sin OAEP/PSS, raw modular exponentiation
- Cifrado determinista

entonces los ataques algebraicos y el abuso de oracles se vuelven mucho más probables.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Si ves dos ciphertexts bajo el mismo modulus con mensajes que están relacionados algebraicamente (por ejemplo, `m2 = a*m1 + b`), busca ataques de "related-message", como Franklin–Reiter. Normalmente requieren:

- mismo modulus `n`
- mismo exponent `e`
- relación conocida entre los plaintexts

En la práctica, esto suele resolverse con Sage configurando polinomios módulo `n` y calculando un GCD.

## Lattices / Coppersmith

Recurre a esto cuando tengas bits parciales, plaintext estructurado o relaciones cercanas que hagan que el valor desconocido sea pequeño.

Los métodos de lattice (LLL/Coppersmith) aparecen siempre que tienes información parcial:

- Plaintext parcialmente conocido (mensaje estructurado con un tail desconocido)
- `p`/`q` parcialmente conocidos (high bits filtrados)
- Diferencias desconocidas pequeñas entre valores relacionados

### What to recognize

Indicadores típicos en challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

En la práctica usarás Sage para LLL y un template conocido para la instancia específica.

Buenos puntos de partida:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
