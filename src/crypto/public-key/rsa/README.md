# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Recopila:

- `n`, `e`, `c` (y cualquier ciphertext adicional)
- Cualquier relación entre mensajes (¿same plaintext? ¿shared modulus? ¿structured plaintext?)
- Cualquier leak (partial `p/q`, bits de `d`, `dp/dq`, known padding)

Luego prueba:

- Factorization check (Factordb / `sage: factor(n)` para casos pequeños)
- Patrones de low exponent (`e=3`, broadcast)
- Common modulus / repeated primes
- Métodos de lattice (Coppersmith/LLL) cuando algo es casi conocido

## Common RSA attacks

### Common modulus

Si dos ciphertexts `c1, c2` cifran el **mismo mensaje** bajo el **mismo modulus** `n` pero con exponentes distintos `e1, e2` (y `gcd(e1,e2)=1`), puedes recuperar `m` usando el algoritmo extendido de Euclides:

`m = c1^a * c2^b mod n` donde `a*e1 + b*e2 = 1`.

Esquema de ejemplo:

1. Calcula `(a, b) = xgcd(e1, e2)` para que `a*e1 + b*e2 = 1`
2. Si `a < 0`, interpreta `c1^a` como `inv(c1)^{-a} mod n` (igual para `b`)
3. Multiplica y reduce módulo `n`

### Shared primes across moduli

Si tienes varios RSA moduli del mismo challenge, comprueba si comparten un prime:

- `gcd(n1, n2) != 1` implica un fallo catastrófico en la generación de claves.

Esto aparece con frecuencia en CTFs como "generamos muchas claves rápido" o "bad randomness".

### Sparse / short-sleeve moduli

Algunos generadores rotos de big-integer filtran estructura directamente al public modulus: cada limb contiene solo un pequeño subcampo aleatorio y el resto de los bits son `0`. En la práctica esto aparece como **regularly spaced zero blocks** a lo largo de `n`, a menudo alineados a limbs de 32 bits o 128 bits.

Comprobaciones rápidas:

- Saca `n` en hex y busca ventanas de ceros repetidas con un stride fijo.
- Re-slice `n` como limbs (`2^32`, `2^64`, `2^128`) e inspecciona si cada limb es inusualmente pequeño.
- Audita public SSH/TLS keys con herramientas como **badkeys** cuando sospeches weak host-key generation.

Esto es más grave que un sesgo estadístico: si ambos factores privados `p` y `q` son short-sleeved, el modulus puede volverse **easy to factor**.

### Polynomial factorization of structured RSA keys

Para un ancho de limb sospechoso `w`, escribe el modulus en base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Como la evaluación es multiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Si los factores también tienen sparse limb coefficients, entonces:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Esquema de ataque:

1. Adivina el ancho de limb `w`.
2. Convierte el public modulus `n` en `f_n(x)` usando base `2^w`.
3. Factoriza `f_n(x)` sobre los enteros.
4. Evalúa los factores candidatos de vuelta en `B = 2^w`.
5. Verifica qué candidatos multiplican `n`.

Esto **no rompe normal RSA**. Solo funciona cuando los factores primos en sí tienen coeficientes de limb muy pequeños y altamente estructurados.

### Shifted limb leakage

Los sparse bytes no siempre están alineados en el extremo inferior de cada limb. Si la conversión directa a base `2^w` produce coeficientes grandes, busca shifts `i,j` tales que `2^i p` y `2^j q` se vuelvan sparse en esa base de limbs. El polinomio del producto todavía puede derivarse del public modulus, factorizarse y recombinarse en los factores enteros originales.

### Implementation smell: byte-to-limb RNG bug

Un patrón peligroso es calcular el número de **32-bit limbs**, reservar solo esa cantidad de **bytes**, y copiarlos al array de limbs:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Esto le da a cada limb de 32 bits solo **8 bits de entropía** más un bit superior forzado en el último limb. Los primos RSA resultantes a menudo pueden reconocerse y factorizarse solo a partir de la public key.

### Related DSA failure mode

Si la misma rutina rota de big-integer se reutiliza para la generación del private exponent de DSA, la public key `y = g^x` puede filtrar un espacio de búsqueda **drásticamente reducido y estructurado** para `x`. Una vez que se conoce el patrón de los limbs, ataques de discrete-log como **baby-step giant-step** pueden volverse prácticos contra los public parameters.

### Håstad broadcast / low exponent

Si el mismo plaintext se envía a múltiples recipients con `e` pequeño (a menudo `e=3`) y sin padding adecuado, puedes recuperar `m` mediante CRT y integer root.

Technical condition:

Si tienes `e` ciphertexts del mismo mensaje bajo moduli `n_i` coprimos por pares:

- Usa CRT para recuperar `M = m^e` sobre el producto `N = Π n_i`
- Si `m^e < N`, entonces `M` es la verdadera potencia entera, y `m = integer_root(M, e)`

### Wiener attack: small private exponent

Si `d` es demasiado pequeño, continued fractions pueden recuperarlo a partir de `e/n`.

### Textbook RSA pitfalls

Si ves:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

entonces los algebraic attacks y el abuso de oracle se vuelven mucho más probables.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Si ves dos ciphertexts bajo el mismo modulus con messages que están relacionados algebraicamente (por ejemplo, `m2 = a*m1 + b`), busca ataques "related-message" como Franklin–Reiter. Normalmente requieren:

- same modulus `n`
- same exponent `e`
- known relationship between plaintexts

En la práctica esto suele resolverse con Sage configurando polynomials módulo `n` y calculando un GCD.

## Lattices / Coppersmith

Úsalo cuando tengas partial bits, structured plaintext, o relaciones cercanas que hagan pequeño lo desconocido.

Los lattice methods (LLL/Coppersmith) aparecen siempre que tienes partial information:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences between related values

### What to recognize

Pistas típicas en challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

En la práctica usarás Sage para LLL y una plantilla conocida para la instancia específica.

Buenos puntos de partida:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
