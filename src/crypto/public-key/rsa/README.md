# Ataques RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triaje rápido

Recopilar:

- `n`, `e`, `c` (y cualquier ciphertext adicional)
- Cualquier relación entre mensajes (same plaintext? shared modulus? structured plaintext?)
- Cualquier leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Luego intenta:

- Comprobación de factorización (Factordb / `sage: factor(n)` para casos pequeños)
- Patrones de exponente bajo (`e=3`, broadcast)
- Módulo común / primos repetidos
- Métodos de lattice (Coppersmith/LLL) cuando algo está casi conocido

## Ataques RSA comunes

### Módulo común

Si dos ciphertexts `c1, c2` cifran el **mismo mensaje** bajo el **mismo modulus** `n` pero con exponentes diferentes `e1, e2` (y `gcd(e1,e2)=1`), puedes recuperar `m` usando el algoritmo extendido de Euclides:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Esquema de ejemplo:

1. Compute `(a, b) = xgcd(e1, e2)` so `a*e1 + b*e2 = 1`
2. Si `a < 0`, interpreta `c1^a` como `inv(c1)^{-a} mod n` (lo mismo para `b`)
3. Multiplica y reduce módulo `n`

### Primos compartidos entre módulos

Si tienes múltiples módulos RSA del mismo reto, verifica si comparten un primo:

- `gcd(n1, n2) != 1` implica un fallo catastrófico en la generación de claves.

Esto aparece frecuentemente en CTFs como "we generated many keys quickly" o "bad randomness".

### Håstad broadcast / exponente bajo

Si el mismo plaintext se envía a múltiples destinatarios con `e` pequeño (a menudo `e=3`) y sin padding adecuado, puedes recuperar `m` mediante CRT y raíz entera.

Condición técnica:

Si tienes `e` ciphertexts del mismo mensaje bajo módulos coprimos por pares `n_i`:

- Usa CRT para recuperar `M = m^e` sobre el producto `N = Π n_i`
- Si `m^e < N`, entonces `M` es la potencia entera real, y `m = integer_root(M, e)`

### Ataque de Wiener: exponente privado pequeño

Si `d` es demasiado pequeño, las fracciones continuas pueden recuperarlo a partir de `e/n`.

### Peligros del Textbook RSA

Si ves:

- Sin OAEP/PSS, exponentiación modular sin procesar
- Cifrado determinista

entonces los ataques algebraicos y el abuso de oráculos se vuelven mucho más probables.

### Herramientas

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Patrones de mensajes relacionados

Si ves dos ciphertexts bajo el mismo modulus con mensajes que están algebraicamente relacionados (p. ej., `m2 = a*m1 + b`), busca ataques "related-message" como Franklin–Reiter. Estos típicamente requieren:

- mismo modulus `n`
- mismo exponente `e`
- relación conocida entre plaintexts

En la práctica esto suele resolverse con Sage configurando polinomios modulo `n` y calculando un GCD.

## Lattices / Coppersmith

Recurre a esto cuando tengas bits parciales, plaintext estructurado o relaciones cercanas que hagan que lo desconocido sea pequeño.

Los métodos de lattice (LLL/Coppersmith) aparecen siempre que tengas información parcial:

- Plaintext parcialmente conocido (mensaje estructurado con sufijo desconocido)
- `p`/`q` parcialmente conocido (leaked high bits)
- Pequeñas diferencias desconocidas entre valores relacionados

### Qué reconocer

Indicadores típicos en retos:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Herramientas

En la práctica usarás Sage para LLL y una plantilla conocida para el caso específico.

Buenos puntos de partida:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
