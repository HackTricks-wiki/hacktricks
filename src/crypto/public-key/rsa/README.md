# Ataques RSA

{{#include ../../../banners/hacktricks-training.md}}

## Análisis rápido

Recopila:

- `n`, `e`, `c` (y cualquier ciphertext adicional)
- Cualquier relación entre los mensajes (¿mismo plaintext?, ¿módulo compartido?, ¿plaintext estructurado?)
- Cualquier leak (parte de `p/q`, bits de `d`, `dp/dq`, padding conocido)

Después, prueba:

- Comprobar la factorización (Factordb / `sage: factor(n)` para valores relativamente pequeños)
- Patrones de exponente bajo (`e=3`, broadcast)
- Módulo común / primos repetidos
- Métodos de lattice (Coppersmith/LLL) cuando se conoce casi toda la información

## Ataques RSA comunes

### Common modulus

Si dos ciphertexts `c1, c2` cifran el **mismo mensaje** con el **mismo módulo** `n`, pero con exponentes diferentes `e1, e2` (y `gcd(e1,e2)=1`), puedes recuperar `m` mediante el algoritmo de Euclides extendido:

`m = c1^a * c2^b mod n` donde `a*e1 + b*e2 = 1`.

Esquema del ejemplo:

1. Calcula `(a, b) = xgcd(e1, e2)` para que `a*e1 + b*e2 = 1`
2. Si `a < 0`, interpreta `c1^a` como `inv(c1)^{-a} mod n` (lo mismo para `b`)
3. Multiplica y reduce módulo `n`

### Primos compartidos entre módulos

Si tienes varios módulos RSA del mismo challenge, comprueba si comparten un primo:

- `gcd(n1, n2) != 1` implica un fallo catastrófico en la generación de claves.

Esto aparece con frecuencia en CTFs con frases como «generamos muchas claves rápidamente» o «mala aleatoriedad».

### Moduli sparse / short-sleeve

Algunos generadores de enteros grandes defectuosos filtran directamente su estructura al módulo público: cada limb contiene solo un pequeño subcampo aleatorio, y el resto de los bits son `0`. En la práctica, esto aparece como **bloques de ceros espaciados regularmente** a lo largo de `n`, a menudo alineados con limbs de 32 o 128 bits.<sup>[[1]](#references)</sup>

Comprobaciones rápidas:

- Muestra `n` en hexadecimal y busca ventanas de ceros repetidas con un intervalo fijo.
- Vuelve a dividir `n` en limbs (`2^32`, `2^64`, `2^128`) e inspecciona si cada limb es inusualmente pequeño.
- Audita claves públicas SSH/TLS con herramientas como **badkeys** cuando sospeches que la generación de host keys es débil.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Esto es más grave que un sesgo estadístico: si ambos factores privados `p` y `q` tienen short-sleeve, el módulo puede ser **fácil de factorizar**.<sup>[[1]](#references)</sup>

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
5. Verifica qué candidatos multiplicados dan `n`.

Esto **no rompe RSA normal**. Solo funciona cuando los factores primos tienen coeficientes de limb muy pequeños y altamente estructurados.<sup>[[1]](#references)</sup>

### Leak de limbs desplazados

Los bytes sparse no siempre están alineados en el extremo inferior de cada limb. Si la conversión directa a base `2^w` produce coeficientes grandes, busca desplazamientos `i,j` tales que `2^i p` y `2^j q` se vuelvan sparse en esa base de limbs. Aun así, el polinomio del producto puede derivarse del módulo público, factorizarse y recombinarse para obtener los factores enteros originales.<sup>[[1]](#references)</sup>

### Señal de una implementación defectuosa: bug del RNG de byte a limb

Un patrón peligroso consiste en calcular el número de limbs de **32 bits**, asignar solo esa cantidad de **bytes** y copiarlos en el array de limbs:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

This gives each limb de 32 bits solo **8 bits de entropía** más un bit superior forzado en el último limb. Los primos RSA resultantes a menudo pueden reconocerse y factorizarse usando solo la clave pública.<sup>[[1]](#references)</sup>

### Modo de fallo relacionado con DSA

Si se reutiliza la misma rutina defectuosa para números enteros grandes al generar el exponente privado de DSA, la clave pública `y = g^x` puede filtrar un espacio de búsqueda para `x` **drásticamente reducido y estructurado**. Una vez conocido el patrón de los limbs, los ataques de logaritmo discreto, como **baby-step giant-step**, pueden ser prácticos contra los parámetros públicos.<sup>[[1]](#references)</sup>

### Ataque de difusión de Håstad / exponente pequeño

Si el mismo texto plano se envía a varios destinatarios con un `e` pequeño (a menudo `e=3`) y sin el padding adecuado, puedes recuperar `m` mediante CRT y una raíz entera.

Condición técnica:

Si tienes `e` textos cifrados del mismo mensaje con módulos `n_i` coprimos por pares:

- Usa CRT para recuperar `M = m^e` sobre el producto `N = Π n_i`
- Si `m^e < N`, entonces `M` es la potencia entera verdadera, y `m = integer_root(M, e)`

### Ataque de Wiener: exponente privado pequeño

Si `d` es demasiado pequeño, las fracciones continuas pueden recuperarlo a partir de `e/n`.

### Errores con RSA de libro de texto

Si ves:

- Sin OAEP/PSS, exponenciación modular sin procesar
- Cifrado determinista

entonces los ataques algebraicos y el abuso de oráculos son mucho más probables.

### Herramientas

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, raíces, CF): https://www.sagemath.org/

## Patrones de mensajes relacionados

Si ves dos textos cifrados bajo el mismo módulo con mensajes relacionados algebraicamente (p. ej., `m2 = a*m1 + b`), busca ataques de "related-message", como Franklin–Reiter. Estos suelen requerir:

- el mismo módulo `n`
- el mismo exponente `e`
- una relación conocida entre los textos planos

En la práctica, esto suele resolverse con Sage, definiendo polinomios módulo `n` y calculando un MCD.

## Retículos / Coppersmith

Recurre a esto cuando tengas bits parciales, texto plano estructurado o relaciones cercanas que hagan que el valor desconocido sea pequeño.

Los métodos de retículos (LLL/Coppersmith) aparecen cuando tienes información parcial:

- Texto plano conocido parcialmente (mensaje estructurado con una cola desconocida)
- `p`/`q` conocidos parcialmente (se han filtrado los bits más significativos)
- Diferencias desconocidas pequeñas entre valores relacionados

### Qué reconocer

Pistas típicas en los desafíos:

- "Se filtraron los bits superiores/inferiores de p"
- "La flag está incrustada así: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Usamos RSA, pero con un padding aleatorio pequeño"

### Herramientas

En la práctica, usarás Sage para LLL y una plantilla conocida para la instancia específica.

Buenos puntos de partida:

- Plantillas de criptografía de Sage CTF: https://github.com/defund/coppersmith
- Una referencia tipo reseña: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factorizar claves RSA de "manga corta" con polinomios](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [Herramienta independiente de badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

