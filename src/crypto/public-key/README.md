# Criptografía de clave pública

{{#include ../../banners/hacktricks-training.md}}

Muchos desafíos avanzados de criptografía en CTF implican RSA, criptografía de curvas elípticas (ECC), ECDSA, lattices o weak randomness.

## Herramientas recomendadas

- [SageMath](https://www.sagemath.org/) para aritmética modular, curvas elípticas y lattice reduction<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) para probar debilidades comunes de RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) para comprobar si un entero tiene factores conocidos<sup>[[3]](#references)</sup>
- La [librería `ecdsa` de Python](https://ecdsa.readthedocs.io/) para analizar claves, firmar y verificar<sup>[[7]](#references)</sup>

## RSA

Empieza aquí cuando un desafío proporcione `n`, `e` y `c`, además de una pista como un módulo compartido, un exponente bajo, bits parciales de la clave o mensajes relacionados.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si hay firmas involucradas, comprueba si existe reutilización, bias o leakage del nonce antes de asumir que es necesario resolver el problema subyacente del logaritmo discreto.

### ECDSA nonce reuse / bias

ECDSA requiere un número secreto `k` nuevo para cada mensaje. Si el mismo `k` firma dos hashes de mensaje diferentes, la clave privada puede recuperarse a partir de los valores públicos de las firmas.<sup>[[4]](#references)</sup>

Aunque `k` no sea idéntico, el bias o leakage de bits del nonce en muchas firmas puede permitir una recuperación basada en lattices.<sup>[[5]](#references)</sup>

Recuperación técnica cuando se reutiliza `k`:<sup>[[4]](#references)</sup>

Ecuaciones de firma ECDSA (orden del grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si el mismo `k` se reutiliza para dos mensajes `m1, m2` que producen las firmas `(r, s1)` y `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Si un protocolo no valida que un punto de entrada se encuentre en la curva esperada y en el subgroup correcto, un atacante puede forzar operaciones en un grupo más débil y recuperar información sobre un escalar secreto. SEC 1 especifica comprobaciones de validación de clave pública destinadas a evitar este tipo de entradas.<sup>[[6]](#references)</sup>

Nota técnica:

- Valida que los puntos no sean el punto en el infinito, tengan coordenadas válidas, satisfagan la ecuación de la curva y pertenezcan al subgroup requerido.<sup>[[6]](#references)</sup>
- En los desafíos CTF, esto suele modelarse como un servidor que multiplica un punto elegido por el atacante por un escalar secreto y devuelve un valor derivado.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Estándar de firma digital](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner y Heninger: Biased Nonce Sense — ataques con lattices contra firmas ECDSA débiles](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Criptografía de curvas elípticas](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentación de `ecdsa` de Python](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
