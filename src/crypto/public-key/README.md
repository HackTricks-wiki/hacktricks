# Criptografía de clave pública

{{#include ../../banners/hacktricks-training.md}}

Muchos desafíos avanzados de criptografía en CTF involucran RSA, criptografía de curva elíptica (ECC), ECDSA, retículos o aleatoriedad débil.

## Herramientas recomendadas

- [SageMath](https://www.sagemath.org/) para aritmética modular, curvas elípticas y reducción de retículos<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) para probar debilidades comunes de RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) para comprobar si un entero tiene factores conocidos<sup>[[3]](#references)</sup>
- La [biblioteca `ecdsa` de Python](https://ecdsa.readthedocs.io/) para analizar claves, firmar y verificar<sup>[[7]](#references)</sup>

## RSA

Empieza aquí cuando un desafío proporcione `n`, `e` y `c`, junto con una pista como un módulo compartido, un exponente bajo, bits parciales de la clave o mensajes relacionados.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si hay firmas involucradas, comprueba si hay reutilización, sesgo o leak del nonce antes de asumir que hay que resolver el problema subyacente del logaritmo discreto.

### Reutilización/sesgo del nonce ECDSA

ECDSA requiere un número secreto nuevo `k` para cada mensaje. Si se usa el mismo `k` para firmar los hashes de dos mensajes distintos, se puede recuperar la clave privada a partir de los valores públicos de las firmas.<sup>[[4]](#references)</sup>

Aunque `k` no sea idéntico, el sesgo o el leak de bits del nonce en muchas firmas puede permitir su recuperación mediante retículos.<sup>[[5]](#references)</sup>

Recuperación técnica cuando se reutiliza `k`:<sup>[[4]](#references)</sup>

Ecuaciones de firma ECDSA (orden del grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si se reutiliza el mismo `k` para dos mensajes `m1, m2` y se producen las firmas `(r, s1)` y `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Si un protocolo no valida que un punto de entrada esté en la curva esperada y en el subgrupo correcto, un atacante puede forzar operaciones en un grupo más débil y recuperar información sobre un escalar secreto. SEC 1 especifica comprobaciones de validación de clave pública para impedir este tipo de entradas.<sup>[[6]](#references)</sup>

Nota técnica:

- Valida que los puntos no sean el punto en el infinito, tengan coordenadas válidas, satisfagan la ecuación de la curva y pertenezcan al subgrupo requerido.<sup>[[6]](#references)</sup>
- En los desafíos CTF, esto suele modelarse como un servidor que multiplica un punto elegido por el atacante por un escalar secreto y devuelve un valor derivado.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Estándar de firma digital](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner y Heninger: Nonce Sense sesgado — Ataques con retículos contra firmas ECDSA débiles](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Criptografía de curva elíptica](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentación de la biblioteca `ecdsa` de Python](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
