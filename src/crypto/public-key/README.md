# Criptografía de clave pública

{{#include ../../banners/hacktricks-training.md}}

Muchos desafíos avanzados de criptografía en CTF implican RSA, criptografía de curvas elípticas (ECC), ECDSA, retículos o aleatoriedad débil.

## Herramientas recomendadas

- [SageMath](https://www.sagemath.org/) para aritmética modular, curvas elípticas y reducción de retículos<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) para probar debilidades comunes de RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) para comprobar si un entero tiene factores conocidos<sup>[[3]](#references)</sup>
- La [biblioteca `ecdsa` de Python](https://ecdsa.readthedocs.io/) para analizar claves, firmar y verificar<sup>[[7]](#references)</sup>

## RSA

Empieza aquí cuando un desafío proporcione `n`, `e` y `c`, además de una pista como un módulo compartido, un exponente bajo, bits parciales de la clave o mensajes relacionados.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si hay firmas involucradas, comprueba si hay reutilización, sesgo o filtración del nonce antes de asumir que hay que resolver el problema subyacente del logaritmo discreto.

### Reutilización / sesgo del nonce en ECDSA

ECDSA requiere un número secreto nuevo `k` para cada mensaje. Si se usa el mismo `k` para firmar dos hashes de mensaje distintos, se puede recuperar la clave privada a partir de los valores públicos de las firmas.<sup>[[4]](#references)</sup>

Aunque `k` no sea idéntico, el sesgo o la filtración de bits del nonce en muchas firmas puede permitir su recuperación mediante retículos.<sup>[[5]](#references)</sup>

Recuperación técnica cuando se reutiliza `k`:<sup>[[4]](#references)</sup>

Ecuaciones de firma de ECDSA (orden del grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si se reutiliza el mismo `k` para dos mensajes `m1, m2`, que producen las firmas `(r, s1)` y `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Ataques de curva inválida

Si un protocolo no valida que un punto de entrada pertenezca a la curva esperada y al subgrupo correcto, un atacante puede forzar operaciones en un grupo más débil y recuperar información sobre un escalar secreto. SEC 1 especifica comprobaciones de validación de clave pública destinadas a prevenir este tipo de entradas.<sup>[[6]](#references)</sup>

Nota técnica:

- Valida que los puntos no sean el punto en el infinito, tengan coordenadas válidas, satisfagan la ecuación de la curva y pertenezcan al subgrupo requerido.<sup>[[6]](#references)</sup>
- En los desafíos CTF, esto suele modelarse como un servidor que multiplica un punto elegido por el atacante por un escalar secreto y devuelve un valor derivado.

## Claves de firma ML-DSA malformadas y filtración por muestreo de rechazo

La clave privada expandida de ML-DSA codifica los vectores polinómicos `s1` y `s2` con coeficientes en `[-η, η]`. FIPS 204 señala que decodificar bytes malformados de una clave secreta puede producir coeficientes fuera de este intervalo. El algoritmo de firma no requiere por sí mismo una comprobación adicional de consistencia de la clave privada.<sup>[[8]](#references)</sup>

El requisito previo pertinente es tener control sobre una **clave de firma expandida antes de importarla o usarla para firmar**, no enviar una clave pública malformada a un verificador. Una ruta de importación permisiva puede aceptar coeficientes empaquetados alterados y aun así producir firmas válidas. Compara la aceptación durante la importación y la firma, y luego comprueba las firmas resultantes mediante el [flujo de trabajo de fuzzing de codificación de claves criptográficas](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

La firma calcula `z = y + c·s1` y `r0 = LowBits(w − c·s2)`, y rechaza un candidato cuando `||z||∞ ≥ γ1 − β` o `||r0||∞ ≥ γ2 − β`. Estas comprobaciones hacen que las salidas aceptadas sean independientes de los secretos pequeños válidos. Los coeficientes secretos fuera de rango pueden alterar el argumento de muestreo de rechazo e introducir un sesgo dependiente del secreto. Este es un mecanismo de filtración condicional, **no** una recuperación completa de la clave demostrada a partir de la discrepancia reportada entre bibliotecas.<sup>[[8]](#references)[[10]](#references)</sup>

La validación de la clave privada es distinta de la verificación de firmas. En la comparación reportada, OpenSSL, BoringSSL y SymCrypt aplicaron comprobaciones adicionales de la clave privada, mientras que liboqs aceptó claves expandidas malformadas durante la firma; su componente subyacente `mldsa-native` ofrece un validador `pk_from_sk()` que liboqs no expuso. FIPS 204 no exige esas comprobaciones de validación adicionales.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Estándar de firma digital](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner y Heninger: Biased Nonce Sense — Ataques de retículos contra firmas ECDSA débiles](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Criptografía de curvas elípticas](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentación de `ecdsa` para Python](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Estándar de firma digital basado en retículos modulares](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Faltan comprobaciones de claves ML-DSA y ML-KEM - incidencia #2517 de liboqs](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Estado de las implementaciones de criptografía poscuántica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
