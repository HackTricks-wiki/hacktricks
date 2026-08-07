# Criptografía de clave pública

{{#include ../../banners/hacktricks-training.md}}


La mayoría de los retos de criptografía difícil en CTF terminan aquí: RSA, ECC/ECDSA, lattices y mala aleatoriedad.

## Herramientas recomendadas

- SageMath (LLL/lattices, aritmética modular): https://www.sagemath.org/
- RsaCtfTool (navaja suiza): https://github.com/Ganapati/RsaCtfTool
- factordb (comprobaciones rápidas de factorización): http://factordb.com/

## RSA

Empieza aquí cuando tengas `n,e,c` y alguna pista adicional (módulo compartido, exponente bajo, bits parciales, mensajes relacionados).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si hay firmas involucradas, comprueba primero los problemas de nonce (reuse/bias/leaks) antes de asumir que se trata de matemáticas difíciles.

### Reutilización / bias del nonce en ECDSA

Si dos firmas reutilizan el mismo nonce `k`, se puede recuperar la clave privada.

Aunque `k` no sea idéntico, el **bias/leakage** de bits del nonce entre firmas puede ser suficiente para recuperarlo mediante lattices (un tema común en CTF).

Recuperación técnica cuando se reutiliza `k`:

Ecuaciones de firma ECDSA (orden del grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si se reutiliza el mismo `k` para dos mensajes `m1, m2` que producen las firmas `(r, s1)` y `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Ataques de curva inválida

Si un protocolo no valida que los puntos estén en la curva esperada (o en el subgrupo), un atacante puede forzar operaciones en un grupo débil y recuperar secretos.

Nota técnica:

- Valida que los puntos estén en la curva y en el subgrupo correcto.
- Muchas tareas de CTF modelan esto como "el server multiplica un punto elegido por el atacante por un escalar secreto y devuelve algo".

### Herramientas

- SageMath para aritmética de curvas / lattices
- Librería de Python `ecdsa` para parseo/verificación

{{#include ../../banners/hacktricks-training.md}}
