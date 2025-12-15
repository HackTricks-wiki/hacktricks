# Criptografía de clave pública

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los problemas cripto difíciles de CTF terminan aquí: RSA, ECC/ECDSA, lattices, y mala aleatoriedad.

## Herramientas recomendadas

- SageMath (LLL/lattices, aritmética modular): https://www.sagemath.org/
- RsaCtfTool (navaja suiza): https://github.com/Ganapati/RsaCtfTool
- factordb (verificaciones rápidas de factorización): http://factordb.com/

## RSA

Empieza aquí cuando tengas `n,e,c` y alguna pista extra (módulo compartido, exponente bajo, bits parciales, mensajes relacionados).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si hay firmas involucradas, prueba primero problemas con el nonce (reuse/bias/leaks) antes de asumir que se trata de matemática difícil.

### ECDSA nonce reuse / bias

Si dos firmas reutilizan el mismo nonce `k`, la clave privada puede recuperarse.

Incluso si `k` no es idéntico, **bias/leakage** de bits del nonce entre firmas puede ser suficiente para recuperación por lattices (tema común en CTF).

Recuperación técnica cuando `k` se reutiliza:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

If the same `k` is reused for two messages `m1, m2` producing signatures `(r, s1)` and `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Si un protocolo no valida que los puntos estén en la curva esperada (o en el subgrupo correcto), un atacante puede forzar operaciones en un grupo débil y recuperar secretos.

Nota técnica:

- Valida que los puntos estén en la curva y en el subgrupo correcto.
- Muchas tareas de CTF modelan esto como "server multiplies attacker-chosen point by secret scalar and returns something."

### Herramientas

- SageMath para aritmética de curvas / lattices
- Biblioteca Python `ecdsa` para parseo/verificación

{{#include ../../banners/hacktricks-training.md}}
