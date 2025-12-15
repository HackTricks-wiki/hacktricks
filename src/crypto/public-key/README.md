# Criptografia de Chave Pública

{{#include ../../banners/hacktricks-training.md}}

A maior parte do cripto difícil de CTF acaba aqui: RSA, ECC/ECDSA, lattices, e aleatoriedade fraca.

## Ferramentas recomendadas

- SageMath (LLL/lattices, aritmética modular): https://www.sagemath.org/
- RsaCtfTool (canivete suíço): https://github.com/Ganapati/RsaCtfTool
- factordb (verificações rápidas de fatores): http://factordb.com/

## RSA

Comece aqui quando você tiver `n,e,c` e alguma dica extra (módulo compartilhado, expoente baixo, bits parciais, mensagens relacionadas).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se assinaturas estiverem envolvidas, teste problemas de nonce primeiro (reuse/bias/leaks) antes de assumir matemática difícil.

### ECDSA nonce reuse / bias

Se duas assinaturas reutilizam o mesmo nonce `k`, a chave privada pode ser recuperada.

Mesmo se `k` não for idêntico, **bias/leakage** de bits do nonce entre assinaturas pode ser suficiente para recuperação por lattice (tema comum em CTF).

Recuperação técnica quando `k` é reutilizado:

Equações de assinatura ECDSA (ordem do grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se o mesmo `k` for reutilizado para duas mensagens `m1, m2` produzindo assinaturas `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Se um protocolo não validar que os pontos estão na curva esperada (ou subgrupo), um atacante pode forçar operações em um grupo fraco e recuperar segredos.

Nota técnica:

- Valide que os pontos estão na curva e no subgrupo correto.
- Muitas tarefas de CTF modelam isso como "o servidor multiplica um ponto escolhido pelo atacante por um escalar secreto e retorna algo."

### Ferramentas

- SageMath para aritmética de curvas / lattices
- `ecdsa` biblioteca Python para parsing/verificação

{{#include ../../banners/hacktricks-training.md}}
