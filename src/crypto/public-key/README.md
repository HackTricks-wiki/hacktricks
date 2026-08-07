# Criptografia de Chave Pública

{{#include ../../banners/hacktricks-training.md}}


A maior parte da criptografia difícil de CTF acaba aqui: RSA, ECC/ECDSA, lattices e randomização inadequada.

## Ferramentas recomendadas

- SageMath (LLL/lattices, aritmética modular): https://www.sagemath.org/
- RsaCtfTool (canivete suíço): https://github.com/Ganapati/RsaCtfTool
- factordb (verificações rápidas de fatoração): http://factordb.com/

## RSA

Comece aqui quando você tiver `n,e,c` e alguma dica extra (shared modulus, low exponent, bits parciais, mensagens relacionadas).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se houver assinaturas envolvidas, teste primeiro problemas de nonce (reuse/bias/leaks) antes de presumir que a matemática é difícil.

### Reutilização / bias de nonce no ECDSA

Se duas assinaturas reutilizarem o mesmo nonce `k`, a chave privada poderá ser recuperada.

Mesmo que `k` não seja idêntico, **bias/leakage** dos bits do nonce entre assinaturas pode ser suficiente para a recuperação com lattices (um tema comum em CTFs).

Recuperação técnica quando `k` é reutilizado:

Equações de assinatura do ECDSA (ordem do grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se o mesmo `k` for reutilizado para duas mensagens `m1, m2`, produzindo as assinaturas `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Ataques de curva inválida

Se um protocolo não validar que os pontos estão na curva esperada (ou no subgroup), um atacante poderá forçar operações em um grupo fraco e recuperar secrets.

Nota técnica:

- Valide se os pontos estão na curva e no subgroup correto.
- Muitas tarefas de CTF modelam isso como "o server multiplica um ponto escolhido pelo atacante por um scalar secreto e retorna algo."

### Ferramentas

- SageMath para aritmética de curvas / lattices
- Biblioteca Python `ecdsa` para parsing/verificação

{{#include ../../banners/hacktricks-training.md}}
