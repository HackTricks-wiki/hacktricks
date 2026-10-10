# Criptografia de chave pública

{{#include ../../banners/hacktricks-training.md}}

Muitos desafios avançados de criptografia em CTF envolvem RSA, criptografia de curvas elípticas (ECC), ECDSA, reticulados ou aleatoriedade fraca.

## Ferramentas recomendadas

- [SageMath](https://www.sagemath.org/) para aritmética modular, curvas elípticas e redução de reticulados<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) para testar vulnerabilidades comuns de RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) para verificar se um inteiro tem fatores conhecidos<sup>[[3]](#references)</sup>
- A [biblioteca `ecdsa` do Python](https://ecdsa.readthedocs.io/) para análise de chaves, assinatura e verificação<sup>[[7]](#references)</sup>

## RSA

Comece por aqui quando um desafio fornecer `n`, `e` e `c`, além de uma dica como um módulo compartilhado, expoente baixo, bits parciais da chave ou mensagens relacionadas.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se houver assinaturas, teste se houve reutilização do nonce, viés ou vazamento antes de presumir que é preciso resolver o problema subjacente do logaritmo discreto.

### Reutilização / viés de nonce em ECDSA

O ECDSA exige um número secreto `k` novo para cada mensagem. Se o mesmo `k` assinar os hashes de duas mensagens diferentes, é possível recuperar a chave privada a partir dos valores públicos das assinaturas.<sup>[[4]](#references)</sup>

Mesmo quando `k` não é idêntico, o viés ou o vazamento de bits do nonce em muitas assinaturas pode permitir a recuperação baseada em reticulados.<sup>[[5]](#references)</sup>

Recuperação técnica quando `k` é reutilizado:<sup>[[4]](#references)</sup>

Equações de assinatura do ECDSA (ordem do grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se o mesmo `k` for reutilizado para duas mensagens `m1, m2`, produzindo as assinaturas `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Se um protocolo não validar se um ponto de entrada está na curva esperada e no subgrupo correto, um atacante pode forçar operações em um grupo mais fraco e recuperar informações sobre um escalar secreto. A SEC 1 especifica verificações de validação de chave pública para impedir esse tipo de entrada.<sup>[[6]](#references)</sup>

Nota técnica:

- Valide se os pontos não são o ponto no infinito, têm coordenadas válidas, satisfazem a equação da curva e pertencem ao subgrupo exigido.<sup>[[6]](#references)</sup>
- Em desafios de CTF, isso costuma ser modelado como um servidor que multiplica um ponto escolhido pelo atacante por um escalar secreto e retorna um valor derivado.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Padrão de Assinatura Digital](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner e Heninger: Nonces com viés — ataques de reticulados contra assinaturas ECDSA fracas](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Criptografia de curvas elípticas](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentação do Python `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
