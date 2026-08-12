# Criptografia de Chave Pública

{{#include ../../banners/hacktricks-training.md}}

Muitos desafios avançados de criptografia em CTF envolvem RSA, criptografia de curvas elípticas (ECC), ECDSA, lattices ou weak randomness.

## Ferramentas recomendadas

- [SageMath](https://www.sagemath.org/) para aritmética modular, curvas elípticas e redução de lattices<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) para testar fraquezas comuns do RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) para verificar se um inteiro possui fatores conhecidos<sup>[[3]](#references)</sup>
- A [biblioteca `ecdsa` do Python](https://ecdsa.readthedocs.io/) para análise de chaves, assinatura e verificação<sup>[[7]](#references)</sup>

## RSA

Comece aqui quando um desafio fornecer `n`, `e` e `c`, além de uma dica como um módulo compartilhado, expoente baixo, bits parciais da chave ou mensagens relacionadas.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se houver assinaturas envolvidas, teste a reutilização, o viés ou o leak do nonce antes de presumir que o problema subjacente do logaritmo discreto precisa ser resolvido.

### Reutilização / viés de nonce do ECDSA

O ECDSA exige um número secreto `k` novo para cada mensagem. Se o mesmo `k` assinar dois hashes de mensagens diferentes, a chave privada poderá ser recuperada a partir dos valores públicos das assinaturas.<sup>[[4]](#references)</sup>

Mesmo quando `k` não é idêntico, o viés ou o leak de bits do nonce em muitas assinaturas pode permitir a recuperação baseada em lattices.<sup>[[5]](#references)</sup>

Recuperação técnica quando `k` é reutilizado:<sup>[[4]](#references)</sup>

Equações de assinatura do ECDSA (ordem do grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se o mesmo `k` for reutilizado para duas mensagens `m1, m2`, produzindo as assinaturas `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Se um protocolo não validar que um ponto de entrada pertence à curva esperada e ao subgrupo correto, um atacante poderá forçar operações em um grupo mais fraco e recuperar informações sobre um scalar secreto. A SEC 1 especifica verificações de validação de chave pública destinadas a impedir essas entradas.<sup>[[6]](#references)</sup>

Nota técnica:

- Valide que os pontos não sejam o ponto no infinito, tenham coordenadas válidas, satisfaçam a equação da curva e pertençam ao subgrupo exigido.<sup>[[6]](#references)</sup>
- Em desafios de CTF, isso geralmente é modelado como um servidor que multiplica um ponto escolhido pelo atacante por um scalar secreto e retorna um valor derivado.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Padrão de Assinatura Digital](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner e Heninger: Biased Nonce Sense — Ataques de Lattice contra Assinaturas ECDSA Fracas](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Criptografia de Curvas Elípticas](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentação do Python `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
