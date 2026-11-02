# Criptografia de chave pública

{{#include ../../banners/hacktricks-training.md}}

Muitos desafios avançados de criptografia em CTF envolvem RSA, criptografia de curva elíptica (ECC), ECDSA, reticulados ou aleatoriedade fraca.

## Ferramentas recomendadas

- [SageMath](https://www.sagemath.org/) para aritmética modular, curvas elípticas e redução de reticulados<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) para testar vulnerabilidades comuns de RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) para verificar se um inteiro tem fatores conhecidos<sup>[[3]](#references)</sup>
- A [biblioteca `ecdsa` do Python](https://ecdsa.readthedocs.io/) para analisar chaves, assinar e verificar<sup>[[7]](#references)</sup>

## RSA

Comece por aqui quando um desafio fornecer `n`, `e` e `c`, além de uma dica como módulo compartilhado, expoente baixo, bits parciais da chave ou mensagens relacionadas.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se houver assinaturas, teste a reutilização, o viés ou o vazamento do nonce antes de presumir que é necessário resolver o problema do logaritmo discreto subjacente.

### Reutilização / viés do nonce em ECDSA

O ECDSA exige um número secreto `k` novo para cada mensagem. Se o mesmo `k` assinar hashes de duas mensagens diferentes, é possível recuperar a chave privada a partir dos valores públicos das assinaturas.<sup>[[4]](#references)</sup>

Mesmo que `k` não seja idêntico, o viés ou o vazamento de bits do nonce em muitas assinaturas pode permitir a recuperação baseada em reticulados.<sup>[[5]](#references)</sup>

Recuperação técnica quando `k` é reutilizado:<sup>[[4]](#references)</sup>

Equações de assinatura do ECDSA (ordem do grupo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se o mesmo `k` for reutilizado para duas mensagens `m1, m2`, produzindo as assinaturas `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Ataques de curva inválida

Se um protocolo não validar que um ponto de entrada pertence à curva esperada e ao subgrupo correto, um atacante pode forçar operações em um grupo mais fraco e recuperar informações sobre um escalar secreto. A SEC 1 especifica verificações de validação de chave pública destinadas a impedir essas entradas.<sup>[[6]](#references)</sup>

Nota técnica:

- Valide que os pontos não são o ponto no infinito, têm coordenadas válidas, satisfazem a equação da curva e pertencem ao subgrupo exigido.<sup>[[6]](#references)</sup>
- Em desafios de CTF, isso costuma ser modelado como um servidor que multiplica um ponto escolhido pelo atacante por um escalar secreto e retorna um valor derivado.

## Chaves de assinatura ML-DSA malformadas e vazamento por amostragem por rejeição

A chave privada expandida do ML-DSA codifica vetores polinomiais `s1` e `s2` com coeficientes em `[-η, η]`. A FIPS 204 observa que a decodificação de bytes malformados de uma chave secreta pode produzir coeficientes fora desse intervalo. O algoritmo de assinatura não exige, por si só, uma verificação adicional de consistência da chave privada.<sup>[[8]](#references)</sup>

O requisito relevante é controlar uma **chave de assinatura expandida antes de ela ser importada ou usada para assinar**, e não enviar uma chave pública malformada a um verificador. Um caminho de importação permissivo pode aceitar coeficientes compactados alterados e ainda produzir assinaturas válidas na verificação. Compare a aceitação durante a importação e a assinatura e, em seguida, verifique as assinaturas resultantes usando o [fluxo de trabalho de fuzzing de codificações de chaves criptográficas](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

A assinatura calcula `z = y + c·s1` e `r0 = LowBits(w − c·s2)`, rejeitando um candidato quando `||z||∞ ≥ γ1 − β` ou `||r0||∞ ≥ γ2 − β`. Essas verificações tornam as saídas aceitas independentes dos segredos pequenos válidos. Coeficientes secretos fora do intervalo podem comprometer esse argumento de amostragem por rejeição e introduzir um viés dependente do segredo. Esse é um mecanismo de vazamento condicional, **não** uma recuperação demonstrada da chave completa a partir da discrepância relatada entre bibliotecas.<sup>[[8]](#references)[[10]](#references)</sup>

A validação da chave privada é distinta da verificação da assinatura. Na comparação relatada, OpenSSL, BoringSSL e SymCrypt aplicaram verificações adicionais da chave privada, enquanto liboqs aceitou chaves expandidas malformadas durante a assinatura; a implementação subjacente `mldsa-native` fornece um validador `pk_from_sk()` que liboqs não expôs. A FIPS 204 não exige essas verificações adicionais de validação.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Padrão de Assinatura Digital](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner e Heninger: Viés no nonce — ataques de reticulados contra assinaturas ECDSA fracas](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Criptografia de curva elíptica](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentação de `ecdsa` para Python](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Padrão de Assinatura Digital Baseado em Reticulados de Módulos](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Verificações ausentes de chaves ML-DSA e ML-KEM - issue #2517 do liboqs](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Estado das implementações de criptografia pós-quântica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
