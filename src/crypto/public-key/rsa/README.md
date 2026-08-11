# Ataques RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triagem rápida

Colete:

- `n`, `e`, `c` (e quaisquer ciphertexts adicionais)
- Quaisquer relações entre mensagens (mesmo plaintext? modulus compartilhado? plaintext estruturado?)
- Quaisquer leaks (`p/q` parciais, bits de `d`, `dp/dq`, padding conhecido)

Depois tente:

- Verificação de fatoração (Factordb / `sage: factor(n)` para valores relativamente pequenos)
- Padrões de expoente baixo (`e=3`, broadcast)
- Common modulus / primos repetidos
- Métodos de lattice (Coppersmith/LLL) quando algo é quase conhecido

## Ataques RSA comuns

### Common modulus

Se dois ciphertexts `c1, c2` criptografam a **mesma mensagem** sob o **mesmo modulus** `n`, mas com expoentes diferentes `e1, e2` (e `gcd(e1,e2)=1`), você pode recuperar `m` usando o algoritmo de Euclides estendido:

`m = c1^a * c2^b mod n` onde `a*e1 + b*e2 = 1`.

Exemplo:

1. Calcule `(a, b) = xgcd(e1, e2)` para que `a*e1 + b*e2 = 1`
2. Se `a < 0`, interprete `c1^a` como `inv(c1)^{-a} mod n` (o mesmo para `b`)
3. Multiplique e reduza módulo `n`

### Primos compartilhados entre moduli

Se você tiver vários moduli RSA do mesmo desafio, verifique se eles compartilham um primo:

- `gcd(n1, n2) != 1` implica uma falha catastrófica na geração da chave.

Isso aparece frequentemente em CTFs como "geramos muitas chaves rapidamente" ou "randomness ruim".

### Moduli esparsos / short-sleeve

Alguns geradores de inteiros grandes defeituosos vazam diretamente uma estrutura no modulus público: cada limb contém apenas um pequeno subcampo aleatório, e o restante dos bits é `0`. Na prática, isso aparece como **blocos de zeros regularmente espaçados** ao longo de `n`, geralmente alinhados a limbs de 32 ou 128 bits.<sup>[[1]](#references)</sup>

Verificações rápidas:

- Exiba `n` em hexadecimal e procure por janelas de zeros repetidas em um stride fixo.
- Divida novamente `n` em limbs (`2^32`, `2^64`, `2^128`) e verifique se cada limb é incomumente pequeno.
- Audite chaves públicas SSH/TLS com ferramentas como **badkeys** quando suspeitar de uma geração fraca de host-key.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Isso é mais grave do que um viés estatístico: se ambos os fatores privados `p` e `q` forem short-sleeve, o modulus pode se tornar **fácil de fatorar**.<sup>[[1]](#references)</sup>

### Fatoração polinomial de chaves RSA estruturadas

Para uma largura de limb suspeita `w`, escreva o modulus na base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Como a avaliação é multiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Se os fatores também tiverem coeficientes de limb esparsos, então:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Exemplo de ataque:

1. Considere a largura de limb `w`.
2. Converta o modulus público `n` em `f_n(x)` usando a base `2^w`.
3. Fatore `f_n(x)` sobre os inteiros.
4. Avalie os fatores candidatos novamente em `B = 2^w`.
5. Verifique quais candidatos, multiplicados, resultam em `n`.

Isso **não quebra o RSA normal**. Só funciona quando os fatores primos têm coeficientes de limb muito pequenos e altamente estruturados.<sup>[[1]](#references)</sup>

### Vazamento de limb deslocado

Os bytes esparsos nem sempre estão alinhados na extremidade inferior de cada limb. Se a conversão direta para a base `2^w` produzir coeficientes grandes, procure shifts `i,j` tais que `2^i p` e `2^j q` se tornem esparsos nessa base de limbs. O polinômio do produto ainda pode ser derivado do modulus público, fatorado e recombinado nos fatores inteiros originais.<sup>[[1]](#references)</sup>

### Problema de implementação: bug de RNG de byte para limb

Um padrão perigoso é calcular o número de **limbs de 32 bits**, alocar apenas essa quantidade de **bytes** e copiá-los para o array de limbs:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Isso dá a cada limb de 32 bits apenas **8 bits de entropia**, além de um bit superior forçado no último limb. Os primos RSA resultantes podem frequentemente ser reconhecidos e fatorados apenas a partir da chave pública.<sup>[[1]](#references)</sup>

### Modo de falha relacionado do DSA

Se a mesma rotina defeituosa de big integers for reutilizada para a geração do expoente privado do DSA, a chave pública `y = g^x` poderá vazar um espaço de busca **drasticamente reduzido e estruturado** para `x`. Quando o padrão dos limbs é conhecido, ataques de logaritmo discreto, como **baby-step giant-step**, podem se tornar viáveis contra os parâmetros públicos.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Se o mesmo plaintext for enviado a vários destinatários com `e` pequeno (frequentemente `e=3`) e sem padding adequado, você poderá recuperar `m` usando CRT e uma raiz inteira.

Condição técnica:

Se você tiver `e` ciphertexts da mesma mensagem sob módulos `n_i` coprimos entre si:

- Use CRT para recuperar `M = m^e` sobre o produto `N = Π n_i`
- Se `m^e < N`, então `M` é a potência inteira verdadeira, e `m = integer_root(M, e)`

### Wiener attack: small private exponent

Se `d` for pequeno demais, frações contínuas poderão recuperá-lo a partir de `e/n`.

### Armadilhas do textbook RSA

Se você vir:

- Nenhum OAEP/PSS, apenas exponenciação modular bruta
- Encryption determinística

então ataques algébricos e abuso de oracles se tornam muito mais prováveis.

### Ferramentas

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Padrões de mensagens relacionadas

Se você vir dois ciphertexts sob o mesmo módulo com mensagens relacionadas algebricamente (por exemplo, `m2 = a*m1 + b`), procure ataques de "related-message", como Franklin–Reiter. Normalmente, eles exigem:

- mesmo módulo `n`
- mesmo expoente `e`
- relação conhecida entre os plaintexts

Na prática, isso geralmente é resolvido com Sage, configurando polinômios módulo `n` e calculando um GCD.

## Lattices / Coppersmith

Use isso quando tiver bits parciais, plaintext estruturado ou relações próximas que tornem o desconhecido pequeno.

Métodos de lattice (LLL/Coppersmith) aparecem sempre que você tem informações parciais:

- Plaintext parcialmente conhecido (mensagem estruturada com cauda desconhecida)
- `p`/`q` parcialmente conhecidos (bits superiores vazados)
- Pequenas diferenças desconhecidas entre valores relacionados

### O que reconhecer

Indícios típicos em challenges:

- "Vazamos os bits superiores/inferiores de p"
- "A flag está incorporada assim: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Usamos RSA, mas com um pequeno padding aleatório"

### Ferramentas

Na prática, você usará Sage para LLL e um template conhecido para a instância específica.

Bons pontos de partida:

- Templates de crypto para CTF no Sage: https://github.com/defund/coppersmith
- Uma referência em estilo de survey: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Fatorando chaves RSA "short-sleeve" com polinômios](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [ferramenta standalone badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
