# Ataques RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triagem rápida

Colete:

- `n`, `e`, `c` (e quaisquer ciphertexts adicionais)
- Quaisquer relações entre as mensagens (mesmo plaintext? módulo compartilhado? plaintext estruturado?)
- Quaisquer leaks (parte de `p/q`, bits de `d`, `dp/dq`, padding conhecido)

Em seguida, tente:

- Verificação de fatoração (Factordb / `sage: factor(n)` para valores não muito grandes)
- Padrões de expoente baixo (`e=3`, broadcast)
- Módulo compartilhado / primos repetidos
- Métodos de lattice (Coppersmith/LLL) quando algo é quase conhecido

## Ataques RSA comuns

### Common modulus

Se dois ciphertexts `c1, c2` criptografam a **mesma mensagem** sob o **mesmo módulo** `n`, mas com expoentes diferentes `e1, e2` (e `gcd(e1,e2)=1`), você pode recuperar `m` usando o algoritmo de Euclides estendido:

`m = c1^a * c2^b mod n` onde `a*e1 + b*e2 = 1`.

Exemplo:

1. Calcule `(a, b) = xgcd(e1, e2)` de modo que `a*e1 + b*e2 = 1`
2. Se `a < 0`, interprete `c1^a` como `inv(c1)^{-a} mod n` (o mesmo vale para `b`)
3. Multiplique e reduza módulo `n`

### Primos compartilhados entre módulos

Se você tiver vários módulos RSA do mesmo desafio, verifique se eles compartilham um primo:

- `gcd(n1, n2) != 1` implica uma falha catastrófica na geração das chaves.

Isso aparece com frequência em CTFs como "geramos muitas chaves rapidamente" ou "aleatoriedade ruim".

### Módulos sparse / short-sleeve

Alguns geradores defeituosos de inteiros grandes vazam estrutura diretamente para o módulo público: cada limb contém apenas um pequeno subcampo aleatório e o restante dos bits é `0`. Na prática, isso aparece como **blocos de zeros espaçados regularmente** ao longo de `n`, geralmente alinhados a limbs de 32 bits ou 128 bits.<sup>[[1]](#references)</sup>

Verificações rápidas:

- Exiba `n` em hexadecimal e procure janelas de zeros repetidas em intervalos fixos.
- Divida novamente `n` em limbs (`2^32`, `2^64`, `2^128`) e verifique se cada limb é excepcionalmente pequeno.
- Audite chaves públicas SSH/TLS com ferramentas como **badkeys** quando suspeitar de uma geração fraca de host keys.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Isso é mais grave do que um viés estatístico: se ambos os fatores privados `p` e `q` forem short-sleeve, o módulo pode se tornar **fácil de fatorar**.<sup>[[1]](#references)</sup>

### Fatoração polinomial de chaves RSA estruturadas

Para uma largura de limb suspeita `w`, escreva o módulo na base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Como a avaliação é multiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Se os fatores também tiverem coeficientes de limb esparsos, então:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Etapas do ataque:

1. Adivinhe a largura do limb `w`.
2. Converta o módulo público `n` em `f_n(x)` usando a base `2^w`.
3. Fatore `f_n(x)` sobre os inteiros.
4. Avalie os fatores candidatos novamente em `B = 2^w`.
5. Verifique quais candidatos, multiplicados, resultam em `n`.

Isso **não quebra o RSA normal**. Só funciona quando os próprios fatores primos têm coeficientes de limb muito pequenos e altamente estruturados.<sup>[[1]](#references)</sup>

### Vazamento de limb deslocado

Os bytes esparsos nem sempre estão alinhados na extremidade de menor peso de cada limb. Se a conversão direta para a base `2^w` produzir coeficientes grandes, procure deslocamentos `i,j` tais que `2^i p` e `2^j q` se tornem esparsos nessa base de limbs. Ainda é possível derivar o polinômio do produto a partir do módulo público, fatorá-lo e recombiná-lo para obter os fatores inteiros originais.<sup>[[1]](#references)</sup>

### Indício de implementação: bug de RNG na conversão de byte para limb

Um padrão perigoso é calcular o número de **limbs de 32 bits**, alocar apenas essa quantidade de **bytes** e copiá-los para o array de limbs:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

Isso deixa cada limb de 32 bits com apenas **8 bits de entropia** mais um bit superior forçado no último limb. Os primos RSA resultantes muitas vezes podem ser reconhecidos e fatorados apenas a partir da chave pública.<sup>[[1]](#references)</sup>

### Modo de falha relacionado do DSA

Se a mesma rotina defeituosa para inteiros grandes for reutilizada na geração do expoente privado do DSA, a chave pública `y = g^x` pode revelar um espaço de busca para `x` **drasticamente reduzido e estruturado**. Quando o padrão dos limbs é conhecido, ataques de logaritmo discreto, como **baby-step giant-step**, podem se tornar viáveis contra os parâmetros públicos.<sup>[[1]](#references)</sup>

### Broadcast de Håstad / expoente baixo

Se a mesma mensagem for enviada a vários destinatários com um `e` pequeno (geralmente `e=3`) e sem padding adequado, você pode recuperar `m` usando CRT e uma raiz inteira.

Condição técnica:

Se você tiver `e` textos cifrados da mesma mensagem sob módulos `n_i` coprimos par a par:

- Use CRT para recuperar `M = m^e` sobre o produto `N = Π n_i`
- Se `m^e < N`, então `M` é a verdadeira potência inteira, e `m = integer_root(M, e)`

### Ataque de Wiener: expoente privado pequeno

Se `d` for pequeno demais, frações contínuas podem recuperá-lo a partir de `e/n`.

### Armadilhas do RSA de livro-texto

Se você encontrar:

- Sem OAEP/PSS, exponenciação modular direta
- Criptografia determinística

então ataques algébricos e abuso de oráculos se tornam muito mais prováveis.

### Ferramentas

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, raízes, CF): https://www.sagemath.org/

## Padrões de mensagens relacionadas

Se você encontrar dois textos cifrados sob o mesmo módulo com mensagens que têm uma relação algébrica (por exemplo, `m2 = a*m1 + b`), procure ataques de "related-message", como Franklin–Reiter. Em geral, eles exigem:

- mesmo módulo `n`
- mesmo expoente `e`
- relação conhecida entre os textos simples

Na prática, isso costuma ser resolvido com Sage, definindo polinômios módulo `n` e calculando um MDC.

## Reticulados / Coppersmith

Use isso quando tiver bits parciais, texto simples estruturado ou relações próximas que tornem a incógnita pequena.

Métodos de reticulados (LLL/Coppersmith) aparecem sempre que você tem informação parcial:

- Texto simples parcialmente conhecido (mensagem estruturada com sufixo desconhecido)
- `p`/`q` parcialmente conhecidos (bits mais significativos vazados)
- Pequenas diferenças desconhecidas entre valores relacionados

### O que reconhecer

Indícios comuns em desafios:

- "Vazamos os bits superiores/inferiores de p"
- "A flag está embutida assim: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Usamos RSA, mas com um pequeno padding aleatório"

### Ferramentas

Na prática, você usará Sage para LLL e um template conhecido para a instância específica.

Bons pontos de partida:

- Templates de criptografia CTF para Sage: https://github.com/defund/coppersmith
- Uma referência em formato de levantamento: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Fatorando chaves RSA "short-sleeve" com polinômios](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [ferramenta standalone badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

