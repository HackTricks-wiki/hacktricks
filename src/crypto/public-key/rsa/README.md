# Ataques RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triagem rápida

Colete:

- `n`, `e`, `c` (e quaisquer ciphertexts adicionais)
- Quaisquer relações entre as mensagens (mesmo plaintext? modulus compartilhado? plaintext estruturado?)
- Quaisquer leaks (`p/q` parciais, bits de `d`, `dp/dq`, padding conhecido)

Em seguida, tente:

- Verificação de fatoração (Factordb / `sage: factor(n)` para valores pequenos)
- Padrões de expoente baixo (`e=3`, broadcast)
- Common modulus / primos repetidos
- Métodos de lattice (Coppersmith/LLL) quando algo é quase conhecido

## Ataques RSA comuns

### Common modulus

Se dois ciphertexts `c1, c2` criptografam a **mesma mensagem** sob o **mesmo modulus** `n`, mas com expoentes diferentes `e1, e2` (e `gcd(e1,e2)=1`), você pode recuperar `m` usando o algoritmo de Euclides estendido:

`m = c1^a * c2^b mod n`, onde `a*e1 + b*e2 = 1`.

Exemplo:

1. Calcule `(a, b) = xgcd(e1, e2)` para que `a*e1 + b*e2 = 1`
2. Se `a < 0`, interprete `c1^a` como `inv(c1)^{-a} mod n` (o mesmo para `b`)
3. Multiplique e reduza módulo `n`

### Primos compartilhados entre moduli

Se você tiver vários moduli RSA do mesmo challenge, verifique se eles compartilham um primo:

- `gcd(n1, n2) != 1` implica uma falha catastrófica na geração da chave.

Isso aparece frequentemente em CTFs como "geramos muitas chaves rapidamente" ou "randomness ruim".

### Moduli esparsos / short-sleeve

Alguns geradores de big integers com falhas expõem diretamente uma estrutura no modulus público: cada limb contém apenas um pequeno subcampo aleatório, e o restante dos bits é `0`. Na prática, isso aparece como **blocos de zeros espaçados regularmente** ao longo de `n`, frequentemente alinhados a limbs de 32 ou 128 bits.<sup>[[1]](#references)</sup>

Verificações rápidas:

- Exiba `n` em hexadecimal e procure janelas de zeros repetidas em um stride fixo.
- Reorganize `n` em limbs (`2^32`, `2^64`, `2^128`) e verifique se cada limb é anormalmente pequeno.
- Audite chaves públicas SSH/TLS com ferramentas como **badkeys** quando suspeitar de uma geração fraca de host keys.<sup>[[2]](#references)[[3]](#references)</sup>

Isso é mais grave do que um viés estatístico: se ambos os fatores privados `p` e `q` forem short-sleeve, o modulus pode se tornar **fácil de fatorar**.<sup>[[1]](#references)</sup>

### Fatoração polinomial de chaves RSA estruturadas

Para uma largura de limb suspeita `w`, escreva o modulus na base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Como a avaliação é multiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Se os fatores também tiverem coeficientes de limb esparsos, então:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Visão geral do ataque:

1. Adivinhe a largura do limb `w`.
2. Converta o modulus público `n` em `f_n(x)` usando a base `2^w`.
3. Fatore `f_n(x)` sobre os inteiros.
4. Avalie os fatores candidatos novamente em `B = 2^w`.
5. Verifique quais candidatos, quando multiplicados, resultam em `n`.

Isso **não quebra o RSA normal**. Funciona apenas quando os fatores primos têm coeficientes de limb muito pequenos e altamente estruturados.<sup>[[1]](#references)</sup>

### Vazamento de limbs deslocados

Os bytes esparsos nem sempre estão alinhados na extremidade inferior de cada limb. Se a conversão direta para a base `2^w` produzir coeficientes grandes, procure shifts `i,j` tais que `2^i p` e `2^j q` se tornem esparsos nessa base de limbs. O polinômio do produto ainda pode ser derivado do modulus público, fatorado e recombinado nos fatores inteiros originais.<sup>[[1]](#references)</sup>

### Sinal de alerta na implementação: bug de RNG na conversão de bytes para limbs

Um padrão perigoso é calcular o número de **limbs de 32 bits**, alocar apenas essa quantidade de **bytes** e copiá-los para o array de limbs:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Isso dá a cada limb de 32 bits apenas **8 bits de entropia**, além de um bit superior forçado no último limb. Os primos RSA resultantes podem frequentemente ser reconhecidos e fatorados apenas a partir da chave pública.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Se a mesma rotina defeituosa de big-integer for reutilizada para a geração do expoente privado DSA, a chave pública `y = g^x` poderá causar um **leak de um espaço de busca drasticamente reduzido e estruturado** para `x`. Quando o padrão dos limbs é conhecido, ataques de discrete-log, como **baby-step giant-step**, podem se tornar práticos contra os parâmetros públicos.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Se a mesma mensagem plaintext for enviada a vários recipients com um `e` pequeno (frequentemente `e=3`) e sem padding adequado, você poderá recuperar `m` via CRT e integer root.

Condição técnica:

Se você tiver `e` ciphertexts da mesma mensagem sob moduli `n_i` coprimos entre si:

- Use CRT para recuperar `M = m^e` sobre o produto `N = Π n_i`
- Se `m^e < N`, então `M` é a potência inteira verdadeira, e `m = integer_root(M, e)`

### Wiener attack: small private exponent

Se `d` for pequeno demais, continued fractions poderão recuperá-lo a partir de `e/n`.

### Textbook RSA pitfalls

Se você encontrar:

- Nenhum OAEP/PSS, raw modular exponentiation
- Deterministic encryption

então ataques algébricos e oracle abuse se tornam muito mais prováveis.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Se você encontrar dois ciphertexts sob o mesmo modulus com mensagens que tenham uma relação algébrica (por exemplo, `m2 = a*m1 + b`), procure ataques de "related-message", como Franklin–Reiter. Normalmente, eles exigem:

- mesmo modulus `n`
- mesmo exponent `e`
- relação conhecida entre os plaintexts

Na prática, isso geralmente é resolvido com Sage, definindo polynomials módulo `n` e calculando um GCD.

## Lattices / Coppersmith

Use isso quando você tiver bits parciais, plaintext estruturado ou relações próximas que tornem o desconhecido pequeno.

Métodos de lattice (LLL/Coppersmith) aparecem sempre que você tem informações parciais:

- Plaintext parcialmente conhecido (mensagem estruturada com tail desconhecido)
- `p`/`q` parcialmente conhecidos (bits superiores em leak)
- Pequenas diferenças desconhecidas entre valores relacionados

### What to recognize

Dicas típicas em challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

Na prática, você usará Sage para LLL e um template conhecido para a instância específica.

Bons pontos de partida:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
