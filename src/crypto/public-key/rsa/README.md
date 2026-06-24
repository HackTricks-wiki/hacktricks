# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Triagem rápida

Colete:

- `n`, `e`, `c` (e quaisquer ciphertexts adicionais)
- Quaisquer relações entre mensagens (mesmo plaintext? shared modulus? structured plaintext?)
- Quaisquer leaks (partial `p/q`, bits de `d`, `dp/dq`, known padding)

Depois tente:

- Verificação de fatoração (Factordb / `sage: factor(n)` para valores pequenos)
- Padrões de baixo expoente (`e=3`, broadcast)
- Common modulus / repeated primes
- Métodos de lattice (Coppersmith/LLL) quando algo estiver quase conhecido

## Ataques RSA comuns

### Common modulus

Se dois ciphertexts `c1, c2` cifram a **mesma mensagem** sob o **mesmo modulus** `n`, mas com expoentes diferentes `e1, e2` (e `gcd(e1,e2)=1`), você pode recuperar `m` usando o algoritmo de Euclides estendido:

`m = c1^a * c2^b mod n` onde `a*e1 + b*e2 = 1`.

Esboço do exemplo:

1. Compute `(a, b) = xgcd(e1, e2)` para que `a*e1 + b*e2 = 1`
2. Se `a < 0`, interprete `c1^a` como `inv(c1)^{-a} mod n` (o mesmo para `b`)
3. Multiplique e reduza modulo `n`

### Shared primes across moduli

Se você tiver múltiplos RSA moduli da mesma challenge, verifique se compartilham um primo:

- `gcd(n1, n2) != 1` implica uma falha catastrófica na geração de chave.

Isso aparece com frequência em CTFs como "geramos muitas chaves rapidamente" ou "bad randomness".

### Sparse / short-sleeve moduli

Alguns geradores de big-integer quebrados vazam estrutura diretamente para o public modulus: cada limb contém apenas um pequeno subcampo aleatório e o restante dos bits é `0`. Na prática isso aparece como **blocos de zeros regularmente espaçados** ao longo de `n`, frequentemente alinhados a limbs de 32 bits ou 128 bits.

Verificações rápidas:

- Faça dump de `n` em hex e procure janelas de zeros repetidas com um stride fixo.
- Re-slice `n` como limbs (`2^32`, `2^64`, `2^128`) e inspecione se cada limb é incomumente pequeno.
- Audite public SSH/TLS keys com ferramentas como **badkeys** quando suspeitar de geração fraca da host-key.

Isso é mais grave do que um viés estatístico: se ambos os fatores privados `p` e `q` forem short-sleeved, o modulus pode se tornar **fácil de fatorar**.

### Polynomial factorization of structured RSA keys

Para uma largura de limb suspeita `w`, escreva o modulus na base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Como a avaliação é multiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Se os fatores também tiverem coeficientes de limb esparsos, então:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Esboço do ataque:

1. Adivinhe a largura do limb `w`.
2. Converta o public modulus `n` em `f_n(x)` usando a base `2^w`.
3. Fatore `f_n(x)` sobre os inteiros.
4. Avalie os possíveis fatores de volta em `B = 2^w`.
5. Verifique quais candidatos multiplicam para `n`.

Isso **não quebra RSA normal**. Só funciona quando os fatores primos em si têm coeficientes de limb muito pequenos e altamente estruturados.

### Shifted limb leakage

Os bytes esparsos nem sempre estão alinhados na extremidade baixa de cada limb. Se a conversão direta na base `2^w` produzir coeficientes grandes, procure shifts `i,j` tais que `2^i p` e `2^j q` se tornem esparsos nessa base de limb. O polinômio do produto ainda pode ser derivado do public modulus, fatorado e recombinado nos fatores inteiros originais.

### Implementation smell: byte-to-limb RNG bug

Um padrão perigoso é calcular o número de **32-bit limbs**, alocar apenas essa quantidade de **bytes** e copiá-los para o array de limbs:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Isso dá a cada limb de 32 bits apenas **8 bits de entropy** mais um bit alto forçado no último limb. Os primos RSA resultantes muitas vezes podem ser reconhecidos e fatorados apenas a partir da public key.

### Related DSA failure mode

Se a mesma rotina broken de big-integer for reutilizada para a geração do private exponent do DSA, a public key `y = g^x` pode leak um espaço de busca **drasticamente reduzido e estruturado** para `x`. Uma vez que o padrão dos limbs é conhecido, ataques de discrete-log como **baby-step giant-step** podem se tornar práticos contra os public parameters.

### Håstad broadcast / low exponent

Se o mesmo plaintext for enviado a múltiplos recipients com `e` pequeno (geralmente `e=3`) e sem padding adequado, você pode recuperar `m` via CRT e integer root.

Condição técnica:

Se você tiver `e` ciphertexts da mesma mensagem sob moduli `n_i` pairwise-coprime:

- Use CRT para recuperar `M = m^e` sobre o produto `N = Π n_i`
- Se `m^e < N`, então `M` é a potência inteira verdadeira, e `m = integer_root(M, e)`

### Wiener attack: small private exponent

Se `d` for pequeno demais, continued fractions podem recuperá-lo a partir de `e/n`.

### Armadilhas do Textbook RSA

Se você vir:

- Sem OAEP/PSS, raw modular exponentiation
- Deterministic encryption

então ataques algébricos e abuso de oracle se tornam muito mais prováveis.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Se você vir dois ciphertexts sob o mesmo modulus com messages que são algebraicamente related (por exemplo, `m2 = a*m1 + b`), procure por ataques de "related-message" como Franklin–Reiter. Esses normalmente exigem:

- mesmo modulus `n`
- mesmo exponent `e`
- relação conhecida entre plaintexts

Na prática, isso geralmente é resolvido com Sage configurando polynomials modulo `n` e computando um GCD.

## Lattices / Coppersmith

Use isso quando você tiver partial bits, structured plaintext, ou close relations que tornam o unknown pequeno.

Métodos de lattice (LLL/Coppersmith) aparecem sempre que você tem partial information:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences between related values

### O que reconhecer

Pistas típicas em challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

Na prática, você vai usar Sage para LLL e um template conhecido para a instância específica.

Bons pontos de partida:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Uma referência no estilo survey: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
