# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Triagem rápida

Coletar:

- `n`, `e`, `c` (e quaisquer ciphertexts adicionais)
- Quaisquer relacionamentos entre mensagens (mesmo plaintext? shared modulus? plaintext estruturado?)
- Quaisquer leaks (parciais `p/q`, bits de `d`, `dp/dq`, padding conhecido)

Então tente:

- Verificação de fatoração (Factordb / `sage: factor(n)` para valores pequenos)
- Padrões de expoente baixo (`e=3`, broadcast)
- Common modulus / repeated primes
- Métodos de lattice (Coppersmith/LLL) quando algo está quase conhecido

## Common RSA attacks

### Common modulus

Se dois ciphertexts `c1, c2` criptografarem a **mesma mensagem** sob o **mesmo modulus** `n` mas com expoentes diferentes `e1, e2` (e `gcd(e1,e2)=1`), você pode recuperar `m` usando o algoritmo de Euclides estendido:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Exemplo resumido:

1. Calcule `(a, b) = xgcd(e1, e2)` tal que `a*e1 + b*e2 = 1`
2. Se `a < 0`, interprete `c1^a` como `inv(c1)^{-a} mod n` (o mesmo para `b`)
3. Multiplique e reduza módulo `n`

### Shared primes across moduli

Se você tem múltiplos RSA moduli do mesmo desafio, verifique se eles compartilham um primo:

- `gcd(n1, n2) != 1` implica uma falha catastrófica na geração de chaves.

Isso aparece com frequência em CTFs como "we generated many keys quickly" ou "bad randomness".

### Håstad broadcast / low exponent

Se o mesmo plaintext for enviado para múltiplos destinatários com pequeno `e` (frequentemente `e=3`) e sem padding adequado, você pode recuperar `m` via CRT e raiz inteira.

Condição técnica:

Se você tem `e` ciphertexts da mesma mensagem sob moduli pairwise-coprime `n_i`:

- Use CRT para recuperar `M = m^e` sobre o produto `N = Π n_i`
- Se `m^e < N`, então `M` é a verdadeira potência inteira, e `m = integer_root(M, e)`

### Wiener attack: small private exponent

Se `d` for muito pequeno, frações contínuas podem recuperá-lo a partir de `e/n`.

### Textbook RSA pitfalls

Se você observar:

- Sem OAEP/PSS, exponenciação modular crua
- Criptografia determinística

então ataques algébricos e abuso de oracle tornam-se muito mais prováveis.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Se você vir dois ciphertexts sob o mesmo modulus com mensagens que são algebraicamente relacionadas (por ex., `m2 = a*m1 + b`), procure por ataques "related-message" tais como Franklin–Reiter. Estes tipicamente requerem:

- mesmo modulus `n`
- mesmo exponent `e`
- relação conhecida entre plaintexts

Na prática isso é frequentemente resolvido com Sage montando polinômios modulo `n` e calculando um GCD.

## Lattices / Coppersmith

Use isso quando você tiver bits parciais, plaintext estruturado, ou relações próximas que tornam o desconhecido pequeno.

Métodos de lattice (LLL/Coppersmith) aparecem sempre que você tem informação parcial:

- Plaintext parcialmente conhecido (mensagem estruturada com sufixo desconhecido)
- `p`/`q` parcialmente conhecidos (high bits leaked)
- Pequenas diferenças desconhecidas entre valores relacionados

### O que reconhecer

Pistas típicas em desafios:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Ferramentas

Na prática você usará Sage para LLL e um template conhecido para a instância específica.

Bons pontos de partida:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
