# RSA Angriffe

{{#include ../../../banners/hacktricks-training.md}}

## Schnelle Triage

Sammeln:

- `n`, `e`, `c` (und alle zusätzlichen Ciphertexte)
- Jegliche Beziehungen zwischen Nachrichten (gleicher Plaintext? gemeinsamer Modulus? strukturierter Plaintext?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Dann versuchen:

- Faktorisierungsprüfung (Factordb / `sage: factor(n)` für relativ kleine n)
- Muster bei kleinem Exponenten (`e=3`, broadcast)
- Gemeinsamer Modulus / wiederholte Primfaktoren
- Gittermethoden (Coppersmith/LLL), wenn etwas fast bekannt ist

## Common RSA attacks

### Common modulus

If two ciphertexts `c1, c2` encrypt the **same message** under the **same modulus** `n` but with different exponents `e1, e2` (and `gcd(e1,e2)=1`), you can recover `m` using the extended Euclidean algorithm:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Example outline:

1. Compute `(a, b) = xgcd(e1, e2)` so `a*e1 + b*e2 = 1`
2. If `a < 0`, interpret `c1^a` as `inv(c1)^{-a} mod n` (same for `b`)
3. Multiply and reduce modulo `n`

### Shared primes across moduli

If you have multiple RSA moduli from the same challenge, check whether they share a prime:

- `gcd(n1, n2) != 1` implies a catastrophic key-generation failure.

This shows up frequently in CTFs as "we generated many keys quickly" or "bad randomness".

### Håstad broadcast / low exponent

If the same plaintext is sent to multiple recipients with small `e` (often `e=3`) and no proper padding, you can recover `m` via CRT and integer root.

Technical condition:

If you have `e` ciphertexts of the same message under pairwise-coprime moduli `n_i`:

- Use CRT to recover `M = m^e` over the product `N = Π n_i`
- If `m^e < N`, then `M` is the true integer power, and `m = integer_root(M, e)`

### Wiener attack: small private exponent

If `d` is too small, continued fractions can recover it from `e/n`.

### Textbook RSA pitfalls

If you see:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

then algebraic attacks and oracle abuse become much more likely.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

If you see two ciphertexts under the same modulus with messages that are algebraically related (e.g., `m2 = a*m1 + b`), look for "related-message" attacks such as Franklin–Reiter. These typically require:

- same modulus `n`
- same exponent `e`
- known relationship between plaintexts

In practice this is often solved with Sage by setting up polynomials modulo `n` and computing a GCD.

## Lattices / Coppersmith

Reach for this when you have partial bits, structured plaintext, or close relations that make the unknown small.

Lattice methods (LLL/Coppersmith) show up whenever you have partial information:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences between related values

### What to recognize

Typical hints in challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

In practice you’ll use Sage for LLL and a known template for the specific instance.

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
