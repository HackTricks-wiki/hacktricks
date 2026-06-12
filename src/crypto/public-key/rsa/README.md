# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Collect:

- `n`, `e`, `c` (and any additional ciphertexts)
- Any relationships between messages (same plaintext? shared modulus? structured plaintext?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Then try:

- Factorization check (Factordb / `sage: factor(n)` for small-ish)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) when something is almost known

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

### Sparse / short-sleeve moduli

Some broken big-integer generators leak structure directly into the public modulus: each limb contains only a small random subfield and the rest of the bits are `0`. In practice this appears as **regularly spaced zero blocks** across `n`, often aligned to 32-bit or 128-bit limbs.

Quick checks:

- Dump `n` in hex and look for repeated zero windows at a fixed stride.
- Re-slice `n` as limbs (`2^32`, `2^64`, `2^128`) and inspect whether each limb is unusually small.
- Audit public SSH/TLS keys with tooling such as **badkeys** when you suspect weak host-key generation.

This is more serious than a statistical bias: if both private factors `p` and `q` are short-sleeved, the modulus may become **easy to factor**.

### Polynomial factorization of structured RSA keys

For a suspected limb width `w`, write the modulus in base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Because evaluation is multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. If the factors also have sparse limb coefficients, then:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. Guess the limb width `w`.
2. Convert the public modulus `n` into `f_n(x)` using base `2^w`.
3. Factor `f_n(x)` over the integers.
4. Evaluate candidate factors back at `B = 2^w`.
5. Verify which candidates multiply to `n`.

This **does not break normal RSA**. It only works when the prime factors themselves have very small, highly structured limb coefficients.

### Shifted limb leakage

The sparse bytes are not always aligned at the low end of each limb. If direct base-`2^w` conversion produces large coefficients, search for shifts `i,j` such that `2^i p` and `2^j q` become sparse in that limb basis. The product polynomial can still be derived from the public modulus, factored, and recombined into the original integer factors.

### Implementation smell: byte-to-limb RNG bug

A dangerous pattern is computing the number of **32-bit limbs**, allocating only that many **bytes**, and copying them into the limb array:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

This gives each 32-bit limb only **8 bits of entropy** plus a forced top bit in the last limb. The resulting RSA primes can often be recognized and factored from the public key alone.

### Related DSA failure mode

If the same broken big-integer routine is reused for DSA private exponent generation, the public key `y = g^x` may leak a **dramatically reduced and structured** search space for `x`. Once the limb pattern is known, discrete-log attacks such as **baby-step giant-step** can become practical against the public parameters.

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

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
