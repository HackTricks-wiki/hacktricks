# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Collect:

- `n`, `e`, `c` (और कोई अतिरिक्त ciphertexts)
- संदेशों के बीच कोई भी संबंध (same plaintext? shared modulus? structured plaintext?)
- कोई भी leaks (partial `p/q`, `d` के bits, `dp/dq`, known padding)

Then try:

- Factorization check (Factordb / `sage: factor(n)` for small-ish)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) जब कुछ लगभग known हो

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
यह प्रत्येक 32-bit limb को केवल **8 bits of entropy** देता है, साथ ही आख़िरी limb में एक forced top bit भी। इसके परिणामस्वरूप RSA primes को अक्सर public key alone से पहचाना और factor किया जा सकता है।

### Related DSA failure mode

यदि वही broken big-integer routine DSA private exponent generation के लिए फिर से उपयोग की जाती है, तो public key `y = g^x` एक **काफी कम और structured** search space को `x` के लिए leak कर सकती है। एक बार limb pattern पता चल जाने पर, **baby-step giant-step** जैसे discrete-log attacks public parameters के खिलाफ practical हो सकते हैं।

### Håstad broadcast / low exponent

यदि वही plaintext कई recipients को छोटे `e` (अक्सर `e=3`) और बिना proper padding के भेजा जाता है, तो आप `CRT` और integer root की मदद से `m` recover कर सकते हैं।

Technical condition:

यदि आपके पास pairwise-coprime moduli `n_i` के तहत same message के `e` ciphertexts हैं:

- `CRT` का उपयोग करके `M = m^e` को product `N = Π n_i` पर recover करें
- यदि `m^e < N` हो, तो `M` ही true integer power है, और `m = integer_root(M, e)`

### Wiener attack: small private exponent

यदि `d` बहुत छोटा है, तो continued fractions `e/n` से इसे recover कर सकती हैं।

### Textbook RSA pitfalls

यदि आप यह देखें:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

तो algebraic attacks और oracle abuse कहीं अधिक likely हो जाते हैं।

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

यदि आप same modulus के तहत दो ciphertexts देखें जिनके messages algebraically related हों (e.g., `m2 = a*m1 + b`), तो Franklin–Reiter जैसे "related-message" attacks देखें। इनके लिए आम तौर पर यह चाहिए:

- same modulus `n`
- same exponent `e`
- plaintexts के बीच known relationship

प्रैक्टिस में इसे अक्सर Sage से polynomials को modulo `n` set up करके और GCD compute करके solve किया जाता है।

## Lattices / Coppersmith

जब आपके पास partial bits, structured plaintext, या close relations हों जो unknown को छोटा बनाती हों, तब इसका उपयोग करें।

Lattice methods (LLL/Coppersmith) तब सामने आते हैं जब आपके पास partial information हो:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Related values के बीच छोटे unknown differences

### What to recognize

Challenges में typical hints:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

प्रैक्टिस में आप LLL के लिए Sage और specific instance के लिए एक known template का उपयोग करेंगे।

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
