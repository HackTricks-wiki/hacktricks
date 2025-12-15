# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

इकट्ठा करें:

- `n`, `e`, `c` (और किसी भी अतिरिक्त ciphertexts)
- संदेशों के बीच कोई संबंध (same plaintext? shared modulus? structured plaintext?)
- कोई leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

फिर प्रयास करें:

- Factorization check (Factordb / `sage: factor(n)` for small-ish)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) when something is almost known

## Common RSA attacks

### Common modulus

यदि दो ciphertexts `c1, c2` समान message को समान modulus `n` के तहत अलग exponents `e1, e2` (और `gcd(e1,e2)=1`) से encrypt करते हैं, तो आप extended Euclidean algorithm का उपयोग करके `m` recover कर सकते हैं:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

उदाहरण रूपरेखा:

1. Compute `(a, b) = xgcd(e1, e2)` so `a*e1 + b*e2 = 1`
2. If `a < 0`, interpret `c1^a` as `inv(c1)^{-a} mod n` (same for `b`)
3. Multiply and reduce modulo `n`

### Shared primes across moduli

यदि आपके पास एक ही challenge से multiple RSA moduli हैं, तो जांचें कि क्या वे कोई prime share करते हैं:

- `gcd(n1, n2) != 1` implies a catastrophic key-generation failure.

यह अक्सर CTFs में दिखाई देता है जैसे "we generated many keys quickly" या "bad randomness".

### Håstad broadcast / low exponent

यदि वही plaintext छोटे `e` (अक्सर `e=3`) के साथ कई recipients को भेजा गया है और कोई proper padding नहीं है, तो आप CRT और integer root के माध्यम से `m` recover कर सकते हैं।

तकनीकी शर्त:

यदि आपके पास pairwise-coprime moduli `n_i` के अंतर्गत समान संदेश के `e` ciphertexts हैं:

- Use CRT to recover `M = m^e` over the product `N = Π n_i`
- If `m^e < N`, then `M` is the true integer power, and `m = integer_root(M, e)`

### Wiener attack: small private exponent

यदि `d` बहुत छोटा है, तो continued fractions से इसे `e/n` से recover किया जा सकता है।

### Textbook RSA pitfalls

यदि आप देखते हैं:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

तो algebraic attacks और oracle abuse बहुत अधिक संभावित हो जाते हैं।

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

यदि आप दो ciphertexts देखते हैं जो समान modulus के तहत algebraically related messages हैं (उदा., `m2 = a*m1 + b`), तो related-message attacks जैसे Franklin–Reiter के लिए देखें। इनके लिए आमतौर पर आवश्यक होता है:

- same modulus `n`
- same exponent `e`
- known relationship between plaintexts

अमल में इसे अक्सर Sage में polynomials को modulo `n` पर सेट करके और GCD compute करके हल किया जाता है।

## Lattices / Coppersmith

इसे तब उपयोग करें जब आपके पास partial bits, structured plaintext, या ऐसी close relations हों जो unknown को छोटा बनाती हों।

Lattice methods (LLL/Coppersmith) तब काम आते हैं जब आपके पास partial information हो:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences between related values

### What to recognize

Challenges में सामान्य संकेत:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

व्यवहार में आप LLL के लिए Sage और विशेष instance के लिए उपलब्ध template का उपयोग करेंगे।

शुरू करने के लिए उपयोगी स्रोत:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
