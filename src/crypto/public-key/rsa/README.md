# RSA हमले

{{#include ../../../banners/hacktricks-training.md}}

## त्वरित triage

Collect:

- `n`, `e`, `c` (और कोई भी additional ciphertexts)
- Messages के बीच कोई भी relationships (same plaintext? shared modulus? structured plaintext?)
- कोई भी leaks (partial `p/q`, `d` के bits, `dp/dq`, known padding)

फिर आज़माएँ:

- Factorization check (छोटे आकार के लिए Factordb / `sage: factor(n)`)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL), जब कुछ लगभग ज्ञात हो

## Common RSA attacks

### Common modulus

यदि दो ciphertexts `c1, c2` **same message** को **same modulus** `n` के अंतर्गत, अलग-अलग exponents `e1, e2` के साथ encrypt करते हैं (और `gcd(e1,e2)=1`), तो आप extended Euclidean algorithm का उपयोग करके `m` recover कर सकते हैं:

`m = c1^a * c2^b mod n` जहाँ `a*e1 + b*e2 = 1`।

Example outline:

1. `(a, b) = xgcd(e1, e2)` compute करें ताकि `a*e1 + b*e2 = 1`
2. यदि `a < 0` है, तो `c1^a` को `inv(c1)^{-a} mod n` के रूप में interpret करें (`b` के लिए भी यही)
3. Multiply करें और `n` के modulo में reduce करें

### Shared primes across moduli

यदि आपके पास same challenge से multiple RSA moduli हैं, तो जाँचें कि क्या उनमें कोई prime shared है:

- `gcd(n1, n2) != 1` एक catastrophic key-generation failure को दर्शाता है।

यह CTFs में अक्सर `"we generated many keys quickly"` या `"bad randomness"` के रूप में दिखाई देता है।

### Sparse / short-sleeve moduli

कुछ broken big-integer generators public modulus में सीधे structure leak करते हैं: प्रत्येक limb में केवल एक छोटा random subfield होता है और बाकी bits `0` होते हैं। व्यवहार में यह `n` में **regularly spaced zero blocks** के रूप में दिखाई देता है, जो अक्सर 32-bit या 128-bit limbs के साथ aligned होते हैं।<sup>[[1]](#references)</sup>

Quick checks:

- `n` को hex में dump करें और fixed stride पर repeated zero windows खोजें।
- `n` को limbs (`2^32`, `2^64`, `2^128`) के रूप में re-slice करें और जाँचें कि क्या प्रत्येक limb असामान्य रूप से छोटा है।
- जब आपको weak host-key generation का संदेह हो, तो **badkeys** जैसे tooling से public SSH/TLS keys का audit करें।<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

यह statistical bias से अधिक गंभीर है: यदि दोनों private factors `p` और `q` short-sleeved हैं, तो modulus **easy to factor** हो सकता है।<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

किसी suspected limb width `w` के लिए, modulus को base `B = 2^w` में लिखें:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

क्योंकि evaluation multiplicative होती है, `f_a(B) * f_c(B) = (f_a * f_c)(B)`। यदि factors में भी sparse limb coefficients हों, तो:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. Limb width `w` का अनुमान लगाएँ।
2. Base `2^w` का उपयोग करके public modulus `n` को `f_n(x)` में convert करें।
3. `f_n(x)` को integers पर factor करें।
4. Candidate factors को `B = 2^w` पर फिर से evaluate करें।
5. Verify करें कि कौन से candidates multiply होकर `n` बनाते हैं।

यह **normal RSA को break नहीं करता**। यह केवल तब काम करता है जब prime factors में स्वयं बहुत छोटे, अत्यधिक structured limb coefficients हों।<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse bytes हमेशा प्रत्येक limb के low end पर aligned नहीं होते। यदि direct base-`2^w` conversion से बड़े coefficients मिलते हैं, तो ऐसे shifts `i,j` खोजें जिनसे `2^i p` और `2^j q` उस limb basis में sparse हो जाएँ। Product polynomial अभी भी public modulus से derive और factor किया जा सकता है, फिर original integer factors में recombine किया जा सकता है।<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

एक dangerous pattern है **32-bit limbs** की संख्या compute करना, केवल उतने ही **bytes** allocate करना, और उन्हें limb array में copy करना:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
यह प्रत्येक 32-bit limb को केवल **8 bits of entropy** और अंतिम limb में एक forced top bit देता है। परिणामी RSA primes को अक्सर केवल public key से पहचाना और factor किया जा सकता है।<sup>[[1]](#references)</sup>

### संबंधित DSA failure mode

यदि उसी broken big-integer routine का उपयोग DSA private exponent generation के लिए दोबारा किया जाता है, तो public key `y = g^x`, `x` के लिए एक **नाटकीय रूप से कम और structured** search space leak कर सकता है। एक बार limb pattern ज्ञात हो जाने पर, **baby-step giant-step** जैसे discrete-log attacks public parameters के विरुद्ध practical हो सकते हैं।<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

यदि वही plaintext छोटे `e` (अक्सर `e=3`) वाले कई recipients को भेजा जाता है और proper padding नहीं होती, तो आप CRT और integer root के माध्यम से `m` recover कर सकते हैं।

Technical condition:

यदि आपके पास pairwise-coprime moduli `n_i` के अंतर्गत एक ही message के `e` ciphertexts हैं:

- product `N = Π n_i` पर `M = m^e` recover करने के लिए CRT का उपयोग करें
- यदि `m^e < N` है, तो `M` वास्तविक integer power है, और `m = integer_root(M, e)`

### Wiener attack: small private exponent

यदि `d` बहुत छोटा है, तो continued fractions `e/n` से इसे recover कर सकते हैं।

### Textbook RSA pitfalls

यदि आपको दिखे:

- कोई OAEP/PSS नहीं, raw modular exponentiation
- Deterministic encryption

तो algebraic attacks और oracle abuse की संभावना बहुत अधिक हो जाती है।

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

यदि आपको same modulus के अंतर्गत दो ciphertexts दिखाई दें, जिनके messages algebraically related हैं (जैसे, `m2 = a*m1 + b`), तो Franklin–Reiter जैसे "related-message" attacks देखें। इनके लिए आमतौर पर आवश्यक है:

- same modulus `n`
- same exponent `e`
- plaintexts के बीच known relationship

व्यवहार में इसे अक्सर Sage के माध्यम से `n` modulo polynomials स्थापित करके और GCD compute करके solve किया जाता है।

## Lattices / Coppersmith

जब आपके पास partial bits, structured plaintext या close relations हों, जो unknown को छोटा बनाते हैं, तब इसका उपयोग करें।

जब भी आपके पास partial information हो, lattice methods (LLL/Coppersmith) सामने आते हैं:

- Partially known plaintext (unknown tail वाला structured message)
- Partially known `p`/`q` (high bits leaked)
- Related values के बीच small unknown differences

### What to recognize

Challenges में सामान्य hints:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

व्यवहार में आप LLL के लिए Sage और specific instance के लिए एक known template उपयोग करेंगे।

अच्छे starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
