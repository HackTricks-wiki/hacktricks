# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

एकत्र करें:

- `n`, `e`, `c` (और कोई भी अतिरिक्त ciphertexts)
- Messages के बीच कोई भी संबंध (समान plaintext? shared modulus? structured plaintext?)
- कोई भी leaks (आंशिक `p/q`, `d` के bits, `dp/dq`, ज्ञात padding)

फिर आज़माएँ:

- Factorization check (Factordb / छोटे आकार के लिए `sage: factor(n)`)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL), जब कोई चीज़ लगभग ज्ञात हो

## Common RSA attacks

### Common modulus

यदि दो ciphertexts `c1, c2` **समान message** को **समान modulus** `n` के अंतर्गत, अलग-अलग exponents `e1, e2` के साथ encrypt करते हैं (और `gcd(e1,e2)=1`), तो extended Euclidean algorithm का उपयोग करके आप `m` recover कर सकते हैं:

`m = c1^a * c2^b mod n` जहाँ `a*e1 + b*e2 = 1`।

उदाहरण की रूपरेखा:

1. `(a, b) = xgcd(e1, e2)` compute करें ताकि `a*e1 + b*e2 = 1`
2. यदि `a < 0` है, तो `c1^a` को `inv(c1)^{-a} mod n` के रूप में interpret करें (`b` के लिए भी यही)
3. Multiply करें और `n` modulo में reduce करें

### Shared primes across moduli

यदि आपके पास एक ही challenge से कई RSA moduli हैं, तो जाँचें कि क्या उनमें कोई prime साझा है:

- `gcd(n1, n2) != 1` एक catastrophic key-generation failure को दर्शाता है।

यह CTFs में अक्सर इस रूप में दिखाई देता है: "हमने बहुत-सी keys जल्दी generate कीं" या "bad randomness"।

### Sparse / short-sleeve moduli

कुछ broken big-integer generators public modulus में सीधे structure leak करते हैं: प्रत्येक limb में केवल एक छोटा random subfield होता है और बाकी bits `0` होते हैं। व्यवहार में यह `n` में **नियमित अंतराल पर zero blocks** के रूप में दिखाई देता है, जो अक्सर 32-bit या 128-bit limbs के साथ aligned होते हैं।<sup>[[1]](#references)</sup>

त्वरित जाँच:

- `n` को hex में dump करें और fixed stride पर दोहराई गई zero windows खोजें।
- `n` को limbs (`2^32`, `2^64`, `2^128`) के रूप में फिर से slice करें और जाँचें कि क्या प्रत्येक limb असामान्य रूप से छोटा है।
- जब आपको weak host-key generation का संदेह हो, तो **badkeys** जैसे tooling का उपयोग करके public SSH/TLS keys का audit करें।<sup>[[2]](#references)[[3]](#references)</sup>

यह केवल statistical bias से अधिक गंभीर है: यदि दोनों private factors `p` और `q` short-sleeved हैं, तो modulus को **आसानी से factor** किया जा सकता है।<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

संदिग्ध limb width `w` के लिए modulus को base `B = 2^w` में लिखें:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

क्योंकि evaluation multiplicative होता है, `f_a(B) * f_c(B) = (f_a * f_c)(B)`। यदि factors में भी sparse limb coefficients हैं, तो:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack की रूपरेखा:

1. Limb width `w` का अनुमान लगाएँ।
2. Base `2^w` का उपयोग करके public modulus `n` को `f_n(x)` में convert करें।
3. `f_n(x)` को integers पर factor करें।
4. Candidate factors को `B = 2^w` पर फिर से evaluate करें।
5. Verify करें कि कौन-से candidates multiply होकर `n` बनाते हैं।

यह **normal RSA को break नहीं करता**। यह केवल तब काम करता है जब prime factors में स्वयं बहुत छोटे, अत्यधिक structured limb coefficients हों।<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse bytes हमेशा प्रत्येक limb के low end पर aligned नहीं होते। यदि direct base-`2^w` conversion से बड़े coefficients प्राप्त होते हैं, तो ऐसे shifts `i,j` खोजें जिनसे `2^i p` और `2^j q` उस limb basis में sparse हो जाएँ। Product polynomial को public modulus से फिर भी derive किया जा सकता है, factor किया जा सकता है और original integer factors में recombine किया जा सकता है।<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

एक खतरनाक pattern यह है कि **32-bit limbs** की संख्या calculate की जाती है, केवल उतने ही **bytes** allocate किए जाते हैं, और उन्हें limb array में copy किया जाता है:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
यह प्रत्येक 32-bit limb को केवल **8 bits of entropy** और अंतिम limb में एक forced top bit देता है। परिणामी RSA primes को अक्सर केवल public key से पहचाना और factor किया जा सकता है।<sup>[[1]](#references)</sup>

### Related DSA failure mode

यदि उसी broken big-integer routine का पुनः उपयोग DSA private exponent generation के लिए किया जाता है, तो public key `y = g^x`, `x` के लिए एक **dramatically reduced and structured** search space leak कर सकती है। Limb pattern ज्ञात होने पर, **baby-step giant-step** जैसे discrete-log attacks public parameters के विरुद्ध practical हो सकते हैं।<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

यदि वही plaintext छोटे `e` (अक्सर `e=3`) वाले multiple recipients को भेजा जाता है और proper padding नहीं होती, तो आप CRT और integer root के माध्यम से `m` recover कर सकते हैं।

Technical condition:

यदि आपके पास pairwise-coprime moduli `n_i` के अंतर्गत उसी message के `e` ciphertexts हैं:

- CRT का उपयोग करके product `N = Π n_i` पर `M = m^e` recover करें
- यदि `m^e < N` है, तो `M` true integer power है, और `m = integer_root(M, e)`

### Wiener attack: small private exponent

यदि `d` बहुत छोटा है, तो continued fractions `e/n` से इसे recover कर सकते हैं।

### Textbook RSA pitfalls

यदि आपको दिखाई दे:

- कोई OAEP/PSS नहीं, raw modular exponentiation
- Deterministic encryption

तो algebraic attacks और oracle abuse की संभावना बहुत अधिक हो जाती है।

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

यदि आपको same modulus के अंतर्गत दो ciphertexts दिखाई दें, जिनके messages algebraically related हैं (जैसे, `m2 = a*m1 + b`), तो Franklin–Reiter जैसे "related-message" attacks देखें। इनके लिए सामान्यतः आवश्यक है:

- same modulus `n`
- same exponent `e`
- plaintexts के बीच known relationship

व्यवहार में इसे अक्सर Sage द्वारा `n` modulo polynomials सेट up करके और GCD compute करके solve किया जाता है।

## Lattices / Coppersmith

जब आपके पास partial bits, structured plaintext, या close relations हों, जो unknown को छोटा बनाती हों, तब इसका उपयोग करें।

Lattice methods (LLL/Coppersmith) तब सामने आते हैं जब आपके पास partial information हो:

- Partially known plaintext (unknown tail वाला structured message)
- Partially known `p`/`q` (high bits leaked)
- Related values के बीच small unknown differences

### What to recognize

Challenges में typical hints:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

व्यवहार में आप LLL के लिए Sage और specific instance के लिए एक known template का उपयोग करेंगे।

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
