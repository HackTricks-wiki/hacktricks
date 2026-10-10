# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## तेज़ शुरुआती जाँच

इकट्ठा करें:

- `n`, `e`, `c` (और कोई अतिरिक्त ciphertext)
- Messages के बीच कोई संबंध (एक ही plaintext? साझा modulus? संरचित plaintext?)
- कोई leaks (आंशिक `p/q`, `d` के bits, `dp/dq`, ज्ञात padding)

फिर आज़माएँ:

- Factorization जाँच (Factordb / छोटे `n` के लिए `sage: factor(n)`)
- कम exponent वाले पैटर्न (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL), जब कोई जानकारी लगभग ज्ञात हो

## आम RSA attacks

### Common modulus

यदि दो ciphertexts `c1, c2` एक ही modulus `n` के तहत अलग-अलग exponents `e1, e2` के साथ **एक ही message** को encrypt करते हैं (और `gcd(e1,e2)=1` है), तो extended Euclidean algorithm का उपयोग करके `m` recover किया जा सकता है:

`m = c1^a * c2^b mod n` जहाँ `a*e1 + b*e2 = 1`।

उदाहरण की रूपरेखा:

1. `(a, b) = xgcd(e1, e2)` निकालें ताकि `a*e1 + b*e2 = 1` हो
2. यदि `a < 0` है, तो `c1^a` को `inv(c1)^{-a} mod n` के रूप में लें (`b` के लिए भी यही)
3. गुणा करें और modulo `n` से reduce करें

### Moduli के बीच साझा primes

यदि आपके पास एक ही challenge से कई RSA moduli हैं, तो जाँचें कि क्या उनमें कोई prime साझा है:

- `gcd(n1, n2) != 1` का अर्थ है कि key-generation में विनाशकारी विफलता हुई है।

CTFs में यह अक्सर "हमने जल्दी-जल्दी कई keys बनाई" या "खराब randomness" के रूप में दिखता है।

### Sparse / short-sleeve moduli

कुछ खराब big-integer generators सीधे public modulus में structure leak करते हैं: हर limb में केवल एक छोटा random subfield होता है और बाकी bits `0` होते हैं। व्यवहार में यह `n` में नियमित अंतराल पर zero blocks के रूप में दिखता है, जो अक्सर 32-bit या 128-bit limbs के साथ aligned होते हैं।<sup>[[1]](#references)</sup>

त्वरित जाँच:

- `n` को hex में dump करें और एक तय stride पर बार-बार आने वाली zero windows देखें।
- `n` को limbs (`2^32`, `2^64`, `2^128`) के रूप में फिर से बाँटें और देखें कि क्या हर limb असामान्य रूप से छोटा है।
- यदि आपको कमजोर host-key generation का संदेह है, तो **badkeys** जैसे tooling से public SSH/TLS keys का audit करें।<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

यह किसी statistical bias से कहीं अधिक गंभीर है: यदि दोनों private factors `p` और `q` short-sleeved हों, तो modulus को **factor करना आसान** हो सकता है।<sup>[[1]](#references)</sup>

### संरचित RSA keys का Polynomial factorization

संदिग्ध limb width `w` के लिए, modulus को base `B = 2^w` में लिखें:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

क्योंकि evaluation multiplicative होता है, `f_a(B) * f_c(B) = (f_a * f_c)(B)`। यदि factors के limb coefficients भी sparse हों, तो:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack की रूपरेखा:

1. Limb width `w` का अनुमान लगाएँ।
2. Base `2^w` का उपयोग करके public modulus `n` को `f_n(x)` में बदलें।
3. Integers पर `f_n(x)` का factorization करें।
4. Candidate factors को वापस `B = 2^w` पर evaluate करें।
5. जाँचें कि कौन-से candidates का गुणनफल `n` है।

यह **सामान्य RSA को नहीं तोड़ता**। यह तभी काम करता है जब prime factors के limb coefficients स्वयं बहुत छोटे और अत्यधिक संरचित हों।<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse bytes हमेशा हर limb के निचले सिरे पर aligned नहीं होते। यदि सीधे base-`2^w` में बदलने पर बड़े coefficients मिलें, तो ऐसे shifts `i,j` खोजें जिनसे `2^i p` और `2^j q` उस limb basis में sparse हो जाएँ। Product polynomial फिर भी public modulus से निकाला, factor किया और मूल integer factors में फिर से जोड़ा जा सकता है।<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

एक खतरनाक pattern में **32-bit limbs** की संख्या की गणना की जाती है, केवल उतने ही **bytes** allocate किए जाते हैं, और उन्हें limb array में copy किया जाता है:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

यह हर 32-bit limb में केवल **8 bits की entropy** छोड़ता है, साथ ही आखिरी limb में एक अनिवार्य top bit भी रखता है। परिणामी RSA primes को अक्सर केवल public key से पहचाना और factor किया जा सकता है।<sup>[[1]](#references)</sup>

### संबंधित DSA विफलता का तरीका

अगर उसी खराब big-integer routine का इस्तेमाल DSA private exponent बनाने के लिए किया जाता है, तो public key `y = g^x` से `x` के लिए **काफी कम और संरचित** search space leak हो सकता है। Limb pattern पता होने पर, **baby-step giant-step** जैसे discrete-log attacks public parameters के विरुद्ध व्यावहारिक हो सकते हैं।<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

अगर एक ही plaintext को कई recipients को छोटे `e` (अक्सर `e=3`) के साथ और उचित padding के बिना भेजा जाता है, तो CRT और integer root के ज़रिए `m` recover किया जा सकता है।

तकनीकी शर्त:

अगर आपके पास pairwise-coprime moduli `n_i` के तहत एक ही message के `e` ciphertexts हैं:

- CRT का इस्तेमाल करके `N = Π n_i` के गुणनफल पर `M = m^e` recover करें
- अगर `m^e < N` है, तो `M` वास्तविक integer power है, और `m = integer_root(M, e)`

### Wiener attack: छोटा private exponent

अगर `d` बहुत छोटा है, तो continued fractions के ज़रिए `e/n` से इसे recover किया जा सकता है।

### Textbook RSA की कमियाँ

अगर आपको दिखे:

- OAEP/PSS नहीं है, raw modular exponentiation है
- Deterministic encryption

तो algebraic attacks और oracle abuse की संभावना बहुत बढ़ जाती है।

### टूल

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## संबंधित-message पैटर्न

अगर आपको एक ही modulus के तहत दो ciphertexts दिखें, जिनके messages बीजगणितीय रूप से संबंधित हों (जैसे, `m2 = a*m1 + b`), तो Franklin–Reiter जैसे "related-message" attacks देखें। इनके लिए आमतौर पर ये ज़रूरी होते हैं:

- एक ही modulus `n`
- एक ही exponent `e`
- plaintexts के बीच ज्ञात संबंध

व्यवहार में, अक्सर Sage में `n` modulo polynomials सेट करके और GCD निकालकर इसे हल किया जाता है।

## Lattices / Coppersmith

जब आपके पास partial bits, structured plaintext या ऐसे निकट संबंध हों जिनसे अज्ञात मान छोटा हो, तब यह तरीका अपनाएँ।

जब भी आपके पास आंशिक जानकारी हो, lattice methods (LLL/Coppersmith) काम आते हैं:

- आंशिक रूप से ज्ञात plaintext (अज्ञात tail वाला structured message)
- आंशिक रूप से ज्ञात `p`/`q` (high bits leak हुए हों)
- संबंधित मानों के बीच छोटे अज्ञात अंतर

### किन बातों पर ध्यान दें

Challenges में आम संकेत:

- "हमने p के top/bottom bits leak किए"
- "Flag इस तरह embed किया गया है: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "हमने RSA इस्तेमाल किया, लेकिन छोटी random padding के साथ"

### टूलिंग

व्यवहार में, आप LLL के लिए Sage और उस विशेष instance के लिए एक ज्ञात template इस्तेमाल करेंगे।

शुरुआत के लिए अच्छे विकल्प:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- सर्वे-शैली का संदर्भ: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - polynomials के ज़रिए "short-sleeve" RSA keys को factor करना](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

