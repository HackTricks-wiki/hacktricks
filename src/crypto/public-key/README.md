# पब्लिक-की क्रिप्टोग्राफी

{{#include ../../banners/hacktricks-training.md}}

कई उन्नत CTF क्रिप्टोग्राफी चुनौतियों में RSA, elliptic-curve cryptography (ECC), ECDSA, lattices या कमजोर randomness शामिल होते हैं।

## सुझाए गए टूल

- [SageMath](https://www.sagemath.org/) modular arithmetic, elliptic curves और lattice reduction के लिए<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) आम RSA कमजोरियों की जाँच के लिए<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) यह जाँचने के लिए कि किसी integer के ज्ञात factors हैं या नहीं<sup>[[3]](#references)</sup>
- key parsing, signing और verification के लिए Python की [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

जब किसी चुनौती में `n`, `e` और `c` दिए गए हों और साथ में shared modulus, low exponent, partial key bits या related messages जैसा कोई संकेत हो, तो यहाँ से शुरू करें।

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

यदि signatures शामिल हों, तो यह मानने से पहले कि underlying discrete-logarithm problem हल करनी होगी, nonce reuse, bias या leakage की जाँच करें।

### ECDSA nonce reuse / bias

ECDSA में हर message के लिए नया secret number `k` आवश्यक है। यदि एक ही `k` से दो अलग-अलग message hashes पर signatures बनाए गए हों, तो public signature values से private key recover की जा सकती है।<sup>[[4]](#references)</sup>

`k` एक जैसा न होने पर भी, कई signatures में nonce bits का bias या leakage lattice-based recovery को संभव बना सकता है।<sup>[[5]](#references)</sup>

`k` reuse होने पर recovery की तकनीकी प्रक्रिया:<sup>[[4]](#references)</sup>

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

यदि दो messages `m1, m2` के लिए एक ही `k` reuse किया जाए और signatures `(r, s1)` तथा `(r, s2)` बनें:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

यदि कोई protocol यह validate नहीं करता कि input point अपेक्षित curve पर है और सही subgroup में है, तो attacker कमज़ोर group में operations करवाकर secret scalar के बारे में जानकारी recover कर सकता है। SEC 1 ऐसे inputs को रोकने के लिए public-key validation checks निर्दिष्ट करता है।<sup>[[6]](#references)</sup>

तकनीकी टिप्पणी:

- Validate करें कि points point at infinity न हों, उनके coordinates valid हों, वे curve equation को संतुष्ट करते हों और आवश्यक subgroup में हों।<sup>[[6]](#references)</sup>
- CTF चुनौतियों में इसे अक्सर ऐसे model किया जाता है: server attacker द्वारा चुने गए point को secret scalar से multiply करता है और एक derived value लौटाता है।

## Malformed ML-DSA signing keys और rejection-sampling leakage

ML-DSA की expanded private key में polynomial vectors `s1` और `s2` को `[-η, η]` में coefficients के रूप में encode किया जाता है। FIPS 204 बताता है कि malformed secret-key bytes को decode करने पर इस range से बाहर के coefficients मिल सकते हैं। Signing algorithm में अपने-आप कोई अतिरिक्त private-key consistency check आवश्यक नहीं है।<sup>[[8]](#references)</sup>

यहाँ ज़रूरी शर्त है **expanded signing key को import करने या उससे sign करने से पहले उस पर नियंत्रण**, न कि verifier को malformed public key देना। कोई permissive import path बदले हुए packed coefficients स्वीकार कर सकता है और फिर भी ऐसे signatures बना सकता है जो verify हो जाएँ। [cryptographic key-encoding fuzzing workflow](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings) का उपयोग करके import और signing के दौरान acceptance की तुलना करें, फिर resulting signatures जाँचें।<sup>[[9]](#references)[[10]](#references)</sup>

Signing में `z = y + c·s1` और `r0 = LowBits(w − c·s2)` की गणना होती है। यदि `||z||∞ ≥ γ1 − β` या `||r0||∞ ≥ γ2 − β` हो, तो candidate को reject कर दिया जाता है। इन checks के कारण accepted outputs, valid छोटे secrets से independent रहते हैं। Range से बाहर के secret coefficients इस rejection-sampling तर्क को बिगाड़ सकते हैं और secret-dependent bias ला सकते हैं। यह एक conditional leakage mechanism है, **reported library discrepancy से full-key recovery का प्रदर्शित उदाहरण नहीं**।<sup>[[8]](#references)[[10]](#references)</sup>

Private-key validation और signature verification अलग-अलग चीज़ें हैं। Reported comparison में OpenSSL, BoringSSL और SymCrypt ने अतिरिक्त private-key checks लागू किए, जबकि liboqs ने signing के दौरान malformed expanded keys स्वीकार किए; इसके underlying `mldsa-native` में `pk_from_sk()` validator मौजूद है, जिसे liboqs ने उपलब्ध नहीं कराया। FIPS 204 इन अतिरिक्त validation checks को अनिवार्य नहीं करता।<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner और Heninger: Biased Nonce Sense — कमज़ोर ECDSA signatures पर lattice attacks](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` का दस्तावेज़ीकरण](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [ML-DSA और ML-KEM key checks की कमी - liboqs issue #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Post-Quantum Cryptography implementations की स्थिति](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
