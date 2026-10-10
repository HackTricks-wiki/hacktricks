# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

कई उन्नत CTF क्रिप्टोग्राफी चुनौतियों में RSA, elliptic-curve cryptography (ECC), ECDSA, lattices या कमजोर randomness शामिल होते हैं।

## सुझाए गए टूल

- [SageMath](https://www.sagemath.org/) modular arithmetic, elliptic curves और lattice reduction के लिए<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) आम RSA कमजोरियों की जांच के लिए<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) यह जांचने के लिए कि किसी integer के ज्ञात factors हैं या नहीं<sup>[[3]](#references)</sup>
- key parsing, signing और verification के लिए Python [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

जब किसी चुनौती में `n`, `e` और `c` दिए हों और साथ में shared modulus, low exponent, partial key bits या related messages जैसा कोई hint हो, तो यहां से शुरू करें।

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

अगर signatures शामिल हों, तो यह मानने से पहले कि underlying discrete-logarithm problem को हल करना होगा, nonce reuse, bias या leakage की जांच करें।

### ECDSA nonce reuse / bias

ECDSA में हर message के लिए एक नया secret number `k` जरूरी है। अगर एक ही `k` से दो अलग-अलग message hashes पर signature किया जाता है, तो public signature values से private key recover की जा सकती है।<sup>[[4]](#references)</sup>

`k` एक जैसा न होने पर भी, कई signatures में nonce bits का bias या leakage lattice-based recovery संभव बना सकता है।<sup>[[5]](#references)</sup>

`k` के reuse होने पर recovery की तकनीकी विधि:<sup>[[4]](#references)</sup>

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

अगर दो messages `m1, m2` के लिए एक ही `k` reuse किया जाता है और signatures `(r, s1)` और `(r, s2)` मिलते हैं:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

अगर कोई protocol यह validate नहीं करता कि input point अपेक्षित curve पर है और सही subgroup में है, तो attacker कमजोर group में operations करवाकर secret scalar के बारे में जानकारी recover कर सकता है। SEC 1 ऐसे inputs को रोकने के लिए public-key validation checks निर्दिष्ट करता है।<sup>[[6]](#references)</sup>

तकनीकी नोट:

- Validate करें कि points point at infinity न हों, उनके coordinates मान्य हों, वे curve equation को satisfy करते हों और आवश्यक subgroup में हों।<sup>[[6]](#references)</sup>
- CTF चुनौतियों में, इसे अक्सर ऐसे model किया जाता है कि server attacker द्वारा चुने गए point को secret scalar से multiply करता है और derived value लौटाता है।

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: डिजिटल सिग्नेचर मानक](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner और Heninger: Biased Nonce Sense — कमजोर ECDSA signatures पर lattice attacks](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` दस्तावेज़](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
