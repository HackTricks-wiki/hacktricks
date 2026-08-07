# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}


अधिकांश CTF का कठिन crypto आखिरकार यहीं आकर रुकता है: RSA, ECC/ECDSA, lattices और खराब randomness।

## Recommended tooling

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (त्वरित factor checks): http://factordb.com/

## RSA

जब आपके पास `n,e,c` और कोई अतिरिक्त hint हो (shared modulus, low exponent, partial bits, related messages), तो यहां से शुरू करें।

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

यदि signatures शामिल हों, तो कठिन mathematics मानने से पहले nonce problems (reuse/bias/leaks) की जांच करें।

### ECDSA nonce reuse / bias

यदि दो signatures में एक ही nonce `k` का reuse हो, तो private key recover की जा सकती है।

भले ही `k` बिल्कुल समान न हो, signatures में nonce bits का **bias/leakage** lattice recovery के लिए पर्याप्त हो सकता है (यह एक सामान्य CTF theme है)।

जब `k` का reuse हो, तब technical recovery:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

यदि एक ही `k` को दो messages `m1, m2` के लिए reuse किया जाए और signatures `(r, s1)` तथा `(r, s2)` प्राप्त हों:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

यदि कोई protocol यह validate करने में विफल रहता है कि points अपेक्षित curve (या subgroup) पर हैं, तो attacker operations को किसी weak group में कराने और secrets recover करने के लिए मजबूर कर सकता है।

Technical note:

- Validate करें कि points on-curve और correct subgroup में हैं।
- कई CTF tasks इसे इस रूप में model करते हैं: "server attacker-chosen point को secret scalar से multiply करता है और कुछ return करता है।"

### Tooling

- Curve arithmetic / lattices के लिए SageMath
- Parsing/verification के लिए `ecdsa` Python library

{{#include ../../banners/hacktricks-training.md}}
