# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

Most CTF hard crypto ends up here: RSA, ECC/ECDSA, lattices, and bad randomness.

## अनुशंसित टूलिंग

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (quick factor checks): http://factordb.com/

## RSA

Start here when you have `n,e,c` and some extra hint (shared modulus, low exponent, partial bits, related messages).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

If signatures are involved, test nonce problems first (reuse/bias/leaks) before assuming hard math.

### ECDSA nonce reuse / bias

If two signatures reuse the same nonce `k`, the private key can be recovered.

Even if `k` isn’t identical, **bias/leakage** of nonce bits across signatures can be enough for lattice recovery (common CTF theme).

Technical recovery when `k` is reused:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

If the same `k` is reused for two messages `m1, m2` producing signatures `(r, s1)` and `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

यदि कोई protocol यह सत्यापित करने में विफल रहता है कि points अपेक्षित curve (या subgroup) पर हैं, तो एक attacker कमजोर group में operations को मजबूर कर सकता है और secrets recover कर सकता है।

Technical note:

- Validate points are on-curve and in the correct subgroup.
- Many CTF tasks model this as "server multiplies attacker-chosen point by secret scalar and returns something."

### Tooling

- SageMath — curve arithmetic / lattices के लिए
- `ecdsa` Python library for parsing/verification

{{#include ../../banners/hacktricks-training.md}}
