# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}


CTF nyingi za hard crypto huishia hapa: RSA, ECC/ECDSA, lattices, na bad randomness.

## Zana zinazopendekezwa

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (ukaguzi wa haraka wa factors): http://factordb.com/

## RSA

Anza hapa unapokuwa na `n,e,c` na hint ya ziada (shared modulus, low exponent, partial bits, related messages).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ikiwa signatures zinahusika, kwanza test matatizo ya nonce (reuse/bias/leaks) kabla ya kudhani kuwa inahitaji hard math.

### ECDSA nonce reuse / bias

Ikiwa signatures mbili zinatumia nonce `k` ileile, private key inaweza kurecovered.

Hata kama `k` si identical, **bias/leakage** ya nonce bits katika signatures nyingi inaweza kutosha kwa lattice recovery (mada ya kawaida katika CTF).

Technical recovery wakati `k` inatumiwa tena:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ikiwa `k` ileile inatumiwa tena kwa messages mbili `m1, m2` zinazozalisha signatures `(r, s1)` na `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Ikiwa protocol inashindwa kuthibitisha kuwa points ziko kwenye curve inayotarajiwa (au subgroup), attacker anaweza kulazimisha operations kwenye weak group na kurecover secrets.

Technical note:

- Thibitisha kuwa points ziko on-curve na kwenye subgroup sahihi.
- CTF tasks nyingi huwasilisha hii kama "server multiplies attacker-chosen point by secret scalar and returns something."

### Zana

- SageMath kwa curve arithmetic / lattices
- `ecdsa` Python library kwa parsing/verification

{{#include ../../banners/hacktricks-training.md}}
