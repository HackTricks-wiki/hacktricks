# Kriptografia ya Ufunguo wa Umma

{{#include ../../banners/hacktricks-training.md}}

Mara nyingi crypto ngumu za CTF zinaishia hapa: RSA, ECC/ECDSA, lattices, na randomness mbaya.

## Zana zilizopendekezwa

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (quick factor checks): http://factordb.com/

## RSA

Anza hapa unapokuwa na `n,e,c` na dalili za ziada (shared modulus, low exponent, partial bits, related messages).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ikiwa signatures zinahusishwa, kagua matatizo ya nonce kwanza (reuse/bias/leaks) kabla ya kudhani ni hesabu ngumu.

### ECDSA nonce reuse / bias

Ikiwa signatures mbili zinatumia tena nonce ile ile `k`, funguo binafsi inaweza kurejeshwa.

Hata kama `k` sio sawa kabisa, **bias/leakage** ya bit za nonce katika signatures inaweza kutosha kwa recovery ya lattice (mada ya kawaida ya CTF).

Technical recovery when `k` is reused:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

If the same `k` is reused for two messages `m1, m2` producing signatures `(r, s1)` and `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Inapotumika itifaki bila kuthibitisha kwamba point ziko kwenye curve inayotarajiwa (au subgroup sahihi), mshambuliaji anaweza kulazimisha operesheni katika group dhaifu na kurejesha siri.

Technical note:

- Validate points are on-curve and in the correct subgroup.
- Many CTF tasks model this as "server multiplies attacker-chosen point by secret scalar and returns something."

### Vyombo

- SageMath for curve arithmetic / lattices
- `ecdsa` Python library kwa kuchanganua/uthibitisho

{{#include ../../banners/hacktricks-training.md}}
