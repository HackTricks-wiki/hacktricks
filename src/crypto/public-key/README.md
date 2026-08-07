# Openbare-sleutel-kriptografie

{{#include ../../banners/hacktricks-training.md}}


Die meeste CTF hard crypto eindig hier: RSA, ECC/ECDSA, lattices en swak randomness.

## Aanbevole tools

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (vinnige faktor-kontroles): http://factordb.com/

## RSA

Begin hier wanneer jy `n,e,c` en ’n ekstra hint het (gedeelde modulus, lae eksponent, gedeeltelike bisse, verwante boodskappe).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Indien signatures betrokke is, toets eers vir nonce-probleme (hergebruik/bias/leaks) voordat jy aanvaar dat dit moeilike wiskunde vereis.

### ECDSA nonce reuse / bias

Indien twee signatures dieselfde nonce `k` hergebruik, kan die private key herwin word.

Selfs indien `k` nie identies is nie, kan **bias/leakage** van nonce-bisse oor signatures genoeg wees vir lattice recovery (’n algemene CTF-tema).

Tegniese recovery wanneer `k` hergebruik word:

ECDSA signature equations (groeporde `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Indien dieselfde `k` vir twee boodskappe `m1, m2` hergebruik word en signatures `(r, s1)` en `(r, s2)` produseer:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Indien ’n protokol nie valideer dat punte op die verwagte curve (of subgroup) is nie, kan ’n aanvaller bewerkings in ’n swak groep afdwing en secrets herwin.

Tegniese nota:

- Valideer dat punte on-curve en in die korrekte subgroup is.
- Baie CTF-take modelleer dit as "server vermenigvuldig ’n aanvallergekose punt met ’n geheime scalar en retourneer iets."

### Tools

- SageMath vir curve arithmetic / lattices
- `ecdsa` Python library vir parsing/verifikasie

{{#include ../../banners/hacktricks-training.md}}
