# Publieke-sleutel-kriptografie

{{#include ../../banners/hacktricks-training.md}}

Die meeste moeilike CTF-crypto eindig hier: RSA, ECC/ECDSA, lattices, en swak willekeurigheid.

## Aanbevole gereedskap

- SageMath (LLL/lattices, modulêre rekenkunde): https://www.sagemath.org/
- RsaCtfTool (veeldoelige gereedskap): https://github.com/Ganapati/RsaCtfTool
- factordb (vinnige faktor kontroles): http://factordb.com/

## RSA

Begin hier as jy `n,e,c` en 'n ekstra wenk het (gedeelde modulus, lae eksponent, gedeeltelike bits, verwante boodskappe).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

As handtekeninge betrokke is, toets eers nonce-probleme (reuse/bias/leaks) voordat jy moeilike wiskunde aanvaar.

### ECDSA nonce hergebruik / bias

As twee handtekeninge dieselfde nonce `k` hergebruik, kan die private sleutel herstel word.

Selfs as `k` nie identies is nie, **bias/leakage** van nonce-bits oor handtekeninge kan genoeg wees vir lattice recovery (algemene CTF-tema).

Tekniese herstel wanneer `k` hergebruik word:

ECDSA-handtekeningvergelykings (groeporde `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

As dieselfde `k` hergebruik word vir twee boodskappe `m1, m2` wat handtekeninge `(r, s1)` en `(r, s2)` produseer:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve-aanvalle

As 'n protokol nie valideer dat punte op die verwagte curve (of subgroep) is nie, kan 'n aanvaller operasies in 'n swak groep afdwing en geheime herstel.

Tegniese nota:

- Valideer dat punte op die curve is en in die korrekte subgroep.
- Baie CTF-take modelleer dit as "server multiplies attacker-chosen point by secret scalar and returns something."

### Gereedskap

- SageMath vir curve-aritmetiek / lattices
- `ecdsa` Python-biblioteek vir ontleding/verifikasie

{{#include ../../banners/hacktricks-training.md}}
