# Publieke-sleutel-kriptografie

{{#include ../../banners/hacktricks-training.md}}

Baie gevorderde CTF-kriptografie-uitdagings behels RSA, elliptiese-kromme-kriptografie (ECC), ECDSA, lattices of swak ewekansigheid.

## Aanbevole tooling

- [SageMath](https://www.sagemath.org/) vir modulêre rekenkunde, elliptiese krommes en lattice reduction<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) vir die toets van algemene RSA-weaknesses<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) om te kontroleer of ’n heelgetal bekende faktore het<sup>[[3]](#references)</sup>
- Die Python [`ecdsa` library](https://ecdsa.readthedocs.io/) vir key parsing, signing en verification<sup>[[7]](#references)</sup>

## RSA

Begin hier wanneer ’n challenge `n`, `e` en `c` verskaf, plus ’n hint soos ’n shared modulus, low exponent, partial key bits of related messages.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

As signatures betrokke is, toets vir nonce reuse, bias of leakage voordat jy aanvaar dat die onderliggende discrete-logarithm-probleem opgelos moet word.

### ECDSA nonce reuse / bias

ECDSA vereis ’n vars secret number `k` per boodskap. As dieselfde `k` twee verskillende boodskap-hashes sign, kan die private key uit die publieke signature values herwin word.<sup>[[4]](#references)</sup>

Selfs wanneer `k` nie identies is nie, kan bias of leakage van nonce-bits oor baie signatures lattice-based recovery moontlik maak.<sup>[[5]](#references)</sup>

Technical recovery wanneer `k` hergebruik word:<sup>[[4]](#references)</sup>

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

As dieselfde `k` vir twee boodskappe `m1, m2` hergebruik word en signatures `(r, s1)` en `(r, s2)` produseer:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

As ’n protokol nie valideer dat ’n input point op die verwagte curve en in die korrekte subgroup lê nie, kan ’n aanvaller bewerkings in ’n weaker group afdwing en inligting oor ’n secret scalar herwin. SEC 1 spesifiseer public-key validation checks wat bedoel is om sulke inputs te voorkom.<sup>[[6]](#references)</sup>

Technical note:

- Valideer dat points nie die point at infinity is nie, geldige coordinates het, aan die curve equation voldoen en aan die vereiste subgroup behoort.<sup>[[6]](#references)</sup>
- In CTF challenges word dit dikwels gemodelleer as ’n server wat ’n attacker-chosen point met ’n secret scalar vermenigvuldig en ’n derived value terugstuur.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digitale Handtekeningstandaard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner en Heninger: Biased Nonce Sense — Lattice-aanvalle teen swak ECDSA-handtekeninge](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptiese Kromme-kriptografie](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa`-dokumentasie](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
