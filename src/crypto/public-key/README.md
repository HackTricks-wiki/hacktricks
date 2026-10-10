# Publieke-sleutel-kriptografie

{{#include ../../banners/hacktricks-training.md}}

Baie gevorderde CTF-kriptografie-uitdagings behels RSA, elliptiese-kromme-kriptografie (ECC), ECDSA, lattices of swak ewekansigheid.

## Aanbevole gereedskap

- [SageMath](https://www.sagemath.org/) vir modulêre rekenkunde, elliptiese krommes en lattice-reduksie<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) om algemene RSA-kwesbaarhede te toets<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) om te kyk of ’n heelgetal bekende faktore het<sup>[[3]](#references)</sup>
- Die Python-biblioteek [`ecdsa`](https://ecdsa.readthedocs.io/) vir sleutelontleding, ondertekening en verifikasie<sup>[[7]](#references)</sup>

## RSA

Begin hier wanneer ’n uitdaging `n`, `e` en `c` verskaf, saam met ’n wenk soos ’n gedeelde modulus, lae eksponent, gedeeltelike sleutelbisse of verwante boodskappe.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

As handtekeninge betrokke is, toets vir hergebruik van nonce, vooroordeel of uitlek voordat jy aanvaar dat die onderliggende diskrete-logaritmeprobleem opgelos moet word.

### Hergebruik / vooroordeel van ECDSA-nonce

ECDSA vereis ’n nuwe geheime getal `k` vir elke boodskap. As dieselfde `k` twee verskillende boodskaphashes onderteken, kan die private sleutel uit die publieke handtekeningwaardes herwin word.<sup>[[4]](#references)</sup>

Selfs wanneer `k` nie identies is nie, kan vooroordeel of uitlek van nonce-bisse oor baie handtekeninge lattice-gebaseerde herwinning moontlik maak.<sup>[[5]](#references)</sup>

Tegniese herwinning wanneer `k` hergebruik word:<sup>[[4]](#references)</sup>

ECDSA-handtekeningvergelykings (groeporde `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

As dieselfde `k` vir twee boodskappe `m1, m2` hergebruik word, wat handtekeninge `(r, s1)` en `(r, s2)` oplewer:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Aanvalle met ongeldige krommes

As ’n protokol nie bevestig dat ’n invoerpunt op die verwagte kromme lê en aan die korrekte subgroep behoort nie, kan ’n aanvaller bewerkings in ’n swakker groep afdwing en inligting oor ’n geheime skalaar herwin. SEC 1 spesifiseer publieke-sleutelvalideringskontroles wat bedoel is om sulke invoere te voorkom.<sup>[[6]](#references)</sup>

Tegniese nota:

- Bevestig dat punte nie die punt op oneindig is nie, geldige koördinate het, aan die krommevergelyking voldoen en aan die vereiste subgroep behoort.<sup>[[6]](#references)</sup>
- In CTF-uitdagings word dit dikwels gemodelleer as ’n bediener wat ’n punt wat deur ’n aanvaller gekies is met ’n geheime skalaar vermenigvuldig en ’n afgeleide waarde terugstuur.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digitale-handtekeningstandaard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner en Heninger: Biased Nonce Sense — Lattice-aanvalle teen swak ECDSA-handtekeninge](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptiese-kromme-kriptografie](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa`-dokumentasie](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
