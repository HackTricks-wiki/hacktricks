# Publieke-sleutel-kriptografie

{{#include ../../banners/hacktricks-training.md}}

Baie gevorderde CTF-kriptografie-uitdagings behels RSA, elliptiese-kromme-kriptografie (ECC), ECDSA, roosters of swak ewekansigheid.

## Aanbevole gereedskap

- [SageMath](https://www.sagemath.org/) vir modulêre rekenkunde, elliptiese krommes en roosterreduksie<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) om algemene RSA-swakhede te toets<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) om te kyk of ’n heelgetal bekende faktore het<sup>[[3]](#references)</sup>
- Die Python-[`ecdsa`-biblioteek](https://ecdsa.readthedocs.io/) vir sleutelontleding, ondertekening en verifikasie<sup>[[7]](#references)</sup>

## RSA

Begin hier wanneer ’n uitdaging `n`, `e` en `c` verskaf, saam met ’n wenk soos ’n gedeelde modulus, lae eksponent, gedeeltelike sleutelbisse of verwante boodskappe.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

As handtekeninge betrokke is, toets vir nonce-hergebruik, vooroordeel of lekkasie voordat jy aanvaar dat die onderliggende diskrete-logaritmeprobleem opgelos moet word.

### ECDSA-nonce-hergebruik / vooroordeel

ECDSA vereis ’n vars geheime getal `k` vir elke boodskap. As dieselfde `k` twee verskillende boodskaphashes onderteken, kan die private sleutel uit die publieke handtekeningwaardes herwin word.<sup>[[4]](#references)</sup>

Selfs wanneer `k` nie identies is nie, kan vooroordeel of lekkasie van nonce-bisse oor baie handtekeninge roostergebaseerde herwinning moontlik maak.<sup>[[5]](#references)</sup>

Tegniese herwinning wanneer `k` hergebruik word:<sup>[[4]](#references)</sup>

ECDSA-handtekeningsvergelykings (groeporde `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

As dieselfde `k` vir twee boodskappe `m1, m2` hergebruik word, wat handtekeninge `(r, s1)` en `(r, s2)` oplewer:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Ongeldige-kromme-aanvalle

As ’n protokol nie bevestig dat ’n invoerpunt op die verwagte kromme lê en in die korrekte deelgroep is nie, kan ’n aanvaller bewerkings in ’n swakker groep afdwing en inligting oor ’n geheime skalaar herwin. SEC 1 spesifiseer publieke-sleutel-valideringstoetse wat bedoel is om sulke invoere te voorkom.<sup>[[6]](#references)</sup>

Tegniese nota:

- Bevestig dat punte nie die punt op oneindig is nie, geldige koördinate het, aan die krommevergelyking voldoen en tot die vereiste deelgroep behoort.<sup>[[6]](#references)</sup>
- In CTF-uitdagings word dit dikwels gemodelleer as ’n bediener wat ’n aanvallergekose punt met ’n geheime skalaar vermenigvuldig en ’n afgeleide waarde terugstuur.

## Misvormde ML-DSA-ondertekeningsleutels en lekkasie deur verwerpingssteekproefneming

ML-DSA se uitgebreide private sleutel kodeer polinoomvektore `s1` en `s2` met koëffisiënte in `[-η, η]`. FIPS 204 merk op dat die dekodering van misvormde geheime-sleutelgrepe koëffisiënte buite hierdie reeks kan oplewer. Die ondertekeningsalgoritme vereis nie self ’n bykomende konsekwentheidstoets vir die private sleutel nie.<sup>[[8]](#references)</sup>

Die relevante voorvereiste is beheer oor ’n **uitgebreide ondertekeningsleutel voordat dit ingevoer of gebruik word om te onderteken**, nie ’n misvormde publieke sleutel wat by ’n verifieerder ingedien word nie. ’n Toegeeflike invoerpad kan veranderde gepakte koëffisiënte aanvaar en steeds handtekeninge lewer wat verifieer. Vergelyk die aanvaarding tydens invoer en ondertekening, en kontroleer dan die gevolglike handtekeninge deur die [kriptografiese sleutel-enkodering-fuzzing-werkvloei](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings) te gebruik.<sup>[[9]](#references)[[10]](#references)</sup>

Ondertekening bereken `z = y + c·s1` en `r0 = LowBits(w − c·s2)`, en verwerp ’n kandidaat wanneer `||z||∞ ≥ γ1 − β` of `||r0||∞ ≥ γ2 − β`. Hierdie toetse maak aanvaarde uitsette onafhanklik van die geldige klein geheime. Koëffisiënte van geheime wat buite die reeks val, kan hierdie argument vir verwerpingssteekproefneming ondermyn en ’n geheim-afhanklike vooroordeel veroorsaak. Dit is ’n voorwaardelike lekkasiemeganisme, **nie** ’n gedemonstreerde herwinning van die volledige sleutel op grond van die gerapporteerde biblioteekverskil nie.<sup>[[8]](#references)[[10]](#references)</sup>

Private-sleutel-validering verskil van handtekeningverifikasie. In die gerapporteerde vergelyking het OpenSSL, BoringSSL en SymCrypt ekstra private-sleuteltoetse toegepas, terwyl liboqs misvormde uitgebreide sleutels tydens ondertekening aanvaar het; die onderliggende `mldsa-native` daarvan verskaf ’n `pk_from_sk()`-valideerder wat liboqs nie blootgelê het nie. FIPS 204 vereis nie hierdie ekstra valideringstoetse nie.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digitale handtekeningstandaard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner en Heninger: Vooroordeel in nonce — Roosteraanvalle teen swak ECDSA-handtekeninge](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptiese-kromme-kriptografie](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa`-dokumentasie](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Digitale handtekeningstandaard gebaseer op module-roosters](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Ontbrekende ML-DSA- en ML-KEM-sleuteltoetse - liboqs-kwessie #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Die stand van post-kwantumkriptografie-implementerings](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
