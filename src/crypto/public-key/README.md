# Kriptografija javnim ključem

{{#include ../../banners/hacktricks-training.md}}

Mnogi napredni CTF izazovi iz kriptografije obuhvataju RSA, kriptografiju eliptičnih krivih (ECC), ECDSA, rešetke ili slabu slučajnost.

## Preporučeni alati

- [SageMath](https://www.sagemath.org/) za modularnu aritmetiku, eliptične krive i redukciju rešetki<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) za testiranje uobičajenih slabosti RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) za proveru da li neki ceo broj ima poznate faktore<sup>[[3]](#references)</sup>
- Python biblioteka [`ecdsa`](https://ecdsa.readthedocs.io/) za učitavanje ključeva, potpisivanje i verifikaciju<sup>[[7]](#references)</sup>

## RSA

Počnite ovde kada izazov sadrži `n`, `e` i `c`, uz naznaku kao što su zajednički modul, mali eksponent, delimični bitovi ključa ili povezane poruke.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ako su uključeni potpisi, proverite ponovnu upotrebu nonce vrednosti, pristrasnost ili leakage pre nego što pretpostavite da morate rešiti osnovni problem diskretnog logaritma.

### ECDSA nonce reuse / pristrasnost

ECDSA zahteva nov tajni broj `k` za svaku poruku. Ako ista vrednost `k` potpiše dva različita sažetka poruka, privatni ključ može se oporaviti iz javnih vrednosti potpisa.<sup>[[4]](#references)</sup>

Čak i kada `k` nije identičan, pristrasnost ili leakage bitova nonce vrednosti kroz mnogo potpisa mogu omogućiti oporavak zasnovan na rešetkama.<sup>[[5]](#references)</sup>

Tehnički postupak oporavka kada se `k` ponovo koristi:<sup>[[4]](#references)</sup>

Jednačine ECDSA potpisa (red grupe `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ako se ista vrednost `k` ponovo koristi za dve poruke `m1, m2`, koje daju potpise `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Ako protokol ne proverava da li se ulazna tačka nalazi na očekivanoj krivoj i u ispravnoj podgrupi, napadač može da nametne operacije u slabijoj grupi i oporavi informacije o tajnom skalaru. Standard SEC 1 definiše provere validacije javnog ključa kojima se sprečavaju takvi ulazi.<sup>[[6]](#references)</sup>

Tehnička napomena:

- Proverite da tačke nisu tačka u beskonačnosti, da imaju validne koordinate, zadovoljavaju jednačinu krive i pripadaju zahtevanoj podgrupi.<sup>[[6]](#references)</sup>
- U CTF izazovima, ovo se često modeluje tako što server množi tačku koju je izabrao napadač tajnim skalarom i vraća izvedenu vrednost.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard za digitalne potpise](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner i Heninger: Pristrasni nonce — napadi rešetkama na slabe ECDSA potpise](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kriptografija eliptičnih krivih](https://www.secg.org/sec1-v2.pdf)
- [7] [Python dokumentacija za `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
