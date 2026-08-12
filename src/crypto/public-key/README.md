# Kriptografija javnog ključa

{{#include ../../banners/hacktricks-training.md}}

Mnogi napredni CTF kriptografski izazovi uključuju RSA, kriptografiju eliptičkih krivih (ECC), ECDSA, rešetke ili slabu slučajnost.

## Preporučeni alati

- [SageMath](https://www.sagemath.org/) za modularnu aritmetiku, eliptičke krive i redukciju rešetki<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) za testiranje uobičajenih RSA slabosti<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) za proveru da li ceo broj ima poznate faktore<sup>[[3]](#references)</sup>
- Python [`ecdsa` library](https://ecdsa.readthedocs.io/) za parsiranje ključeva, potpisivanje i verifikaciju<sup>[[7]](#references)</sup>

## RSA

Počnite ovde kada izazov pruža `n`, `e` i `c`, uz nagoveštaj kao što su zajednički modulus, mali eksponent, delimični bitovi ključa ili povezane poruke.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ako su uključeni potpisi, testirajte ponovnu upotrebu nonce-a, pristrasnost ili curenje pre nego što pretpostavite da se osnovni problem diskretnog logaritma mora rešiti.

### ECDSA nonce reuse / bias

ECDSA zahteva novi tajni broj `k` za svaku poruku. Ako isti `k` potpiše dva različita hash-a poruka, privatni ključ može biti oporavljen iz javnih vrednosti potpisa.<sup>[[4]](#references)</sup>

Čak i kada `k` nije identičan, pristrasnost ili curenje bitova nonce-a kroz veliki broj potpisa može omogućiti oporavak zasnovan na rešetkama.<sup>[[5]](#references)</sup>

Tehnički oporavak kada se `k` ponovo koristi:<sup>[[4]](#references)</sup>

ECDSA jednačine potpisa (redosled grupe `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ako se isti `k` ponovo koristi za dve poruke `m1, m2`, koje daju potpise `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Ako protokol ne proverava da se ulazna tačka nalazi na očekivanoj krivoj i u odgovarajućoj podgrupi, napadač može primorati operacije u slabijoj grupi i oporaviti informacije o tajnom skalaru. SEC 1 definiše provere validacije javnog ključa namenjene sprečavanju takvih ulaza.<sup>[[6]](#references)</sup>

Tehnička napomena:

- Proverite da tačke nisu tačka u beskonačnosti, da imaju važeće koordinate, da zadovoljavaju jednačinu krive i da pripadaju zahtevanoj podgrupi.<sup>[[6]](#references)</sup>
- U CTF izazovima ovo se često modeluje kao server koji množi tačku koju je izabrao napadač tajnim skalarom i vraća izvedenu vrednost.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard digitalnog potpisa](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — Lattice Attacks against Weak ECDSA Signatures](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kriptografija eliptičkih krivih](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
