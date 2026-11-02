# Kriptografija javnim ključem

{{#include ../../banners/hacktricks-training.md}}

Mnogi napredni CTF izazovi iz kriptografije uključuju RSA, kriptografiju eliptičkih krivih (ECC), ECDSA, rešetke ili slabu slučajnost.

## Preporučeni alati

- [SageMath](https://www.sagemath.org/) za modularnu aritmetiku, eliptičke krive i redukciju rešetki<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) za testiranje uobičajenih slabosti RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) za proveru da li ceo broj ima poznate činioce<sup>[[3]](#references)</sup>
- Python biblioteka [`ecdsa`](https://ecdsa.readthedocs.io/) za parsiranje ključeva, potpisivanje i verifikaciju<sup>[[7]](#references)</sup>

## RSA

Počnite ovde kada izazov pruža `n`, `e` i `c`, uz nagoveštaj kao što je zajednički modul, mali eksponent, delimični bitovi ključa ili povezane poruke.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ako su uključeni potpisi, proverite da li je došlo do ponovne upotrebe nonce-a, pristrasnosti ili curenja pre nego što pretpostavite da morate rešiti problem diskretnog logaritma.

### Ponovna upotreba nonce-a / pristrasnost kod ECDSA

ECDSA zahteva nov tajni broj `k` za svaku poruku. Ako isti `k` potpiše dva različita sažetka poruke, privatni ključ može se oporaviti iz javnih vrednosti potpisa.<sup>[[4]](#references)</sup>

Čak i kada `k` nije isti, pristrasnost ili leak bitova nonce-a u mnogim potpisima mogu omogućiti oporavak zasnovan na rešetkama.<sup>[[5]](#references)</sup>

Tehnički postupak oporavka kada se `k` ponovo upotrebi:<sup>[[4]](#references)</sup>

Jednačine potpisa ECDSA (red grupe `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ako se isti `k` ponovo upotrebi za dve poruke `m1, m2`, čime nastanu potpisi `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Napadi nevažećom krivom

Ako protokol ne proveri da li ulazna tačka leži na očekivanoj krivoj i u odgovarajućoj podgrupi, napadač može da nametne operacije u slabijoj grupi i oporavi informacije o tajnom skalaru. SEC 1 definiše provere validnosti javnog ključa koje treba da spreče takve ulaze.<sup>[[6]](#references)</sup>

Tehnička napomena:

- Proverite da tačke nisu tačka u beskonačnosti, da imaju validne koordinate, zadovoljavaju jednačinu krive i pripadaju zahtevanoj podgrupi.<sup>[[6]](#references)</sup>
- U CTF izazovima, ovo se često modeluje tako što server množi tačku koju je izabrao napadač tajnim skalarom i vraća izvedenu vrednost.

## Neispravni ključevi za potpisivanje ML-DSA i leak usled odbacivanja uzoraka

Prošireni privatni ključ ML-DSA kodira polinomske vektore `s1` i `s2` čiji su koeficijenti u opsegu `[-η, η]`. FIPS 204 napominje da dekodiranje neispravnih bajtova tajnog ključa može proizvesti koeficijente izvan tog opsega. Algoritam za potpisivanje sam po sebi ne zahteva dodatnu proveru konzistentnosti privatnog ključa.<sup>[[8]](#references)</sup>

Relevantan preduslov je kontrola nad **proširenim ključem za potpisivanje pre nego što se on uveze ili upotrebi za potpisivanje**, a ne slanje neispravnog javnog ključa verifikatoru. Popustljiva putanja za uvoz može prihvatiti izmenjene upakovane koeficijente, a ipak proizvesti potpise koji prolaze verifikaciju. Uporedite prihvatanje pri uvozu i potpisivanju, a zatim proverite dobijene potpise pomoću [radnog postupka za fuzzing kodiranja kriptografskih ključeva](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

Potpisivanje izračunava `z = y + c·s1` i `r0 = LowBits(w − c·s2)`, odbacujući kandidata kada je `||z||∞ ≥ γ1 − β` ili `||r0||∞ ≥ γ2 − β`. Ove provere čine prihvaćene izlaze nezavisnim od validnih malih tajnih vrednosti. Koeficijenti tajnog ključa izvan opsega mogu narušiti taj argument za odbacivanje uzoraka i uvesti pristrasnost zavisnu od tajnih vrednosti. Ovo je uslovni mehanizam curenja, **a ne demonstriran oporavak celog ključa na osnovu prijavljenog neslaganja između biblioteka**.<sup>[[8]](#references)[[10]](#references)</sup>

Validacija privatnog ključa razlikuje se od verifikacije potpisa. U prijavljenom poređenju, OpenSSL, BoringSSL i SymCrypt primenili su dodatne provere privatnog ključa, dok je liboqs prihvatao neispravne proširene ključeve tokom potpisivanja; osnovni `mldsa-native` sadrži validator `pk_from_sk()`, koji liboqs nije izložio. FIPS 204 ne nalaže te dodatne provere validacije.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard za digitalni potpis](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner i Heninger: Biased Nonce Sense — napadi rešetkama na slabe ECDSA potpise](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kriptografija eliptičkih krivih](https://www.secg.org/sec1-v2.pdf)
- [7] [Python dokumentacija za `ecdsa`](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Standard za digitalni potpis zasnovan na modulskim rešetkama](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Nedostajuće provere ključeva za ML-DSA i ML-KEM - liboqs issue #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Stanje implementacija postkvantne kriptografije](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
