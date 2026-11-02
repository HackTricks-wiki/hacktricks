# Kriptografia ya Ufunguo wa Umma

{{#include ../../banners/hacktricks-training.md}}

Changamoto nyingi za hali ya juu za kriptografia za CTF zinahusisha RSA, kriptografia ya curve za duaradufu (ECC), ECDSA, latisi, au randomness dhaifu.

## Zana zinazopendekezwa

- [SageMath](https://www.sagemath.org/) kwa hesabu za modular, curve za duaradufu, na upunguzaji wa latisi<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) kwa kujaribu udhaifu wa kawaida wa RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) kwa kuangalia kama integer ina factors zinazojulikana<sup>[[3]](#references)</sup>
- [Maktaba ya Python `ecdsa`](https://ecdsa.readthedocs.io/) kwa kuchanganua keys, kusaini, na kuthibitisha<sup>[[7]](#references)</sup>

## RSA

Anza hapa changamoto inapotoa `n`, `e`, na `c`, pamoja na kidokezo kama modulus ya pamoja, exponent ndogo, bits za key za sehemu, au messages zinazohusiana.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ikiwa signatures zinahusika, jaribu reuse, bias, au leakage ya nonce kabla ya kudhani kwamba ni lazima kutatua tatizo la msingi la discrete logarithm.

### Reuse / bias ya ECDSA nonce

ECDSA inahitaji nambari mpya ya siri `k` kwa kila message. Ikiwa `k` ileile itasaini hashes mbili tofauti za message, private key inaweza kurejeshwa kutoka kwa thamani za signature za umma.<sup>[[4]](#references)</sup>

Hata kama `k` si ileile, bias au leakage ya bits za nonce katika signatures nyingi inaweza kuwezesha urejeshaji unaotegemea latisi.<sup>[[5]](#references)</sup>

Urejeshaji wa kiufundi wakati `k` imetumika tena:<sup>[[4]](#references)</sup>

Milinganyo ya signature ya ECDSA (mpangilio wa group `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ikiwa `k` ileile imetumika tena kwa messages mbili `m1, m2` na kutoa signatures `(r, s1)` na `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Mashambulizi ya curve batili

Ikiwa protocol haithibitishi kwamba pointi ya ingizo iko kwenye curve inayotarajiwa na katika subgroup sahihi, mshambuliaji anaweza kulazimisha operesheni zitumie group dhaifu na kurejesha taarifa kuhusu scalar ya siri. SEC 1 inabainisha ukaguzi wa uthibitishaji wa public key unaokusudiwa kuzuia ingizo kama hizo.<sup>[[6]](#references)</sup>

Dokezo la kiufundi:

- Thibitisha kwamba pointi si pointi iliyo infinity, zina coordinates halali, zinakidhi mlinganyo wa curve, na ziko katika subgroup inayohitajika.<sup>[[6]](#references)</sup>
- Katika changamoto za CTF, hili mara nyingi huwakilishwa na server inayozidisha pointi iliyochaguliwa na mshambuliaji kwa scalar ya siri na kurudisha thamani iliyotokana nayo.

## Signing keys za ML-DSA zilizoharibika na leakage ya rejection-sampling

Private key iliyopanuliwa ya ML-DSA husimba polynomial vectors `s1` na `s2` zenye coefficients katika `[-η, η]`. FIPS 204 inabainisha kwamba decoding ya bytes zilizoharibika za secret key inaweza kutoa coefficients zilizo nje ya masafa haya. Algorithm ya signing haihitaji yenyewe ukaguzi wa ziada wa uthabiti wa private key.<sup>[[8]](#references)</sup>

Sharti husika ni kuwa na udhibiti wa **signing key iliyopanuliwa kabla haijaingizwa au kutumiwa kusaini**, si public key iliyoharibika inayowasilishwa kwa verifier. Njia ya import inayokubali data kwa urahisi inaweza kukubali coefficients zilizofungashwa zilizobadilishwa na bado kutoa signatures zinazothibitishwa. Linganisha kukubaliwa wakati wa import na signing, kisha kagua signatures zinazotokana nazo kwa kutumia [cryptographic key-encoding fuzzing workflow](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

Signing hukokotoa `z = y + c·s1` na `r0 = LowBits(w − c·s2)`, na hukataa candidate pale `||z||∞ ≥ γ1 − β` au `||r0||∞ ≥ γ2 − β`. Ukaguzi huu hufanya matokeo yanayokubaliwa yasiwe tegemezi kwa secrets halali zilizo ndogo. Coefficients za siri zilizo nje ya masafa zinaweza kuvuruga hoja hiyo ya rejection-sampling na kuleta bias inayotegemea siri. Huu ni utaratibu wa leakage wa masharti, **si** urejeshaji kamili wa key uliothibitishwa kutokana na tofauti iliyoripotiwa ya library.<sup>[[8]](#references)[[10]](#references)</sup>

Uthibitishaji wa private key ni tofauti na verification ya signature. Katika ulinganisho ulioripotiwa, OpenSSL, BoringSSL, na SymCrypt zilifanya ukaguzi wa ziada wa private key, huku liboqs ikikubali keys zilizopanuliwa zilizoharibika wakati wa signing; `mldsa-native` yake ya msingi ina validator ya `pk_from_sk()` ambayo liboqs haikuiweka wazi. FIPS 204 hailazimishi ukaguzi huo wa ziada wa uthibitishaji.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Kiwango cha Saini za Kidijitali](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner na Heninger: Hisia Potofu kuhusu Nonce Iliyopendelea — Mashambulizi ya Latisi dhidi ya Signatures Dhaifu za ECDSA](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kriptografia ya Curve za Duru](https://www.secg.org/sec1-v2.pdf)
- [7] [Nyaraka za Python `ecdsa`](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Kiwango cha Saini za Kidijitali Zinazotegemea Module-Lattice](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Ukosefu wa ukaguzi wa keys za ML-DSA na ML-KEM - suala #2517 la liboqs](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Hali ya Utekelezaji wa Kriptografia ya Baada ya Quantum](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
