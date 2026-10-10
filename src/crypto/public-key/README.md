# Kriptografia ya Ufunguo wa Umma

{{#include ../../banners/hacktricks-training.md}}

Changamoto nyingi za hali ya juu za cryptography za CTF zinahusisha RSA, elliptic-curve cryptography (ECC), ECDSA, lattices, au randomness dhaifu.

## Zana zinazopendekezwa

- [SageMath](https://www.sagemath.org/) kwa hesabu za modular, mikunjo ya elliptic, na upunguzaji wa lattice<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) kwa kupima udhaifu wa kawaida wa RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) kwa kuangalia kama nambari kamili ina factors zinazojulikana<sup>[[3]](#references)</sup>
- Python [`ecdsa library`](https://ecdsa.readthedocs.io/) kwa kuchanganua keys, kusaini, na kuthibitisha<sup>[[7]](#references)</sup>

## RSA

Anzia hapa ikiwa changamoto inatoa `n`, `e`, na `c`, pamoja na dokezo kama modulus inayoshirikiwa, exponent ndogo, bits za key zilizotolewa kwa sehemu, au ujumbe unaohusiana.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ikiwa signatures zinahusika, jaribu kubaini kama kuna nonce inayotumika tena, upendeleo, au uvujaji kabla ya kudhani kwamba lazima utatue tatizo la discrete logarithm.

### Matumizi tena ya nonce ya ECDSA / upendeleo

ECDSA inahitaji nambari ya siri mpya ya kila ujumbe `k`. Ikiwa `k` ileile itasaini hashes mbili tofauti za ujumbe, private key inaweza kupatikana kutokana na thamani za signature za umma.<sup>[[4]](#references)</sup>

Hata kama `k` si ileile, upendeleo au uvujaji wa bits za nonce katika signatures nyingi unaweza kuruhusu urejeshaji unaotegemea lattice.<sup>[[5]](#references)</sup>

Urejeshaji wa kiufundi wakati `k` inatumiwa tena:<sup>[[4]](#references)</sup>

Milinganyo ya signature ya ECDSA (mpangilio wa kundi `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ikiwa `k` ileile inatumiwa tena kwa ujumbe miwili `m1, m2` na kutoa signatures `(r, s1)` na `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Ikiwa itifaki haitathibitisha kwamba pointi ya ingizo iko kwenye curve inayotarajiwa na kwenye subgroup sahihi, mshambuliaji anaweza kulazimisha utendakazi ufanyike katika kundi dhaifu na kupata taarifa kuhusu scalar ya siri. SEC 1 inabainisha ukaguzi wa uthibitishaji wa public key unaokusudiwa kuzuia ingizo za aina hii.<sup>[[6]](#references)</sup>

Dokezo la kiufundi:

- Thibitisha kwamba pointi si pointi ya infinity, ina coordinates halali, inatimiza mlinganyo wa curve, na iko kwenye subgroup inayohitajika.<sup>[[6]](#references)</sup>
- Katika changamoto za CTF, mara nyingi hali hii huigwa kwa seva kuzidisha pointi iliyochaguliwa na mshambuliaji kwa scalar ya siri na kurudisha thamani iliyotokana nayo.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Kiwango cha Saini za Kidijitali](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner na Heninger: Hisia za Nonce Yenye Upendeleo — Mashambulizi ya Lattice dhidi ya Saini Dhaifu za ECDSA](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kriptografia ya Mikunjo ya Elliptic](https://www.secg.org/sec1-v2.pdf)
- [7] [Nyaraka za Python `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
