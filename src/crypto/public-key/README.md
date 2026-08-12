# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

Birçok gelişmiş CTF cryptography challenge'ı RSA, elliptic-curve cryptography (ECC), ECDSA, lattices veya weak randomness içerir.

## Önerilen araçlar

- [SageMath](https://www.sagemath.org/) modular arithmetic, elliptic curves ve lattice reduction için<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) yaygın RSA zafiyetlerini test etmek için<sup>[[2]](#references)</sup>
- Bir integer'ın bilinen çarpanlara sahip olup olmadığını kontrol etmek için [FactorDB](https://factordb.com/)<sup>[[3]](#references)</sup>
- Key parsing, signing ve verification için Python [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

Bir challenge `n`, `e` ve `c` sağladığında ve shared modulus, low exponent, partial key bits veya related messages gibi bir ipucu verdiğinde buradan başlayın.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Signatures söz konusuysa, underlying discrete-logarithm problem'in çözülmesi gerektiğini varsaymadan önce nonce reuse, bias veya leak olup olmadığını test edin.

### ECDSA nonce reuse / bias

ECDSA, her mesaj için yeni bir secret number `k` gerektirir. Aynı `k` iki farklı message hash'i imzalamak için kullanılırsa private key, public signature değerlerinden recover edilebilir.<sup>[[4]](#references)</sup>

`k` aynı olmasa bile birçok signature boyunca nonce bit'lerindeki bias veya leak, lattice-based recovery'yi mümkün kılabilir.<sup>[[5]](#references)</sup>

`k` yeniden kullanıldığında teknik recovery:<sup>[[4]](#references)</sup>

ECDSA signature denklemleri (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Aynı `k`, `(r, s1)` ve `(r, s2)` signature'larını üreten iki mesaj `m1, m2` için yeniden kullanılırsa:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Bir protocol, bir input point'in beklenen curve üzerinde ve doğru subgroup içinde olduğunu validate edemezse attacker, daha weak bir group içinde operation'ları zorlayabilir ve secret scalar hakkında bilgi recover edebilir. SEC 1, bu tür input'ları önlemeyi amaçlayan public-key validation kontrollerini belirtir.<sup>[[6]](#references)</sup>

Technical note:

- Point'lerin point at infinity olmadığını, geçerli coordinate'lere sahip olduğunu, curve equation'ı sağladığını ve gerekli subgroup'a ait olduğunu validate edin.<sup>[[6]](#references)</sup>
- CTF challenge'larında bu genellikle server'ın attacker tarafından seçilen bir point'i secret scalar ile çarpması ve türetilmiş bir value döndürmesi şeklinde modellenir.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — Weak ECDSA Signatures'a karşı Lattice Attacks](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
