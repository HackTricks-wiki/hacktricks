# Açık Anahtarlı Kriptografi

{{#include ../../banners/hacktricks-training.md}}

Birçok ileri seviye CTF kriptografi challenge'ı RSA, eliptik eğri kriptografisi (ECC), ECDSA, lattice'ler veya zayıf rastgelelik içerir.

## Önerilen araçlar

- Modüler aritmetik, eliptik eğriler ve lattice reduction için [SageMath](https://www.sagemath.org/)<sup>[[1]](#references)</sup>
- Yaygın RSA zayıflıklarını test etmek için [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)<sup>[[2]](#references)</sup>
- Bir tamsayının bilinen çarpanları olup olmadığını kontrol etmek için [FactorDB](https://factordb.com/)<sup>[[3]](#references)</sup>
- Anahtar ayrıştırma, imzalama ve doğrulama için Python [`ecdsa` kütüphanesi](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

Bir challenge `n`, `e` ve `c` değerlerini; ayrıca ortak modulus, düşük üs, kısmi anahtar bitleri veya ilişkili mesajlar gibi bir ipucunu sağlıyorsa buradan başlayın.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

İmzalar söz konusuysa, altta yatan discrete-logarithm problemini çözmeniz gerektiğini varsaymadan önce nonce tekrarını, bias'ı veya leak'i test edin.

### ECDSA nonce reuse / bias

ECDSA, her mesaj için yeni bir gizli `k` sayısı gerektirir. Aynı `k` iki farklı mesaj hash'ini imzalamak için kullanılırsa, imza değerlerinden özel anahtar kurtarılabilir.<sup>[[4]](#references)</sup>

`k` aynı olmasa bile, çok sayıda imzadaki bias veya nonce bitlerinin leak'i lattice tabanlı kurtarmayı mümkün kılabilir.<sup>[[5]](#references)</sup>

`k` yeniden kullanıldığında teknik kurtarma:<sup>[[4]](#references)</sup>

ECDSA imza denklemleri (grup mertebesi `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Aynı `k`, `(r, s1)` ve `(r, s2)` imzalarını üreten iki `m1, m2` mesajı için yeniden kullanılırsa:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Geçersiz eğri saldırıları

Bir protokol, girdi noktasının beklenen eğri üzerinde ve doğru alt grupta olduğunu doğrulamazsa saldırgan, işlemleri daha zayıf bir grupta yaptırabilir ve gizli bir scalar hakkında bilgi kurtarabilir. SEC 1, bu tür girdileri önlemeyi amaçlayan açık anahtar doğrulama kontrollerini belirtir.<sup>[[6]](#references)</sup>

Teknik not:

- Noktaların sonsuzdaki nokta olmadığını, geçerli koordinatlara sahip olduğunu, eğri denklemini sağladığını ve gerekli alt gruba ait olduğunu doğrulayın.<sup>[[6]](#references)</sup>
- CTF challenge'larında bu durum genellikle bir saldırganın seçtiği noktayı gizli bir scalar ile çarpıp türetilmiş bir değer döndüren sunucu olarak modellenir.

## Bozuk ML-DSA imzalama anahtarları ve rejection-sampling leak'i

ML-DSA'nın genişletilmiş özel anahtarı, katsayıları `[-η, η]` aralığında olan polinom vektörleri `s1` ve `s2`'yi kodlar. FIPS 204, bozuk özel anahtar baytlarının çözülmesinin bu aralığın dışındaki katsayılar üretebileceğini belirtir. İmzalama algoritması ayrıca bir özel anahtar tutarlılık kontrolü yapılmasını gerektirmez.<sup>[[8]](#references)</sup>

Gerekli koşul, doğrulayıcıya gönderilen bozuk bir açık anahtarı değil, **içe aktarılmadan veya imzalama için kullanılmadan önce genişletilmiş bir imzalama anahtarını kontrol edebilmektir**. Esnek bir içe aktarma yolu, değiştirilmiş paketlenmiş katsayıları kabul edip yine de doğrulanan imzalar üretebilir. [Kriptografik anahtar kodlaması fuzzing iş akışını](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings) kullanarak içe aktarma ve imzalama aşamalarındaki kabul durumlarını karşılaştırın, ardından ortaya çıkan imzaları kontrol edin.<sup>[[9]](#references)[[10]](#references)</sup>

İmzalama, `z = y + c·s1` ve `r0 = LowBits(w − c·s2)` hesaplar; `||z||∞ ≥ γ1 − β` veya `||r0||∞ ≥ γ2 − β` olduğunda aday reddedilir. Bu kontroller, kabul edilen çıktıları geçerli küçük sırlardan bağımsız kılar. Aralık dışındaki gizli katsayılar bu rejection-sampling argümanını bozabilir ve sırlara bağlı bias oluşturabilir. Bu, koşullu bir leak mekanizmasıdır; **bildirilen kütüphane farklılığından tam anahtar kurtarmanın gösterilmiş olduğu anlamına gelmez**.<sup>[[8]](#references)[[10]](#references)</sup>

Özel anahtar doğrulaması, imza doğrulamasından farklıdır. Bildirilen karşılaştırmada OpenSSL, BoringSSL ve SymCrypt ek özel anahtar kontrolleri uygularken, liboqs imzalama sırasında bozuk genişletilmiş anahtarları kabul etti; temelindeki `mldsa-native`, liboqs'un dışarı açmadığı bir `pk_from_sk()` doğrulayıcısı sağlar. FIPS 204 bu ek doğrulama kontrollerini zorunlu kılmaz.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Dijital İmza Standardı](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner ve Heninger: Biased Nonce Sense — Zayıf ECDSA İmzalarına Karşı Lattice Saldırıları](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Eliptik Eğri Kriptografisi](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` belgeleri](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Modül-Lattice Tabanlı Dijital İmza Standardı](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Eksik ML-DSA ve ML-KEM anahtar kontrolleri - liboqs issue #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Post-Quantum Kriptografi Uygulamalarının Durumu](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
