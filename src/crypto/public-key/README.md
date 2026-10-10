# Açık Anahtarlı Kriptografi

{{#include ../../banners/hacktricks-training.md}}

Birçok ileri düzey CTF kriptografi challenge'ı RSA, eliptik eğri kriptografisi (ECC), ECDSA, kafesler veya zayıf rastgelelik içerir.

## Önerilen araçlar

- Modüler aritmetik, eliptik eğriler ve kafes indirgeme için [SageMath](https://www.sagemath.org/)<sup>[[1]](#references)</sup>
- Yaygın RSA zayıflıklarını test etmek için [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)<sup>[[2]](#references)</sup>
- Bir tamsayının bilinen çarpanları olup olmadığını kontrol etmek için [FactorDB](https://factordb.com/)<sup>[[3]](#references)</sup>
- Anahtar ayrıştırma, imzalama ve doğrulama için Python [`ecdsa` kütüphanesi](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

Bir challenge `n`, `e` ve `c` değerlerini sağlıyor ve ortak modül, düşük üs, kısmi anahtar bitleri veya ilişkili mesajlar gibi bir ipucu veriyorsa buradan başlayın.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

İmzalar söz konusuysa, temel ayrık logaritma problemini çözmeniz gerektiğini varsaymadan önce nonce tekrarını, yanlılığı veya nonce sızıntısını test edin.

### ECDSA nonce tekrarı / yanlılığı

ECDSA, her mesaj için yeni bir gizli sayı `k` gerektirir. Aynı `k` iki farklı mesaj hash'ini imzalamak için kullanılırsa, özel anahtar herkese açık imza değerlerinden kurtarılabilir.<sup>[[4]](#references)</sup>

`k` aynı olmasa bile, birçok imzada nonce bitlerinin yanlılığı veya sızıntısı kafes tabanlı kurtarmayı mümkün kılabilir.<sup>[[5]](#references)</sup>

`k` tekrar kullanıldığında teknik kurtarma:<sup>[[4]](#references)</sup>

ECDSA imza denklemleri (grup mertebesi `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Aynı `k`, `(r, s1)` ve `(r, s2)` imzalarını üreten iki `m1, m2` mesajı için tekrar kullanılırsa:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Geçersiz eğri saldırıları

Bir protokol, girdi noktasının beklenen eğri üzerinde ve doğru alt grupta olduğunu doğrulamazsa saldırgan daha zayıf bir grupta işlem yapılmasını sağlayabilir ve gizli skaler hakkındaki bilgileri kurtarabilir. SEC 1, bu tür girdileri önlemeyi amaçlayan açık anahtar doğrulama kontrollerini belirtir.<sup>[[6]](#references)</sup>

Teknik not:

- Noktaların sonsuzdaki nokta olmadığını, koordinatlarının geçerli olduğunu, eğri denklemini sağladığını ve gereken alt gruba ait olduğunu doğrulayın.<sup>[[6]](#references)</sup>
- CTF challenge'larında bu durum çoğunlukla, sunucunun saldırgan tarafından seçilen bir noktayı gizli skalerle çarpıp türetilmiş bir değer döndürmesi şeklinde modellenir.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Dijital İmza Standardı](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner ve Heninger: Yanlı Nonce — Zayıf ECDSA İmzalarına Karşı Kafes Saldırıları](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Eliptik Eğri Kriptografisi](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` belgeleri](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
