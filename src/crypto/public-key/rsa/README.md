# RSA Saldırıları

{{#include ../../../banners/hacktricks-training.md}}

## Hızlı ön değerlendirme

Şunları toplayın:

- `n`, `e`, `c` (ve varsa ek ciphertext'ler)
- Mesajlar arasındaki ilişkiler (aynı plaintext mi? ortak modulus mu? yapılandırılmış plaintext mi?)
- Varsa leak'ler (`p/q`'nun bir kısmı, `d`'nin bitleri, `dp/dq`, bilinen padding)

Ardından şunları deneyin:

- Çarpanlara ayırma kontrolü (Factordb / küçük sayılar için `sage: factor(n)`)
- Düşük üs örüntüleri (`e=3`, broadcast)
- Ortak modulus / tekrarlanan asal sayılar
- Bir şey neredeyse biliniyorsa lattice yöntemleri (Coppersmith/LLL)

## Yaygın RSA saldırıları

### Ortak modulus

İki ciphertext `c1, c2`, **aynı mesajı** farklı üslerle `e1, e2` (ve `gcd(e1,e2)=1`) kullanarak **aynı modulus** `n` altında şifreliyorsa, genişletilmiş Öklid algoritmasını kullanarak `m` değerini kurtarabilirsiniz:

`m = c1^a * c2^b mod n`; burada `a*e1 + b*e2 = 1`.

Örnek adımlar:

1. `(a, b) = xgcd(e1, e2)` hesaplayarak `a*e1 + b*e2 = 1` koşulunu sağlayın
2. `a < 0` ise `c1^a` ifadesini `inv(c1)^{-a} mod n` olarak yorumlayın (`b` için de aynı şekilde)
3. Çarpın ve sonucu modulo `n` olacak şekilde indirgeyin

### Modulus'lar arasında ortak asal sayılar

Aynı challenge'dan birden fazla RSA modulus'u varsa, ortak asal sayı içerip içermediklerini kontrol edin:

- `gcd(n1, n2) != 1` olması, anahtar üretiminde feci bir hataya işaret eder.

Bu durum CTF'lerde sıklıkla "çok sayıda anahtarı hızlıca ürettik" veya "zayıf randomness" şeklinde karşımıza çıkar.

### Seyrek / short-sleeve modulus'lar

Bazı bozuk büyük tamsayı üreteçleri, yapıyı doğrudan public modulus'a sızdırır: Her limb yalnızca küçük bir random alt alan içerir ve bitlerin geri kalanı `0` olur. Pratikte bu, genellikle `n` boyunca düzenli aralıklarla tekrarlanan sıfır blokları olarak görülür ve bu bloklar çoğu kez 32-bit veya 128-bit limb'lerle hizalanır.<sup>[[1]](#references)</sup>

Hızlı kontroller:

- `n` değerini hex biçiminde döküp sabit aralıklarla yinelenen sıfır pencereleri arayın.
- `n` değerini limb'lere (`2^32`, `2^64`, `2^128`) bölüp her limb'in olağandışı derecede küçük olup olmadığını inceleyin.
- Zayıf host-key üretiminden şüpheleniyorsanız, **badkeys** gibi araçlarla public SSH/TLS anahtarlarını denetleyin.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Bu, istatistiksel bir yanlılıktan daha ciddi bir durumdur: `p` ve `q` özel çarpanlarının ikisi de short-sleeve ise modulus'u **çarpanlarına ayırmak kolaylaşabilir**.<sup>[[1]](#references)</sup>

### Yapılandırılmış RSA anahtarlarının polinom çarpanlarına ayrılması

Şüphelenilen limb genişliği `w` için, modulus'u `B = 2^w` tabanında yazın:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Değer yerine koyma çarpımsal olduğundan, `f_a(B) * f_c(B) = (f_a * f_c)(B)` olur. Çarpanların limb katsayıları da seyrekse:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Saldırı adımları:

1. Limb genişliği `w` değerini tahmin edin.
2. `2^w` tabanını kullanarak public modulus `n` değerini `f_n(x)` biçimine dönüştürün.
3. `f_n(x)` polinomunu tamsayılar üzerinde çarpanlarına ayırın.
4. Aday çarpanları `B = 2^w` değerinde hesaplayın.
5. Hangi adayların çarpımının `n` olduğunu doğrulayın.

Bu yöntem **normal RSA'yı kırmaz**. Yalnızca asal çarpanların kendileri çok küçük ve yüksek derecede yapılandırılmış limb katsayılarına sahip olduğunda işe yarar.<sup>[[1]](#references)</sup>

### Kaymış limb sızıntısı

Seyrek baytlar her zaman her limb'in alt ucunda hizalı olmaz. Doğrudan `2^w` tabanına dönüştürme büyük katsayılar veriyorsa, `2^i p` ve `2^j q` değerlerinin o limb tabanında seyrek hâle geldiği `i,j` kaydırmalarını arayın. Çarpım polinomu yine de public modulus'tan türetilebilir, çarpanlarına ayrılabilir ve özgün tamsayı çarpanları elde etmek üzere yeniden birleştirilebilir.<sup>[[1]](#references)</sup>

### Uygulama sorunu: byte-to-limb RNG hatası

Tehlikeli bir örüntü, **32-bit limb** sayısını hesaplayıp yalnızca o sayıda **byte** ayırmak ve bunları limb dizisine kopyalamaktır:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

This, her 32-bit limb'e yalnızca **8 bit entropi** ve son limb'de zorunlu bir üst bit verir. Ortaya çıkan RSA asal sayıları, çoğu zaman yalnızca public key'den tanınabilir ve çarpanlarına ayrılabilir.<sup>[[1]](#references)</sup>

### İlgili DSA hata modu

Aynı bozuk big-integer rutini DSA private exponent üretiminde yeniden kullanılırsa, public key `y = g^x`, `x` için **önemli ölçüde daralmış ve yapılandırılmış** bir arama alanı sızdırabilir. Limb kalıbı bilindiğinde, **baby-step giant-step** gibi discrete-log saldırıları public parametrelere karşı uygulanabilir hâle gelebilir.<sup>[[1]](#references)</sup>

### Håstad broadcast / düşük üs

Aynı plaintext küçük `e` ile (genellikle `e=3`) birden fazla alıcıya ve uygun padding olmadan gönderilirse, CRT ve integer root kullanarak `m` değerini kurtarabilirsiniz.

Teknik koşul:

Aynı mesajın pairwise-coprime moduli `n_i` altında şifrelenmiş `e` ciphertext'i varsa:

- CRT kullanarak, `N = Π n_i` çarpımı üzerinde `M = m^e` değerini kurtarın
- `m^e < N` ise `M` gerçek tam sayı kuvvetidir ve `m = integer_root(M, e)` olur

### Wiener saldırısı: küçük private exponent

`d` çok küçükse, continued fractions `e/n` üzerinden `d` değerini kurtarabilir.

### Textbook RSA tuzakları

Şunları görürseniz:

- OAEP/PSS yok, ham modular exponentiation
- Deterministic encryption

cebirsel saldırılar ve oracle abuse olasılığı çok daha yüksektir.

### Araçlar

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## İlişkili mesaj kalıpları

Aynı modulus altında, mesajları cebirsel olarak ilişkili olan (ör. `m2 = a*m1 + b`) iki ciphertext görürseniz Franklin–Reiter gibi "related-message" saldırılarına bakın. Bunlar genellikle şunları gerektirir:

- aynı modulus `n`
- aynı exponent `e`
- plaintext'ler arasındaki ilişkinin bilinmesi

Pratikte bu, genellikle Sage ile `n` modülünde polinomlar kurup GCD hesaplanarak çözülür.

## Lattices / Coppersmith

Kısmi bitler, yapılandırılmış plaintext veya bilinmeyeni küçük kılan yakın ilişkiler olduğunda bu yönteme başvurun.

Lattice yöntemleri (LLL/Coppersmith), kısmi bilgi olduğunda karşınıza çıkar:

- Kısmen bilinen plaintext (bilinmeyen son kısmı olan yapılandırılmış mesaj)
- Kısmen bilinen `p`/`q` (üst bitler sızdırılmış)
- İlişkili değerler arasındaki küçük bilinmeyen farklar

### Neleri tanımalı

Challenge'larda sık görülen ipuçları:

- "p'nin üst/alt bitlerini sızdırdık"
- "Flag şu şekilde gömülü: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "RSA kullandık ama küçük bir random padding ile"

### Araçlar

Pratikte LLL için Sage ve ilgili örneğe özel bilinen bir template kullanırsınız.

İyi başlangıç kaynakları:

- Sage CTF crypto şablonları: https://github.com/defund/coppersmith
- Survey tarzı bir kaynak: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Polinomlarla "short-sleeve" RSA anahtarlarını çarpanlarına ayırma](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

