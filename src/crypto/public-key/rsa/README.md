# RSA Saldırıları

{{#include ../../../banners/hacktricks-training.md}}

## Hızlı triage

Şunları toplayın:

- `n`, `e`, `c` (ve ek ciphertext'ler)
- Mesajlar arasındaki ilişkiler (aynı plaintext mi? paylaşılan modulus mu? yapılandırılmış plaintext mi?)
- Herhangi bir leak (`p/q`'nun bir kısmı, `d` bit'leri, `dp/dq`, bilinen padding)

Ardından şunları deneyin:

- Factorization kontrolü (Factordb / küçük sayılar için `sage: factor(n)`)
- Düşük exponent kalıpları (`e=3`, broadcast)
- Common modulus / tekrarlanan prime'lar
- Bir şey neredeyse biliniyorsa lattice yöntemleri (Coppersmith/LLL)

## Yaygın RSA saldırıları

### Common modulus

İki ciphertext `c1, c2`, **aynı modulus** `n` altında farklı exponent'ler `e1, e2` ile **aynı mesajı** şifreliyorsa (ve `gcd(e1,e2)=1` ise), extended Euclidean algorithm kullanarak `m` değerini kurtarabilirsiniz:

`m = c1^a * c2^b mod n`, burada `a*e1 + b*e2 = 1`.

Örnek akış:

1. `(a, b) = xgcd(e1, e2)` hesaplayın; böylece `a*e1 + b*e2 = 1` olur
2. `a < 0` ise `c1^a` ifadesini `inv(c1)^{-a} mod n` olarak yorumlayın (`b` için de aynısı geçerlidir)
3. Çarpın ve `n` modülüne göre indirgeyin

### Modulus'lar arasında paylaşılan prime'lar

Aynı challenge içinden birden fazla RSA modulus'una sahipseniz, bunların bir prime paylaşıp paylaşmadığını kontrol edin:

- `gcd(n1, n2) != 1`, kritik bir key-generation hatası olduğunu gösterir.

Bu durum CTF'lerde genellikle "çok sayıda key'i hızlıca ürettik" veya "kötü randomness" şeklinde ortaya çıkar.

### Sparse / short-sleeve modulus'lar

Bazı bozuk big-integer generator'ları yapıyı doğrudan public modulus'a sızdırır: her limb yalnızca küçük bir random subfield içerir ve bit'lerin geri kalanı `0` olur. Pratikte bu, genellikle `n` boyunca düzenli aralıklarla yerleşmiş, çoğunlukla 32-bit veya 128-bit limb'lerle hizalanmış **düzenli sıfır blokları** şeklinde görünür.<sup>[[1]](#references)</sup>

Hızlı kontroller:

- `n` değerini hex olarak dökün ve sabit bir stride'da tekrarlanan sıfır pencerelerini arayın.
- `n` değerini limb'ler (`2^32`, `2^64`, `2^128`) olarak yeniden bölün ve her limb'in olağandışı derecede küçük olup olmadığını inceleyin.
- Zayıf host-key generation'ından şüpheleniyorsanız, **badkeys** gibi tooling kullanarak public SSH/TLS key'lerini denetleyin.<sup>[[2]](#references)[[3]](#references)</sup>

Bu, istatistiksel bir bias'tan daha ciddidir: private factor'lerin `p` ve `q` her ikisi de short-sleeve ise modulus **kolayca factor edilebilir**.<sup>[[1]](#references)</sup>

### Yapılandırılmış RSA key'lerinin polynomial factorization'ı

Şüphelenilen limb genişliği `w` için modulus'u `B = 2^w` tabanında yazın:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Evaluation çarpımsal olduğundan, `f_a(B) * f_c(B) = (f_a * f_c)(B)` olur. Factor'ler de sparse limb coefficient'lerine sahipse:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack akışı:

1. Limb genişliği `w`'yi tahmin edin.
2. Public modulus `n` değerini, base `2^w` kullanarak `f_n(x)` biçimine dönüştürün.
3. `f_n(x)` değerini integers üzerinde factor edin.
4. Candidate factor'leri `B = 2^w` değerinde evaluate edin.
5. Hangi candidate'lerin çarpımının `n` olduğunu doğrulayın.

Bu yöntem **normal RSA'yı kırmaz**. Yalnızca prime factor'lerin kendisi çok küçük ve yüksek ölçüde yapılandırılmış limb coefficient'lerine sahip olduğunda çalışır.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse byte'lar her zaman her limb'in low end kısmıyla hizalı değildir. Doğrudan base-`2^w` dönüşümü büyük coefficient'ler üretiyorsa, `2^i p` ve `2^j q` değerlerinin bu limb basis'te sparse hâle geldiği `i,j` shift'lerini arayın. Product polynomial yine public modulus'tan türetilebilir, factor edilebilir ve original integer factor'lerde yeniden birleştirilebilir.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug'ı

Tehlikeli bir pattern, **32-bit limb** sayısını hesaplamak, yalnızca bu kadar **byte** allocate etmek ve bunları limb array'ine kopyalamaktır:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Bu, her 32-bit limb'e yalnızca **8 bit entropy** ve son limb'de zorunlu bir üst bit verir. Ortaya çıkan RSA asal sayıları çoğu zaman yalnızca public key'den tanınabilir ve factor edilebilir.<sup>[[1]](#references)</sup>

### İlgili DSA hata modu

Aynı bozuk big-integer routine DSA private exponent üretiminde yeniden kullanılırsa public key `y = g^x`, `x` için **dramatik biçimde küçültülmüş ve yapılandırılmış** bir search space leak edebilir. Limb pattern bilindiğinde, **baby-step giant-step** gibi discrete-log attack'leri public parameter'lara karşı pratik hâle gelebilir.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Aynı plaintext küçük `e` (çoğunlukla `e=3`) ile birden fazla recipient'a gönderilir ve uygun padding kullanılmazsa, CRT ve integer root aracılığıyla `m`'yi recover edebilirsiniz.

Teknik koşul:

Aynı mesajın pairwise-coprime modulus `n_i` altında `e` ciphertext'ine sahipseniz:

- `M = m^e` değerini product `N = Π n_i` üzerinde recover etmek için CRT kullanın
- `m^e < N` ise `M` gerçek integer power'dır ve `m = integer_root(M, e)`

### Wiener attack: küçük private exponent

`d` çok küçükse, continued fraction'lar `e/n` üzerinden bunu recover edebilir.

### Textbook RSA tuzakları

Şunları görürseniz:

- OAEP/PSS yok, raw modular exponentiation
- Deterministic encryption

algebraic attack'ler ve oracle abuse çok daha olası hâle gelir.

### Araçlar

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message pattern'leri

Aynı modulus altında, algebraic olarak ilişkili mesajlara (ör. `m2 = a*m1 + b`) ait iki ciphertext görürseniz, Franklin–Reiter gibi "related-message" attack'lerini arayın. Bunlar genellikle şunları gerektirir:

- aynı modulus `n`
- aynı exponent `e`
- plaintext'ler arasındaki ilişkinin bilinmesi

Pratikte bu genellikle Sage kullanılarak `n` modulo polynomials oluşturulması ve bir GCD hesaplanmasıyla çözülür.

## Lattices / Coppersmith

Bilinmeyen değeri küçük hâle getiren partial bits, structured plaintext veya yakın ilişkiler olduğunda buna başvurun.

Lattice method'ları (LLL/Coppersmith), partial information bulunduğunda karşınıza çıkar:

- Partially known plaintext (bilinmeyen tail içeren structured message)
- Partially known `p`/`q` (high bits leak edilmiş)
- Related value'lar arasındaki small unknown differences

### Neyi tanımak gerekir

Challenge'larda tipik ipuçları:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

Pratikte LLL için Sage ve ilgili instance'a yönelik bilinen bir template kullanacaksınız.

İyi başlangıç noktaları:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## Kaynaklar

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
