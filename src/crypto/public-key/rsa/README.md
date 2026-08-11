# RSA Saldırıları

{{#include ../../../banners/hacktricks-training.md}}

## Hızlı triage

Şunları toplayın:

- `n`, `e`, `c` (ve ek ciphertext'ler)
- Mesajlar arasındaki ilişkiler (aynı plaintext mi? paylaşılan modulus mu? yapılandırılmış plaintext mi?)
- Herhangi bir leak (kısmi `p/q`, `d` bitleri, `dp/dq`, bilinen padding)

Ardından şunları deneyin:

- Factorization kontrolü (Factordb / küçük sayılar için `sage: factor(n)`)
- Low exponent pattern'leri (`e=3`, broadcast)
- Common modulus / tekrarlanan prime'lar
- Bir şeyin neredeyse bilindiği durumlarda lattice yöntemleri (Coppersmith/LLL)

## Yaygın RSA saldırıları

### Common modulus

İki ciphertext `c1, c2`, **aynı mesajı** **aynı modulus** `n` altında ancak farklı exponent'lar `e1, e2` ile şifreliyorsa (ve `gcd(e1,e2)=1`), extended Euclidean algorithm kullanarak `m` değerini kurtarabilirsiniz:

`m = c1^a * c2^b mod n` burada `a*e1 + b*e2 = 1`.

Örnek akış:

1. `(a, b) = xgcd(e1, e2)` hesaplayın; böylece `a*e1 + b*e2 = 1`
2. `a < 0` ise `c1^a` ifadesini `inv(c1)^{-a} mod n` olarak yorumlayın (`b` için de aynısı geçerlidir)
3. Çarpın ve `n` modulo'suna göre indirgeyin

### Shared primes across moduli

Aynı challenge'dan birden fazla RSA modulus'unuz varsa, ortak bir prime paylaşıp paylaşmadıklarını kontrol edin:

- `gcd(n1, n2) != 1`, felaket niteliğinde bir key-generation hatası olduğunu gösterir.

Bu durum CTF'lerde "we generated many keys quickly" veya "bad randomness" şeklinde sıkça karşımıza çıkar.

### Sparse / short-sleeve moduli

Bazı bozuk big-integer generator'ları yapıyı doğrudan public modulus içine leak eder: her limb yalnızca küçük bir random subfield içerir ve bitlerin geri kalanı `0` olur. Pratikte bu, genellikle `n` boyunca düzenli aralıklarla yerleşmiş, çoğunlukla 32-bit veya 128-bit limb'lerle hizalanmış **zero block**'lar şeklinde görülür.<sup>[[1]](#references)</sup>

Hızlı kontroller:

- `n` değerini hex olarak dump edin ve sabit bir stride'da tekrarlanan zero window'lar arayın.
- `n` değerini limb'ler (`2^32`, `2^64`, `2^128`) olarak yeniden bölün ve her limb'in olağandışı derecede küçük olup olmadığını inceleyin.
- Zayıf host-key generation'dan şüphelendiğinizde public SSH/TLS key'lerini **badkeys** gibi tooling kullanarak denetleyin.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Bu, statistical bias'tan daha ciddi bir durumdur: private factor'ların her ikisi de `p` ve `q` short-sleeve ise modulus **kolayca factor edilebilir**.<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

Şüphelenilen limb genişliği `w` için modulus'u `B = 2^w` tabanında yazın:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Evaluation işlemi çarpımsal olduğundan, `f_a(B) * f_c(B) = (f_a * f_c)(B)` olur. Factor'ların da sparse limb coefficient'larına sahip olması durumunda:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack akışı:

1. Limb genişliği `w` değerini tahmin edin.
2. Public modulus `n` değerini `2^w` tabanını kullanarak `f_n(x)` biçimine dönüştürün.
3. `f_n(x)` değerini integer'lar üzerinde factor edin.
4. Candidate factor'ları `B = 2^w` değerinde evaluate edin.
5. Hangi candidate'ların çarpımının `n` değerini verdiğini doğrulayın.

Bu yöntem **normal RSA'yı kırmaz**. Yalnızca prime factor'ların kendilerinin çok küçük ve yüksek ölçüde yapılandırılmış limb coefficient'larına sahip olduğu durumlarda çalışır.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse byte'lar her zaman her limb'in low end kısmıyla hizalı değildir. Doğrudan base-`2^w` dönüşümü büyük coefficient'lar üretiyorsa, `2^i p` ve `2^j q` değerlerinin ilgili limb basis içinde sparse hâle geldiği `i,j` shift'lerini arayın. Product polynomial hâlâ public modulus'tan türetilebilir, factor edilebilir ve original integer factor'lara recombine edilebilir.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Tehlikeli bir pattern, **32-bit limb** sayısını hesaplamak, yalnızca o kadar **byte** allocate etmek ve bunları limb array'ine kopyalamaktır:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Bu, her 32-bit limb'e yalnızca **8 bit entropi** ve son limb'de zorunlu bir üst bit verir. Ortaya çıkan RSA asalları çoğu zaman yalnızca public key'den tanınabilir ve çarpanlarına ayrılabilir.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Aynı hatalı big-integer rutini DSA private exponent üretiminde yeniden kullanılırsa public key `y = g^x`, `x` için **dramatik ölçüde küçültülmüş ve yapılandırılmış** bir arama uzayını leak edebilir. Limb pattern bilindiğinde, **baby-step giant-step** gibi discrete-log saldırıları public parametrelere karşı pratik hale gelebilir.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Aynı plaintext, küçük `e` değerleriyle (çoğunlukla `e=3`) ve uygun padding olmadan birden fazla alıcıya gönderilirse `m` değerini CRT ve integer root kullanarak kurtarabilirsiniz.

Technical condition:

Aynı mesajın pairwise-coprime moduli `n_i` altında `e` ciphertext'i elinizdeyse:

- CRT kullanarak çarpım `N = Π n_i` üzerinden `M = m^e` değerini kurtarın
- `m^e < N` ise `M` gerçek integer power'dır ve `m = integer_root(M, e)`

### Wiener attack: small private exponent

`d` çok küçükse, continued fractions `e/n` değerinden bunu kurtarabilir.

### Textbook RSA pitfalls

Şunları görürseniz:

- OAEP/PSS yok, raw modular exponentiation
- Deterministic encryption

algebraic attacks ve oracle abuse olasılığı çok daha yüksek hale gelir.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Aynı modulus altında, algebraically related mesajlara (ör. `m2 = a*m1 + b`) ait iki ciphertext görürseniz Franklin–Reiter gibi "related-message" saldırılarını arayın. Bunlar genellikle şunları gerektirir:

- aynı modulus `n`
- aynı exponent `e`
- plaintext'ler arasındaki ilişkinin bilinmesi

Pratikte bu işlem çoğunlukla Sage kullanılarak polinomların `n` modulo'sunda kurulması ve bir GCD hesaplanmasıyla çözülür.

## Lattices / Coppersmith

Kısmi bitlere, structured plaintext'e veya bilinmeyeni küçük hale getiren yakın ilişkilere sahip olduğunuzda buna başvurun.

Lattice yöntemleri (LLL/Coppersmith), kısmi bilgiye sahip olduğunuz her durumda karşınıza çıkar:

- Kısmen bilinen plaintext (bilinmeyen tail içeren structured message)
- Kısmen bilinen `p`/`q` (high bits leak edilmiş)
- İlişkili değerler arasındaki küçük bilinmeyen farklar

### What to recognize

Challenge'larda tipik ipuçları:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

Pratikte LLL için Sage ve ilgili instance'a uygun bilinen bir template kullanacaksınız.

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Polinomlarla "short-sleeve" RSA anahtarlarının çarpanlarına ayrılması](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys bağımsız aracı](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
