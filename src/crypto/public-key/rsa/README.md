# RSA Saldırıları

{{#include ../../../banners/hacktricks-training.md}}

## Hızlı triage

Topla:

- `n`, `e`, `c` (ve varsa ek ciphertext'ler)
- Mesajlar arasındaki ilişkiler (aynı plaintext? shared modulus? structured plaintext?)
- Her türlü leak (kısmi `p/q`, `d` bitleri, `dp/dq`, bilinen padding)

Sonra dene:

- Factorization kontrolü (Factordb / küçük değerler için `sage: factor(n)`)
- Düşük üs kalıpları (`e=3`, broadcast)
- Common modulus / repeated primes
- Bir şey neredeyse biliniyorsa lattice yöntemleri (Coppersmith/LLL)

## Yaygın RSA saldırıları

### Common modulus

Eğer iki ciphertext `c1, c2`, **aynı mesajı** **aynı modulus** `n` altında ama farklı üslerle `e1, e2` şifreliyorsa (`gcd(e1,e2)=1` ise), extended Euclidean algorithm ile `m` kurtarılabilir:

`m = c1^a * c2^b mod n` burada `a*e1 + b*e2 = 1`.

Örnek akış:

1. `(a, b) = xgcd(e1, e2)` hesapla, böylece `a*e1 + b*e2 = 1`
2. `a < 0` ise `c1^a` ifadesini `inv(c1)^{-a} mod n` olarak yorumla (`b` için de aynı)
3. Çarp ve `n` ile mod al

### Modüller arasında shared primes

Aynı challenge'dan birden fazla RSA modulus'un varsa, ortak bir asal paylaşıp paylaşmadıklarını kontrol et:

- `gcd(n1, n2) != 1` anahtar üretiminde felaket bir başarısızlığa işaret eder.

Bu, CTF'lerde sıkça "bir sürü anahtarı hızlıca ürettik" veya "kötü randomness" olarak görünür.

### Sparse / short-sleeve moduli

Bazı bozuk big-integer generator'lar yapıyı doğrudan public modulus içine sızdırır: her limb yalnızca küçük bir random subfield içerir, bitlerin geri kalanı `0` olur. Pratikte bu, `n` boyunca **düzenli aralıklı zero block'lar** olarak görünür; çoğu zaman 32-bit veya 128-bit limb'lere hizalanır.

Hızlı kontroller:

- `n`'yi hex olarak dök ve sabit bir aralıkta tekrar eden zero window'lar ara.
- `n`'yi limb'lere (`2^32`, `2^64`, `2^128`) ayırıp her limb'in alışılmadık derecede küçük olup olmadığını incele.
- Zayıf host-key generation şüphesi varsa, **badkeys** gibi tooling ile public SSH/TLS key'leri denetle.

Bu, istatistiksel bir bias'tan daha ciddidir: Eğer hem private factor `p` hem de `q` short-sleeved ise, modulus **kolayca factor edilebilir** hale gelebilir.

### Structured RSA key'lerin polynomial factorization'ı

Şüpheli bir limb genişliği `w` için modulus'u `B = 2^w` tabanında yaz:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Evaluation multiplicative olduğu için `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Eğer factors da sparse limb coefficients'a sahipse, o zaman:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Saldırı akışı:

1. Limb genişliği `w` için tahmin yap.
2. Public modulus `n`'yi `2^w` tabanını kullanarak `f_n(x)`'e çevir.
3. `f_n(x)`'i integers üzerinde factor et.
4. Aday factor'ları tekrar `B = 2^w`'da değerlendir.
5. Hangi adayların `n`'yi verdiğini doğrula.

Bu, normal RSA'yı **kırmaz**. Yalnızca prime factor'ların kendileri çok küçük, yüksek derecede structured limb coefficients'a sahip olduğunda çalışır.

### Shifted limb leakage

Sparse byte'lar her zaman her limb'in düşük ucuna hizalı olmaz. Doğrudan `2^w` tabanına çeviri büyük coefficients üretirse, `2^i p` ve `2^j q`'nun o limb basis içinde sparse hale geldiği shift'ler `i,j` ara. Product polynomial yine public modulus'tan türetilebilir, factor edilebilir ve orijinal integer factor'larla yeniden birleştirilebilir.

### Implementation smell: byte-to-limb RNG bug

Tehlikeli bir pattern, **32-bit limb** sayısını hesaplayıp yalnızca o kadar **byte** allocate etmek ve bunları limb array'ine kopyalamaktır:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Bu, her 32-bit limb için yalnızca **8 bit entropy** verir, ayrıca son limb’de zorunlu bir üst bit bulunur. Ortaya çıkan RSA primes çoğu zaman yalnızca public key’den tanınabilir ve factored edilebilir.

### Related DSA failure mode

Aynı bozuk big-integer routine, DSA private exponent üretimi için yeniden kullanılırsa, public key `y = g^x`, `x` için **dramatik biçimde azaltılmış ve yapılandırılmış** bir search space sızdırabilir. Limb pattern bilindiğinde, **baby-step giant-step** gibi discrete-log attacks public parameters’a karşı pratik hale gelebilir.

### Håstad broadcast / low exponent

Aynı plaintext, küçük `e` ile (çoğunlukla `e=3`) ve düzgün padding olmadan birden fazla alıcıya gönderilirse, `m` değerini CRT ve integer root ile geri kazanabilirsiniz.

Teknik koşul:

Aynı message için, pairwise-coprime moduli `n_i` altında `e` ciphertext’e sahipseniz:

- CRT kullanarak ürün `N = Π n_i` üzerinde `M = m^e` değerini geri kazan
- Eğer `m^e < N` ise, `M` gerçek integer power’dır ve `m = integer_root(M, e)`

### Wiener attack: small private exponent

Eğer `d` çok küçükse, continued fractions onu `e/n`’den geri kazanabilir.

### Textbook RSA pitfalls

Eğer şunları görürseniz:

- OAEP/PSS yok, raw modular exponentiation
- Deterministic encryption

o zaman algebraic attacks ve oracle abuse çok daha olası hale gelir.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Aynı modulus altında, mesajları algebraically related olan iki ciphertext görürseniz (ör. `m2 = a*m1 + b`), Franklin–Reiter gibi "related-message" attacks arayın. Bunlar genellikle şunları gerektirir:

- same modulus `n`
- same exponent `e`
- plaintext’ler arasında bilinen ilişki

Pratikte bu çoğu zaman Sage ile, `n` modunda polinomlar kurup bir GCD hesaplayarak çözülür.

## Lattices / Coppersmith

Bilinmeyen kısmın küçük olmasını sağlayan partial bits, structured plaintext veya close relations varsa buna yönelin.

Lattice methods (LLL/Coppersmith), partial information olduğunda ortaya çıkar:

- Partially known plaintext (unknown tail içeren structured message)
- Partially known `p`/`q` (high bits leaked)
- Related values arasında küçük unknown differences

### What to recognize

Challenges içinde tipik ipuçları:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

Pratikte LLL için Sage ve belirli örnek için bilinen bir template kullanırsınız.

İyi başlangıç noktaları:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
