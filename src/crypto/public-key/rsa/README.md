# RSA Saldırıları

{{#include ../../../banners/hacktricks-training.md}}

## Hızlı triaj

Toplanacaklar:

- `n`, `e`, `c` (ve varsa ek ciphertextler)
- Mesajlar arasındaki herhangi bir ilişki (aynı plaintext mi? paylaşılan modulus? yapılandırılmış plaintext?)
- Herhangi bir leaks (kısmi `p/q`, `d` bitleri, `dp/dq`, bilinen padding)

Sonra dene:

- Faktörleme kontrolü (Factordb / `sage: factor(n)` küçük-ish için)
- Low exponent patternleri (`e=3`, broadcast)
- Common modulus / tekrarlayan prime'ler
- Lattice yöntemleri (Coppersmith/LLL) bir şey neredeyse biliniyorsa

## Yaygın RSA saldırıları

### Common modulus

Eğer iki ciphertext `c1, c2` aynı mesajı **aynı modulus** `n` altında fakat farklı üslerle `e1, e2` (ve `gcd(e1,e2)=1`) şifrelenmişse, genişletilmiş Öklid algoritması ile `m` kurtarılabilir:

`m = c1^a * c2^b mod n` burada `a*e1 + b*e2 = 1`.

Örnek özet:

1. `(a, b) = xgcd(e1, e2)` hesapla böylece `a*e1 + b*e2 = 1`
2. Eğer `a < 0` ise, `c1^a` ifadesini `inv(c1)^{-a} mod n` (aynı şeyi `b` için yap) olarak yorumla
3. Çarp ve modulo `n` ile indir

### Shared primes across moduli

Aynı challenge'dan birden fazla RSA modülü varsa, paylaşılan prime olup olmadığını kontrol et:

- `gcd(n1, n2) != 1` anahtar oluşturma sürecinde katastrofik bir hataya işaret eder.

Bu durum CTF'lerde sıkça "birçok anahtarı hızlıca ürettik" veya "kötü randomness" olarak ortaya çıkar.

### Håstad broadcast / low exponent

Aynı plaintext küçük `e` ile (genelde `e=3`) ve uygun padding olmadan birden fazla alıcıya gönderilmişse, CRT ve tamsayı kökü ile `m` kurtarılabilir.

Teknik şart:

Aynı mesajın pairwise-coprime modüller `n_i` altında `e` ciphertext'ine sahipseniz:

- CRT kullanarak `N = Π n_i` üzerinde `M = m^e`'yi yeniden oluştur
- Eğer `m^e < N` ise, o zaman `M` gerçek integer kuvvetidir ve `m = integer_root(M, e)`

### Wiener attack: small private exponent

Eğer `d` çok küçükse, sürekli kesirler (continued fractions) `e/n`'den `d`'yi kurtarabilir.

### Textbook RSA pitfalls

Eğer şöyle bir şey görürseniz:

- OAEP/PSS yok, ham modular üstelleme
- Deterministic encryption

o zaman cebrik saldırılar ve oracle abuse çok daha olası hale gelir.

### Araçlar

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Aynı modulus altında iki ciphertext görürseniz ve mesajlar cebrik olarak ilişkiliyse (ör. `m2 = a*m1 + b`), Franklin–Reiter gibi "related-message" saldırılarını ara. Bunlar genellikle şunu gerektirir:

- aynı modulus `n`
- aynı üs `e`
- plaintext'ler arasındaki bilinen ilişki

Pratikte bu genellikle Sage ile polinomları modulo `n` olarak kurup bir GCD hesaplamakla çözülür.

## Lattices / Coppersmith

Bilinmeyen küçük olduğunda veya kısmi bitler, yapılandırılmış plaintext ya da yakın ilişkiler olduğunda buna başvur.

Lattice yöntemleri (LLL/Coppersmith) kısmi bilgi olduğunda ortaya çıkar:

- Kısmen bilinen plaintext (bilinmeyen kuyruk içeren yapılandırılmış mesaj)
- Kısmen bilinen `p`/`q` (üst bitler leaked)
- İlişkili değerler arasındaki küçük bilinmeyen farklar

### Tanınması gerekenler

Challenge'lardaki tipik ipuçları:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Araçlar

Pratikte LLL için Sage ve spesifik örnek için bilinen bir şablon kullanırsınız.

İyi başlangıç noktaları:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Bir survey-style referans: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
