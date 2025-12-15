# Açık Anahtar Kriptografi

{{#include ../../banners/hacktricks-training.md}}

Çoğu CTF zor kriptografi genellikle burada toplanır: RSA, ECC/ECDSA, lattices ve kötü rastgelelik.

## Önerilen araçlar

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (çok amaçlı araç): https://github.com/Ganapati/RsaCtfTool
- factordb (hızlı çarpan kontrolleri): http://factordb.com/

## RSA

Buradan başlayın: elinizde `n,e,c` ve bazı ek ipuçları (shared modulus, low exponent, partial bits, related messages) olduğunda.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

İmzalar dahilse, zor matematiği varsaymadan önce nonce problemlerini test edin (reuse/bias/leaks).

### ECDSA nonce reuse / bias

İki imza aynı nonce `k`'yı tekrar kullanırsa, özel anahtar geri alınabilir.

K `k` aynı olmasa bile, nonce bitlerinin imzalar arasında **bias/leakage** olması lattice yöntemiyle kurtarma için yeterli olabilir (yaygın CTF teması).

Teknik kurtarma `k` tekrar kullanıldığında:

ECDSA imza denklemleri (grup mertebesi `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Aynı `k` iki mesaj `m1, m2` için yeniden kullanılır ve imzalar `(r, s1)` ve `(r, s2)` üretilirse:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Bir protokol noktaların beklenen eğride (veya altgrupta) olduğunu doğrulamazsa, saldırgan zayıf bir grupta işlemler yaptırıp sırları geri alabilir.

Teknik not:

- Noktaların curve üzerinde ve doğru altgrupta olduğunu doğrulayın.
- Birçok CTF görevi bunu "server multiplies attacker-chosen point by secret scalar and returns something" şeklinde model eder.

### Tooling

- SageMath for curve arithmetic / lattices
- `ecdsa` Python library for parsing/verification

{{#include ../../banners/hacktricks-training.md}}
