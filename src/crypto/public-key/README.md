# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}


Çoğu CTF zor kripto görevi burada karşınıza çıkar: RSA, ECC/ECDSA, lattices ve kötü randomness.

## Önerilen araçlar

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (İsviçre çakısı): https://github.com/Ganapati/RsaCtfTool
- factordb (hızlı factor kontrolleri): http://factordb.com/

## RSA

`n,e,c` ve bazı ek ipuçlarına (shared modulus, low exponent, partial bits, related messages) sahip olduğunuzda buradan başlayın.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Signatures işin içindeyse, zor matematik varsayımında bulunmadan önce nonce problemlerini (reuse/bias/leaks) test edin.

### ECDSA nonce reuse / bias

İki signature aynı nonce `k` değerini yeniden kullanıyorsa private key kurtarılabilir.

`k` aynı olmasa bile signatures genelinde nonce bitlerindeki **bias/leakage**, lattice recovery için yeterli olabilir (yaygın CTF teması).

`k` yeniden kullanıldığında teknik kurtarma:

ECDSA signature denklemleri (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Aynı `k`, signatures `(r, s1)` ve `(r, s2)` üreten iki mesaj `m1, m2` için yeniden kullanılıyorsa:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Bir protokol, noktaların beklenen curve (veya subgroup) üzerinde olduğunu doğrulayamazsa attacker işlemleri weak bir group içinde zorlayabilir ve secrets kurtarabilir.

Teknik not:

- Noktaların curve üzerinde ve doğru subgroup içinde olduğunu doğrulayın.
- Birçok CTF görevi bunu, "server attacker tarafından seçilen point'i secret scalar ile çarpar ve bir şey döndürür" şeklinde modeller.

### Araçlar

- SageMath for curve arithmetic / lattices
- `ecdsa` Python library for parsing/verification

{{#include ../../banners/hacktricks-training.md}}
