# Kriptografija javnog ključa

{{#include ../../banners/hacktricks-training.md}}

Većina teškog CTF crypto-a završava ovde: RSA, ECC/ECDSA, lattices, i loša nasumičnost.

## Preporučeni alati

- SageMath (LLL/lattices, modularna aritmetika): https://www.sagemath.org/
- RsaCtfTool (višenamenski alat): https://github.com/Ganapati/RsaCtfTool
- factordb (brze provere faktora): http://factordb.com/

## RSA

Počnite ovde kada imate `n,e,c` i neki dodatni nagoveštaj (deljeni modul, mali eksponent, delimični bitovi, povezane poruke).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ako su uključeni potpisi, prvo proverite probleme sa nonce-om (reuse/bias/leaks) pre nego što pretpostavite tešku matematiku.

### ECDSA nonce reuse / bias

Ako dva potpisa ponovo koriste isti nonce `k`, privatni ključ može biti rekonstruisan.

Čak i ako `k` nije identičan, bias/leakage bitova nonce-a kroz potpise može biti dovoljan za oporavak korišćenjem lattices (uobičajena tema u CTF-u).

Tehnički oporavak kada se `k` ponovo koristi:

ECDSA jednačine potpisa (red grupe `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ako se isti `k` ponovo koristi za dve poruke `m1, m2` koje daju potpise `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Napadi na nevažeće krive

Ako protokol ne proverava da li su tačke na očekivanoj krivi (ili podgrupi), napadač može primorati operacije u slaboj grupi i rekonstruisati tajne.

Tehnička napomena:

- Proverite da li su tačke na krivi i u ispravnoj podgrupi.
- Mnogi CTF zadaci modeluju ovo kao "server pomnoži napadačem odabranu tačku tajnim skalarom i vrati nešto."

### Alati

- SageMath za aritmetiku krive / lattices
- `ecdsa` Python library za parsiranje/verifikaciju

{{#include ../../banners/hacktricks-training.md}}
