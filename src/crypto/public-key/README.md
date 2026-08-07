# Kriptografija javnog ključa

{{#include ../../banners/hacktricks-training.md}}


Većina hard crypto CTF zadataka na kraju se svodi na ovo: RSA, ECC/ECDSA, lattice pristupe i lošu slučajnost.

## Preporučeni alati

- SageMath (LLL/lattices, modularna aritmetika): https://www.sagemath.org/
- RsaCtfTool (švajcarski nož): https://github.com/Ganapati/RsaCtfTool
- factordb (brza provera faktora): http://factordb.com/

## RSA

Počnite ovde kada imate `n,e,c` i neki dodatni hint (shared modulus, low exponent, partial bits, related messages).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ako su uključeni potpisi, prvo testirajte nonce probleme (reuse/bias/leaks) pre nego što pretpostavite da je potrebna napredna matematika.

### ECDSA nonce reuse / bias

Ako dva potpisa koriste isti nonce `k`, private key se može povratiti.

Čak i kada `k` nije identičan, **bias/leakage** nonce bitova kroz više potpisa može biti dovoljan za lattice recovery (česta CTF tema).

Tehnički postupak oporavka kada se `k` ponavlja:

ECDSA jednačine potpisa (red grupe `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ako se isti `k` koristi za dve poruke `m1, m2`, pri čemu se dobijaju potpisi `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Ako protokol ne proverava da li se tačke nalaze na očekivanoj krivoj (ili podgrupi), napadač može da natera operacije da se izvršavaju u slaboj grupi i povrati tajne.

Tehnička napomena:

- Proverite da li su tačke na krivoj i u odgovarajućoj podgrupi.
- Mnogi CTF zadaci ovo modeluju kao: "server množi point koji je izabrao napadač tajnim skalarom i vraća nešto."

### Alati

- SageMath za računanje na krivama / lattices
- `ecdsa` Python biblioteka za parsiranje/verifikaciju

{{#include ../../banners/hacktricks-training.md}}
