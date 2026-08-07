# Kryptografia klucza publicznego

{{#include ../../banners/hacktricks-training.md}}


Większość trudnych zadań kryptograficznych w CTF sprowadza się do tych zagadnień: RSA, ECC/ECDSA, lattices oraz zła losowość.

## Recommended tooling

- SageMath (LLL/lattices, arytmetyka modularna): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (szybkie sprawdzanie faktoryzacji): http://factordb.com/

## RSA

Zacznij tutaj, gdy masz `n,e,c` oraz dodatkową wskazówkę (wspólny modulus, niski wykładnik, częściowe bity, powiązane wiadomości).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Jeśli występują signatures, najpierw sprawdź problemy z nonce (reuse/bias/leaks), zanim założysz, że potrzebna jest trudna matematyka.

### ECDSA nonce reuse / bias

Jeśli dwie signatures używają tego samego nonce `k`, można odzyskać private key.

Nawet jeśli `k` nie jest identyczne, **bias/leakage** bitów nonce pomiędzy signatures może wystarczyć do recovery za pomocą lattices (częsty motyw w CTF).

Techniczne odzyskiwanie, gdy `k` jest ponownie używane:

Równania signature ECDSA (order grupy `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Jeśli to samo `k` jest używane dla dwóch wiadomości `m1, m2`, tworząc signatures `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Jeśli protokół nie sprawdza, czy punkty znajdują się na oczekiwanej krzywej (lub w oczekiwanej podgrupie), attacker może wymusić operacje w słabej grupie i odzyskać secrets.

Uwaga techniczna:

- Sprawdzaj, czy punkty leżą na krzywej i należą do właściwej podgrupy.
- W wielu zadaniach CTF jest to modelowane jako „server mnoży wybrany przez attackera punkt przez secret scalar i zwraca wynik”.

### Tooling

- SageMath do arytmetyki na krzywych / lattices
- Python library `ecdsa` do parsowania/weryfikacji

{{#include ../../banners/hacktricks-training.md}}
