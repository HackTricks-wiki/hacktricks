# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

Większość trudnych zadań crypto z CTF kończy się tutaj: RSA, ECC/ECDSA, lattices, i słaba losowość.

## Zalecane narzędzia

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (uniwersalne narzędzie): https://github.com/Ganapati/RsaCtfTool
- factordb (szybkie sprawdzenie faktoryzacji): http://factordb.com/

## RSA

Rozpocznij tutaj, gdy masz `n,e,c` i dodatkową wskazówkę (wspólny moduł, niski wykładnik, częściowe bity, powiązane wiadomości).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Jeśli w grę wchodzą podpisy, najpierw przetestuj problemy z nonce (reuse/bias/leaks) zanim założysz, że to trudna matematyka.

### ECDSA nonce reuse / bias

Jeśli dwa podpisy użyją tego samego nonce `k`, prywatny klucz można odzyskać.

Nawet jeśli `k` nie jest identyczne, **bias/leakage** bitów nonce między podpisami może wystarczyć do odzyskania przy użyciu lattices (częsty motyw w CTF).

Techniczne odzyskiwanie, gdy `k` jest ponownie użyte:

Równania podpisu ECDSA (porządek grupy `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Jeśli ten sam `k` jest użyty dla dwóch wiadomości `m1, m2` dając podpisy `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

If a protocol fails to validate that points are on the expected curve (or subgroup), an attacker may force operations in a weak group and recover secrets.

Uwaga techniczna:

- Weryfikuj, że punkty należą do krzywej i do właściwej podgrupy.
- Wiele zadań CTF modeluje to jako "server multiplies attacker-chosen point by secret scalar and returns something."

### Narzędzia

- SageMath do arytmetyki krzywych / lattices
- `ecdsa` biblioteka Python do parsowania/weryfikacji

{{#include ../../banners/hacktricks-training.md}}
