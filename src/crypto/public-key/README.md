# Kryptografia klucza publicznego

{{#include ../../banners/hacktricks-training.md}}

Wiele zaawansowanych wyzwań kryptograficznych CTF obejmuje RSA, kryptografię krzywych eliptycznych (ECC), ECDSA, lattices lub słabą losowość.

## Zalecane narzędzia

- [SageMath](https://www.sagemath.org/) do arytmetyki modularnej, krzywych eliptycznych i redukcji lattice<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) do testowania typowych słabości RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) do sprawdzania, czy liczba całkowita ma znane czynniki<sup>[[3]](#references)</sup>
- Biblioteka Pythona [`ecdsa`](https://ecdsa.readthedocs.io/) do parsowania kluczy, podpisywania i weryfikacji<sup>[[7]](#references)</sup>

## RSA

Zacznij tutaj, gdy challenge dostarcza `n`, `e` i `c` oraz podpowiedź, taką jak współdzielony modulus, niski wykładnik, częściowe bity klucza lub powiązane wiadomości.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Jeśli występują podpisy, sprawdź ponowne użycie nonce, bias lub leak przed założeniem, że trzeba rozwiązać bazowy problem logarytmu dyskretnego.

### ECDSA nonce reuse / bias

ECDSA wymaga świeżej, sekretnej liczby `k` dla każdej wiadomości. Jeśli to samo `k` podpisze dwa różne hashe wiadomości, klucz prywatny można odzyskać na podstawie publicznych wartości podpisów.<sup>[[4]](#references)</sup>

Nawet gdy `k` nie jest identyczne, bias lub leak bitów nonce w wielu podpisach może umożliwić odzyskanie oparte na lattices.<sup>[[5]](#references)</sup>

Techniczne odzyskiwanie, gdy `k` jest używane ponownie:<sup>[[4]](#references)</sup>

Równania podpisu ECDSA (rząd grupy `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Jeśli to samo `k` zostanie użyte ponownie dla dwóch wiadomości `m1, m2`, tworząc podpisy `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Jeśli protokół nie sprawdza, czy punkt wejściowy leży na oczekiwanej krzywej i w poprawnej podgrupie, attacker może wymusić operacje w słabszej grupie i odzyskać informacje o sekretnym skalarze. SEC 1 określa mechanizmy walidacji klucza publicznego mające zapobiegać takim danym wejściowym.<sup>[[6]](#references)</sup>

Uwaga techniczna:

- Sprawdź, czy punkty nie są punktem w nieskończoności, mają poprawne współrzędne, spełniają równanie krzywej i należą do wymaganej podgrupy.<sup>[[6]](#references)</sup>
- W challenge'ach CTF jest to często modelowane jako serwer mnożący punkt wybrany przez attackera przez sekretny skalar i zwracający wartość pochodną.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard podpisu cyfrowego](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner i Heninger: Biased Nonce Sense — ataki lattice na słabe podpisy ECDSA](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kryptografia krzywych eliptycznych](https://www.secg.org/sec1-v2.pdf)
- [7] [Dokumentacja Pythona `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
