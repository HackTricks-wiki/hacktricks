# Kryptografia klucza publicznego

{{#include ../../banners/hacktricks-training.md}}

Wiele zaawansowanych wyzwań kryptograficznych CTF dotyczy RSA, kryptografii krzywych eliptycznych (ECC), ECDSA, krat lub słabej losowości.

## Zalecane narzędzia

- [SageMath](https://www.sagemath.org/) do arytmetyki modularnej, krzywych eliptycznych i redukcji krat<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) do testowania typowych słabości RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) do sprawdzania, czy liczba całkowita ma znane czynniki<sup>[[3]](#references)</sup>
- Pythonowa [biblioteka `ecdsa`](https://ecdsa.readthedocs.io/) do parsowania kluczy, podpisywania i weryfikacji<sup>[[7]](#references)</sup>

## RSA

Zacznij tutaj, gdy wyzwanie zawiera `n`, `e` i `c` oraz wskazówkę, na przykład dotyczącą wspólnego modułu, małego wykładnika, częściowych bitów klucza lub powiązanych wiadomości.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Jeśli w grę wchodzą podpisy, sprawdź ponowne użycie nonce, jego stronniczość lub wyciek informacji, zanim założysz, że trzeba rozwiązać bazowy problem logarytmu dyskretnego.

### Ponowne użycie nonce / stronniczość w ECDSA

ECDSA wymaga świeżej, tajnej liczby `k` dla każdej wiadomości. Jeśli to samo `k` podpisze skróty dwóch różnych wiadomości, klucz prywatny można odzyskać na podstawie wartości publicznych podpisów.<sup>[[4]](#references)</sup>

Nawet jeśli `k` nie jest identyczne, stronniczość lub wyciek bitów nonce w wielu podpisach może umożliwić odzyskanie klucza metodami opartymi na kratach.<sup>[[5]](#references)</sup>

Techniczne odzyskiwanie klucza w przypadku ponownego użycia `k`:<sup>[[4]](#references)</sup>

Równania podpisu ECDSA (rząd grupy `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Jeśli to samo `k` zostanie użyte ponownie dla dwóch wiadomości `m1, m2`, tworząc podpisy `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Ataki na nieprawidłową krzywą

Jeśli protokół nie sprawdza, czy punkt wejściowy leży na oczekiwanej krzywej i w prawidłowej podgrupie, atakujący może wymusić operacje w słabszej grupie i odzyskać informacje o tajnym skalarze. SEC 1 określa kontrole walidacji klucza publicznego, które mają zapobiegać takim wejściom.<sup>[[6]](#references)</sup>

Uwaga techniczna:

- Sprawdź, czy punkty nie są punktem w nieskończoności, mają prawidłowe współrzędne, spełniają równanie krzywej i należą do wymaganej podgrupy.<sup>[[6]](#references)</sup>
- W wyzwaniach CTF często modeluje się to jako serwer mnożący wybrany przez atakującego punkt przez tajny skalar i zwracający wartość pochodną.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard podpisu cyfrowego](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner i Heninger: Stronniczy nonce — ataki kratowe na słabe podpisy ECDSA](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kryptografia krzywych eliptycznych](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` — dokumentacja](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
