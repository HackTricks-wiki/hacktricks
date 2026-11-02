# Kryptografia klucza publicznego

{{#include ../../banners/hacktricks-training.md}}

Wiele zaawansowanych wyzwań kryptograficznych CTF obejmuje RSA, kryptografię krzywych eliptycznych (ECC), ECDSA, kraty lub słabą losowość.

## Zalecane narzędzia

- [SageMath](https://www.sagemath.org/) do arytmetyki modularnej, krzywych eliptycznych i redukcji krat<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) do testowania typowych słabości RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) do sprawdzania, czy dla liczby całkowitej znane są czynniki<sup>[[3]](#references)</sup>
- Pythonowa [biblioteka `ecdsa`](https://ecdsa.readthedocs.io/) do parsowania kluczy, podpisywania i weryfikacji<sup>[[7]](#references)</sup>

## RSA

Zacznij tutaj, gdy wyzwanie udostępnia `n`, `e` i `c` oraz wskazówkę, taką jak wspólny moduł, mały wykładnik, częściowe bity klucza lub powiązane wiadomości.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Jeśli w grę wchodzą podpisy, sprawdź ponowne użycie nonce, obciążenie lub wyciek, zanim założysz, że trzeba rozwiązać podstawowy problem logarytmu dyskretnego.

### Ponowne użycie nonce w ECDSA / obciążenie

ECDSA wymaga świeżej, tajnej liczby `k` dla każdej wiadomości. Jeśli to samo `k` podpisze dwa różne skróty wiadomości, z wartości podpisów publicznych można odzyskać klucz prywatny.<sup>[[4]](#references)</sup>

Nawet gdy `k` nie jest identyczne, obciążenie lub wyciek bitów nonce z wielu podpisów może umożliwić odzyskanie klucza metodami opartymi na kratach.<sup>[[5]](#references)</sup>

Techniczne odzyskiwanie, gdy `k` jest ponownie użyte:<sup>[[4]](#references)</sup>

Równania podpisu ECDSA (rząd grupy `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Jeśli to samo `k` zostanie ponownie użyte dla dwóch wiadomości `m1, m2`, dając podpisy `(r, s1)` i `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Ataki na nieprawidłową krzywą

Jeśli protokół nie sprawdza, czy punkt wejściowy leży na oczekiwanej krzywej i należy do właściwej podgrupy, atakujący może wymusić operacje w słabszej grupie i odzyskać informacje o tajnym skalarze. SEC 1 określa kontrole walidacji klucza publicznego, które mają zapobiegać takim wejściom.<sup>[[6]](#references)</sup>

Uwaga techniczna:

- Sprawdź, czy punkty nie są punktem w nieskończoności, mają prawidłowe współrzędne, spełniają równanie krzywej i należą do wymaganej podgrupy.<sup>[[6]](#references)</sup>
- W wyzwaniach CTF często modeluje się to jako serwer mnożący punkt wybrany przez atakującego przez tajny skalar i zwracający wartość pochodną.

## Nieprawidłowe klucze podpisujące ML-DSA i wyciek przez próbkowanie odrzucające

Rozszerzony klucz prywatny ML-DSA koduje wektory wielomianów `s1` i `s2` o współczynnikach z przedziału `[-η, η]`. FIPS 204 wskazuje, że dekodowanie nieprawidłowych bajtów tajnego klucza może dać współczynniki spoza tego zakresu. Algorytm podpisywania sam w sobie nie wymaga dodatkowej kontroli spójności klucza prywatnego.<sup>[[8]](#references)</sup>

Wymaganym warunkiem wstępnym jest kontrola nad **rozszerzonym kluczem podpisującym przed jego zaimportowaniem lub użyciem do podpisywania**, a nie przesłanie nieprawidłowego klucza publicznego weryfikatorowi. Pobłażliwa ścieżka importu może zaakceptować zmodyfikowane spakowane współczynniki, a mimo to tworzyć podpisy, które przechodzą weryfikację. Porównaj akceptację podczas importu i podpisywania, a następnie sprawdź wynikowe podpisy, korzystając z [procedury fuzzingu kodowania kluczy kryptograficznych](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

Podpisywanie oblicza `z = y + c·s1` oraz `r0 = LowBits(w − c·s2)`, odrzucając kandydata, gdy `||z||∞ ≥ γ1 − β` lub `||r0||∞ ≥ γ2 − β`. Te kontrole sprawiają, że zaakceptowane wyniki są niezależne od prawidłowych małych wartości tajnych. Współczynniki tajne spoza zakresu mogą zaburzyć to uzasadnienie próbkowania odrzucającego i wprowadzić obciążenie zależne od sekretu. Jest to warunkowy mechanizm wycieku, **a nie** wykazane odzyskanie całego klucza na podstawie zgłoszonej rozbieżności między bibliotekami.<sup>[[8]](#references)[[10]](#references)</sup>

Walidacja klucza prywatnego różni się od weryfikacji podpisu. W opisywanym porównaniu OpenSSL, BoringSSL i SymCrypt stosowały dodatkowe kontrole klucza prywatnego, podczas gdy liboqs akceptował nieprawidłowe klucze rozszerzone podczas podpisywania; bazowa biblioteka `mldsa-native` udostępnia walidator `pk_from_sk()`, którego liboqs nie udostępniał. FIPS 204 nie wymaga tych dodatkowych kontroli walidacyjnych.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard podpisu cyfrowego](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner i Heninger: Biased Nonce Sense — ataki oparte na kratach na słabe podpisy ECDSA](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: kryptografia krzywych eliptycznych](https://www.secg.org/sec1-v2.pdf)
- [7] [Dokumentacja Pythonowej biblioteki `ecdsa`](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: standard podpisu cyfrowego opartego na kratach modułowych](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Brak kontroli kluczy ML-DSA i ML-KEM — zgłoszenie #2517 w liboqs](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Stan implementacji kryptografii postkwantowej](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
