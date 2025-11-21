# Algorytmy kryptograficzne i kompresji

{{#include ../../banners/hacktricks-training.md}}

## Identyfikacja algorytmów

Jeżeli kod kończy się na instrukcjach używających przesunięć w prawo i w lewo, xorów oraz kilku operacji arytmetycznych, istnieje duże prawdopodobieństwo, że jest to implementacja algorytmu kryptograficznego. Poniżej przedstawiono kilka sposobów, jak zidentyfikować używany algorytm bez konieczności odwracania każdego kroku.

### Funkcje API

**CryptDeriveKey**

Jeśli ta funkcja jest użyta, możesz sprawdzić, który **algorytm jest używany** kontrolując wartość drugiego parametru:

![](<../../images/image (156).png>)

Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje podany bufor danych.

**CryptAcquireContext**

Zgodnie z [dokumentacją](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): funkcja **CryptAcquireContext** służy do pozyskania uchwytu do konkretnego kontenera kluczy w ramach określonego cryptographic service provider (CSP). **Zwrócony uchwyt jest używany w wywołaniach funkcji CryptoAPI** korzystających z wybranego CSP.

**CryptCreateHash**

Rozpoczyna hashowanie strumienia danych. Jeśli ta funkcja jest użyta, możesz sprawdzić, który **algorytm jest używany** kontrolując wartość drugiego parametru:

![](<../../images/image (549).png>)

\
Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Stałe w kodzie

Czasami bardzo łatwo jest zidentyfikować algorytm dzięki temu, że używa specjalnej, unikatowej wartości.

![](<../../images/image (833).png>)

Jeśli wyszukasz pierwszą stałą w Google, otrzymasz taki wynik:

![](<../../images/image (529).png>)

Wobec tego możesz założyć, że zdekompilowana funkcja jest kalkulatorem sha256.\
Możesz wyszukać dowolną z pozostałych stałych i otrzymasz (prawdopodobnie) ten sam wynik.

### Informacje o danych

Jeśli kod nie zawiera istotnych stałych, może ładować informacje z sekcji .data.\
Możesz uzyskać dostęp do tych danych, pogrupować pierwszy dword i wyszukać go w Google, tak jak zrobiliśmy w poprzedniej sekcji:

![](<../../images/image (531).png>)

W tym przypadku, jeśli wyszukasz **0xA56363C6**, możesz znaleźć, że jest to związane z tabelami algorytmu AES.

## RC4 (Symmetric Crypt)

### Cechy

Składa się z 3 głównych części:

- Initialization stage/Substitution Box: Tworzy tabelę wartości od 0x00 do 0xFF (256 bajtów w sumie, 0x100). Ta tabela jest powszechnie nazywana Substitution Box (lub SBox).
- Scrambling stage: Przechodzi pętlą przez wcześniej utworzoną tabelę (pętla o 0x100 iteracjach) modyfikując każdą wartość pół-losowymi bajtami. Do generowania tych pół-losowych bajtów używany jest klucz RC4. Klucze RC4 mogą mieć długość od 1 do 256 bajtów, jednak zazwyczaj zaleca się, aby miały więcej niż 5 bajtów. Najczęściej klucze RC4 mają długość 16 bajtów.
- XOR stage: Na końcu tekst jawny lub szyfrogram jest XORowany z wartościami utworzonymi wcześniej. Funkcja szyfrująca i deszyfrująca jest taka sama. Wykonywana jest pętla po utworzonych 256 bajtach tyle razy, ile jest potrzeba. Zazwyczaj rozpoznaje się to w zdekompilowanym kodzie po użyciu %256 (mod 256).

> [!TIP]
> **Aby zidentyfikować RC4 w disassemblacji/dekompilowanym kodzie można sprawdzić występowanie 2 pętli o rozmiarze 0x100 (z użyciem klucza), a następnie XOR wejściowych danych z 256 wartości utworzonych wcześniej w tych 2 pętlach, prawdopodobnie używając %256 (mod 256).**

### Initialization stage/Substitution Box: (Zwróć uwagę na liczbę 256 używaną jako licznik i na to, że w każdym miejscu z zapisuje się 0)

![](<../../images/image (584).png>)

### Scrambling Stage:

![](<../../images/image (835).png>)

### XOR Stage:

![](<../../images/image (904).png>)

## AES (Symmetric Crypt)

### Cechy

- Użycie substitution boxes i tabel wyszukiwania (lookup tables)
- Można rozpoznać AES dzięki użyciu specyficznych wartości w tabelach wyszukiwania (stałych). Zauważ, że **stała** może być **przechowywana** w binarium lub **tworzona** **dynamicznie**.
- Klucz szyfrowania musi być podzielny przez 16 (zwykle 32B), a zazwyczaj używany jest IV o wielkości 16B.

### Stałe SBox

![](<../../images/image (208).png>)

## Serpent (Symmetric Crypt)

### Cechy

- Rzadko spotykane w malware, ale są przykłady (Ursnif)
- Łatwo określić, czy algorytm to Serpent, bazując na jego długości (bardzo długa funkcja)

### Identyfikacja

Na poniższym obrazie zwróć uwagę, jak używana jest stała **0x9E3779B9** (uwaga: ta stała jest również wykorzystywana przez inne algorytmy kryptograficzne, np. **TEA** - Tiny Encryption Algorithm).\
Zwróć też uwagę na **rozmiar pętli** (**132**) i **liczbę operacji XOR** w instrukcjach disassemblacji oraz w przykładzie kodu:

![](<../../images/image (547).png>)

Jak wspomniano wcześniej, ten kod będzie widoczny w dekompilatorze jako **bardzo długa funkcja**, ponieważ **brakuje w niej skoków**. Zdekompilowany kod może wyglądać tak:

![](<../../images/image (513).png>)

Można więc zidentyfikować ten algorytm, sprawdzając magiczną liczbę i początkowe XORy, zauważając bardzo długą funkcję oraz porównując niektóre instrukcje długiej funkcji z implementacją (np. shift left o 7 i rotate left o 22).

## RSA (Asymmetric Crypt)

### Cechy

- Bardziej złożony niż algorytmy symetryczne
- Brak stałych! (niestandardowe implementacje trudno zidentyfikować)
- KANAL (analizator kryptograficzny) nie pokazuje wskazówek dla RSA, bo opiera się na stałych.

### Identyfikacja przez porównania

![](<../../images/image (1113).png>)

- W linii 11 (po lewej) jest `+7) >> 3`, co jest takie samo jak w linii 35 (po prawej): `+7) / 8`
- Linia 12 (po lewej) sprawdza `modulus_len < 0x040`, a w linii 36 (po prawej) sprawdzane jest `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Cechy

- 3 funkcje: Init, Update, Final
- Podobne funkcje inicjalizujące

### Identyfikacja

**Init**

Możesz zidentyfikować oba, sprawdzając stałe. Zauważ, że sha_init ma jedną stałą, której MD5 nie posiada:

![](<../../images/image (406).png>)

**MD5 Transform**

Zwróć uwagę na użycie większej liczby stałych

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Mniejsze i bardziej wydajne, ponieważ ich funkcją jest wykrywanie przypadkowych zmian w danych
- Używa tabel wyszukiwania (lookup tables), więc można zidentyfikować go po stałych

### Identyfikacja

Sprawdź stałe tabel wyszukiwania:

![](<../../images/image (508).png>)

Algorytm CRC wygląda tak:

![](<../../images/image (391).png>)

## APLib (Compression)

### Cechy

- Brak rozpoznawalnych stałych
- Możesz spróbować napisać algorytm w Pythonie i wyszukać podobne rzeczy online

### Identyfikacja

Graf jest dość duży:

![](<../../images/image (207) (2) (1).png>)

Sprawdź **3 porównania, aby go rozpoznać**:

![](<../../images/image (430).png>)

## Błędy implementacji podpisów na krzywych eliptycznych

### EdDSA wymuszanie zakresu skalarów (malleability HashEdDSA)

- FIPS 186-5 §7.8.2 wymaga, aby weryfikatory HashEdDSA rozdzielały podpis `sig = R || s` i odrzucały każdy skalar z `s \geq n`, gdzie `n` jest rzędem grupy. Biblioteka `elliptic` w JS pominęła tę kontrolę zakresu, więc każdy atakujący, który zna poprawną parę `(msg, R || s)`, może sfałszować alternatywne podpisy `s' = s + k·n` i dalej ponownie kodować `sig' = R || s'`.
- Rutyny weryfikujące konsumują tylko `s mod n`, dlatego wszystkie `s'` kongruentne z `s` są akceptowane, mimo że są różnymi ciągami bajtów. Systemy traktujące podpisy jako kanoniczne tokeny (konsensus blockchain, cache odtwarzania, klucze w bazach danych itp.) mogą zostać desynchronizowane, ponieważ ścisłe implementacje odrzucą `s'`.
- Podczas audytu innego kodu HashEdDSA upewnij się, że parser waliduje zarówno punkt `R`, jak i długość skalaru; spróbuj dodać wielokrotności `n` do znanego poprawnego `s`, aby potwierdzić, że weryfikator zamyka weryfikację (fails closed).

### ECDSA — obcinanie vs. hashe z wiodącymi zerami

- Weryfikatory ECDSA muszą używać jedynie najbardziej znaczących `log2(n)` bitów skrótu wiadomości `H`. W `elliptic` pomocnik do obcinania obliczał `delta = (BN(msg).byteLength()*8) - bitlen(n)`; konstruktor `BN` usuwał wiodące zera oktetów, więc każdy hash zaczynający się od ≥4 zerowych bajtów na krzywych takich jak secp192r1 (rząd 192 bity) wydawał się mieć tylko 224 bity zamiast 256.
- Weryfikator przesuwał w prawo o 32 bity zamiast 64, produkując `E`, które nie odpowiadało wartości użytej przez podpisującego. Poprawne podpisy na takich haszach więc nie przechodziły z prawdopodobieństwem ≈`2^-32` dla wejść SHA-256.
- Dostarcz zarówno "dobry" wektor testowy, jak i warianty z wiodącymi zerami (np. przypadek Wycheproof `ecdsa_secp192r1_sha256_test.json` `tc296`) do testowanej implementacji; jeśli weryfikator różni się od podpisującego, znalazłeś podatny błąd obcinania.

### Testowanie wektorów Wycheproof przeciw bibliotekom
- Wycheproof dostarcza zestawy testowe w JSON, które kodują zniekształcone punkty, podatne skalary, niecodzienne hashe i inne przypadki brzegowe. Zbudowanie harnessu wokół `elliptic` (lub dowolnej biblioteki kryptograficznej) jest proste: załaduj JSON, zde-serializuj każdy przypadek testowy i sprawdź, czy implementacja zgadza się z oczekiwanym polem `result`.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Wyniki testów powinny być triage'owane, aby odróżnić naruszenia specyfikacji od false positives. Dla dwóch powyższych błędów, nieudane przypadki Wycheproof od razu wskazały na brakujące sprawdzenia zakresu skalarów (EdDSA) i nieprawidłowe obcinanie hasha (ECDSA).
- Zintegruj harness z CI, tak aby regresje w parsowaniu skalarów, obsłudze hasha lub poprawności współrzędnych wywoływały testy natychmiast po ich wprowadzeniu. Jest to szczególnie przydatne dla języków wysokiego poziomu (JS, Python, Go), gdzie subtelne konwersje bignumów łatwo mogą pójść źle.

## Źródła

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
