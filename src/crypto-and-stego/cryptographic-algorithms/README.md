# Kryptograficzne/Algorytmy kompresji

{{#include ../../banners/hacktricks-training.md}}

## Identyfikacja algorytmów

Jeśli trafisz na kod, który **używa rotacji w prawo i w lewo, xorów oraz kilku operacji arytmetycznych**, istnieje duże prawdopodobieństwo, że to implementacja **algorytmu kryptograficznego**. Poniżej pokazano sposoby na **zidentyfikowanie używanego algorytmu bez konieczności odwracania każdego kroku**.

### Funkcje API

**CryptDeriveKey**

Jeśli ta funkcja jest używana, możesz sprawdzić, który **algorytm jest używany** patrząc na wartość drugiego parametru:

![](<../../images/image (156).png>)

Sprawdź tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dany bufor danych.

**CryptAcquireContext**

Z dokumentacji: The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Inicjuje hashowanie strumienia danych. Jeśli ta funkcja jest używana, możesz sprawdzić, który **algorytm jest używany** patrząc na wartość drugiego parametru:

![](<../../images/image (549).png>)

\
Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Stałe w kodzie

Czasami łatwo zidentyfikować algorytm dzięki temu, że używa on specyficznej i unikalnej wartości.

![](<../../images/image (833).png>)

Jeśli wyszukasz pierwszą stałą w Google, otrzymasz takie wyniki:

![](<../../images/image (529).png>)

W związku z tym możesz założyć, że zdekompilowana funkcja to **kalkulator sha256.**\
Możesz wyszukać dowolną z pozostałych stałych i najprawdopodobniej otrzymasz podobny rezultat.

### informacje o danych

Jeśli kod nie ma znaczących stałych, może **ładować informacje z sekcji .data**.\
Możesz uzyskać dostęp do tych danych, **pogroupować pierwszy dword** i wyszukać go w Google tak jak w poprzedniej sekcji:

![](<../../images/image (531).png>)

W tym przypadku, jeśli poszukasz **0xA56363C6**, znajdziesz, że jest powiązany z **tablicami algorytmu AES**.

## RC4 **(Symmetric Crypt)**

### Charakterystyka

Składa się z 3 głównych części:

- **Etap inicjalizacji/**: Tworzy **tablicę wartości od 0x00 do 0xFF** (256 bajtów, 0x100). Ta tablica jest powszechnie nazywana **Substitution Box** (lub SBox).
- **Etap mieszania**: Będzie **iterować po wcześniej utworzonej tablicy** (pętla o 0x100 iteracjach) modyfikując każdą wartość przy użyciu **półlosowych** bajtów. Do stworzenia tych półlosowych bajtów używany jest **klucz RC4**. Klucze RC4 mogą mieć **od 1 do 256 bajtów długości**, jednak zwykle zaleca się, aby miały więcej niż 5 bajtów. Typowo klucze RC4 mają długość 16 bajtów.
- **Etap XOR**: Wreszcie, plaintext lub ciphertext jest **XORowany z wartościami stworzymi wcześniej**. Funkcja szyfrująca i deszyfrująca jest taka sama. W tym celu wykonywana jest **pętla przez utworzone 256 bajtów** tak często, jak jest to potrzebne. Zwykle rozpoznawalne w zdekompilowanym kodzie przez użycie **%256 (mod 256)**.

> [!TIP]
> **Aby zidentyfikować RC4 w disassembl/ zdekompilowanym kodzie możesz sprawdzić obecność 2 pętli o rozmiarze 0x100 (z użyciem klucza) a następnie XOR danych wejściowych z 256 wartościami utworzonymi wcześniej, prawdopodobnie używając %256 (mod 256)**

### **Etap inicjalizacji/Substitution Box:** (Zwróć uwagę na użycie liczby 256 jako licznika i na zapisanie 0 w każdym miejscu 256 znaków)

![](<../../images/image (584).png>)

### **Etap mieszania:**

![](<../../images/image (835).png>)

### **Etap XOR:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **Charakterystyka**

- Zastosowanie **tablic podstawień i lookup tables**
- Można **odróżnić AES dzięki użyciu specyficznych wartości w tabelach lookup** (stałe). _Zauważ, że **stała** może być **przechowywana** w binarce **lub tworzona** **dynamicznie**._
- **Klucz szyfrujący** powinien mieć długość będącą wielokrotnością **16** (zwykle 32B) i zwykle używany jest **IV** o długości 16B.

### Stałe SBox

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Charakterystyka

- Rzadko spotyka się malware używające go, ale istnieją przykłady (Ursnif)
- Łatwo określić, czy algorytm to Serpent na podstawie jego długości (wyjątkowo długa funkcja)

### Identyfikacja

Na poniższym obrazie zwróć uwagę, jak użyto stałej **0x9E3779B9** (ta stała jest też używana przez inne algorytmy kryptograficzne jak **TEA** - Tiny Encryption Algorithm).\
Zauważ też **rozmiar pętli** (**132**) oraz **liczbę operacji XOR** w instrukcjach disassembly i w przykładzie kodu:

![](<../../images/image (547).png>)

Jak wspomniano wcześniej, ten kod w dekompilatorze wygląda jak **bardzo długa funkcja**, ponieważ **brakuje w niej skoków**. Zdekompilowany kod może wyglądać następująco:

![](<../../images/image (513).png>)

W związku z tym możliwe jest zidentyfikowanie tego algorytmu sprawdzając **liczbę magiczną** i **początkowe XORy**, widząc **bardzo długą funkcję** i **porównując** niektóre **instrukcje** tej funkcji z implementacją referencyjną (np. przesunięcie w lewo o 7 i rotacja w lewo o 22).

## RSA **(Asymmetric Crypt)**

### Charakterystyka

- Bardziej złożony niż algorytmy symetryczne
- Brak stałych! (własne implementacje są trudne do rozpoznania)
- KANAL (analizator kryptograficzny) nie potrafi wskazać wskazówek dotyczących RSA, ponieważ opiera się na stałych.

### Identyfikacja przez porównania

![](<../../images/image (1113).png>)

- W linii 11 (lewo) jest `+7) >> 3` co jest takie samo jak w linii 35 (prawo): `+7) / 8`
- Linia 12 (lewo) sprawdza czy `modulus_len < 0x040` a w linii 36 (prawo) sprawdza czy `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Charakterystyka

- 3 funkcje: Init, Update, Final
- Podobne funkcje inicjalizujące

### Identyfikacja

**Init**

Możesz zidentyfikować oba sprawdzając stałe. Zauważ, że sha_init ma jedną stałą, której MD5 nie ma:

![](<../../images/image (406).png>)

**MD5 Transform**

Zwróć uwagę na użycie większej liczby stałych

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Mniejszy i wydajniejszy, ponieważ jego funkcją jest wykrywanie przypadkowych zmian w danych
- Używa tabel lookup (więc możesz zidentyfikować po stałych)

### Identyfikacja

Sprawdź **stałe tabel lookup**:

![](<../../images/image (508).png>)

Algorytm CRC wygląda tak:

![](<../../images/image (391).png>)

## APLib (Compression)

### Charakterystyka

- Brak rozpoznawalnych stałych
- Możesz spróbować napisać algorytm w Pythonie i wyszukać podobieństwa online

### Identyfikacja

Graf jest dość duży:

![](<../../images/image (207) (2) (1).png>)

Sprawdź **3 porównania, aby go rozpoznać**:

![](<../../images/image (430).png>)

## Błędy implementacji podpisów na krzywych eliptycznych

### Egzekwowanie zakresu skalarnego w EdDSA ( podatność na modyfikowalność HashEdDSA )

- FIPS 186-5 §7.8.2 wymaga, aby weryfikatory HashEdDSA rozdzielały podpis `sig = R || s` i odrzucały każdy skalar z `s \geq n`, gdzie `n` to rząd grupy. Biblioteka `elliptic` w JS pominęła tę kontrolę zakresu, więc każdy atakujący, który zna prawidłową parę `(msg, R || s)` może sfałszować alternatywne podpisy `s' = s + k·n` i dalej kodować `sig' = R || s'`.
- Rutyny weryfikacyjne zużywają tylko `s mod n`, dlatego wszystkie `s'` kongruentne z `s` są akceptowane nawet jeśli są różnymi ciągami bajtów. Systemy traktujące podpisy jako kanoniczne tokeny (konsensus w blockchain, cache replay, klucze DB itd.) mogą zostać desynchronizowane, ponieważ ścisłe implementacje odrzucą `s'`.
- Audytując inne implementacje HashEdDSA, upewnij się, że parser waliduje zarówno punkt `R`, jak i długość skalaru; spróbuj dopisać wielokrotności `n` do znanego poprawnego `s`, aby potwierdzić, że weryfikator poprawnie odrzuca takie przypadki.

### Ucinanie ECDSA vs. hashe z wiodącymi zerami

- Weryfikatory ECDSA muszą używać tylko lewostronnych `log2(n)` bitów hasha wiadomości `H`. W `elliptic` helper do ucinania obliczał `delta = (BN(msg).byteLength()*8) - bitlen(n)`; konstruktor `BN` usuwa wiodące zera oktetów, więc każdy hash zaczynający się od ≥4 zerowych bajtów na krzywych takich jak secp192r1 (rząd 192-bitowy) wydawał się mieć tylko 224 bity zamiast 256.
- Weryfikator przesuwał w prawo o 32 bity zamiast 64, produkując `E`, które nie odpowiada wartości użytej przez podpisującego. Prawidłowe podpisy na tych hashach więc nie przechodzą weryfikacji z prawdopodobieństwem ≈`2^-32` dla wejść SHA-256.
- Dostarcz zarówno „dobry” wektor testowy, jak i warianty z wiodącymi zerami (np. Wycheproof `ecdsa_secp192r1_sha256_test.json` przypadek `tc296`) do testowanej implementacji; jeśli weryfikator nie zgadza się z podpisującym, znalazłeś wykorzystywalny błąd ucinania.

### Testowanie wektorów Wycheproof przeciw bibliotekom
- Wycheproof dostarcza zestawy testów w JSON, które kodują nieprawidłowe punkty, modyfikowalne skalary, nietypowe hashe i inne przypadki brzegowe. Zbudowanie harnessu wokół `elliptic` (lub dowolnej biblioteki kryptograficznej) jest proste: załaduj JSON, zdeserializuj każdy przypadek testowy i sprawdź, czy implementacja zgadza się z oczekiwanym flagiem `result`.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Należy przeprowadzić triage błędów, aby odróżnić naruszenia specyfikacji od fałszywych alarmów. W przypadku dwóch powyższych błędów nieprawidłowe przypadki Wycheproof od razu wskazały na brak sprawdzeń zakresu skalarów (EdDSA) oraz nieprawidłowe obcinanie hasha (ECDSA).
- Zintegruj harness z CI tak, aby regresje w parsowaniu skalarów, obsłudze hasha lub walidacji współrzędnych uruchamiały testy natychmiast po ich wprowadzeniu. Jest to szczególnie przydatne w językach wysokiego poziomu (JS, Python, Go), gdzie subtelne konwersje bignumów łatwo mogą być błędne.

## References

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
