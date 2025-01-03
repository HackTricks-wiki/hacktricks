# Algorytmy kryptograficzne/kompresji

## Algorytmy kryptograficzne/kompresji

{{#include ../../banners/hacktricks-training.md}}

## Identyfikacja algorytmów

Jeśli kończysz w kodzie **używając przesunięć w prawo i w lewo, xorów oraz kilku operacji arytmetycznych**, jest bardzo prawdopodobne, że to implementacja **algorytmu kryptograficznego**. Poniżej przedstawione zostaną sposoby na **identyfikację algorytmu, który jest używany bez potrzeby odwracania każdego kroku**.

### Funkcje API

**CryptDeriveKey**

Jeśli ta funkcja jest używana, możesz znaleźć, który **algorytm jest używany**, sprawdzając wartość drugiego parametru:

![](<../../images/image (156).png>)

Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dany bufor danych.

**CryptAcquireContext**

Z [dokumentacji](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcja **CryptAcquireContext** jest używana do uzyskania uchwytu do konkretnego kontenera kluczy w danym dostawcy usług kryptograficznych (CSP). **Ten zwrócony uchwyt jest używany w wywołaniach funkcji CryptoAPI**, które korzystają z wybranego CSP.

**CryptCreateHash**

Inicjuje haszowanie strumienia danych. Jeśli ta funkcja jest używana, możesz znaleźć, który **algorytm jest używany**, sprawdzając wartość drugiego parametru:

![](<../../images/image (549).png>)

\
Sprawdź tutaj tabelę możliwych algorytmów i ich przypisanych wartości: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Stałe kodu

Czasami naprawdę łatwo jest zidentyfikować algorytm dzięki temu, że musi używać specjalnej i unikalnej wartości.

![](<../../images/image (833).png>)

Jeśli wyszukasz pierwszą stałą w Google, oto co otrzymasz:

![](<../../images/image (529).png>)

Dlatego możesz założyć, że zdekompilowana funkcja to **kalkulator sha256.**\
Możesz wyszukać dowolną z innych stałych, a prawdopodobnie uzyskasz ten sam wynik.

### Informacje o danych

Jeśli kod nie ma żadnej istotnej stałej, może być **ładowany informacje z sekcji .data**.\
Możesz uzyskać dostęp do tych danych, **grupując pierwszy dword** i wyszukując go w Google, jak zrobiliśmy w poprzedniej sekcji:

![](<../../images/image (531).png>)

W tym przypadku, jeśli poszukasz **0xA56363C6**, możesz znaleźć, że jest związany z **tabelami algorytmu AES**.

## RC4 **(Symetryczna kryptografia)**

### Cechy

Składa się z 3 głównych części:

- **Etap inicjalizacji/**: Tworzy **tabelę wartości od 0x00 do 0xFF** (łącznie 256 bajtów, 0x100). Ta tabela jest powszechnie nazywana **Substitution Box** (lub SBox).
- **Etap mieszania**: Będzie **przechodzić przez tabelę** utworzoną wcześniej (pętla 0x100 iteracji, ponownie) modyfikując każdą wartość za pomocą **półlosowych** bajtów. Aby stworzyć te półlosowe bajty, używany jest klucz RC4. Klucze RC4 mogą mieć **od 1 do 256 bajtów długości**, jednak zazwyczaj zaleca się, aby miały więcej niż 5 bajtów. Zwykle klucze RC4 mają długość 16 bajtów.
- **Etap XOR**: Na koniec, tekst jawny lub szyfrogram jest **XORowany z wartościami utworzonymi wcześniej**. Funkcja do szyfrowania i deszyfrowania jest taka sama. W tym celu zostanie wykonana **pętla przez utworzone 256 bajtów** tyle razy, ile to konieczne. Zwykle jest to rozpoznawane w zdekompilowanym kodzie z **%256 (mod 256)**.

> [!NOTE]
> **Aby zidentyfikować RC4 w kodzie disassembly/zdekompilowanym, możesz sprawdzić 2 pętle o rozmiarze 0x100 (z użyciem klucza), a następnie XOR danych wejściowych z 256 wartościami utworzonymi wcześniej w 2 pętlach, prawdopodobnie używając %256 (mod 256)**

### **Etap inicjalizacji/Substitution Box:** (Zauważ liczbę 256 używaną jako licznik i jak 0 jest zapisywane w każdym miejscu 256 znaków)

![](<../../images/image (584).png>)

### **Etap mieszania:**

![](<../../images/image (835).png>)

### **Etap XOR:**

![](<../../images/image (904).png>)

## **AES (Symetryczna kryptografia)**

### **Cechy**

- Użycie **tabel substytucji i tabel wyszukiwania**
- Możliwe jest **rozróżnienie AES dzięki użyciu specyficznych wartości tabel wyszukiwania** (stałych). _Zauważ, że **stała** może być **przechowywana** w binarnym **lub tworzona** _**dynamicznie**._
- **Klucz szyfrowania** musi być **podzielny** przez **16** (zwykle 32B) i zazwyczaj używa się **IV** o długości 16B.

### Stałe SBox

![](<../../images/image (208).png>)

## Serpent **(Symetryczna kryptografia)**

### Cechy

- Rzadko można znaleźć złośliwe oprogramowanie używające go, ale są przykłady (Ursnif)
- Łatwo określić, czy algorytm to Serpent, czy nie, na podstawie jego długości (ekstremalnie długa funkcja)

### Identyfikacja

Na poniższym obrazie zauważ, jak stała **0x9E3779B9** jest używana (zauważ, że ta stała jest również używana przez inne algorytmy kryptograficzne, takie jak **TEA** - Tiny Encryption Algorithm).\
Zauważ także **rozmiar pętli** (**132**) oraz **liczbę operacji XOR** w instrukcjach **disassembly** i w przykładzie **kodu**:

![](<../../images/image (547).png>)

Jak wspomniano wcześniej, ten kod można zobaczyć w dowolnym dekompilatorze jako **bardzo długą funkcję**, ponieważ **nie ma skoków** w jej wnętrzu. Zdekompilowany kod może wyglądać następująco:

![](<../../images/image (513).png>)

Dlatego możliwe jest zidentyfikowanie tego algorytmu, sprawdzając **magiczną liczbę** i **początkowe XOR**, widząc **bardzo długą funkcję** i **porównując** niektóre **instrukcje** długiej funkcji **z implementacją** (jak przesunięcie w lewo o 7 i obrót w lewo o 22).

## RSA **(Asymetryczna kryptografia)**

### Cechy

- Bardziej złożone niż algorytmy symetryczne
- Nie ma stałych! (trudno określić niestandardowe implementacje)
- KANAL (analityk kryptograficzny) nie pokazuje wskazówek dotyczących RSA, ponieważ opiera się na stałych.

### Identyfikacja przez porównania

![](<../../images/image (1113).png>)

- W linii 11 (po lewej) jest `+7) >> 3`, co jest takie samo jak w linii 35 (po prawej): `+7) / 8`
- Linia 12 (po lewej) sprawdza, czy `modulus_len < 0x040`, a w linii 36 (po prawej) sprawdza, czy `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Cechy

- 3 funkcje: Init, Update, Final
- Podobne funkcje inicjalizacyjne

### Identyfikacja

**Init**

Możesz zidentyfikować obie, sprawdzając stałe. Zauważ, że sha_init ma 1 stałą, której MD5 nie ma:

![](<../../images/image (406).png>)

**MD5 Transform**

Zauważ użycie większej liczby stałych

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Mniejszy i bardziej wydajny, ponieważ jego funkcją jest znajdowanie przypadkowych zmian w danych
- Używa tabel wyszukiwania (więc możesz zidentyfikować stałe)

### Identyfikacja

Sprawdź **stałe tabeli wyszukiwania**:

![](<../../images/image (508).png>)

Algorytm haszujący CRC wygląda jak:

![](<../../images/image (391).png>)

## APLib (Kompresja)

### Cechy

- Brak rozpoznawalnych stałych
- Możesz spróbować napisać algorytm w Pythonie i poszukać podobnych rzeczy w Internecie

### Identyfikacja

Wykres jest dość duży:

![](<../../images/image (207) (2) (1).png>)

Sprawdź **3 porównania, aby go rozpoznać**:

![](<../../images/image (430).png>)

{{#include ../../banners/hacktricks-training.md}}
