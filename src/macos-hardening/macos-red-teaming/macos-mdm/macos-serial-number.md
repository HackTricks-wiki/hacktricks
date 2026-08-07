# Numer seryjny macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Urządzenia Apple wyprodukowane po 2010 roku mają numery seryjne składające się z **12 znaków alfanumerycznych**, przy czym każdy segment przekazuje określone informacje:

- **Pierwsze 3 znaki**: Wskazują **miejsce produkcji**.
- **Znaki 4 i 5**: Oznaczają **rok i tydzień produkcji**.
- **Znaki od 6 do 8**: Służą jako **unikalny identyfikator** każdego urządzenia.
- **Ostatnie 4 znaki**: Określają **numer modelu**.

Na przykład numer seryjny **C02L13ECF8J2** ma taką strukturę.

### **Miejsca produkcji (pierwsze 3 znaki)**

Niektóre kody oznaczają konkretne fabryki:

- **FC, F, XA/XB/QP/G8**: Różne lokalizacje w USA.
- **RN**: Meksyk.
- **CK**: Cork, Irlandia.
- **VM**: Foxconn, Czechy.
- **SG/E**: Singapur.
- **MB**: Malezja.
- **PT/CY**: Korea.
- **EE/QT/UV**: Tajwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Różne lokalizacje w Chinach.
- **C0, C3, C7**: Konkretne miasta w Chinach.
- **RM**: Odnowione urządzenia.

### **Rok produkcji (4. znak)**

Ten znak zmienia się od „C” (oznaczającego pierwszą połowę 2010 roku) do „Z” (drugą połowę 2019 roku), przy czym różne litery wskazują różne okresy półroczne.

### **Tydzień produkcji (5. znak)**

Cyfry 1–9 odpowiadają tygodniom od 1 do 9. Litery C–Y (z wyłączeniem samogłosek i „S”) oznaczają tygodnie od 10 do 27. W przypadku drugiej połowy roku do tej liczby dodaje się 26.

{{#include ../../../banners/hacktricks-training.md}}
