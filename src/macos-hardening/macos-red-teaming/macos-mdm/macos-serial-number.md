# macOS Numer seryjny

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Urządzenia Apple po 2010 roku mają numery seryjne składające się z **12 znaków alfanumerycznych**, z których każdy segment przekazuje konkretne informacje:

- **Pierwsze 3 znaki**: Wskazują na **miejsce produkcji**.
- **Znaki 4 i 5**: Oznaczają **rok i tydzień produkcji**.
- **Znaki 6 do 8**: Służą jako **unikalny identyfikator** dla każdego urządzenia.
- **Ostatnie 4 znaki**: Określają **numer modelu**.

Na przykład, numer seryjny **C02L13ECF8J2** podąża za tą strukturą.

### **Miejsca produkcji (Pierwsze 3 znaki)**

Niektóre kody reprezentują konkretne fabryki:

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

Ten znak zmienia się od 'C' (reprezentujący pierwszą połowę 2010 roku) do 'Z' (drugą połowę 2019 roku), przy czym różne litery wskazują różne półroczne okresy.

### **Tydzień produkcji (5. znak)**

Cyfry 1-9 odpowiadają tygodniom 1-9. Litery C-Y (z wyjątkiem samogłosków i 'S') reprezentują tygodnie 10-27. Dla drugiej połowy roku dodaje się 26 do tej liczby.

{{#include ../../../banners/hacktricks-training.md}}
