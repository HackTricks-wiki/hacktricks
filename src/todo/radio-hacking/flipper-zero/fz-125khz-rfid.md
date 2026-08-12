# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Informacje o działaniu tagów 125 kHz znajdziesz tutaj:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Wprowadzenie do RFID niskiej częstotliwości](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) wyjaśnia popularne rodziny tagów i ich formaty danych.

## Działania

### Odczyt

Użyj opcji **Read**, aby przechwycić dane tagu. Po pomyślnym odczycie Flipper Zero może emulować zapisany tag.<sup>[[1]](#references)</sup>

> [!WARNING]
> Niektóre czytniki interkomów próbują wykryć zapisywalne duplikaty tagów, wysyłając polecenie zapisu przed odczytem. Emulacja Flipper Zero nie udostępnia pamięci zapisywalnego tagu w ten sam sposób.<sup>[[1]](#references)</sup>

### Dodawanie ręczne

Możesz ręcznie wprowadzić dane tagu do Flipper Zero, zapisać je, a następnie emulować tag.<sup>[[1]](#references)</sup>

#### Identyfikatory na kartach

Czasami całość lub część identyfikatora karty jest nadrukowana na jej obudowie.

- **EM Marin**

Na przykład przedstawiona karta EM-Marin ujawnia trzy ostatnie z pięciu bajtów identyfikatora. Jeśli nie można odczytać tagu, dwa brakujące bajty można brute-force'ować.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Podobnie przedstawiona karta HID ma nadrukowane tylko dwa z trzech bajtów identyfikatora.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulacja/zapis

Po odczytaniu tagu lub ręcznym wprowadzeniu jego identyfikatora Flipper Zero może emulować zapisane dane uwierzytelniające. W przypadku obsługiwanych zapisywalnych tagów może również zapisać zapisane dane na kompatybilnej karcie.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Zagłębiając się w protokoły RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
