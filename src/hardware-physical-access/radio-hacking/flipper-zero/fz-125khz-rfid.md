# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Informacje o działaniu tagów 125 kHz znajdziesz tutaj:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Wprowadzenie do RFID niskiej częstotliwości](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) opisuje popularne rodziny tagów i ich formaty danych.

## Akcje

### Odczyt

Użyj opcji **Read**, aby przechwycić dane tagu. Po pomyślnym odczycie Flipper Zero może emulować zapisany tag.<sup>[[1]](#references)</sup>

> [!WARNING]
> Niektóre czytniki domofonowe próbują wykrywać zapisywalne duplikaty tagów, wysyłając polecenie zapisu przed odczytem. Emulacja Flipper Zero nie udostępnia pamięci zapisywalnego tagu w ten sam sposób.<sup>[[1]](#references)</sup>

### Dodawanie ręczne

Możesz ręcznie wprowadzić dane tagu do Flipper Zero, zapisać je, a następnie emulować tag.<sup>[[1]](#references)</sup>

#### ID na kartach

Czasami na zewnętrznej stronie karty nadrukowane jest całe lub część jej ID.

- **EM Marin**

Na przykład na przedstawionej karcie EM-Marin widoczne są trzy ostatnie z pięciu bajtów ID. Jeśli tagu nie da się odczytać, brakujące dwa bajty można odgadnąć metodą brute-force.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Podobnie na przedstawionej karcie HID nadrukowane są tylko dwa z trzech bajtów ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulacja/zapis

Po odczytaniu tagu lub ręcznym wprowadzeniu jego ID Flipper Zero może emulować zapisane poświadczenie. W przypadku obsługiwanych tagów zapisywalnych może też zapisać dane na kompatybilnej karcie.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Zagłębianie się w protokoły RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
