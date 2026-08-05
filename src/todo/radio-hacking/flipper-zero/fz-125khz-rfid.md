# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Wprowadzenie

Więcej informacji o działaniu tagów 125 kHz znajdziesz tutaj:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Działania

Więcej informacji o tych typach tagów znajdziesz w [**tym wprowadzeniu**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Odczyt

Próbuje **odczytać** informacje z karty. Następnie może ją **emulować**.<sup>[[1]](#references)</sup>

> [!WARNING]
> Pamiętaj, że niektóre interkomy próbują chronić się przed duplikowaniem kluczy, wysyłając polecenie zapisu przed odczytem. Jeśli zapis się powiedzie, tag jest uznawany za fałszywy. Podczas emulowania RFID przez Flippera czytnik nie ma możliwości odróżnienia go od oryginalnego tagu, więc takie problemy nie występują.

### Dodaj ręcznie

Możesz utworzyć **fałszywe karty w Flipper Zero, wprowadzając ręcznie dane**, a następnie je emulować.

#### Identyfikatory na kartach

Czasami po otrzymaniu karty można znaleźć zapisany na niej, widoczny identyfikator (lub jego część).

- **EM Marin**

Na przykład w przypadku tej karty EM-Marin można **odczytać jawnie ostatnie 3 z 5 bajtów** z fizycznej karty.\
Pozostałe 2 można odgadnąć metodą brute-force, jeśli nie można ich odczytać z karty.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

To samo dotyczy tej karty HID, na której nadrukowane są tylko 2 z 3 bajtów

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulowanie/zapis

Po **skopiowaniu** karty lub **ręcznym wprowadzeniu** identyfikatora można ją **emulować** za pomocą Flipper Zero lub **zapisać** na prawdziwej karcie.<sup>[[1]](#references)</sup>

## Referencje

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
