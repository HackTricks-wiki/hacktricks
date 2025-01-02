# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Wstęp

Aby uzyskać więcej informacji na temat działania tagów 125kHz, sprawdź:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Akcje

Aby uzyskać więcej informacji na temat tych typów tagów [**przeczytaj to wprowadzenie**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Odczyt

Próbuje **odczytać** informacje z karty. Następnie może ją **emulować**.

> [!WARNING]
> Zauważ, że niektóre domofony próbują chronić się przed duplikowaniem kluczy, wysyłając polecenie zapisu przed odczytem. Jeśli zapis się powiedzie, ten tag jest uważany za fałszywy. Gdy Flipper emuluje RFID, nie ma sposobu, aby czytnik odróżnił go od oryginału, więc takie problemy nie występują.

### Dodaj ręcznie

Możesz stworzyć **fałszywe karty w Flipper Zero, wskazując dane** ręcznie, a następnie je emulować.

#### ID na kartach

Czasami, gdy otrzymasz kartę, znajdziesz ID (lub jego część) napisane na widocznej stronie karty.

- **EM Marin**

Na przykład w tej karcie EM-Marin na fizycznej karcie można **odczytać ostatnie 3 z 5 bajtów w postaci jawnej**.\
Pozostałe 2 można odgadnąć, jeśli nie możesz ich odczytać z karty.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

To samo dzieje się w tej karcie HID, gdzie tylko 2 z 3 bajtów można znaleźć wydrukowane na karcie.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emuluj/Zapisz

Po **skopiowaniu** karty lub **wprowadzeniu** ID **ręcznie** można ją **emulować** za pomocą Flipper Zero lub **zapisać** na prawdziwej karcie.

## Odniesienia

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
