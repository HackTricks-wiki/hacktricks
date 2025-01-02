# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Intro

Aby uzyskać więcej informacji na temat działania tagów 125kHz, sprawdź:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Aby uzyskać więcej informacji na temat tych typów tagów [**przeczytaj to wprowadzenie**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Próbuje **odczytać** informacje z karty. Następnie może ją **emulować**.

> [!WARNING]
> Zauważ, że niektóre domofony próbują chronić się przed duplikowaniem kluczy, wysyłając polecenie zapisu przed odczytem. Jeśli zapis się powiedzie, ten tag jest uważany za fałszywy. Gdy Flipper emuluje RFID, nie ma sposobu, aby czytnik odróżnił go od oryginału, więc takie problemy nie występują.

### Add Manually

Możesz stworzyć **fałszywe karty w Flipper Zero, wskazując dane** ręcznie, a następnie je emulować.

#### IDs on cards

Czasami, gdy otrzymasz kartę, znajdziesz ID (lub jego część) napisane na widocznej stronie karty.

- **EM Marin**

Na przykład w tej karcie EM-Marin na fizycznej karcie można **odczytać ostatnie 3 z 5 bajtów w postaci jawnej**.\
Pozostałe 2 można odgadnąć, jeśli nie możesz ich odczytać z karty.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

To samo dzieje się w tej karcie HID, gdzie tylko 2 z 3 bajtów można znaleźć wydrukowane na karcie.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Po **skopiowaniu** karty lub **ręcznym wprowadzeniu** ID, możliwe jest **emulowanie** jej za pomocą Flipper Zero lub **zapisanie** jej na prawdziwej karcie.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
