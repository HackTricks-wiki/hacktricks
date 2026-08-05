# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#id-9wrzi" id="id-9wrzi"></a>

Informacje o RFID i NFC znajdziesz na następującej stronie:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Obsługiwane karty NFC <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Oprócz kart NFC Flipper Zero obsługuje **inne typy kart wysokiej częstotliwości**, takie jak niektóre karty **Mifare** Classic i Ultralight oraz **NTAG**.

Do listy obsługiwanych kart będą dodawane nowe typy kart NFC. Flipper Zero obsługuje następujące **karty NFC typu A** (ISO 14443A):

- **Karty bankowe (EMV)** — tylko odczyt UID, SAK i ATQA bez zapisywania.
- **Nieznane karty** — odczyt (UID, SAK, ATQA) i emulacja UID.

W przypadku **kart NFC typu B, typu F i typu V** Flipper Zero może odczytać UID bez jego zapisywania.

### Karty NFC typu A <a href="#uvusf" id="uvusf"></a>

#### Karta bankowa (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero może odczytać UID, SAK, ATQA oraz zapisane dane na kartach bankowych **bez zapisywania**.

Ekran odczytu karty bankowejW przypadku kart bankowych Flipper Zero może odczytać dane wyłącznie **bez ich zapisywania i emulowania**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Nieznane karty <a href="#id-37eo8" id="id-37eo8"></a>

Gdy Flipper Zero **nie może określić typu karty NFC**, można jedynie **odczytać i zapisać** **UID, SAK i ATQA**.

Ekran odczytu nieznanej kartyW przypadku nieznanych kart NFC Flipper Zero może emulować tylko UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Karty NFC typu B, F i V <a href="#wyg51" id="wyg51"></a>

W przypadku **kart NFC typu B, F i V** Flipper Zero może jedynie **odczytać i wyświetlić UID** bez jego zapisywania.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Działania

Wprowadzenie do NFC znajdziesz na [**tej stronie**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Odczyt

Flipper Zero może **odczytywać karty NFC**, jednak **nie rozumie wszystkich protokołów** opartych na ISO 14443. Ponieważ jednak **UID jest atrybutem niskiego poziomu**, możesz znaleźć się w sytuacji, w której **UID został już odczytany, ale protokół transferu danych wysokiego poziomu jest nadal nieznany**. Za pomocą Flippera można odczytywać, emulować i ręcznie wprowadzać UID w przypadku prymitywnych czytników, które używają UID do autoryzacji.<sup>[[1]](#references)</sup>

#### Odczyt UID a odczyt danych wewnątrz <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

W przypadku Flippera odczyt tagów 13.56 MHz można podzielić na dwie części:<sup>[[1]](#references)</sup>

- **Odczyt niskiego poziomu** — odczytuje tylko UID, SAK i ATQA. Flipper próbuje odgadnąć protokół wysokiego poziomu na podstawie tych danych odczytanych z karty. Nie można mieć w tym 100% pewności, ponieważ jest to jedynie założenie oparte na określonych czynnikach.
- **Odczyt wysokiego poziomu** — odczytuje dane z pamięci karty za pomocą określonego protokołu wysokiego poziomu. Oznacza to odczyt danych z Mifare Ultralight, odczyt sektorów z Mifare Classic lub odczyt atrybutów karty z PayPass/Apple Pay.

### Odczyt określonego typu

Jeśli Flipper Zero nie jest w stanie określić typu karty na podstawie danych niskiego poziomu, w `Extra Actions` możesz wybrać `Read Specific Card Type` i **ręcznie** **wskazać typ karty, który chcesz odczytać**.

#### Bankowe karty EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Oprócz prostego odczytu UID można wyodrębnić znacznie więcej danych z karty bankowej. Możliwe jest **uzyskanie pełnego numeru karty** (16 cyfr znajdujących się z przodu karty), **daty ważności**, a w niektórych przypadkach nawet **imienia i nazwiska właściciela** wraz z listą **najnowszych transakcji**.\
Nie można jednak w ten sposób **odczytać kodu CVV** (3 cyfr znajdujących się z tyłu karty). Ponadto **karty bankowe są chronione przed replay attacks**, więc skopiowanie karty za pomocą Flippera, a następnie próba jej emulowania w celu zapłacenia za coś nie zadziała.<sup>[[1]](#references)</sup>

## Referencje

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
