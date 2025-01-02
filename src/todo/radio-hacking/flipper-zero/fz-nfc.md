# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Aby uzyskać informacje o RFID i NFC, sprawdź następującą stronę:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Obsługiwane karty NFC <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Oprócz kart NFC, Flipper Zero obsługuje **inny typ kart wysokiej częstotliwości**, takich jak kilka **Mifare** Classic i Ultralight oraz **NTAG**.

Nowe typy kart NFC będą dodawane do listy obsługiwanych kart. Flipper Zero obsługuje następujące **karty NFC typu A** (ISO 14443A):

- **Karty bankowe (EMV)** — tylko odczyt UID, SAK i ATQA bez zapisywania.
- **Nieznane karty** — odczyt (UID, SAK, ATQA) i emulacja UID.

Dla **kart NFC typu B, F i V**, Flipper Zero może odczytać UID bez zapisywania.

### Karty NFC typu A <a href="#uvusf" id="uvusf"></a>

#### Karta bankowa (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero może tylko odczytać UID, SAK, ATQA i dane przechowywane na kartach bankowych **bez zapisywania**.

Ekran odczytu karty bankowej. Dla kart bankowych Flipper Zero może tylko odczytać dane **bez zapisywania i emulacji**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Nieznane karty <a href="#id-37eo8" id="id-37eo8"></a>

Gdy Flipper Zero jest **niezdolny do określenia typu karty NFC**, można odczytać i **zapisać tylko UID, SAK i ATQA**.

Ekran odczytu nieznanej karty. Dla nieznanych kart NFC Flipper Zero może emulować tylko UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Karty NFC typu B, F i V <a href="#wyg51" id="wyg51"></a>

Dla **kart NFC typu B, F i V**, Flipper Zero może tylko **odczytać i wyświetlić UID** bez zapisywania.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Akcje

Aby uzyskać wprowadzenie do NFC [**przeczytaj tę stronę**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Odczyt

Flipper Zero może **odczytywać karty NFC**, jednak **nie rozumie wszystkich protokołów** opartych na ISO 14443. Ponieważ **UID jest atrybutem niskiego poziomu**, możesz znaleźć się w sytuacji, gdy **UID jest już odczytany, ale protokół transferu danych na wyższym poziomie jest nadal nieznany**. Możesz odczytać, emulować i ręcznie wprowadzić UID za pomocą Flippera dla prymitywnych czytników, które używają UID do autoryzacji.

#### Odczyt UID VS Odczyt Danych Wewnątrz <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

W Flipperze odczyt tagów 13.56 MHz można podzielić na dwie części:

- **Odczyt niskiego poziomu** — odczytuje tylko UID, SAK i ATQA. Flipper próbuje zgadnąć protokół na wyższym poziomie na podstawie tych danych odczytanych z karty. Nie możesz być w 100% pewny, ponieważ jest to tylko przypuszczenie oparte na pewnych czynnikach.
- **Odczyt wysokiego poziomu** — odczytuje dane z pamięci karty za pomocą konkretnego protokołu na wyższym poziomie. Oznacza to odczyt danych z Mifare Ultralight, odczyt sektorów z Mifare Classic lub odczyt atrybutów karty z PayPass/Apple Pay.

### Odczyt Specyficzny

W przypadku, gdy Flipper Zero nie jest w stanie znaleźć typu karty na podstawie danych niskiego poziomu, w `Dodatkowych Akcjach` możesz wybrać `Odczytaj Specyficzny Typ Karty` i **ręcznie** **określić typ karty, którą chcesz odczytać**.

#### Karty Bankowe EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Oprócz prostego odczytu UID, możesz wyodrębnić znacznie więcej danych z karty bankowej. Możliwe jest **uzyskanie pełnego numeru karty** (16 cyfr na przedniej stronie karty), **daty ważności**, a w niektórych przypadkach nawet **nazwy właściciela** wraz z listą **najbardziej recentnych transakcji**.\
Jednak **nie możesz odczytać CVV w ten sposób** (3 cyfry na odwrocie karty). Również **karty bankowe są chronione przed atakami powtórzeniowymi**, więc skopiowanie ich za pomocą Flippera, a następnie próba emulacji w celu zapłaty za coś, nie zadziała.

## Referencje

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
