# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#id-9wrzi" id="id-9wrzi"></a>

Informacje o RFID i NFC znajdziesz na tej stronie:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Obsługiwane karty NFC <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Oprócz kart NFC Flipper Zero obsługuje **inne rodzaje kart wysokiej częstotliwości**, takie jak niektóre karty **Mifare** Classic i Ultralight oraz **NTAG**.

Poniższa lista możliwości dotyczy firmware opisanego w oryginalnym artykule i nie powinna być traktowana jako aktualna, pełna lista obsługiwanych kart. Firmware Flippera z czasem zyskało obsługę kolejnych protokołów i zmieniło sposób działania NFC; sprawdź aktualną oficjalną dokumentację dla zainstalowanego firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Karty bankowe (EMV)** — odczyt UID, SAK i ATQA bez zapisywania.
- **Nieznane karty** — odczyt UID, SAK i ATQA oraz emulacja UID.

W przypadku **kart NFC typu B, F i V** opisane firmware mogło odczytać UID bez zapisywania go.

### Karty NFC typu A <a href="#uvusf" id="uvusf"></a>

#### Karta bankowa (EMV) <a href="#kzmrp" id="kzmrp"></a>

Opisane firmware mogło odczytać UID, SAK, ATQA oraz dostępne dane aplikacji z karty bankowej, **nie zapisując ich**.

W przypadku tych kart bankowych firmware wyświetlało dane, ale nie zapisywało ani nie emulowało karty.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Nieznane karty <a href="#id-37eo8" id="id-37eo8"></a>

Jeśli Flipper Zero **nie może określić typu karty NFC**, można **odczytać i zapisać** tylko **UID, SAK i ATQA**.

W tym trybie można emulować wyłącznie UID nieznanej karty NFC.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Karty NFC typu B, F i V <a href="#wyg51" id="wyg51"></a>

W firmware opisanym w oryginalnym artykule karty NFC typu B, F i V pozwalały jedynie odczytać i wyświetlić identyfikator, bez zapisywania go.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Działania

Wprowadzenie do NFC znajdziesz na [**tej stronie**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Odczyt

Flipper Zero może odczytywać karty NFC, ale nie obsługuje wszystkich protokołów wyższego poziomu opartych na ISO 14443. Może więc odczytać niskopoziomowe UID, SAK i ATQA, nie rozpoznając protokołu aplikacji. W prostych systemach dostępu, które autoryzują wyłącznie na podstawie UID, narzędzie może odczytać i ręcznie wprowadzić ten identyfikator oraz go emulować; w systemach wymagających uwierzytelniania kryptograficznego samo skopiowanie UID nie wystarczy.<sup>[[1]](#references)</sup>

#### Odczyt UID a odczyt danych zapisanych na karcie <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

W Flipperze odczyt tagów 13,56 MHz można podzielić na dwie części:<sup>[[1]](#references)</sup>

- **Odczyt niskopoziomowy** — odczytuje tylko UID, SAK i ATQA. Na podstawie tych danych Flipper próbuje odgadnąć protokół wyższego poziomu. Nie można mieć co do tego całkowitej pewności, ponieważ jest to jedynie przypuszczenie oparte na określonych przesłankach.
- **Odczyt wysokopoziomowy** — odczytuje dane z pamięci karty przy użyciu konkretnego protokołu wyższego poziomu. Obejmuje to odczyt danych z Mifare Ultralight, sektorów z Mifare Classic albo atrybutów karty PayPass/Apple Pay.

### Odczyt określonego typu

Jeśli Flipper Zero nie potrafi określić typu karty na podstawie danych niskopoziomowych, w `Extra Actions` możesz wybrać `Read Specific Card Type` i **ręcznie** **wskazać typ karty, którą chcesz odczytać**.

#### Karty bankowe EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Starsze wersje firmware Flippera i zgodne karty EMV mogły udostępniać więcej danych niż tylko UID, w tym potencjalnie PAN, datę ważności, nazwisko posiadacza karty lub historię transakcji, jeśli karta udostępniała te rekordy. Dostępność zależy od karty, aplikacji i firmware. Wydrukowany na karcie CVV paska magnetycznego nie jest w ten sposób ujawniany, a odczyt tych rekordów nie klonuje kryptograficznej funkcji transakcyjnej wymaganej do płatności zbliżeniowych.<sup>[[1]](#references)</sup>

## References

- [1] [Poznaj protokoły RFID z Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Dokumentacja Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
