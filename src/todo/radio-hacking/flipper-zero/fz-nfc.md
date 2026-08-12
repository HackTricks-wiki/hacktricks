# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#id-9wrzi" id="id-9wrzi"></a>

Informacje o RFID i NFC znajdziesz na następującej stronie:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Obsługiwane karty NFC <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Oprócz kart NFC Flipper Zero obsługuje **inne typy kart wysokiej częstotliwości**, takie jak kilka kart **Mifare** Classic i Ultralight oraz **NTAG**.

Poniższa lista możliwości opisuje firmware udokumentowany w oryginalnym artykule i nie powinna być traktowana jako aktualna, wyczerpująca lista obsługiwanych kart. Firmware Flippera z czasem zyskał nowe protokoły, a jego działanie z NFC ulegało zmianom; sprawdź aktualną oficjalną dokumentację dla zainstalowanego firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Karty bankowe (EMV)** — tylko odczyt UID, SAK i ATQA bez zapisywania.
- **Nieznane karty** — odczyt UID, SAK i ATQA oraz emulacja UID.

W przypadku **kart NFC typu B, F i V** udokumentowany firmware mógł odczytać UID bez jego zapisywania.

### Karty NFC typu A <a href="#uvusf" id="uvusf"></a>

#### Karta bankowa (EMV) <a href="#kzmrp" id="kzmrp"></a>

Udokumentowany firmware mógł odczytać UID, SAK, ATQA oraz dostępne dane aplikacji z karty bankowej **bez ich zapisywania**.

W przypadku tych kart bankowych firmware wyświetlał dane bez zapisywania ani emulowania karty.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Nieznane karty <a href="#id-37eo8" id="id-37eo8"></a>

Gdy Flipper Zero **nie jest w stanie określić typu karty NFC**, można **odczytać i zapisać** jedynie **UID, SAK i ATQA**.

W przypadku nieznanej karty NFC ten tryb może emulować wyłącznie jej UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Karty NFC typu B, F i V <a href="#wyg51" id="wyg51"></a>

W firmware udokumentowanym w oryginalnym artykule można było jedynie odczytać i wyświetlić identyfikator kart NFC typu B, F i V, bez jego zapisywania.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Działania

Wprowadzenie do NFC znajdziesz na [**tej stronie**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Odczyt

Flipper Zero może odczytywać karty NFC, ale nie implementuje każdego protokołu wyższego poziomu opartego na ISO 14443. Może więc odzyskać niskopoziomowe UID, SAK i ATQA, pozostawiając nieznany protokół aplikacji. W przypadku prymitywnych systemów dostępu, które autoryzują wyłącznie na podstawie UID, narzędzie może odczytać, ręcznie wprowadzić i emulować ten identyfikator; systemy wymagające uwierzytelniania kryptograficznego potrzebują czegoś więcej niż skopiowanego UID.<sup>[[1]](#references)</sup>

#### Odczyt UID A odczyt danych wewnątrz <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

W Flipperze odczyt tagów 13,56 MHz można podzielić na dwie części:<sup>[[1]](#references)</sup>

- **Odczyt niskopoziomowy** — odczytuje tylko UID, SAK i ATQA. Flipper próbuje odgadnąć protokół wysokiego poziomu na podstawie tych danych odczytanych z karty. Nie można mieć w tej kwestii 100% pewności, ponieważ jest to jedynie założenie oparte na określonych czynnikach.
- **Odczyt wysokopoziomowy** — odczytuje dane z pamięci karty przy użyciu określonego protokołu wysokiego poziomu. Oznacza to odczyt danych z Mifare Ultralight, odczyt sektorów z Mifare Classic lub odczyt atrybutów karty z PayPass/Apple Pay.

### Odczyt określonego typu

Jeśli Flipper Zero nie jest w stanie określić typu karty na podstawie danych niskopoziomowych, w `Extra Actions` możesz wybrać `Read Specific Card Type` i **ręcznie** **wskazać typ karty, który chcesz odczytać**.

#### Karty bankowe EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Starszy firmware Flippera i kompatybilne karty EMV mogły udostępniać więcej niż UID, potencjalnie w tym PAN, datę ważności, imię i nazwisko posiadacza karty lub rejestr transakcji, jeśli karta udostępniała takie rekordy. Dostępność zależy od karty, aplikacji i firmware. CVV paska magnetycznego wydrukowany na karcie nie jest w ten sposób ujawniany, a odczyt tych rekordów nie klonuje kryptograficznych możliwości transakcyjnych wymaganych do wykonania płatności zbliżeniowej.<sup>[[1]](#references)</sup>

## References

- [1] [Zgłębianie protokołów RFID za pomocą Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Dokumentacja Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
