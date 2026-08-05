# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung <a href="#id-9wrzi" id="id-9wrzi"></a>

Informationen zu RFID und NFC findest du auf der folgenden Seite:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Unterstützte NFC-Karten <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Neben NFC-Karten unterstützt Flipper Zero **andere Arten von Hochfrequenzkarten**, darunter mehrere **Mifare** Classic und Ultralight sowie **NTAG**.

Der Liste der unterstützten Karten werden neue NFC-Kartentypen hinzugefügt. Flipper Zero unterstützt die folgenden **NFC-Karten des Typs A** (ISO 14443A):

- **Bankkarten (EMV)** — liest nur UID, SAK und ATQA ohne zu speichern.
- **Unbekannte Karten** — liest (UID, SAK, ATQA) und emuliert eine UID.

Bei **NFC-Karten des Typs B, Typ F und Typ V** kann Flipper Zero eine UID lesen, ohne sie zu speichern.

### NFC-Karten des Typs A <a href="#uvusf" id="uvusf"></a>

#### Bankkarte (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero kann eine UID, SAK, ATQA und gespeicherte Daten auf Bankkarten **nur ohne Speicherung** lesen.

Bildschirm zum Lesen von BankkartenBei Bankkarten kann Flipper Zero Daten nur **ohne sie zu speichern und zu emulieren** lesen.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unbekannte Karten <a href="#id-37eo8" id="id-37eo8"></a>

Wenn Flipper Zero den **Typ der NFC-Karte nicht bestimmen kann**, können nur **UID, SAK und ATQA** **gelesen und gespeichert** werden.

Bildschirm zum Lesen unbekannter KartenBei unbekannten NFC-Karten kann Flipper Zero nur eine UID emulieren.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC-Karten der Typen B, F und V <a href="#wyg51" id="wyg51"></a>

Bei **NFC-Karten der Typen B, F und V** kann Flipper Zero eine UID nur **lesen und anzeigen**, ohne sie zu speichern.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Aktionen

Eine Einführung zu NFC findest du auf [**dieser Seite**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lesen

Flipper Zero kann **NFC-Karten lesen**, versteht jedoch **nicht alle Protokolle**, die auf ISO 14443 basieren. Da die **UID jedoch ein Low-Level-Attribut ist**, kann es vorkommen, dass die **UID bereits gelesen wurde, das High-Level-Datenübertragungsprotokoll aber noch unbekannt ist**. Du kannst die UID mit Flipper lesen, emulieren und manuell eingeben, um primitive Lesegeräte zu verwenden, die die UID zur Autorisierung nutzen.<sup>[[1]](#references)</sup>

#### Lesen der UID VS Lesen der darin enthaltenen Daten <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Das Lesen von 13,56-MHz-Tags mit Flipper lässt sich in zwei Teile unterteilen:<sup>[[1]](#references)</sup>

- **Low-Level-Lesen** — liest nur UID, SAK und ATQA. Flipper versucht, anhand dieser von der Karte gelesenen Daten das High-Level-Protokoll zu erraten. Dabei kannst du dir nicht zu 100 % sicher sein, da es sich nur um eine auf bestimmten Faktoren basierende Annahme handelt.
- **High-Level-Lesen** — liest die Daten aus dem Speicher der Karte mithilfe eines bestimmten High-Level-Protokolls. Das bedeutet, die Daten einer Mifare Ultralight zu lesen, die Sektoren einer Mifare Classic zu lesen oder die Kartenattribute von PayPass/Apple Pay zu lesen.

### Bestimmten Typ lesen

Falls Flipper Zero den Kartentyp anhand der Low-Level-Daten nicht ermitteln kann, kannst du unter `Extra Actions` die Option `Read Specific Card Type` auswählen und **manuell** **den Typ der Karte angeben, die du lesen möchtest**.

#### EMV-Bankkarten (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Neben dem einfachen Lesen der UID kannst du deutlich mehr Daten aus einer Bankkarte extrahieren. Es ist möglich, **die vollständige Kartennummer** (die 16 Ziffern auf der Vorderseite der Karte), das **Gültigkeitsdatum** und in einigen Fällen sogar den **Namen des Inhabers** zusammen mit einer Liste der **jüngsten Transaktionen** zu erhalten.\
Auf diese Weise kannst du jedoch **nicht den CVV lesen** (die 3 Ziffern auf der Rückseite der Karte). Außerdem sind **Bankkarten vor Replay-Angriffen geschützt**, sodass das Kopieren mit Flipper und der anschließende Versuch, die Karte zum Bezahlen zu emulieren, nicht funktioniert.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
