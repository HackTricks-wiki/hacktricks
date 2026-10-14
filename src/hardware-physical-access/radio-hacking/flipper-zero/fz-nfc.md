# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Informationen zu RFID und NFC findest du auf der folgenden Seite:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Unterstützte NFC-Karten <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Neben NFC-Karten unterstützt Flipper Zero **andere Arten von Hochfrequenzkarten**, darunter mehrere **Mifare** Classic und Ultralight sowie **NTAG**.

Die folgende Liste der Funktionen beschreibt die in dem ursprünglichen Artikel dokumentierte Firmware und sollte nicht als aktuelle, vollständige Support-Matrix betrachtet werden. Die Flipper-Firmware hat im Laufe der Zeit Protokolle hinzugefügt und das NFC-Verhalten geändert. Prüfe daher die aktuelle offizielle Dokumentation für die installierte Firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bankkarten (EMV)** — UID, SAK und ATQA werden nur gelesen, aber nicht gespeichert.
- **Unbekannte Karten** — UID, SAK und ATQA werden gelesen und eine UID wird emuliert.

Bei **NFC-Kartentypen B, F und V** konnte die dokumentierte Firmware eine UID lesen, ohne sie zu speichern.

### NFC-Karten vom Typ A <a href="#uvusf" id="uvusf"></a>

#### Bankkarte (EMV) <a href="#kzmrp" id="kzmrp"></a>

Die dokumentierte Firmware konnte eine UID, SAK, ATQA und verfügbare Anwendungsdaten einer Bankkarte lesen, **ohne sie zu speichern**.

Bei diesen Bankkarten zeigte die Firmware die Daten an, ohne die Karte zu speichern oder zu emulieren.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unbekannte Karten <a href="#id-37eo8" id="id-37eo8"></a>

Wenn Flipper Zero den **Typ der NFC-Karte nicht bestimmen kann**, können nur **UID, SAK und ATQA** **gelesen und gespeichert** werden.

Bei einer unbekannten NFC-Karte kann dieser Modus nur ihre UID emulieren.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC-Kartentypen B, F und V <a href="#wyg51" id="wyg51"></a>

Bei der im ursprünglichen Artikel dokumentierten Firmware konnten NFC-Kartentypen B, F und V nur anhand ihrer Kennung ausgelesen und angezeigt werden, ohne diese zu speichern.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Aktionen

Eine Einführung zu NFC findest du auf [**dieser Seite**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Lesen

Flipper Zero kann NFC-Karten lesen, implementiert aber nicht jedes übergeordnete Protokoll, das auf ISO 14443 aufsetzt. Daher kann es möglicherweise die Low-Level-UID, SAK und ATQA auslesen, während das Anwendungsprotokoll unbekannt bleibt. Bei einfachen Zugangssystemen, die nur anhand der UID autorisieren, kann das Gerät diese Kennung lesen, manuell eingeben und emulieren. Bei kryptografisch authentifizierten Systemen reicht eine kopierte UID nicht aus.<sup>[[1]](#references)</sup>

#### UID lesen VS Daten im Inneren lesen <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper lässt sich das Lesen von 13,56-MHz-Tags in zwei Teile gliedern:<sup>[[1]](#references)</sup>

- **Low-Level-Auslesen** — liest nur UID, SAK und ATQA. Flipper versucht anhand dieser von der Karte ausgelesenen Daten, das übergeordnete Protokoll zu erraten. Dabei kannst du dir nicht hundertprozentig sicher sein, da es sich lediglich um eine Annahme auf Grundlage bestimmter Faktoren handelt.
- **High-Level-Auslesen** — liest die Daten aus dem Speicher der Karte mithilfe eines bestimmten übergeordneten Protokolls. Dazu gehört das Auslesen der Daten auf einer Mifare Ultralight, der Sektoren einer Mifare Classic oder der Kartenattribute von PayPass/Apple Pay.

### Bestimmten Kartentyp auslesen

Falls Flipper Zero den Kartentyp anhand der Low-Level-Daten nicht ermitteln kann, kannst du unter `Extra Actions` die Option `Read Specific Card Type` auswählen und **manuell** **den Kartentyp angeben, den du auslesen möchtest**.

#### EMV-Bankkarten (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Ältere Flipper-Firmware und kompatible EMV-Karten konnten mehr als nur die UID preisgeben, möglicherweise auch die PAN, das Ablaufdatum, den Namen des Karteninhabers oder das Transaktionsprotokoll, sofern diese Datensätze auf der Karte verfügbar waren. Die Verfügbarkeit hängt von der Karte, der Anwendung und der Firmware ab. Der auf die Karte gedruckte CVV des Magnetstreifens wird auf diese Weise nicht ausgelesen. Außerdem lässt sich durch das Auslesen dieser Datensätze nicht die kryptografische Transaktionsfähigkeit klonen, die für kontaktloses Bezahlen erforderlich ist.<sup>[[1]](#references)</sup>

## References

- [1] [Ein Einblick in RFID-Protokolle mit Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Flipper-Zero-Dokumentation - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
