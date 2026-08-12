# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Einführung <a href="#id-9wrzi" id="id-9wrzi"></a>

Informationen zu RFID und NFC findest du auf der folgenden Seite:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Unterstützte NFC-Karten <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Neben NFC-Karten unterstützt Flipper Zero **andere Arten von Hochfrequenzkarten**, darunter mehrere **Mifare** Classic und Ultralight sowie **NTAG**.

Die folgende Liste der Fähigkeiten beschreibt die in dem ursprünglichen Artikel dokumentierte Firmware und sollte nicht als aktuelle, vollständige Support-Matrix betrachtet werden. Die Flipper-Firmware hat im Laufe der Zeit Protokolle hinzugefügt und das NFC-Verhalten geändert. Prüfe die aktuelle offizielle Dokumentation für die installierte Firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bankkarten (EMV)** — nur UID, SAK und ATQA ohne Speicherung auslesen.
- **Unbekannte Karten** — UID, SAK und ATQA auslesen und eine UID emulieren.

Bei **NFC-Kartentypen B, F und V** konnte die dokumentierte Firmware eine UID auslesen, ohne sie zu speichern.

### NFC-Karten des Typs A <a href="#uvusf" id="uvusf"></a>

#### Bankkarte (EMV) <a href="#kzmrp" id="kzmrp"></a>

Die dokumentierte Firmware konnte eine UID, SAK, ATQA und verfügbare Anwendungsdaten einer Bankkarte **ohne Speicherung auslesen**.

Bei diesen Bankkarten zeigte die Firmware die Daten an, ohne die Karte zu speichern oder zu emulieren.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unbekannte Karten <a href="#id-37eo8" id="id-37eo8"></a>

Wenn Flipper Zero den **Typ der NFC-Karte nicht bestimmen kann**, können nur eine **UID, SAK und ATQA** **ausgelesen und gespeichert** werden.

Bei einer unbekannten NFC-Karte kann dieser Modus nur ihre UID emulieren.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC-Kartentypen B, F und V <a href="#wyg51" id="wyg51"></a>

In der in dem ursprünglichen Artikel dokumentierten Firmware konnten bei NFC-Kartentypen B, F und V nur die Kennung ausgelesen und angezeigt werden, ohne sie zu speichern.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Aktionen

Eine Einführung in NFC findest du auf [**dieser Seite**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Auslesen

Flipper Zero kann NFC-Karten auslesen, implementiert jedoch nicht jedes auf ISO 14443 basierende Protokoll höherer Ebene. Daher kann das Gerät möglicherweise die UID, SAK und ATQA der unteren Ebene auslesen, während das Anwendungsprotokoll unbekannt bleibt. Bei einfachen Zugangssystemen, die nur anhand der UID autorisieren, kann das Tool diese Kennung auslesen, manuell eingeben und emulieren. Kryptografisch authentifizierte Systeme erfordern mehr als eine kopierte UID.<sup>[[1]](#references)</sup>

#### UID auslesen VS Daten im Inneren auslesen <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Das Auslesen von 13,56-MHz-Tags in Flipper kann in zwei Teile unterteilt werden:<sup>[[1]](#references)</sup>

- **Auslesen auf niedriger Ebene** — liest nur die UID, SAK und ATQA aus. Flipper versucht, anhand dieser von der Karte ausgelesenen Daten das Protokoll höherer Ebene zu erraten. Dabei kann man sich nicht zu 100 % sicher sein, da dies nur eine auf bestimmten Faktoren basierende Annahme ist.
- **Auslesen auf hoher Ebene** — liest die Daten aus dem Speicher der Karte mithilfe eines bestimmten Protokolls höherer Ebene aus. Dabei werden beispielsweise die Daten einer Mifare Ultralight, die Sektoren einer Mifare Classic oder die Kartenattribute von PayPass/Apple Pay ausgelesen.

### Gezieltes Auslesen

Falls Flipper Zero den Kartentyp anhand der Daten der unteren Ebene nicht ermitteln kann, kannst du unter `Extra Actions` die Option `Read Specific Card Type` auswählen und **manuell** den **Typ der Karte angeben, die du auslesen möchtest**.

#### EMV-Bankkarten (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Ältere Flipper-Firmware und kompatible EMV-Karten konnten mehr als nur die UID offenlegen, darunter möglicherweise die PAN, das Ablaufdatum, den Namen des Karteninhabers oder das Transaktionsprotokoll, sofern diese Datensätze von der Karte bereitgestellt wurden. Die Verfügbarkeit variiert je nach Karte, Anwendung und Firmware. Der auf die Karte aufgedruckte CVV des Magnetstreifens wird auf diese Weise nicht offengelegt. Das Auslesen dieser Datensätze klont außerdem nicht die für eine kontaktlose Zahlung erforderlichen kryptografischen Transaktionsfunktionen.<sup>[[1]](#references)</sup>

## References

- [1] [Eintauchen in RFID-Protokolle mit Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Dokumentation zu Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
