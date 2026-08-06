# Wifi-Pcap-Analyse

{{#include ../../../banners/hacktricks-training.md}}

## BSSIDs überprüfen

Wenn du eine Capture erhältst, deren Hauptdatenverkehr über Wifi läuft, kannst du mit WireShark beginnen, alle SSIDs der Capture über _Wireless --> WLAN Traffic_ zu untersuchen:

![Wifi-Pcap-Analyse – BSSIDs überprüfen: Wenn du eine Capture erhältst, deren Hauptdatenverkehr über Wifi läuft, kannst du mit WireShark beginnen, alle SSIDs der Capture über Wireless --... zu untersuchen](<../../../images/image (106).png>)

![Wifi-Pcap-Analyse – BSSIDs überprüfen: Wenn du eine Capture erhältst, deren Hauptdatenverkehr über Wifi läuft, kannst du mit WireShark beginnen, alle SSIDs der Capture über Wireless --... zu untersuchen](<../../../images/image (492).png>)

### Brute Force

Eine der Spalten dieses Bildschirms zeigt an, ob **eine Authentifizierung innerhalb der pcap gefunden wurde**. Falls dies der Fall ist, kannst du versuchen, sie mit `aircrack-ng` per Brute Force zu knacken:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Beispielsweise ruft es die WPA-Passphrase ab, die einen PSK (pre shared-key) schützt und später zum Entschlüsseln des Datenverkehrs erforderlich ist.

## Daten in Beacons / Side Channel

Wenn du vermutest, dass **Daten innerhalb von Beacons eines Wifi-Netzwerks geleakt werden**, kannst du die Beacons des Netzwerks mit einem Filter wie dem folgenden überprüfen: `wlan contains <NAMEofNETWORK>` oder `wlan.ssid == "NAMEofNETWORK"` und innerhalb der gefilterten Pakete nach verdächtigen Zeichenfolgen suchen.

## Unbekannte MAC-Adressen in einem Wifi-Netzwerk finden

Der folgende Link ist nützlich, um die **Maschinen zu finden, die Daten innerhalb eines Wifi-Netzwerks senden**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Wenn du **MAC-Adressen bereits kennst, kannst du sie aus der Ausgabe entfernen**, indem du Prüfungen wie diese hinzufügst: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Sobald du **unbekannte MAC-Adressen** erkannt hast, die innerhalb des Netzwerks kommunizieren, kannst du **Filter** wie den folgenden verwenden: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`, um deren Datenverkehr zu filtern. Beachte, dass die ftp/http/ssh/telnet-Filter nützlich sind, wenn du den Datenverkehr entschlüsselt hast.

## Datenverkehr entschlüsseln

Bearbeiten --> Einstellungen --> Protokolle --> IEEE 802.11--> Bearbeiten

![Unbekannte MAC-Adressen in einem Wifi-Netzwerk finden – Datenverkehr entschlüsseln: Sobald du unbekannte MAC-Adressen erkannt hast, die innerhalb des Netzwerks kommunizieren, kannst du Filter wie den folgenden verwenden:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
