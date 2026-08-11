# Wifi-Pcap-Analyse

{{#include ../../../banners/hacktricks-training.md}}

## BSSIDs überprüfen

Wenn eine Wi-Fi-Aufzeichnung in Wireshark geöffnet ist, wähle _Wireless → WLAN Traffic_, um die in der Aufzeichnung beobachteten drahtlosen Netzwerke zusammenzufassen. Jede Zeile stellt ein drahtloses Netzwerk dar.<sup>[[1]](#references)</sup>

![Wifi-Pcap-Analyse – BSSIDs überprüfen: Wenn du eine Aufzeichnung erhältst, deren Hauptverkehr Wifi verwendet, kannst du mit Wireshark beginnen, alle SSIDs der Aufzeichnung über Wireless --... zu untersuchen.](<../../../images/image (106).png>)

![Wifi-Pcap-Analyse – BSSIDs überprüfen: Wenn du eine Aufzeichnung erhältst, deren Hauptverkehr Wifi verwendet, kannst du mit Wireshark beginnen, alle SSIDs der Aufzeichnung über Wireless --... zu untersuchen.](<../../../images/image (492).png>)

### Brute Force

Für WPA/WPA2-PSK-Aufzeichnungen benötigt `aircrack-ng` einen verwertbaren EAPOL-Vier-Wege-Handshake und testet mögliche Passphrasen mithilfe eines Wörterbuchs. Verwende `-w`, um die Wordlist anzugeben, und `-b`, um den BSSID des Access Points als Ziel festzulegen:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Wenn ein Kandidat übereinstimmt, stellt Aircrack-ng den Pre-Shared Key wieder her; das passende Passwort und die SSID können anschließend in Wiresharks 802.11-Entschlüsselungseinstellungen konfiguriert werden, sofern Capture und Sicherheitsmodus dies unterstützen.<sup>[[2]](#references)[[5]](#references)</sup>

## Daten in Beacons / Side Channel

Wenn du vermutest, dass **Daten im Beacon-Side-Channel-Traffic geleakt werden**, beginne mit einem Display-Filter wie `wlan contains "NAMEofNETWORK"` oder `wlan.ssid == "NAMEofNETWORK"` und untersuche anschließend passende Frames auf verdächtige Zeichenfolgen. Die erste Form führt eine umfassende Byte-Suche durch; die zweite stimmt mit dem SSID-Feld überein.<sup>[[3]](#references)[[4]](#references)</sup>

## Unbekannte MAC-Adressen in einem Wi-Fi-Netzwerk finden

Wireshark stellt `wlan.ta` als Senderadresse und `wlan.addr` als Hardware-/MAC-Adresse bereit; Display-Filter können diese Felder mit logischen Operatoren kombinieren:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Wenn du **MAC-Adressen bereits kennst, entferne sie aus der Ausgabe**, indem du Prüfungen wie `&& !(wlan.addr == 5c:51:88:31:a0:3b)` hinzufügst.

Sobald du **unbekannte MAC-Adressen** erkannt hast, die innerhalb des Netzwerks kommunizieren, kannst du einen Filter wie `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` verwenden, um ihren Traffic einzugrenzen. Die FTP-, HTTP-, SSH- und Telnet-Filter sind nur nützlich, wenn Wireshark die entsprechenden entschlüsselten Payloads analysieren kann.<sup>[[3]](#references)[[5]](#references)</sup>

## Traffic entschlüsseln

Um einen 802.11-Entschlüsselungsschlüssel in Wireshark hinzuzufügen, öffne _Edit → Preferences → Protocols → IEEE 802.11_ und klicke neben _Decryption Keys_ auf _Edit_.<sup>[[5]](#references)</sup>

![Unbekannte MAC-Adressen in einem Wi-Fi-Netzwerk finden - Traffic entschlüsseln: Sobald du unbekannte MAC-Adressen erkannt hast, die innerhalb des Netzwerks kommunizieren, kannst du Filter wie den folgenden verwenden:...](<../../../images/image (499).png>)

Für WPA/WPA2 benötigt Wireshark normalerweise den vierteiligen EAPOL-Handshake und das passende Passwort/die passende SSID; durch Angabe des Transient Key lässt sich die Anforderung des Handshakes vermeiden. Die Entschlüsselung von WPA3 pro Verbindung erfordert den PMK der Verbindung.<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark-Benutzerhandbuch: WLAN-Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark-Benutzerhandbuch: Display-Filter-Ausdrücke erstellen](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display-Filter-Referenz: Drahtloses LAN nach IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark-Benutzerhandbuch: IEEE-802.11-WLAN-Entschlüsselungsschlüssel](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
