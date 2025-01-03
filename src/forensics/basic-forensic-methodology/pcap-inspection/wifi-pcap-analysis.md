{{#include ../../../banners/hacktricks-training.md}}

# Überprüfen von BSSIDs

Wenn Sie einen Capture erhalten, dessen Hauptverkehr Wifi ist, können Sie mit WireShark alle SSIDs des Captures untersuchen, indem Sie _Wireless --> WLAN Traffic_ auswählen:

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## Brute Force

Eine der Spalten dieses Bildschirms zeigt an, ob **irgendeine Authentifizierung im pcap gefunden wurde**. Wenn dies der Fall ist, können Sie versuchen, es mit `aircrack-ng` zu brute-forcen:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Zum Beispiel wird das WPA-Passwort abgerufen, das einen PSK (pre shared-key) schützt, das später zum Entschlüsseln des Verkehrs benötigt wird.

# Daten in Beacons / Seitenkanal

Wenn Sie vermuten, dass **Daten in Beacons eines Wifi-Netzwerks geleakt werden**, können Sie die Beacons des Netzwerks mit einem Filter wie dem folgenden überprüfen: `wlan contains <NAMEofNETWORK>`, oder `wlan.ssid == "NAMEofNETWORK"` und in den gefilterten Paketen nach verdächtigen Zeichenfolgen suchen.

# Unbekannte MAC-Adressen in einem Wifi-Netzwerk finden

Der folgende Link wird nützlich sein, um die **Maschinen zu finden, die Daten in einem Wifi-Netzwerk senden**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Wenn Sie bereits **MAC-Adressen kennen, können Sie diese aus der Ausgabe entfernen**, indem Sie Überprüfungen wie diese hinzufügen: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Sobald Sie **unbekannte MAC**-Adressen erkannt haben, die im Netzwerk kommunizieren, können Sie **Filter** wie den folgenden verwenden: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`, um den Verkehr zu filtern. Beachten Sie, dass ftp/http/ssh/telnet-Filter nützlich sind, wenn Sie den Verkehr entschlüsselt haben.

# Verkehr entschlüsseln

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
