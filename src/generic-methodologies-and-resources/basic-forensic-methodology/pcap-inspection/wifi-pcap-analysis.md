# Analisi di un Pcap WiFi

{{#include ../../../banners/hacktricks-training.md}}

## Verifica i BSSID

Quando ricevi una cattura il cui traffico principale è WiFi usando WireShark, puoi iniziare a esaminare tutti gli SSID della cattura con _Wireless --> WLAN Traffic_:

![Analisi di un Pcap WiFi - Verifica i BSSID: quando ricevi una cattura il cui traffico principale è WiFi usando WireShark, puoi iniziare a esaminare tutti gli SSID della cattura con Wireless --...](<../../../images/image (106).png>)

![Analisi di un Pcap WiFi - Verifica i BSSID: quando ricevi una cattura il cui traffico principale è WiFi usando WireShark, puoi iniziare a esaminare tutti gli SSID della cattura con Wireless --...](<../../../images/image (492).png>)

### Brute Force

Una delle colonne di quella schermata indica se **è stata trovata un'autenticazione all'interno del pcap**. In tal caso puoi provare a eseguire il Brute force usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Ad esempio, recupererà la passphrase WPA che protegge una PSK (pre shared-key), necessaria per decrittografare il traffico in seguito.

## Dati nei Beacon / Side Channel

Se sospetti che **dei dati vengano divulgati all'interno dei beacon di una rete Wi-Fi**, puoi controllare i beacon della rete usando un filtro come il seguente: `wlan contains <NAMEofNETWORK>`, oppure `wlan.ssid == "NAMEofNETWORK"`; cerca stringhe sospette all'interno dei pacchetti filtrati.

## Trovare indirizzi MAC sconosciuti in una rete Wi-Fi

Il seguente filtro sarà utile per trovare le **macchine che inviano dati all'interno di una rete Wi-Fi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se conosci già gli **indirizzi MAC**, puoi rimuoverli dall'output aggiungendo controlli come questo: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Dopo aver rilevato gli **indirizzi MAC sconosciuti** che comunicano all'interno della rete, puoi usare **filtri** come il seguente: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` per filtrare il relativo traffico. Nota che i filtri ftp/http/ssh/telnet sono utili se hai decrittografato il traffico.

## Decrittografare il traffico

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Trovare indirizzi MAC sconosciuti in una rete Wi-Fi - Decrittografare il traffico: dopo aver rilevato indirizzi MAC sconosciuti che comunicano all'interno della rete, puoi usare filtri come il seguente:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
