# Analisi Wifi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Controlla i BSSID

Quando ricevi una cattura il cui traffico principale è Wifi utilizzando WireShark, puoi iniziare a investigare tutti gli SSID della cattura con _Wireless --> WLAN Traffic_:

![](<../../../images/image (106).png>)

![](<../../../images/image (492).png>)

### Brute Force

Una delle colonne di quella schermata indica se **è stata trovata qualche autenticazione all'interno del pcap**. Se è così, puoi provare a forzarlo con `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Ad esempio, recupererà la passphrase WPA che protegge un PSK (pre shared-key), necessaria per decrittografare il traffico in seguito.

## Dati nei Beacon / Canale Laterale

Se sospetti che **i dati vengano trasmessi all'interno dei beacon di una rete Wifi**, puoi controllare i beacon della rete utilizzando un filtro come il seguente: `wlan contains <NAMEofNETWORK>`, o `wlan.ssid == "NAMEofNETWORK"` cerca all'interno dei pacchetti filtrati stringhe sospette.

## Trova Indirizzi MAC Sconosciuti in una Rete Wifi

Il seguente link sarà utile per trovare le **macchine che inviano dati all'interno di una rete Wifi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se già conosci **gli indirizzi MAC puoi rimuoverli dall'output** aggiungendo controlli come questo: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una volta che hai rilevato **indirizzi MAC sconosciuti** che comunicano all'interno della rete, puoi utilizzare **filtri** come il seguente: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` per filtrare il suo traffico. Nota che i filtri ftp/http/ssh/telnet sono utili se hai decrittografato il traffico.

## Decrittografare il Traffico

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
