# Analisi di Wifi Pcap

## Check BSSIDs

Con una cattura Wi-Fi aperta in Wireshark, seleziona _Wireless → WLAN Traffic_ per riepilogare le reti wireless osservate nella cattura; ogni riga rappresenta una rete wireless.<sup>[[1]](#references)</sup>

![Analisi di Wifi Pcap - Check BSSIDs: Quando ricevi una cattura il cui traffico principale è Wifi usando WireShark, puoi iniziare a esaminare tutti gli SSID della cattura con Wireless --...](<../../../images/image (106).png>)

![Analisi di Wifi Pcap - Check BSSIDs: Quando ricevi una cattura il cui traffico principale è Wifi usando WireShark, puoi iniziare a esaminare tutti gli SSID della cattura con Wireless --...](<../../../images/image (492).png>)

### Brute Force

Per le catture WPA/WPA2-PSK, `aircrack-ng` richiede un handshake EAPOL a quattro vie utilizzabile e testa le passphrase candidate con un dizionario. Usa `-w` per specificare la wordlist e `-b` per scegliere come obiettivo il BSSID dell'access point:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Se un candidato corrisponde, Aircrack-ng recupera la chiave pre-shared; la password e l'SSID corrispondenti possono quindi essere configurati nelle impostazioni di decrittazione 802.11 di Wireshark quando la cattura e la modalità di sicurezza lo supportano.<sup>[[2]](#references)[[5]](#references)</sup>

## Data nei beacon / Side Channel

Se sospetti che **dei dati vengano divulgati nel traffico del side channel dei beacon**, inizia con un display filter come `wlan contains "NAMEofNETWORK"` o `wlan.ssid == "NAMEofNETWORK"`, quindi esamina i frame corrispondenti alla ricerca di stringhe sospette. La prima forma esegue una ricerca ampia sui byte; la seconda corrisponde al campo SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Trovare indirizzi MAC sconosciuti in una rete Wi-Fi

Wireshark espone `wlan.ta` come indirizzo del trasmettitore e `wlan.addr` come indirizzo hardware/MAC; i display filter possono combinare questi campi con operatori logici:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se conosci già gli **indirizzi MAC, rimuovili dall'output** aggiungendo controlli come `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Dopo aver rilevato **indirizzi MAC sconosciuti** che comunicano all'interno della rete, usa un filtro come `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` per restringere il traffico. I filtri FTP, HTTP, SSH e Telnet sono utili solo quando Wireshark può analizzare il payload decrittato corrispondente.<sup>[[3]](#references)[[5]](#references)</sup>

## Decrittare il traffico

Per aggiungere una chiave di decrittazione 802.11 in Wireshark, apri _Edit → Preferences → Protocols → IEEE 802.11_ e fai clic su _Edit_ accanto a _Decryption Keys_.<sup>[[5]](#references)</sup>

![Trovare indirizzi MAC sconosciuti in una rete Wi-Fi - Decrittare il traffico: dopo aver rilevato indirizzi MAC sconosciuti che comunicano all'interno della rete, puoi usare filtri come il seguente:...](<../../../images/image (499).png>)

Per WPA/WPA2, Wireshark normalmente necessita dell'handshake EAPOL a quattro vie e della password/SSID corrispondenti; fornire la chiave transient può evitare il requisito dell'handshake. La decrittazione per-connessione di WPA3 richiede il PMK della connessione.<sup>[[5]](#references)</sup>

## References

- [1] [Guida utente di Wireshark: traffico WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Guida utente di Wireshark: creazione di espressioni per i display filter](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Riferimento dei display filter di Wireshark: wireless LAN IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Guida utente di Wireshark: chiavi di decrittazione WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
