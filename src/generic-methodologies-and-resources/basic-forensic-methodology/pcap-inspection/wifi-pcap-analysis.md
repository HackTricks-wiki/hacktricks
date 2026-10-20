# Analisi Pcap Wi-Fi

{{#include ../../../banners/hacktricks-training.md}}

## Verifica dei BSSID

Con una cattura Wi-Fi aperta in Wireshark, seleziona _Wireless → WLAN Traffic_ per riepilogare le reti wireless osservate nella cattura; ogni riga rappresenta una rete wireless.<sup>[[1]](#references)</sup>

![Analisi Pcap Wi-Fi - Verifica dei BSSID: quando ricevi una cattura il cui traffico principale è Wi-Fi, puoi iniziare a esaminare tutti gli SSID della cattura con Wireless --...](<../../../images/image (106).png>)

![Analisi Pcap Wi-Fi - Verifica dei BSSID: quando ricevi una cattura il cui traffico principale è Wi-Fi, puoi iniziare a esaminare tutti gli SSID della cattura con Wireless --...](<../../../images/image (492).png>)

### Brute Force

Per le catture WPA/WPA2-PSK, `aircrack-ng` richiede un four-way EAPOL handshake utilizzabile e prova le passphrase candidate usando un dizionario. Usa `-w` per specificare la wordlist e `-b` per selezionare il BSSID dell'access point:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Se una corrisponde, Aircrack-ng recupera la chiave pre-condivisa; la password e l'SSID corrispondenti possono quindi essere configurati nelle impostazioni di decrittazione 802.11 di Wireshark, se la cattura e la modalità di sicurezza lo consentono.<sup>[[2]](#references)[[5]](#references)</sup>

## Data in Beacons / Side Channel

Se sospetti che **i dati vengano divulgati nel traffico side-channel dei beacon**, inizia con un filtro di visualizzazione come `wlan contains "NAMEofNETWORK"` o `wlan.ssid == "NAMEofNETWORK"`, quindi esamina i frame corrispondenti alla ricerca di stringhe sospette. La prima forma esegue una ricerca generica nei byte; la seconda corrisponde al campo SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Find Unknown MAC Addresses in a Wi-Fi Network

Wireshark espone `wlan.ta` come indirizzo del trasmettitore e `wlan.addr` come indirizzo hardware/MAC; i filtri di visualizzazione possono combinare questi campi con operatori logici:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se conosci già **gli indirizzi MAC, rimuovili dall'output** aggiungendo controlli come `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Dopo aver individuato **indirizzi MAC sconosciuti** che comunicano all'interno della rete, usa un filtro come `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` per restringere il traffico. I filtri FTP, HTTP, SSH e Telnet sono utili solo quando Wireshark è in grado di analizzare il payload decrittato corrispondente.<sup>[[3]](#references)[[5]](#references)</sup>

## Decrypt Traffic

Per aggiungere una chiave di decrittazione 802.11 in Wireshark, apri _Edit → Preferences → Protocols → IEEE 802.11_ e fai clic su _Edit_ accanto a _Decryption Keys_.<sup>[[5]](#references)</sup>

![Individuare indirizzi MAC sconosciuti in una rete Wi-Fi - Decrittare il traffico: dopo aver individuato indirizzi MAC sconosciuti che comunicano all'interno della rete, puoi usare filtri come il seguente:...](<../../../images/image (499).png>)

Per WPA/WPA2, Wireshark richiede normalmente l'handshake a quattro vie EAPOL e la password/SSID corrispondenti; fornire la chiave temporanea può evitare il requisito dell'handshake. La decrittazione WPA3 per singola connessione richiede la PMK della connessione.<sup>[[5]](#references)</sup>

Per la decrittazione TLS a livello applicativo dopo aver recuperato il traffico Wi-Fi, consulta [Wireshark tricks](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Guida utente di Wireshark: traffico WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Guida utente di Wireshark: creazione di espressioni per i filtri di visualizzazione](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Riferimento ai filtri di visualizzazione di Wireshark: LAN wireless IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Guida utente di Wireshark: chiavi di decrittazione WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
