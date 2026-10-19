# VSAT-Forward-Link-Signalinjektion

{{#include ../../banners/hacktricks-training.md}}

Ein VSAT-Terminal behandelt seinen Satelliten-Downlink normalerweise als Datenverkehr vom Hub des Betreibers. In einem DVB-RCS-System kann dieser Forward Link sowohl IP-Nutzerdatenpakete als auch Modem-Steuernachrichten übertragen. Wenn der Empfänger eine Nachricht vor der Verarbeitung nicht authentifiziert, kann ein lokal eingespeistes Signal die Vertrauensgrenze zwischen Funk- und Control Plane überschreiten. Dies ist **Downlink-Injektion am Terminal**, kein Uplink zum Satelliten und kein passives Abfangen des Downlinks. Das demonstrierte Ergebnis hängt von der Protokollimplementierung und der Nachrichtenauthentifizierung des Modems ab, nicht allein von DVB-RCS.<sup>[[1]](#references)[[2]](#references)</sup>

## Test in einer HF-abgeschirmten Laborumgebung

Verwende ein eigenes Terminal, dessen Firmware und einen SDR, der über geeignete Dämpfungsglieder mit dem Empfangseingang des Modems verbunden ist, oder eine abgeschirmte HF-Umgebung. Sende nicht auf einem aktiven Satellitenkanal. Halte zuerst den konfigurierten Start-up-Träger, die Symbolrate und die Population ID des Terminals fest; sie helfen bei der Akquisition des Forward Links.<sup>[[1]](#references)[[3]](#references)</sup> Die DVB-RCS-Akquisitionskette verwendet die Network Information Table (NIT), um die RCS Map Table (RMT) zu finden, und anschließend die Program Association Table (PAT) und Program Map Table (PMT), um die Forward-Link-Signalisierungsstreams zu lokalisieren. Ein Terminal kann mehrere Transport-Stream-Träger durchstimmen, bevor es den Datenstream erreicht.<sup>[[3]](#references)</sup>

1. Dekodiere oder rekonstruiere den Start-up-Transportstream des Ziels und untersuche dessen NIT, RMT, Service-IDs, Paket-IDs (PIDs) und Umgang mit Taktreferenzen. Vergleiche den Standard mit dem Parser und den Logs des Ziels; herstellerspezifische Reihenfolgen oder Deskriptoren können verhindern, dass ein ansonsten gültiger Stream akzeptiert wird.
2. Kapsle im Laborsender eine harmlose UDP-Probe als `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` und speise sie über einen SDR-Sink in den isolierten Empfangspfad ein. Halte die Program Clock Reference (PCR) des Transportstreams konsistent mit der Byte-Rate, sonst kann das Modem die Synchronisierung verlieren, bevor es die Probe verarbeitet.
3. Bestätige sowohl den **Demodulator-Lock** als auch den Empfang der Probe an einem eigenen internen Endpunkt. Ein Lock allein beweist nur, dass die physikalische Schicht die Wellenform akzeptiert hat. Prüfe anschließend, ob nicht authentifizierte Management- oder Update-*Signalisierung* zugänglich ist, ohne ein Image zu installieren oder die Dienstkonfiguration zu ändern.

Der veröffentlichte MDM2200-Fall verwendete ein GNU-Radio-Quellmodul für DVB-RCS/MPE/MPEG-TS und `gr-dtv` für die DVB-S2-Modulation. Das Modem benötigte zielspezifische Initialisierungsdetails: ein SDT vor der PAT/PMT, einen RCS-Content-Descriptor mit Tabellen-ID `0x3E` und ein RMT-Private-Byte `0x01` für seinen GSE/4CPM-Modus. Gehe nicht davon aus, dass diese Werte auch mit einem anderen Terminal funktionieren.<sup>[[1]](#references)</sup> Die Forschenden beobachteten außerdem, dass Multicast-MPE-Pakete in ihrem Aufbau die Empfangsmodems erreichten. Das Targeting war also nicht auf eine bekannte Unicast-MAC-Adresse beschränkt.<sup>[[1]](#references)</sup> Eine separate Analyse fand im untersuchten System ungeschützte Steuer- und Software-Update-Signalisierung; dieser Befund muss jedoch für jede Implementierung einzeln überprüft werden.<sup>[[2]](#references)</sup>

Ein IPsec- oder VPN-Tunnel für Nutzerdaten authentifiziert weder die vorherige DVB-RCS-Signalisierung noch den Update-Parser des Modems selbst. Unterscheide bei einer autorisierten Prüfung den kryptografischen Schutz von **Nutzer-IP**, **Forward-Link-Steuerdaten** und **Wartungs-/Wiederherstellungsdaten**, statt einen sicheren Nutzertunnel als Beweis dafür zu betrachten, dass Funkinjektion verhindert wird.<sup>[[1]](#references)[[2]](#references)</sup>

Zur ersten I/Q-Untersuchung siehe [Funksignalanalyse](../hardware-hacking/radio.md). Zur Untersuchung von Firmware und Parsern auf Platinenebene siehe [Firmware-Analyse](../firmware-analysis/). Kehre zur [Übersicht über Radio Hacking](./) zurück, um weitere Schnittstellen zu finden.

## References

- [1] [Bisping et al. - Angriffe durch drahtlose Signalinjektion auf VSAT-Satellitenmodems (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: Aufdeckung inhärenter Sicherheitsprobleme in aktuellen VSAT-Systempraktiken (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - DVB-Interaktionskanal für Satellitenverteilungssysteme](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
