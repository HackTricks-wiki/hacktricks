# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Einführung

**Low-Power Wide Area Network** (LPWAN) ist eine Gruppe drahtloser, stromsparender Weitverkehrsnetzwerktechnologien, die für **Kommunikation über große Entfernungen** bei niedriger Bitrate entwickelt wurden.
Abhängig von Funkparametern, Antenne, Regulierungsregion, Gelände und Duty Cycle können LPWAN-Deployments Durchsatz gegen eine Abdeckung von mehreren Kilometern und eine mehrjährige Batterielebensdauer eintauschen. Behandle Angaben von Anbietern zu Reichweite und Batterielebensdauer als Designziele und nicht als Garantien.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) ist derzeit die am weitesten verbreitete LPWAN Physical Layer, und ihre offene MAC-Layer-Spezifikation ist **LoRaWAN**.

---

## LPWAN, LoRa und LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) Physical Layer, entwickelt von Semtech (proprietär, aber dokumentiert).
* LoRaWAN – Offene MAC-/Network-Layer, gepflegt von der LoRa-Alliance. Die Versionen 1.0.x und 1.1 sind in der Praxis weit verbreitet.
* Typische Architektur: *Endgerät → Gateway (packet-forwarder) → Network-Server → Application-Server*.<sup>[[3]](#references)</sup>

> In LoRaWAN 1.1 verwendet das **Sicherheitsmodell** separate AES-128-Anwendungs- und Netzwerk-Root-Keys, um während OTAA rollenspezifische Session-Keys abzuleiten. Frühere 1.0.x-Deployments verwenden normalerweise einen AppKey, um die Netzwerk- und Anwendungs-Session-Keys abzuleiten, während ABP Session-Keys direkt provisioniert. Die durch einen geleakten Key erlangten Möglichkeiten hängen daher von der LoRaWAN-Version und davon ab, welcher Key offengelegt wurde.<sup>[[3]](#references)</sup>

---

## Zusammenfassung der Angriffsfläche

| Layer | Schwachstelle | Praktische Auswirkung |
|-------|----------|------------------|
| PHY | Reaktives / selektives Jamming | Lokalisierter Paketverlust; die Effektivität hängt von Link Budget, Timing, Bandbreite und regulatorischen Einschränkungen ab |
| MAC | Replay von Join- und Daten-Frames, wenn Nonce-/Counter-Zustände wiederverwendet werden | Desynchronisierung von Geräten, Spoofing oder Injection, wenn der Server/das Gerät Replay-Schutzmechanismen verletzt |
| Network-Server | Unsicherer packet-forwarder, schwache MQTT-/UDP-Filter, veraltete Gateway-Firmware | RCE auf Gateways → Pivot in das OT-/IT-Netzwerk |
| Application | Hardcodierte oder vorhersehbare AppKeys | Brute-Force/Entschlüsselung des Datenverkehrs, Imitation von Sensoren |

---

## Repräsentative Schwachstellen in Implementierungen

* **CVE-2024-29862** – Betroffene ChirpStack Gateway Bridge-Versionen vor 4.0.11 und MQTT Forwarder-Versionen vor 4.2.1 konnten eine Verbindung zu einem von Angreifern kontrollierten MQTT-Broker herstellen, da die Validierung von TLS-Serverzertifikaten deaktiviert war. Dadurch konnten Zugangsdaten und Gateway-Datenverkehr offengelegt werden; führe ein Upgrade auf die korrigierten Releases durch.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 beschreibt ein nicht authentifiziertes Directory Listing von `/lib/`, das eine herunterladbare Backup-Datei enthielt; CVE-2022-45228 ist eine CSRF-Schwachstelle mit geringer Kritikalität auf der Logout-Seite. Diese Einträge belegen weder die behauptete Auswirkung auf LG308 noch das Überschreiben der Konfiguration, die Größe der installierten Basis oder den Patch-Stand von 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Eine frühere Version dieser Seite beschrieb ein angebliches Semtech-Problem im UDP packet-forwarder als **ein durch ein manipuliertes Uplink von mehr als 255 Byte verursachtes Stack-Smashing und RCE auf SX130x-Referenzgateways**, das einer „LoRa Exploitation Reloaded“-Präsentation auf der Black Hat Europe 2023 und einem privaten Patch vom Oktober 2023 zugeschrieben wurde. Diese konkreten Details bleiben hier als Rechercheansatz erhalten, konnten jedoch durch kein passendes öffentliches Advisory, keine passende Präsentation und keinen verifizierbaren primären Beleg bestätigt werden. Betrachte das Problem nicht als bekannte Schwachstelle, bevor das betroffene Produkt/die betroffene Version und eine überprüfbare Primärquelle ermittelt wurden.

---

## Praktische Angriffstechniken

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
Diese Befehle bewahren den ursprünglichen Workflow als **illustrative Syntax**; Repository-Struktur und Flags unterscheiden sich je nach Projekt/Release. Passives Capturing legt keinen starken AppKey offen. Offline-Raten ist nur dann nützlich, wenn der Root Key schwach genug ist, um gefunden zu werden, und ein aufgezeichneter Join-Austausch einen Wert liefert, mit dem Kandidaten validiert werden können.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA-Replay-Schutz und Nonce-Status testen

1. In einem autorisierten Testnetz einen legitimen **JoinRequest** aufzeichnen.
2. Dieselbe Anfrage wiederholen und bestätigen, dass der Network Server den wiederverwendeten `DevNonce` ablehnt.
3. Das Testgerät neu starten oder zurücksetzen und die Prüfung wiederholen, um einen verlorenen Nonce-Status zu erkennen. Ein konformer Server muss verwendete Nonces nachverfolgen; das Wiederholen eines JoinRequest allein legt weder die neu abgeleiteten Session Keys offen, noch verschafft es dem Angreifer die Kontrolle über eine Session.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Downgrading der Adaptive Data-Rate (ADR)

Ein Angreifer, der Network-Layer-MAC-Befehle authentifizieren kann – beispielsweise nach der Kompromittierung des zutreffenden Network Session Key oder des Network Servers – kann versuchen, ineffiziente Data-Rate-Parameter zu erzwingen und die Airtime zu erhöhen. Ein nicht authentifizierter Sender in der Nähe kann nicht allein durch Kenntnis einer Geräteadresse legitimerweise ADR-Befehle senden.<sup>[[3]](#references)</sup>

### 4. Reaktives Jamming

Ein reaktiver Jammer kann nach der Erkennung einer LoRa-Präambel senden und Frames selektiv stören. Auf der vorherigen Seite wurde behauptet, dass ein HackRF/GNU-Radio-Setup bei **2 km mit höchstens 200 mW** einen vollständigen Ausfall verursacht habe, allerdings wurde keine unterstützende Messquelle angegeben; diese Werte sollten daher nur als Reproduktionsziel und nicht als erwartetes Ergebnis beibehalten werden. Erforderliche Sendeleistung, Timing, Bandbreite, betroffene Spreading Factors und Reichweite sind umgebungsspezifisch. Tests dürfen nur innerhalb eines autorisierten, HF-abgeschirmten Setups durchgeführt werden; außerdem sind die lokalen Vorschriften für das Spektrum einzuhalten.

---

## Offensive Tools (2025)

| Tool | Zweck | Hinweise |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN-Frames erstellen/parsen/angreifen, DB-basierte Analyzer, Brute-Forcer | Docker-Image; unterstützt Semtech-UDP-Input<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Python-Utility von Trend Micro zum Brute-Forcen von OTAA, Erzeugen von Downlinks und Entschlüsseln von Payloads | Öffentliches Research-Utility; unterstützte Hardware und Protokollversionen überprüfen<sup>[[2]](#references)</sup> |
| **LoRAttack** | Research-Framework für Multi-Channel-LoRaWAN-Capturing, Session-Analyse, Key-Derivation und Replay-Tests | In einer Masterarbeit von 2024 beschrieben; die genaue Implementierung beschaffen und überprüfen, bevor man sich auf die Beispiel-Flags verlässt<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU-Radio-Out-of-Tree-Blöcke für LoRa-Basisbandempfang oder Transceiver-Research | Die Projekte unterscheiden sich hinsichtlich GNU-Radio-Kompatibilität und Funktionsumfang<sup>[[9]](#references)</sup> |

---

## Defensive Empfehlungen (Pentester-Checkliste)

1. **OTAA** bevorzugen und überprüfen, dass Geräte und Server den erforderlichen Nonce-Status persistent speichern; abgelehnte doppelte Joins überwachen.
2. Wenn unterstützt, **LoRaWAN 1.1** bevorzugen, damit Network-Funktionen unterschiedliche Session Keys und eine aktualisierte Nonce-Verarbeitung verwenden.<sup>[[3]](#references)</sup>
3. Frame-Counter im nichtflüchtigen Speicher (**ABP**) speichern oder zu OTAA migrieren.
4. Ein geeignetes **secure element** einsetzen (beispielsweise ATECC608A in einem unterstützten Design), um die Offenlegung von Root Keys in gewöhnlichem Firmware-Speicher zu reduzieren.
5. Konfigurierte UDP-Listener von Packet-Forwardern (üblicherweise 1700) nicht gegenüber nicht vertrauenswürdigen Netzwerken exponieren; das Gateway-Backhaul authentifizieren/verschlüsseln oder mit einem VPN beschränken.
6. Gateways mit vom Hersteller unterstützter Firmware betreiben und das exakte Modell/die Version anhand der zutreffenden Advisories überprüfen.
7. **Traffic-Anomalieerkennung** implementieren (z. B. LAF Analyzer) – Counter-Resets, doppelte Joins und plötzliche ADR-Änderungen markieren.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN-Auditing-Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Übersicht zu Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance – LoRaWAN-L2-1.1-Spezifikation](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD – CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance – regionale Parameter und Join-Synchronisierung von LoRaWAN 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD – CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD – CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU-Arbeitskatalog – LPWAN Protocol Security Analysis Leveraging SDR Technology](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL-`gr-lora_sdr`-GNU-Radio-Transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
