# Low-Power-Wide-Area-Network

{{#include ../../banners/hacktricks-training.md}}

## Einführung

**Low-Power-Wide-Area-Network** (LPWAN) bezeichnet eine Gruppe drahtloser Weitverkehrsnetz-Technologien mit geringem Energieverbrauch, die für **Kommunikation über große Entfernungen** bei niedriger Bitrate ausgelegt sind.
Je nach Funkparametern, Antenne, Regulierungsregion, Gelände und Duty Cycle können LPWAN-Deployments Durchsatz gegen eine Abdeckung über mehrere Kilometer und eine Batterielebensdauer von mehreren Jahren eintauschen. Angaben von Herstellern zu Reichweite und Batterielebensdauer sollten als Designziele und nicht als Garantien betrachtet werden.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) ist derzeit die am weitesten verbreitete physikalische LPWAN-Schicht; die offene MAC-Schichtspezifikation dazu heißt **LoRaWAN**.

---

## LPWAN, LoRa und LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS)-Physikalische Schicht, entwickelt von Semtech (proprietär, aber dokumentiert).
* LoRaWAN – Offene MAC-/Netzwerkschicht, betreut von der LoRa-Alliance. Die Versionen 1.0.x und 1.1 sind in der Praxis weit verbreitet.
* Typische Architektur: *Endgerät → Gateway (packet-forwarder) → Netzwerkserver → Anwendungsserver*.<sup>[[3]](#references)</sup>

> In LoRaWAN 1.1 verwendet das **Sicherheitsmodell** separate AES-128-Anwendungs- und Netzwerk-Root-Keys, um während OTAA rollenspezifische Session-Keys abzuleiten. Bei älteren 1.0.x-Deployments wird normalerweise ein AppKey verwendet, um die Netzwerk- und Anwendungs-Session-Keys abzuleiten, während ABP die Session-Keys direkt bereitstellt. Welche Möglichkeiten ein geleakter Key bietet, hängt daher von der LoRaWAN-Version und davon ab, welcher Key offengelegt wurde.<sup>[[3]](#references)</sup>

---

## Überblick über die Angriffsfläche

| Schicht | Schwachstelle | Praktische Auswirkung |
|-------|----------|------------------|
| PHY | Reaktives / selektives Jamming | Lokaler Paketverlust; die Wirksamkeit hängt von Link-Budget, Timing, Bandbreite und regulatorischen Vorgaben ab |
| MAC | Replay von Join- und Daten-Frames bei wiederverwendetem Nonce-/Counter-Status | Desynchronisierung von Geräten, Spoofing oder Injection, falls Server/Gerät Replay-Schutzmechanismen nicht korrekt umsetzen |
| Netzwerkserver | Unsicherer packet-forwarder, schwache MQTT-/UDP-Filter, veraltete Gateway-Firmware | RCE auf Gateways → Pivot ins OT-/IT-Netzwerk |
| Anwendung | Fest codierte oder vorhersehbare AppKeys | Brute-Force/Entschlüsselung des Datenverkehrs, Sensor-Impersonation |

---

## Repräsentative Schwachstellen in Implementierungen

* **CVE-2024-29862** – Betroffene ChirpStack Gateway Bridge-Versionen vor 4.0.11 und MQTT Forwarder-Versionen vor 4.2.1 konnten eine Verbindung zu einem vom Angreifer kontrollierten MQTT-Broker herstellen, weil die TLS-Serverzertifikatsprüfung deaktiviert war. Dadurch konnten Zugangsdaten und Gateway-Datenverkehr offengelegt werden; aktualisieren Sie auf die fehlerbereinigten Versionen.<sup>[[4]](#references)</sup>
* **Dragino LG01 Firmware 4.3.4** – CVE-2022-45227 beschreibt einen nicht authentifizierten Verzeichnisindex von `/lib/` mit einer herunterladbaren Backup-Datei; CVE-2022-45228 ist eine CSRF-Schwachstelle mit niedriger Schweregrad-Einstufung auf der Logout-Seite. Diese Einträge belegen weder die behaupteten Auswirkungen auf LG308 noch das Überschreiben der Konfiguration, die Größe der betroffenen Population oder den Patch-Status von 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Eine frühere Version dieser Seite beschrieb ein angebliches Problem mit dem Semtech-UDP-packet-forwarder als **manipuliertes Uplink-Paket mit mehr als 255 Byte, das einen Stack-Smash und RCE auf SX130x-Referenz-Gateways verursachen sollte**, und führte es auf eine Präsentation namens „LoRa Exploitation Reloaded“ auf der Black Hat Europe 2023 sowie einen privaten Patch vom Oktober 2023 zurück. Diese konkreten Details bleiben hier als Rechercheansatz erhalten, aber es konnten weder ein passender öffentlicher Sicherheitshinweis noch eine Präsentation oder ein Patch bestätigt werden. Betrachten Sie das Problem nicht als bekannte Schwachstelle, bevor Sie kein betroffenes Produkt bzw. keine betroffene Version und keine überprüfbare Primärquelle gefunden haben.

---

## Praktische Angriffstechniken

### 1. Sniff & Decrypt des Datenverkehrs

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

Diese Befehle bewahren den ursprünglichen Ablauf als **veranschaulichende Syntax**; Verzeichnisstruktur und Flags unterscheiden sich je nach Projekt/Release. Passives Mitschneiden offenbart keinen starken AppKey. Offline-Raten ist nur dann sinnvoll, wenn der Root Key schwach genug ist, um gefunden zu werden, und ein mitgeschnittener Join-Austausch einen Wert liefert, mit dem sich Kandidaten überprüfen lassen.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA-Replay-Schutz und Nonce-Zustand testen

1. In einem autorisierten Testnetz eine legitime **JoinRequest** mitschneiden.
2. Dieselbe Anfrage erneut senden und bestätigen, dass der Network Server die wiederverwendete `DevNonce` zurückweist.
3. Das Testgerät neu starten oder zurücksetzen und die Prüfung wiederholen, um einen Verlust des Nonce-Zustands zu erkennen. Ein konformer Server muss verwendete Nonces nachverfolgen; das erneute Senden einer JoinRequest allein legt weder die neu abgeleiteten Session Keys offen noch gibt es dem Angreifer Kontrolle über eine Sitzung.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) Downgrading

Ein Angreifer, der Network-Layer-MAC-Befehle authentifizieren kann – zum Beispiel nach der Kompromittierung des entsprechenden Network Session Key oder des Network Servers –, kann versuchen, ineffiziente Data-Rate-Parameter zu erzwingen und die Airtime zu erhöhen. Ein nicht authentifizierter Sender in der Nähe kann nicht allein durch Kenntnis einer Geräteadresse legitimerweise ADR-Befehle senden.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Ein Reactive Jammer kann nach Erkennung eines LoRa-Präambels senden und gezielt Frames stören. Auf der vorherigen Seite wurde behauptet, ein HackRF/GNU-Radio-Setup habe bei **2 km mit höchstens 200 mW** einen vollständigen Ausfall verursacht, aber dafür wurde keine Quelle mit Messdaten angegeben; diese Werte sollten daher nur als Reproduktionsziel und nicht als erwartetes Ergebnis betrachtet werden. Erforderliche Sendeleistung, Timing, Bandbreite, betroffene Spreading Factors und Reichweite hängen von der Umgebung ab. Nur in einem autorisierten, HF-abgeschirmten Setup testen und die örtlichen Funkvorschriften einhalten.

---

## Offensive Tools (2025)

| Tool | Zweck | Hinweise |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN-Frames erstellen/parsen/angreifen, DB-gestützte Analyzer, Brute-Forcer | Docker-Image; unterstützt Semtech-UDP-Eingabe<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Python-Tool von Trend Micro zum Brute-Forcen von OTAA, Erzeugen von Downlinks und Entschlüsseln von Payloads | Öffentliches Research-Tool; unterstützte Hardware und Protokollversionen überprüfen<sup>[[2]](#references)</sup> |
| **LoRAttack** | Research-Framework für Multi-Channel-LoRaWAN-Mitschnitte, Sitzungsanalyse, Schlüsselableitung und Replay-Tests | In einer Masterarbeit von 2024 beschrieben; die genaue Implementierung beschaffen und überprüfen, bevor man sich auf die Beispiel-Flags verlässt<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU-Radio-Out-of-Tree-Blöcke für den LoRa-Basisband-Empfang oder Transceiver-Research | Die Projekte unterscheiden sich hinsichtlich GNU-Radio-Kompatibilität und Funktionsumfang<sup>[[9]](#references)</sup> |

---

## Empfehlungen zur Abwehr (Pentester-Checkliste)

1. **OTAA** bevorzugen und überprüfen, dass Geräte und Server den erforderlichen Nonce-Zustand dauerhaft speichern; abgewiesene doppelte Joins überwachen.
2. Wo unterstützt **LoRaWAN 1.1** bevorzugen, damit Netzwerkfunktionen unterschiedliche Session Keys und eine aktualisierte Nonce-Verarbeitung verwenden.<sup>[[3]](#references)</sup>
3. Frame-Counter in nichtflüchtigem Speicher ablegen (**ABP**) oder zu OTAA migrieren.
4. Ein geeignetes **Secure Element** einsetzen (zum Beispiel ATECC608A in einem unterstützten Design), um das Risiko offengelegter Root Keys im gewöhnlichen Firmware-Speicher zu verringern.
5. Konfigurierte UDP-Listener von Packet Forwardern (häufig Port 1700) nicht untrusted Netzwerken zugänglich machen; Gateway-Backhaul authentifizieren/verschlüsseln oder mit einem VPN einschränken.
6. Gateways mit vom Hersteller unterstützter Firmware betreiben und das genaue Modell/die Version anhand der einschlägigen Advisories überprüfen.
7. **Erkennung von Traffic-Anomalien** implementieren (z. B. LAF Analyzer) – Counter-Resets, doppelte Joins und plötzliche ADR-Änderungen markieren.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Überblick zu Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN-L2-Spezifikation 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Regionale Parameter und Join-Synchronisierung für LoRaWAN 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU-Thesenkatalog - Sicherheitsanalyse von LPWAN-Protokollen mithilfe von SDR-Technologie](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL-`gr-lora_sdr`-GNU-Radio-Transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
