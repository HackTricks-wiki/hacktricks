# Low-Power-Wide-Area-Netzwerk

{{#include ../../banners/hacktricks-training.md}}

## Einführung

**Low-Power-Wide-Area-Netzwerk** (LPWAN) ist eine Gruppe drahtloser, stromsparender Weitverkehrsnetzwerktechnologien, die für **Kommunikation über große Entfernungen** bei niedriger Datenrate entwickelt wurden.
Sie können mehr als **sechs Meilen** überbrücken, und ihre **Batterien** können bis zu **20 Jahre** halten.

Long Range (**LoRa**) ist derzeit die am häufigsten eingesetzte physische LPWAN-Schicht, und ihre offene MAC-Layer-Spezifikation ist **LoRaWAN**.

---

## LPWAN, LoRa und LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) physical layer, entwickelt von Semtech (proprietär, aber dokumentiert).
* LoRaWAN – Open MAC/Network layer, gepflegt von der LoRa-Alliance. Die Versionen 1.0.x und 1.1 sind in der Praxis weit verbreitet.
* Typische Architektur: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> Das **Sicherheitsmodell** basiert auf zwei AES-128-Root-Keys (AppKey/NwkKey), aus denen während des *join*-Vorgangs (OTAA) Session-Keys abgeleitet werden, oder die fest kodiert sind (ABP). Wenn ein Schlüssel leakt, erhält der Angreifer vollständige Lese-/Schreibrechte über den entsprechenden Datenverkehr.

---

## Zusammenfassung der Angriffsfläche

| Schicht | Schwachstelle | Praktische Auswirkungen |
|-------|----------|------------------|
| PHY | Reaktives / selektives Jamming | 100 % Paketverlust mit einem einzelnen SDR und einer Ausgangsleistung von <1 W demonstriert |
| MAC | Replay von Join-Accept- und Daten-Frames (Nonce-Wiederverwendung, ABP-Counter-Rollover) | Geräte-Spoofing, Message Injection, DoS |
| Network-Server | Unsicherer packet-forwarder, schwache MQTT/UDP-Filter, veraltete Gateway-Firmware | RCE auf Gateways → Pivot in das OT/IT-Netzwerk |
| Application | Fest kodierte oder vorhersehbare AppKeys | Brute-force/decrypt Datenverkehr, Sensoren impersonieren |

---

## Aktuelle Schwachstellen (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* akzeptierten TCP-Pakete, die zustandsbehaftete Firewall-Regeln auf Kerlink-Gateways umgingen, wodurch die Remote-Management-Schnittstelle offengelegt werden konnte. Behoben in 4.0.11 bzw. 4.2.1 .
* **Dragino-LG01/LG308-Serie** – Mehrere CVEs aus den Jahren 2022-2024 (z. B. 2022-45227 Directory Traversal, 2022-45228 CSRF) wurden 2025 weiterhin ungepatcht beobachtet; sie ermöglichen einen nicht authentifizierten Firmware-Dump oder das Überschreiben der Konfiguration auf Tausenden öffentlichen Gateways .
* Semtech-*packet-forwarder UDP*-Overflow (unveröffentlichte Sicherheitswarnung, im Oktober 2023 gepatcht): Ein manipuliertes Uplink-Paket mit mehr als 255 B löste einen Stack-Smash ‑> RCE auf SX130x-Referenz-Gateways aus (entdeckt auf der Black Hat EU 2023 „LoRa Exploitation Reloaded“).

---

## Praktische Angriffstechniken

### 1. Sniff & Decrypt von Datenverkehr
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA Join-Replay (Wiederverwendung von DevNonce)

1. Einen legitimen **JoinRequest** abfangen.
2. Ihn sofort erneut übertragen (oder RSSI erhöhen), bevor das ursprüngliche Gerät erneut sendet.
3. Der Network-Server weist eine neue DevAddr und neue session keys zu, während das Zielgerät mit der alten session fortfährt → der Angreifer kontrolliert die ungenutzte session und kann gefälschte uplinks einschleusen.

### 3. Herabstufung der Adaptive Data-Rate (ADR)

SF12/125 kHz erzwingen, um die Airtime zu erhöhen → den duty-cycle des Gateways erschöpfen (denial-of-service), während die Auswirkungen auf den Akku des Angreifers gering bleiben (es werden lediglich MAC commands auf Netzwerkebene gesendet).

### 4. Reaktives Jamming

*HackRF One* mit einem GNU Radio-Flowgraph löst bei erkannter Präambel einen breitbandigen Chirp aus – blockiert alle spreading factors mit ≤200 mW TX; vollständiger Ausfall bei einer Reichweite von 2 km gemessen .

---

## Offensive Tools (2025)

| Tool | Zweck | Hinweise |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN-Frames erstellen/parsen/angreifen, DB-basierte Analyzer, Brute-Forcer | Docker-Image, unterstützt Semtech-UDP-Input |
| **LoRaPWN** | Python-Utility von Trend Micro zum Brute-Forcen von OTAA, Erzeugen von downlinks und Entschlüsseln von Payloads | Demo 2023 veröffentlicht, SDR-agnostisch |
| **LoRAttack** | Multi-Channel-Sniffer und Replay mit USRP; exportiert PCAP/LoRaTap | Gute Wireshark-Integration |
| **gr-lora / gr-lorawan** | GNU-Radio-OOT-Blöcke für Baseband-TX/RX | Grundlage für individuelle Angriffe |

---

## Empfehlungen zur Abwehr (Pentester-Checkliste)

1. **OTAA**-Geräte mit wirklich zufälligem DevNonce bevorzugen; Duplikate überwachen.
2. **LoRaWAN 1.1** erzwingen: 32-Bit-Frame-Counter sowie unterschiedliche FNwkSIntKey / SNwkSIntKey.
3. Frame-Counter im nichtflüchtigen Speicher (**ABP**) speichern oder zu OTAA migrieren.
4. Ein **Secure Element** (ATECC608A/SX1262-TRX-SE) einsetzen, um Root-Keys vor Firmware-Extraktion zu schützen.
5. Remote-UDP-Ports von Packet-Forwardern (1700/1701) deaktivieren oder mit WireGuard/VPN beschränken.
6. Gateways aktuell halten; Kerlink/Dragino stellen 2024-gepatchte Images bereit.
7. **Traffic-Anomalieerkennung** (z. B. LAF-Analyzer) implementieren – Counter-Resets, doppelte Joins und plötzliche ADR-Änderungen melden.<sup>[[1]](#references)</sup>



## Referenzen

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
