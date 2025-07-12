# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Einführung

**Low-Power Wide Area Network** (LPWAN) ist eine Gruppe von drahtlosen, energieeffizienten, weitreichenden Netzwerktechnologien, die für **Langstreckenkommunikation** bei niedriger Bitrate entwickelt wurden. Sie können mehr als **sechs Meilen** erreichen und ihre **Batterien** können bis zu **20 Jahre** halten.

Long Range (**LoRa**) ist derzeit die am häufigsten eingesetzte LPWAN-Physikschicht und ihre offene MAC-Schicht-Spezifikation ist **LoRaWAN**.

---

## LPWAN, LoRa und LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) Physikschicht, entwickelt von Semtech (proprietär, aber dokumentiert).
* LoRaWAN – Offene MAC-/Netzwerkschicht, die von der LoRa-Alliance gepflegt wird. Die Versionen 1.0.x und 1.1 sind im Feld verbreitet.
* Typische Architektur: *Endgerät → Gateway (Paketweiterleiter) → Netzwerkserver → Anwendungsserver*.

> Das **Sicherheitsmodell** basiert auf zwei AES-128-Wurzel-Schlüsseln (AppKey/NwkKey), die während des *Join*-Verfahrens (OTAA) Sitzungsschlüssel ableiten oder fest codiert sind (ABP). Wenn ein Schlüssel geleakt wird, erhält der Angreifer vollständige Lese-/Schreibrechte über den entsprechenden Datenverkehr.

---

## Zusammenfassung der Angriffsfläche

| Schicht | Schwäche | Praktische Auswirkungen |
|---------|----------|------------------------|
| PHY     | Reaktive / selektive Störung | 100 % Paketverlust, demonstriert mit einem einzelnen SDR und <1 W Ausgang |
| MAC     | Join-Accept & Datenrahmen-Wiederholung (Nonce-Wiederverwendung, ABP-Zählerüberlauf) | Geräte-Spoofing, Nachrichteninjektion, DoS |
| Netzwerk-Server | Unsicherer Paketweiterleiter, schwache MQTT/UDP-Filter, veraltete Gateway-Firmware | RCE auf Gateways → Pivot in OT/IT-Netzwerk |
| Anwendung | Fest codierte oder vorhersehbare AppKeys | Brute-Force/Entschlüsselung des Datenverkehrs, Nachahmung von Sensoren |

---

## Jüngste Schwachstellen (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* akzeptierte TCP-Pakete, die die zustandsbehafteten Firewall-Regeln auf Kerlink-Gateways umgingen und die Exposition der Fernverwaltungsoberfläche ermöglichten. In 4.0.11 / 4.2.1 behoben.
* **Dragino LG01/LG308-Serie** – Mehrere CVEs von 2022-2024 (z. B. 2022-45227 Verzeichnisdurchquerung, 2022-45228 CSRF) wurden 2025 weiterhin unpatched beobachtet; ermöglicht unauthentifizierten Firmware-Dump oder Konfigurationsüberschreibung auf Tausenden von öffentlichen Gateways.
* Semtech *Paketweiterleiter UDP* Überlauf (nicht veröffentlichtes Advisory, gepatcht 2023-10): gestalteter Uplink größer als 255 B löste Stack-Smash aus ‑> RCE auf SX130x Referenz-Gateways (entdeckt von Black Hat EU 2023 “LoRa Exploitation Reloaded”).

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
### 2. OTAA join-replay (DevNonce-Wiederverwendung)

1. Erfassen Sie eine legitime **JoinRequest**.
2. Übertragen Sie sie sofort erneut (oder erhöhen Sie RSSI), bevor das ursprüngliche Gerät erneut überträgt.
3. Der Netzwerkserver weist eine neue DevAddr & Sitzungsschlüssel zu, während das Zielgerät mit der alten Sitzung fortfährt → Angreifer besitzt die freie Sitzung und kann gefälschte Uplinks injizieren.

### 3. Adaptive Data-Rate (ADR) Herabstufung

Zwingen Sie SF12/125 kHz, um die Sendezeit zu erhöhen → erschöpfen Sie den Duty-Cycle des Gateways (Denial-of-Service), während die Auswirkungen auf den Akku des Angreifers gering bleiben (einfach Netzwerk-MAC-Befehle senden).

### 4. Reaktive Störung

*HackRF One*, das einen GNU Radio-Flowgraph ausführt, löst einen Breitband-Chirp aus, wann immer ein Preamble erkannt wird – blockiert alle Spreizfaktoren mit ≤200 mW TX; vollständiger Ausfall bei 2 km Reichweite gemessen.

---

## Offensive Werkzeuge (2025)

| Tool | Zweck | Anmerkungen |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Erstellen/analysieren/angreifen von LoRaWAN-Frames, DB-unterstützte Analysatoren, Brute-Forcer | Docker-Image, unterstützt Semtech UDP-Eingang |
| **LoRaPWN** | Trend Micro Python-Dienstprogramm zum Brute-Forcen von OTAA, Generieren von Downlinks, Entschlüsseln von Payloads | Demo veröffentlicht 2023, SDR-agnostisch |
| **LoRAttack** | Multi-Channel-Sniffer + Replay mit USRP; exportiert PCAP/LoRaTap | Gute Wireshark-Integration |
| **gr-lora / gr-lorawan** | GNU Radio OOT-Blöcke für Basisband TX/RX | Grundlage für benutzerdefinierte Angriffe |

---

## Defensive Empfehlungen (Pentester-Checkliste)

1. Bevorzugen Sie **OTAA**-Geräte mit wirklich zufälligem DevNonce; überwachen Sie Duplikate.
2. Erzwingen Sie **LoRaWAN 1.1**: 32-Bit-Frame-Zähler, unterschiedliche FNwkSIntKey / SNwkSIntKey.
3. Speichern Sie den Frame-Zähler im nichtflüchtigen Speicher (**ABP**) oder migrieren Sie zu OTAA.
4. Setzen Sie **secure-element** (ATECC608A/SX1262-TRX-SE) ein, um Root-Schlüssel gegen Firmware-Extraktion zu schützen.
5. Deaktivieren Sie Remote-UDP-Paketweiterleitungsports (1700/1701) oder beschränken Sie sie mit WireGuard/VPN.
6. Halten Sie Gateways aktualisiert; Kerlink/Dragino bieten 2024-gepatchte Images an.
7. Implementieren Sie **Traffic-Anomalieerkennung** (z. B. LAF-Analysator) – kennzeichnen Sie Zähler-Resets, doppelte Joins, plötzliche ADR-Änderungen.

## References

* LoRaWAN Auditing Framework (LAF) – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Trend Micro LoRaPWN Übersicht – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
