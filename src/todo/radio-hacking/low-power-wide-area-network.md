# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

**Low-Power Wide Area Network** (LPWAN) to grupa bezprzewodowych technologii sieci rozległych o niskim poborze mocy, zaprojektowanych do **komunikacji dalekiego zasięgu** przy niskiej przepływności.
Mogą osiągać zasięg ponad **sześciu mil**, a ich **baterie** mogą działać nawet **20 lat**.

Long Range (**LoRa**) jest obecnie najczęściej wdrażaną warstwą fizyczną LPWAN, a jej otwarta specyfikacja warstwy MAC to **LoRaWAN**.

---

## LPWAN, LoRa i LoRaWAN

* LoRa – warstwa fizyczna Chirp Spread Spectrum (CSS) opracowana przez firmę Semtech (własnościowa, ale udokumentowana).
* LoRaWAN – otwarta warstwa MAC/sieci utrzymywana przez LoRa-Alliance. W praktyce powszechne są wersje 1.0.x i 1.1.
* Typowa architektura: *urządzenie końcowe → gateway (packet-forwarder) → serwer sieciowy → serwer aplikacji*.

> **Model bezpieczeństwa** opiera się na dwóch głównych kluczach AES-128 (AppKey/NwkKey), z których podczas procedury *join* (OTAA) wyprowadzane są klucze sesyjne, lub które są hard-coded (ABP). Jeśli dojdzie do wycieku dowolnego klucza, atakujący uzyskuje pełne możliwości odczytu/zapisu odpowiedniego ruchu.

---

## Podsumowanie powierzchni ataku

| Warstwa | Słabość | Praktyczny wpływ |
|-------|----------|------------------|
| PHY | Reaktywne / selektywne jamming | Wykazano 100% utraty pakietów przy użyciu pojedynczego SDR i mocy wyjściowej <1 W |
| MAC | Replay Join-Accept i ramek danych (ponowne użycie nonce, przepełnienie licznika ABP) | Podszywanie się pod urządzenia, wstrzykiwanie wiadomości, DoS |
| Network-Server | Niezabezpieczony packet-forwarder, słabe filtry MQTT/UDP, nieaktualny firmware gatewaya | RCE na gatewayach → pivot do sieci OT/IT |
| Application | Hard-coded lub przewidywalne klucze AppKey | Brute-force/deszyfrowanie ruchu, podszywanie się pod sensory |

---

## Najnowsze podatności (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* akceptowały pakiety TCP omijające stanowe reguły firewalla na gatewayach Kerlink, umożliwiając zdalne ujawnienie interfejsu zarządzania. Naprawiono w wersjach odpowiednio 4.0.11 / 4.2.1 .
* **Seria Dragino LG01/LG308** – Wiele CVE z lat 2022-2024 (np. 2022-45227 directory traversal, 2022-45228 CSRF) nadal obserwowano w 2025 r. jako niezałatane; umożliwiały wykonanie nieuwierzytelnionego firmware dump lub nadpisanie konfiguracji na tysiącach publicznych gatewayów .
* Przepełnienie *packet-forwarder UDP* firmy Semtech (nieopublikowane advisory, poprawione w 2023-10): spreparowany uplink większy niż 255 B powodował przepełnienie stosu ‑> RCE na referencyjnych gatewayach SX130x (odkryte przez Black Hat EU 2023 „LoRa Exploitation Reloaded”).

---

## Praktyczne techniki ataku

### 1. Sniff & Decrypt ruchu
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (ponowne użycie DevNonce)

1. Przechwyć prawidłowy **JoinRequest**.
2. Natychmiast retransmituj go (lub zwiększ RSSI), zanim oryginalne urządzenie ponownie rozpocznie transmisję.
3. Network-server przydzieli nowy DevAddr i klucze sesji, podczas gdy urządzenie docelowe będzie nadal korzystać ze starej sesji → atakujący przejmuje wolną sesję i może wstrzykiwać sfałszowane uplinki.

### 3. Adaptive Data-Rate (ADR) downgrading

Wymuś SF12/125 kHz, aby zwiększyć czas transmisji → wyczerp limit duty-cycle gatewaya (denial-of-service), jednocześnie ograniczając wpływ na baterię atakującego (wystarczy wysyłać MAC commands na poziomie sieci).

### 4. Reactive jamming

*HackRF One* uruchamiający flowgraph GNU Radio generuje szerokopasmowy chirp po wykryciu preambuły – blokuje wszystkie spreading factors przy mocy TX ≤200 mW; pełna niedostępność została zmierzona w zasięgu 2 km.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Tworzenie, parsowanie i atakowanie ramek LoRaWAN, analyzery korzystające z DB, brute-forcer | Obraz Docker, obsługa wejścia Semtech UDP |
| **LoRaPWN** | Narzędzie Python firmy Trend Micro do brute OTAA, generowania downlinków i odszyfrowywania payloadów | Demo wydane w 2023 r., niezależne od SDR |
| **LoRAttack** | Wielokanałowy sniffer + replay z USRP; eksport do PCAP/LoRaTap | Dobra integracja z Wiresharkiem |
| **gr-lora / gr-lorawan** | Bloki GNU Radio OOT do transmisji/odbioru basebandu | Podstawa niestandardowych ataków |

---

## Defensive recommendations (pentester checklist)

1. Preferuj urządzenia **OTAA** z rzeczywiście losowym DevNonce; monitoruj duplikaty.
2. Wymuś **LoRaWAN 1.1**: 32-bitowe liczniki ramek, odrębne FNwkSIntKey / SNwkSIntKey.
3. Przechowuj licznik ramek w pamięci nieulotnej (**ABP**) lub migruj do OTAA.
4. Wdróż **secure-element** (ATECC608A/SX1262-TRX-SE), aby chronić klucze główne przed ekstrakcją firmware'u.
5. Wyłącz zdalne porty UDP packet-forwardera (1700/1701) lub ogranicz do nich dostęp za pomocą WireGuard/VPN.
6. Aktualizuj gatewaye; Kerlink/Dragino udostępniają obrazy z poprawkami z 2024 r.
7. Wdróż **traffic anomaly detection** (np. analyzer LAF) – oznaczaj resetowania liczników, zduplikowane joiny i nagłe zmiany ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
