# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

**Low-Power Wide Area Network** (LPWAN) to grupa technologii bezprzewodowych, niskonapięciowych, szerokopasmowych zaprojektowanych do **długozasięgowej komunikacji** przy niskiej przepustowości.
Mogą osiągać więcej niż **sześć mil** i ich **baterie** mogą działać do **20 lat**.

Long Range (**LoRa**) jest obecnie najczęściej wdrażaną warstwą fizyczną LPWAN, a jej otwarta specyfikacja warstwy MAC to **LoRaWAN**.

---

## LPWAN, LoRa i LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) warstwa fizyczna opracowana przez Semtech (własnościowa, ale udokumentowana).
* LoRaWAN – Otwarta warstwa MAC/sieciowa utrzymywana przez LoRa-Alliance. Wersje 1.0.x i 1.1 są powszechnie stosowane w terenie.
* Typowa architektura: *urządzenie końcowe → brama (przekaznik pakietów) → serwer sieciowy → serwer aplikacji*.

> **Model bezpieczeństwa** opiera się na dwóch kluczach głównych AES-128 (AppKey/NwkKey), które generują klucze sesyjne podczas procedury *dołączenia* (OTAA) lub są zakodowane na stałe (ABP). Jeśli jakikolwiek klucz wycieknie, atakujący zyskuje pełną zdolność do odczytu/zapisu odpowiedniego ruchu.

---

## Podsumowanie powierzchni ataku

| Warstwa | Słabość | Praktyczny wpływ |
|---------|---------|------------------|
| PHY     | Reaktywne / selektywne zakłócanie | 100 % utrata pakietów udowodniona przy użyciu pojedynczego SDR i <1 W mocy |
| MAC     | Powtórzenie Join-Accept i ramki danych (ponowne użycie nonce, przepełnienie licznika ABP) | Fałszowanie urządzeń, wstrzykiwanie wiadomości, DoS |
| Serwer-sieciowy | Niezabezpieczony przekaznik pakietów, słabe filtry MQTT/UDP, przestarzałe oprogramowanie bramy | RCE na bramach → pivot do sieci OT/IT |
| Aplikacja | Zakodowane na stałe lub przewidywalne AppKeys | Atak brute-force/odszyfrowanie ruchu, podszywanie się pod czujniki |

---

## Ostatnie luki (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* akceptował pakiety TCP, które omijały zasady zapory stanowej na bramach Kerlink, co pozwalało na ujawnienie interfejsu zarządzania zdalnego. Naprawione w wersjach 4.0.11 / 4.2.1.
* **Seria Dragino LG01/LG308** – Wiele luk CVE z lat 2022-2024 (np. 2022-45227 przejście katalogu, 2022-45228 CSRF) nadal obserwowane jako niezałatane w 2025 roku; umożliwiają nieautoryzowane zrzuty oprogramowania układowego lub nadpisywanie konfiguracji na tysiącach publicznych bram.
* Przepełnienie bufora *przekaznika pakietów UDP* Semtech (nieopublikowane zalecenie, załatane w 2023-10): stworzony uplink większy niż 255 B wywołał przepełnienie stosu ‑> RCE na bramach referencyjnych SX130x (znalezione przez Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Praktyczne techniki ataku

### 1. Podsłuchiwanie i odszyfrowywanie ruchu
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (ponowne użycie DevNonce)

1. Przechwyć legalny **JoinRequest**.
2. Natychmiast go retransmituj (lub zwiększ RSSI) zanim oryginalne urządzenie wyśle ponownie.
3. Serwer sieciowy przydziela nowy DevAddr i klucze sesyjne, podczas gdy docelowe urządzenie kontynuuje z starą sesją → atakujący posiada wolną sesję i może wstrzykiwać sfałszowane uplinki.

### 3. Obniżanie adaptacyjnej stawki danych (ADR)

Wymuś SF12/125 kHz, aby zwiększyć czas transmisji → wyczerp cykl pracy bramy (denial-of-service), jednocześnie minimalizując wpływ na baterię atakującego (po prostu wysyłaj polecenia MAC na poziomie sieci).

### 4. Reaktywne zakłócanie

*HackRF One* działający na GNU Radio flowgraph uruchamia szerokopasmowy sygnał, gdy wykryje preambułę – blokuje wszystkie czynniki rozprzestrzeniania z ≤200 mW TX; pełne zakłócenie zmierzone na odległości 2 km.

---

## Narzędzia ofensywne (2025)

| Narzędzie | Cel | Uwagi |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Tworzenie/analiza/atakowanie ramek LoRaWAN, analizatory oparte na bazach danych, brute-forcer | Obraz Dockera, wspiera wejście Semtech UDP |
| **LoRaPWN** | Narzędzie Python od Trend Micro do brute OTAA, generowania downlinków, deszyfrowania ładunków | Demo wydane w 2023, niezależne od SDR |
| **LoRAttack** | Sniffer wielokanałowy + powtórka z USRP; eksportuje PCAP/LoRaTap | Dobra integracja z Wireshark |
| **gr-lora / gr-lorawan** | Bloki OOT GNU Radio do TX/RX w paśmie podstawowym | Podstawa dla niestandardowych ataków |

---

## Rekomendacje defensywne (lista kontrolna pentestera)

1. Preferuj urządzenia **OTAA** z prawdziwie losowym DevNonce; monitoruj duplikaty.
2. Wymuś **LoRaWAN 1.1**: 32-bitowe liczniki ramek, odrębne FNwkSIntKey / SNwkSIntKey.
3. Przechowuj licznik ramek w pamięci nieulotnej (**ABP**) lub migruj do OTAA.
4. Wdróż **secure-element** (ATECC608A/SX1262-TRX-SE), aby chronić klucze główne przed ekstrakcją firmware.
5. Wyłącz zdalne porty do przesyłania pakietów UDP (1700/1701) lub ogranicz za pomocą WireGuard/VPN.
6. Utrzymuj bramy w aktualizacji; Kerlink/Dragino dostarczają obrazy z poprawkami z 2024 roku.
7. Wdróż **wykrywanie anomalii w ruchu** (np. analizator LAF) – oznaczaj resetowanie liczników, duplikaty połączeń, nagłe zmiany ADR.

## Referencje

* LoRaWAN Auditing Framework (LAF) – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Przegląd Trend Micro LoRaPWN – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
