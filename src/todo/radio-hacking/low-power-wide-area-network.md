# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Вступ

**Low-Power Wide Area Network** (LPWAN) — це група бездротових мережевих технологій із низьким енергоспоживанням і широкою зоною покриття, розроблених для **дальнього зв'язку** з низькою швидкістю передавання даних.
Вони можуть забезпечувати дальність понад **шість миль**, а їхні **батареї** можуть працювати до **20 років**.

Long Range (**LoRa**) наразі є найбільш поширеним фізичним рівнем LPWAN, а його відкрита специфікація MAC-рівня — **LoRaWAN**.

---

## LPWAN, LoRa та LoRaWAN

* LoRa — фізичний рівень Chirp Spread Spectrum (CSS), розроблений Semtech (пропрієтарний, але документований).
* LoRaWAN — відкритий рівень MAC/Network, який підтримує LoRa-Alliance. Версії 1.0.x і 1.1 є поширеними на практиці.
* Типова архітектура: *кінцевий пристрій → gateway (packet-forwarder) → network-server → application-server*.

> **Модель безпеки** покладається на два кореневі ключі AES-128 (AppKey/NwkKey), з яких під час процедури *join* (OTAA) виводяться ключі сеансу, або які жорстко закодовані (ABP). Якщо будь-який ключ leak, зловмисник отримує повну можливість читання/запису відповідного трафіку.

---

## Короткий огляд attack surface

| Рівень | Вразливість | Практичний вплив |
|-------|----------|------------------|
| PHY | Реактивний / вибірковий jamming | Продемонстровано 100 % втрату пакетів за допомогою одного SDR і вихідної потужності <1 Вт |
| MAC | Повторне відтворення Join-Accept і кадрів даних (повторне використання nonce, переповнення лічильника ABP) | Підміна пристроїв, ін'єкція повідомлень, DoS |
| Network-Server | Небезпечний packet-forwarder, слабкі фільтри MQTT/UDP, застаріла прошивка gateway | RCE на gateway → pivot у мережу OT/IT |
| Application | Жорстко закодовані або передбачувані AppKeys | Brute-force/розшифрування трафіку, імітація сенсорів |

---

## Нещодавні вразливості (2023-2025)

* **CVE-2024-29862** — *ChirpStack gateway-bridge & mqtt-forwarder* приймали TCP-пакети, які обходили правила stateful firewall на gateway Kerlink, що дозволяло відкрити інтерфейс віддаленого керування. Виправлено у версіях 4.0.11 / 4.2.1 відповідно .
* **Серії Dragino LG01/LG308** — численні CVE за 2022-2024 роки (наприклад, 2022-45227 — directory traversal, 2022-45228 — CSRF) досі спостерігалися без виправлень у 2025 році; вони дозволяють неавтентифіковане отримання dump прошивки або перезапис конфігурації на тисячах публічних gateway .
* Переповнення *packet-forwarder UDP* Semtech (неопублікований advisory, виправлено у 2023-10): спеціально сформований uplink розміром понад 255 Б спричиняв stack-smash → RCE на reference gateway SX130x (виявлено Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Практичні attack techniques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (повторне використання DevNonce)

1. Перехопити легітимний **JoinRequest**.
2. Негайно повторно передати його (або збільшити RSSI), перш ніж оригінальний пристрій передасть знову.
3. Network-server виділяє новий DevAddr і ключі сесії, тоді як цільовий пристрій продовжує працювати зі старою сесією → attacker отримує вакантну сесію та може інжектити підроблені uplink-повідомлення.

### 3. Зниження Adaptive Data-Rate (ADR)

Примусово встановити SF12/125 kHz, щоб збільшити airtime → вичерпати duty-cycle gateway (denial-of-service), водночас мінімізуючи вплив на батарею attacker (достатньо надсилати MAC-команди на рівні мережі).

### 4. Реактивне jamming

*HackRF One*, що працює з flowgraph GNU Radio, запускає широкосмуговий chirp після виявлення preamble — блокує всі spreading factors за потужності TX ≤200 мВт; повний outage виміряно на відстані 2 км .

---

## Offensive tooling (2025)

| Інструмент | Призначення | Примітки |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Створення/аналіз/атаки на LoRaWAN-фрейми, аналізатори з підтримкою DB, brute-forcer | Docker image, підтримує вхідні дані Semtech UDP |
| **LoRaPWN** | Python-утиліта Trend Micro для brute OTAA, генерації downlink-повідомлень і розшифрування payload | Demo випущено у 2023 році, не залежить від SDR |
| **LoRAttack** | Багатоканальний sniffer і replay із USRP; експортує PCAP/LoRaTap | Добра інтеграція з Wireshark |
| **gr-lora / gr-lorawan** | Блоки GNU Radio OOT для baseband TX/RX | Основа для custom атак |

---

## Defensive recommendations (pentester checklist)

1. Надавайте перевагу пристроям **OTAA** зі справді випадковим DevNonce; відстежуйте дублікати.
2. Забезпечте використання **LoRaWAN 1.1**: 32-бітові лічильники фреймів, окремі FNwkSIntKey / SNwkSIntKey.
3. Зберігайте frame-counter у non-volatile memory (**ABP**) або мігруйте на OTAA.
4. Розгортайте **secure-element** (ATECC608A/SX1262-TRX-SE) для захисту root keys від вилучення з firmware.
5. Вимкніть віддалені UDP-порти packet-forwarder (1700/1701) або обмежте доступ до них за допомогою WireGuard/VPN.
6. Підтримуйте gateways в актуальному стані; Kerlink/Dragino надають images із виправленнями 2024 року.
7. Реалізуйте **traffic anomaly detection** (наприклад, analyzer LAF) — позначайте скидання лічильників, дублікати join-повідомлень і раптові зміни ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
