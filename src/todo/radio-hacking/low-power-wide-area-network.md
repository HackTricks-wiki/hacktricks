# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Вступ

**Low-Power Wide Area Network** (LPWAN) — це група бездротових мережевих технологій із низьким енергоспоживанням і широкою зоною покриття, розроблених для **дальнього зв’язку** з низькою швидкістю передавання даних.
Залежно від радіопараметрів, антени, нормативного регіону, рельєфу та duty cycle, розгортання LPWAN можуть обмінювати пропускну здатність на покриття в кілька кілометрів і багаторічний час роботи від батареї. Показники дальності та роботи від батареї, заявлені постачальниками, слід розглядати як цільові параметри проєктування, а не як гарантії.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) наразі є найбільш розгорнутим фізичним рівнем LPWAN, а його відкрита специфікація MAC-рівня має назву **LoRaWAN**.

---

## LPWAN, LoRa та LoRaWAN

* LoRa — фізичний рівень Chirp Spread Spectrum (CSS), розроблений Semtech (пропрієтарний, але задокументований).
* LoRaWAN — відкритий MAC/мережевий рівень, який підтримує LoRa-Alliance. Версії 1.0.x і 1.1 широко використовуються на практиці.
* Типова архітектура: *кінцевий пристрій → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> У LoRaWAN 1.1 **модель безпеки** використовує окремі кореневі ключі застосунку та мережі AES-128 для отримання рольових сесійних ключів під час OTAA. У попередніх розгортаннях 1.0.x зазвичай використовується один AppKey для отримання сесійних ключів мережі та застосунку, тоді як ABP безпосередньо задає сесійні ключі. Тому можливості, які надає leaked key, залежать від версії LoRaWAN і від того, який саме ключ було розкрито.<sup>[[3]](#references)</sup>

---

## Короткий огляд attack surface

| Рівень | Слабкість | Практичний вплив |
|-------|----------|------------------|
| PHY | Реактивний / вибірковий jamming | Локалізована втрата пакетів; ефективність залежить від бюджету лінії зв’язку, синхронізації, пропускної здатності та нормативних обмежень |
| MAC | Повторне відтворення join і data-frame, коли стан nonce/counter використовується повторно | Десинхронізація пристрою, spoofing або injection, якщо сервер/пристрій порушує захист від replay |
| Network-Server | Небезпечний packet-forwarder, слабкі MQTT/UDP-фільтри, застаріла прошивка gateway | RCE на gateway → pivot у OT/IT-мережу |
| Application | Жорстко задані або передбачувані AppKeys | Brute-force/decrypt трафіку, impersonation сенсорів |

---

## Типові вразливості реалізацій

* **CVE-2024-29862** — уражені версії ChirpStack Gateway Bridge до 4.0.11 і MQTT Forwarder до 4.2.1 могли підключатися до MQTT broker, контрольованого зловмисником, оскільки перевірку TLS-сертифіката сервера було вимкнено. Це могло розкрити облікові дані та трафік gateway; оновіть системи до виправлених релізів.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** — CVE-2022-45227 описує неавторизований перегляд каталогу `/lib/`, що містив файл резервної копії, доступний для завантаження; CVE-2022-45228 — CSRF низького ступеня серйозності на сторінці logout. Ці записи не підтверджують заявлений вплив на LG308, перезапис конфігурації, розмір популяції або стан виправлень у 2025 році.<sup>[[6]](#references)[[7]](#references)</sup>
* У попередній версії цієї сторінки описувалася ймовірна проблема Semtech UDP packet-forwarder як **створений пакет uplink розміром понад 255 байтів, що спричиняє stack smash і RCE на reference gateway SX130x**, яку пов’язували з презентацією “LoRa Exploitation Reloaded” на Black Hat Europe 2023 і приватним виправленням від жовтня 2023 року. Ці точні деталі збережено тут як напрям для дослідження, однак не вдалося підтвердити відповідний публічний advisory, презентацію або patch. Не вважайте цю проблему відомою вразливістю, доки не буде отримано уражений продукт/версію та перевірене первинне джерело.

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
Ці команди зберігають оригінальний workflow як **ілюстративний синтаксис**; структура repository та flags відрізняються між проєктами й релізами. Пасивне захоплення не розкриває сильний AppKey. Offline guessing корисний лише тоді, коли root key достатньо слабкий, щоб його можна було знайти, а захоплений join exchange надає значення для перевірки кандидатів.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Перевірка захисту OTAA від replay та стану nonce

1. В авторизованій тестовій мережі захопіть легітимний **JoinRequest**.
2. Повторно надішліть той самий запит і підтвердьте, що network server відхиляє повторно використаний `DevNonce`.
3. Перезавантажте або скиньте тестовий пристрій і повторіть перевірку, щоб виявити втрату стану nonce. Сумісний зі специфікацією server має відстежувати використані nonce; сам replay JoinRequest не розкриває щойно похідні session keys і не надає тому, хто повторно надсилає запит, контроль над сесією.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Зниження Adaptive Data-Rate (ADR)

Зловмисник, який може автентифікувати MAC-команди network layer — наприклад, після компрометації відповідного network session key або network server, — може спробувати примусово встановити неефективні параметри data-rate та збільшити airtime. Сусідній неавтентифікований transmitter не може легітимно надсилати ADR-команди лише знаючи адресу пристрою.<sup>[[3]](#references)</sup>

### 4. Реактивне глушіння

Реактивний jammer може передавати після виявлення преамбули LoRa та вибірково перешкоджати кадрам. На попередній сторінці стверджувалося, що конфігурація HackRF/GNU Radio спричинила повний збій на відстані **2 km із потужністю не більш ніж 200 mW**, але підтвердженого джерела вимірювань не було надано; зберігайте ці числа лише як ціль для відтворення, а не як очікуваний результат. Необхідні потужність передавання, timing, bandwidth, affected spreading factors і range залежать від середовища. Виконуйте тестування лише в авторизованій setup із RF-ізоляцією та дотримуйтеся місцевих правил використання spectrum.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Створення/парсинг/атака LoRaWAN frames, аналізатори з підтримкою DB, brute-forcer | Docker image; підтримує Semtech UDP input<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Python-utility Trend Micro для brute OTAA, генерації downlinks, розшифрування payloads | Public research utility; перевірте підтримувані hardware та protocol versions<sup>[[2]](#references)</sup> |
| **LoRAttack** | Research framework для multi-channel LoRaWAN capture, session analysis, key derivation і replay testing | Описано в master's thesis 2024 року; отримайте та перевірте точну implementation, перш ніж покладатися на приклад flags<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU Radio out-of-tree blocks для LoRa baseband reception або transceiver research | Проєкти відрізняються сумісністю з GNU Radio та набором функцій<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. Надавайте перевагу **OTAA** та перевіряйте, що пристрої й servers зберігають необхідний стан nonce; відстежуйте відхилені duplicate joins.
2. За можливості надавайте перевагу **LoRaWAN 1.1**, щоб network functions використовували окремі session keys та оновлену обробку nonce.<sup>[[3]](#references)</sup>
3. Зберігайте frame-counter у non-volatile memory (**ABP**) або мігруйте на OTAA.
4. Розгорніть відповідний **secure element** (наприклад, ATECC608A у сумісній design), щоб зменшити exposure root keys у звичайному firmware storage.
5. Не відкривайте налаштовані UDP listeners packet-forwarder (зазвичай 1700) для untrusted networks; автентифікуйте/шифруйте gateway backhaul або обмежте його за допомогою VPN.
6. Підтримуйте gateways на firmware, що підтримується vendor, і перевіряйте точну model/version за відповідними advisories.
7. Реалізуйте **traffic anomaly detection** (наприклад, analyzer LAF) – позначайте resets counters, duplicate joins, раптові ADR changes.<sup>[[1]](#references)</sup>



## References

- [1] [Framework аудиту LoRaWAN (LAF)](https://github.com/IOActive/laf)
- [2] [Огляд LoRaPWN від Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - специфікація LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - регіональні параметри LoRaWAN 1.1 і синхронізація join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Каталог thesis CTU - аналіз безпеки протоколів LPWAN із використанням SDR technology](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Трансивер GNU Radio `gr-lora_sdr` від EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
