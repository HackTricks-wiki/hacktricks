# Атаки побічного каналу через Delivery Receipt в E2EE месенджерах

{{#include ../banners/hacktricks-training.md}}

Delivery receipts є обов’язковими в сучасних end-to-end encrypted (E2EE) месенджерах, бо клієнти мають знати, коли ciphertext був розшифрований, щоб вони могли відкинути ratcheting state та ephemeral keys. Сервер пересилає opaque blobs, тож device acknowledgements (double checkmarks) надсилаються одержувачем після успішного дешифрування. Вимірювання round-trip time (RTT) між дією, ініційованою атакувальником, і відповідним delivery receipt відкриває високоточний timing channel, який leak-ить device state, online presence і може бути використаний для прихованого DoS. У multi-device "client-fanout" розгортаннях leak посилюється, бо кожен зареєстрований пристрій дешифрує probe і повертає свій власний receipt.

## Джерела delivery receipt vs. сигнали, видимі користувачу

Обирайте типи повідомлень, які завжди надсилають delivery receipt, але не показують UI-артефакти на пристрої жертви. Таблиця нижче підсумовує емпірично підтверджену поведінку:

| Messenger | Дія | Delivery receipt | Сповіщення жертви | Примітки |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Текстове повідомлення | ● | ● | Завжди шумно → корисно лише для bootstrap state. |
| | Reaction | ● | ◐ (лише якщо reacting to victim message) | Self-reactions і removals залишаються беззвучними. |
| | Edit | ● | platform-dependent silent push | Вікно edit ≈20 min; все одно ack’d після закінчення строку. |
| | Delete for everyone | ● | ○ | UI дозволяє ~60 h, але пізніші пакети все одно ack’d. |
| **Signal** | Текстове повідомлення | ● | ● | Такі самі обмеження, як у WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions невидимі для жертви. |
| | Edit/Delete | ● | ○ | Сервер примусово застосовує вікно ~48 h, дозволяє до 10 edits, але пізні пакети все одно ack’d. |
| **Threema** | Текстове повідомлення | ● | ● | Multi-device receipts агрегуються, тож видимим стає лише один RTT на probe. |

Легенда: ● = завжди, ◐ = умовно, ○ = ніколи. Platform-dependent UI behavior вказано прямо в тексті. За потреби вимкніть read receipts, але delivery receipts не можна вимкнути в WhatsApp або Signal.

## Цілі атакувальника і моделі

* **G1 – Device fingerprinting:** Порахуйте, скільки receipt приходить на кожен probe, кластеризуйте RTT, щоб вивести OS/client (Android vs iOS vs desktop), і відстежуйте переходи online/offline.
* **G2 – Behavioural monitoring:** Розглядайте високочастотний ряд RTT (≈1 Hz є стабільним) як time-series і виводьте screen on/off, app foreground/background, commuting vs working hours тощо.
* **G3 – Resource exhaustion:** Тримайте radios/CPUs кожного пристрою жертви активними, надсилаючи нескінченні silent probes, розряджаючи battery/data і погіршуючи якість VoIP/RTC.

Для опису поверхні зловживання достатньо двох threat actors:

1. **Creepy companion:** уже має чат із жертвою і зловживає self-reactions, reaction removals або повторними edits/deletes, прив’язаними до наявних message IDs.
2. **Spooky stranger:** реєструє burner account і надсилає reactions, що посилаються на message IDs, яких ніколи не існувало в локальній розмові; WhatsApp і Signal все одно дешифрують і підтверджують їх, навіть якщо UI відкидає зміну стану, тож попередня розмова не потрібна.

## Інструменти для raw protocol access

Покладайтеся на клієнтів, які відкривають underlying E2EE protocol, щоб можна було craft packets поза обмеженнями UI, вказувати довільні `message_id` і логувати точні timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) або [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) дозволяють надсилати raw `ReactionMessage`, `ProtocolMessage` (edit/delete) і `Receipt` frames, зберігаючи double-ratchet state синхронізованим.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) у поєднанні з [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) відкриває кожен тип повідомлення через CLI/API. Поточний синтаксис `signal-cli` використовує `sendReaction RECIPIENT --target-author --target-timestamp`; тримайте `receive` або `daemon` запущеним, щоб delivery receipts справді збиралися. Приклад перемикання self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Source Android-клієнта документує, як delivery receipts консолідуються перед виходом з пристрою, пояснюючи, чому side channel там має незначну пропускну здатність.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) містить WhatsApp/Signal backends, за замовчуванням використовує silent delete probes і позначає `active` vs `standby` за rolling-median threshold (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) — легший WhatsApp-first CLI з `--delay`, `--concurrent`, CSV/Prometheus exporters і Grafana-friendly output. Розглядайте обидва як reconnaissance helpers, а не як protocol references; головний висновок — наскільки мало коду потрібно, коли є raw client access.

Коли custom tooling недоступний, ви все ще можете запускати silent actions з WhatsApp Web або Signal Desktop і sniff encrypted websocket/WebRTC channel, але raw APIs прибирають UI delays і дозволяють invalid operations.

## Creepy companion: silent sampling loop

1. Оберіть будь-яке історичне повідомлення, яке ви авторизували в чаті, щоб жертва ніколи не бачила, як змінюються "reaction" bubbles.
2. Чергуйте видимий emoji і порожній reaction payload (закодований як `""` у WhatsApp protobufs або `--remove` у signal-cli). Кожна передача дає device ack, попри відсутність UI delta для жертви.
3. Позначайте send time і кожен момент arrival delivery receipt. Цикл 1 Hz, як наведений нижче, дає per-device RTT traces безстроково:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Оскільки WhatsApp/Signal приймають необмежену кількість reaction updates, атакувальнику ніколи не потрібно публікувати новий chat content або турбуватися про edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Зареєструйте свіжий WhatsApp/Signal account і отримайте public identity keys для цільового номера (це робиться автоматично під час session setup).
2. Створіть reaction/edit/delete packet, що посилається на випадковий `message_id`, який ніколи не бачили обидві сторони (WhatsApp приймає довільні `key.id` GUIDs; Signal використовує millisecond timestamps).
3. Надішліть packet, навіть якщо thread не існує. Пристрої жертви дешифрують його, не знаходять base message, відкидають зміну стану, але все одно підтверджують вхідний ciphertext, надсилаючи device receipts назад атакувальнику.
4. Повторюйте безперервно, щоб будувати RTT series, ніколи не з’являючись у chat list жертви.

Якщо спершу потрібно з’ясувати, які номери зареєстровані, або ви хочете pre-seed device inventories у масштабі, поєднайте це з [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) замість того, щоб вручну вгадувати випадкові діапазони E.164.

Останні збірки WhatsApp також відкривають `Settings -> Privacy -> Advanced -> Block unknown account messages`. Розглядайте це як throughput limiter, а не як fix: він переважно шкодить тривалому flooding лише від strangers і не має значення, коли ви вже є відомим контактом.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Після того як message було deleted-for-everyone один раз, подальші delete packets, що посилаються на той самий `message_id`, не мають UI effect, але кожен пристрій усе одно дешифрує їх і підтверджує.
* **Out-of-window operations:** WhatsApp примусово застосовує в UI вікна ~60 h для delete / ~20 min для edit; Signal — ~48 h. Сформовані protocol messages поза цими вікнами тихо ігноруються на пристрої жертви, але receipts усе одно передаються, тож атакувальники можуть probe безкінечно довго після завершення розмови.
* **Invalid payloads:** Некоректні edit bodies або deletes, що посилаються на вже очищені messages, викликають ту саму поведінку — decryption плюс receipt, zero user-visible artifacts.

## Multi-device amplification & fingerprinting

* Кожен пов’язаний пристрій (телефон, desktop app, browser companion) дешифрує probe незалежно і повертає свій власний ack. Підрахунок receipts на кожен probe відкриває точну кількість пристроїв.
* Якщо пристрій offline, його receipt ставиться в чергу і надсилається після reconnect. Отже, прогалини leak-ять online/offline цикли і навіть commuting schedules (наприклад, desktop receipts припиняються під час поїздок).
* RTT distributions відрізняються між платформами через OS power management і push wakeups. Кластеризуйте RTT (наприклад, k-means за ознаками median/variance), щоб позначати “Android handset", “iOS handset", “Electron desktop", тощо.
* Оскільки sender має отримати recipient’s key inventory перед encryption, атакувальник також може спостерігати, коли нові пристрої pair-яться; раптове збільшення кількості пристроїв або новий RTT cluster — сильний індикатор.

## Behaviour inference from RTT traces

1. Вимірюйте з частотою ≥1 Hz, щоб захопити OS scheduling effects. У WhatsApp на iOS RTT <1 s сильно корелюють із screen-on/foreground, а >1 s — із screen-off/background throttling.
2. Побудуйте прості classifiers (thresholding або two-cluster k-means), які позначають кожен RTT як "active" або "idle". Агрегуйте мітки в streaks, щоб вивести bedtime, commuting, work hours або коли desktop companion активний.
3. Корелюйте одночасні probes до кожного пристрою, щоб бачити, коли користувачі переходять з mobile на desktop, коли companions go offline і чи rate limited app через push або persistent socket.
4. У реальних мережах уникайте одного жорстко закодованого порога `1 s`. Зробіть bootstrap кожного пристрою коротким warm-up window і підтримуйте rolling baseline (наприклад, `threshold = 0.9 * median RTT`), щоб Wi-Fi/cellular drift не зламав ваш classifier.

## Location inference from delivery RTT

Той самий timing primitive можна перепризначити, щоб визначити, де саме знаходиться одержувач, а не лише те, чи він активний. Робота `Hope of Delivery` показала, що навчання на RTT distributions для відомих location одержувача дозволяє атакувальнику пізніше класифікувати location жертви лише з delivery confirmations:

* Побудуйте baseline для тієї самої цілі, поки вона перебуває в кількох відомих місцях (home, office, campus, country A vs country B тощо).
* Для кожного location зберіть багато normal message RTT і витягніть прості features, як-от median, variance або percentile buckets.
* Під час реальної атаки порівняйте нову series probe з натренованими clusters. У статті зазначено, що навіть locations в межах одного міста часто можна розділити з точністю `>80%` у сценарії з 3 locations.
* Це найкраще працює, коли атакувальник контролює sender environment і робить probes за схожих network conditions, бо виміряний шлях включає recipient access network, wake-up latency і messenger infrastructure.

На відміну від тихих атак reaction/edit/delete вище, location inference не потребує invalid message IDs або stealthy state-changing packets. Достатньо звичайних messages зі стандартними delivery confirmations, тож компроміс — менше stealth, але ширша застосовність для різних messengers.

## Stealthy resource exhaustion

Оскільки кожен silent probe має бути дешифрований і підтверджений, безперервне надсилання reaction toggles, invalid edits або delete-for-everyone packets створює application-layer DoS:

* Примушує radio/modem передавати/приймати щосекунди → помітний battery drain, особливо на idle handsets.
* Генерує неметражований upstream/downstream traffic, який споживає mobile data plans, маскуючись під TLS/WebSocket noise.
* Займає crypto threads і створює jitter у latency-sensitive features (VoIP, video calls), навіть якщо користувач ніколи не бачить notifications.
* У WhatsApp invalid reactions приймають значно більше data, ніж можна було б очікувати від звичайного emoji: опубліковані вимірювання показали server-side acceptance до приблизно `1 MB` на reaction.
* Надто великі reactions перестають давати надійні delivery receipts, коли body перевищує приблизно `30 bytes`, але їх усе одно пересилають і обробляють перед відкиданням. Тримайте reaction bodies маленькими, коли вам потрібні ACKs; збільшуйте їх лише коли мета — чистий drain або прихований one-way transport.
* Публічні вимірювання досягали приблизно `3.7 MB/s` (`~13.3 GB/h`) трафіку жертви в цьому режимі.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
