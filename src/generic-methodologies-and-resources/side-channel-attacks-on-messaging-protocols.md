# Атаки side-channel через Delivery Receipt в E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts є обов’язковими в сучасних end-to-end encrypted (E2EE) messengers, тому що клієнтам потрібно знати, коли ciphertext було розшифровано, щоб вони могли скидати ratcheting state та ephemeral keys. Server передає opaque blobs, тож device acknowledgements (double checkmarks) відправляються отримувачем після успішного дешифрування. Вимірювання round-trip time (RTT) між дією, запущеною attacker, і відповідним delivery receipt відкриває високоточний timing channel, який leak’ить стан device, online presence і може бути використаний для covert DoS. Multi-device "client-fanout" deployments посилюють leak, тому що кожен зареєстрований device розшифровує probe і повертає свій власний receipt.

## Джерела delivery receipt vs. user-visible signals

Обирайте типи повідомлень, які завжди створюють delivery receipt, але не показують UI artifacts на victim. Таблиця нижче підсумовує емпірично підтверджену поведінку:

| Messenger | Дія | Delivery receipt | Сповіщення victim | Примітки |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Завжди noisy → корисно лише для bootstrap state. |
| | Reaction | ● | ◐ (лише якщо reacting to victim message) | Self-reactions і removals залишаються silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; все ще ack’d після expiry. |
| | Delete for everyone | ● | ○ | UI дозволяє ~60 h, але пізніші packets все ще ack’d. |
| **Signal** | Text message | ● | ● | Такі самі обмеження, як у WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions невидимі для victim. |
| | Edit/Delete | ● | ○ | Server enforce’ить ~48 h window, дозволяє до 10 edits, але пізні packets все ще ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts агрегуються, тому лише один RTT на probe стає видимим. |

Легенда: ● = завжди, ◐ = умовно, ○ = ніколи. Platform-dependent UI поведінка зазначена прямо в тексті. За потреби вимкніть read receipts, але delivery receipts не можна вимкнути в WhatsApp або Signal.

## Цілі attacker і моделі

* **G1 – Device fingerprinting:** Підрахувати, скільки receipts приходить на кожен probe, кластеризувати RTT, щоб визначити OS/client (Android vs iOS vs desktop), і відстежувати online/offline переходи.
* **G2 – Behavioural monitoring:** Розглядати високочастотний ряд RTT (≈1 Hz є стабільним) як time-series і визначати screen on/off, app foreground/background, commuting vs working hours тощо.
* **G3 – Resource exhaustion:** Тримати radios/CPUs кожного device victim у активному стані, надсилаючи нескінченні silent probes, розряджаючи батарею/data і погіршуючи якість VoIP/RTC.

Для опису surface abuse достатньо двох threat actors:

1. **Creepy companion:** вже має chat з victim і зловживає self-reactions, reaction removals або repeated edits/deletes, прив’язаними до наявних message IDs.
2. **Spooky stranger:** реєструє burner account і надсилає reactions із посиланням на message IDs, яких ніколи не існувало в локальному conversation; WhatsApp і Signal все одно розшифровують їх і підтверджують, навіть якщо UI відкидає зміну стану, тож попередній conversation не потрібен.

## Tooling для raw protocol access

Покладайтеся на clients, які expose underlying E2EE protocol, щоб ви могли craft packets поза обмеженнями UI, вказувати довільні `message_id`s і логувати точні timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) або [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) дозволяють відправляти raw `ReactionMessage`, `ProtocolMessage` (edit/delete) і `Receipt` frames, зберігаючи double-ratchet state у sync.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) у поєднанні з [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expose’ить кожен message type через CLI/API. Поточний синтаксис `signal-cli` використовує `sendReaction RECIPIENT --target-author --target-timestamp`; тримайте `receive` або `daemon` запущеним, щоб delivery receipts справді збиралися. Приклад toggle self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Source Android client документує, як delivery receipts консолідуються перед тим, як залишити device, пояснюючи, чому side channel там має нехтувану пропускну здатність.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) постачається з WhatsApp/Signal backends, за замовчуванням використовує silent delete probes і позначає `active` vs `standby` за допомогою rolling-median threshold (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) — легший WhatsApp-first CLI з `--delay`, `--concurrent`, CSV/Prometheus exporters і Grafana-friendly output. Розглядайте обидва як reconnaissance helpers, а не як protocol references; важливий висновок — як мало коду потрібно, коли є raw client access.

Коли custom tooling недоступний, ви все ще можете запускати silent actions з WhatsApp Web або Signal Desktop і sniff encrypted websocket/WebRTC channel, але raw APIs прибирають UI delays і дозволяють invalid operations.

## Creepy companion: silent sampling loop

1. Оберіть будь-яке історичне повідомлення, яке ви авторизували в chat, щоб victim ніколи не бачив, як змінюються "reaction" balloons.
2. Чергайте між видимим emoji та порожнім reaction payload (закодованим як `""` у WhatsApp protobufs або `--remove` у signal-cli). Кожна передача дає device ack, попри відсутність UI delta для victim.
3. Позначайте час відправлення і кожного arrival delivery receipt. Цикл на 1 Hz, подібний до наведеного нижче, дає per-device RTT traces без обмеження в часі:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Оскільки WhatsApp/Signal приймають необмежену кількість reaction updates, attacker ніколи не потребує публікувати новий chat content або турбуватися про edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Зареєструйте свіжий WhatsApp/Signal account і отримайте public identity keys для target number (це робиться автоматично під час session setup).
2. Згенеруйте reaction/edit/delete packet, який посилається на випадковий `message_id`, що ніколи не бачили обидві сторони (WhatsApp приймає довільні GUID у `key.id`; Signal використовує millisecond timestamps).
3. Надішліть packet, навіть якщо thread не існує. Victim devices розшифровують його, не можуть зіставити з базовим message, відкидають зміну стану, але все одно підтверджують вхідний ciphertext, відправляючи device receipts назад attacker.
4. Повторюйте безперервно, щоб побудувати RTT series, не з’являючись у chat list victim.

Якщо спочатку потрібно з’ясувати, які номери зареєстровані, або ви хочете pre-seed device inventories у масштабі, поєднуйте це з [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), а не вгадуйте випадкові E.164 ranges вручну.

Опублікована робота з contact-discovery показала, чому це важливо з operational точки зору: з точними phone-prefix tables і помірними ресурсами дослідники змогли query приблизно `10%` US mobile numbers у WhatsApp і `100%` у Signal, перш ніж перейти до targeted probing. На практиці попередня фільтрація live accounts спершу тримає ваш silent-probe budget сфокусованим на номерах, які реально розшифровуватимуть packets.

Нові збірки WhatsApp також відкривають `Settings -> Privacy -> Advanced -> Block unknown account messages`. Розглядайте це як throughput limiter, а не як fix: воно переважно заважає тривалому flooding лише від stranger і не має значення, коли ви вже є відомим contact.

## Перевикористання edits і deletes як covert triggers

* **Repeated deletes:** Після того як message один раз deleted-for-everyone, подальші delete packets, що посилаються на той самий `message_id`, не мають UI effect, але кожен device все одно розшифровує їх і підтверджує.
* **Out-of-window operations:** WhatsApp enforce’ить ~60 h delete / ~20 min edit windows у UI; Signal enforce’ить ~48 h. Згенеровані protocol messages поза цими windows тихо ігноруються на victim device, але receipts усе одно передаються, тож attacker може probe-ити нескінченно довго після завершення conversation.
* **Invalid payloads:** Некоректні edit bodies або deletes, що посилаються на вже очищені messages, викликають таку саму поведінку — decryption плюс receipt, zero user-visible artefacts.

## Multi-device amplification & fingerprinting

* Кожен пов’язаний device (phone, desktop app, browser companion) розшифровує probe незалежно і повертає свій власний ack. Підрахунок receipts на probe показує точну кількість device.
* Якщо device offline, його receipt ставиться в чергу і відправляється після reconnection. Отже, gaps leak’ять online/offline цикли і навіть commuting schedules (наприклад, desktop receipts зупиняються під час поїздок).
* Розподіли RTT відрізняються між platform через OS power management і push wakeups. Кластеризуйте RTT (наприклад, k-means на median/variance features), щоб позначити “Android handset", “iOS handset", “Electron desktop" тощо.
* Оскільки sender повинен отримати key inventory отримувача перед шифруванням, attacker також може спостерігати, коли додаються нові device; раптове збільшення кількості device або новий RTT cluster — сильний індикатор.

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Опубліковані вимірювання показали, що WhatsApp приймав silent-reaction bursts так швидко, як один probe кожні `50 ms`, без очевидного server-side queueing. Це корисно для коротких calibration bursts, швидкого підрахунку device або швидкого запуску drain attack.
* **Signal long-run queueing:** Signal витримував короткі bursts, але починав queue-ити тривалий multi-probe-per-second traffic. Для довготривалого monitoring тримайте cadence близько `1 Hz` (або нижче), щоб кожен receipt усе ще відображав поточний стан device, а не розгрібання backlog.
* **Reconnect artefacts:** Коли device повертається online, деякі clients пакетують або швидко flush-ать кілька delayed receipts. Розглядайте такі bursts receipts як marker transition state, а не як незалежні RTT samples, інакше ваша clustering / `active` vs `idle` classifier переобучиться на reconnect noise.

## Визначення поведінки за RTT traces

1. Семплюйте з частотою ≥1 Hz, щоб захопити ефекти OS scheduling. У WhatsApp на iOS RTT < 1 s сильно корелює зі screen-on/foreground, а >1 s — зі screen-off/background throttling.
2. Побудуйте прості classifiers (thresholding або двокластерний k-means), які позначають кожен RTT як "active" або "idle". Агрегуйте позначки в streaks, щоб визначати bedtimes, commutes, work hours або моменти, коли desktop companion активний.
3. Корелюйте одночасні probes до кожного device, щоб бачити, коли users переходять з mobile на desktop, коли companions go offline, і чи обмежує app rate push чи persistent socket.
4. У реальних networks уникайте одного жорстко заданого `1 s` threshold. Bootstrap-те кожен device коротким warm-up window і тримайте rolling baseline (наприклад, `threshold = 0.9 * median RTT`), щоб Wi-Fi/cellular drift не зламав classifier.

## Визначення location за delivery RTT

Той самий timing primitive можна використати, щоб визначати, де перебуває отримувач, а не лише чи він активний. Робота `Hope of Delivery` показала, що навчання на RTT distributions для відомих receiver locations дозволяє attacker пізніше класифікувати location victim лише з delivery confirmations:

* Побудуйте baseline для тієї самої цілі, поки вона перебуває в кількох відомих місцях (home, office, campus, country A vs country B тощо).
* Для кожної location зберіть багато normal message RTT і витягніть прості features, наприклад median, variance або percentile buckets.
* Під час реальної атаки порівняйте нову probe series з навченою кластеризацією. У роботі зазначено, що навіть locations в межах одного міста часто можна розрізнити, з точністю `>80%` у сценарії з 3 locations.
* Це працює найкраще, коли attacker контролює sender environment і запускає probes за схожих network conditions, тому що виміряний шлях включає recipient access network, wake-up latency і messenger infrastructure.

На відміну від silent reaction/edit/delete attacks вище, визначення location не потребує invalid message IDs або stealthy state-changing packets. Звичайних messages з нормальними delivery confirmations достатньо, тож компроміс — нижча stealth, але ширша застосовність серед messengers.

## Stealthy resource exhaustion

Оскільки кожен silent probe має бути розшифрований і підтверджений, безперервне надсилання reaction toggles, invalid edits або delete-for-everyone packets створює application-layer DoS:

* Примушує radio/modem передавати/приймати щосекунди → помітний battery drain, особливо на idle handsets.
* Генерує unmetered upstream/downstream traffic, який споживає mobile data plans, змішуючись із TLS/WebSocket noise.
* Займає crypto threads і створює jitter у latency-sensitive features (VoIP, video calls), навіть якщо user ніколи не бачить notifications.
* У WhatsApp invalid reactions приймають значно більше data, ніж можна було б очікувати від normal emoji: опубліковані вимірювання показали server-side acceptance до приблизно `1 MB` на reaction.
* Надто великі reactions перестають давати надійні delivery receipts, коли body перевищує приблизно `30 bytes`, але їх усе одно пересилають і обробляють перед discard. Тримайте reaction bodies маленькими, коли потрібні ACKs; збільшуйте їх лише тоді, коли мета — чистий drain або covert one-way transport.
* Публічні вимірювання досягали близько `3.7 MB/s` (`~13.3 GB/h`) victim traffic у цьому режимі.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
