# Атаки побічного каналу через Delivery Receipt в E2EE месенджерах

{{#include ../banners/hacktricks-training.md}}

Delivery receipts є обов’язковими в сучасних end-to-end encrypted (E2EE) месенджерах, тому що клієнтам потрібно знати, коли ciphertext було розшифровано, щоб вони могли скасувати ratcheting state і ephemeral keys. Сервер пересилає opaque blobs, тож device acknowledgements (double checkmarks) відправляються отримувачем після успішного розшифрування. Вимірювання round-trip time (RTT) між дією, ініційованою атакувальником, і відповідним delivery receipt відкриває високоточний timing channel, який leak-ить стан пристрою, online presence і може бути використаний для прихованого DoS. Багатопристроєві розгортання "client-fanout" підсилюють leak, тому що кожен зареєстрований пристрій розшифровує probe і повертає свій власний receipt.

## Джерела delivery receipt vs. сигнали, видимі користувачу

Обирайте типи повідомлень, які завжди emit-ять delivery receipt, але не показують UI artifacts на жертві. Таблиця нижче підсумовує емпірично підтверджену поведінку:

| Messenger | Дія | Delivery receipt | Сповіщення жертві | Примітки |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Завжди noisy → корисно лише для bootstrap стану. |
| | Reaction | ● | ◐ (лише якщо reacting to victim message) | Self-reactions і removals залишаються silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI дозволяє ~60 h, але пізніші пакети still ack’d. |
| **Signal** | Text message | ● | ● | Ті самі обмеження, що й у WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions невидимі для жертви. |
| | Edit/Delete | ● | ○ | Server enforce-ить ~48 h window, дозволяє до 10 edits, але пізні пакети still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts агрегуються, тому видимим стає лише один RTT на probe. |

Легенда: ● = завжди, ◐ = умовно, ○ = ніколи. Platform-dependent UI behaviour зазначено inline. За потреби вимкніть read receipts, але delivery receipts не можна вимкнути в WhatsApp або Signal.

## Цілі атакувальника та моделі

* **G1 – Device fingerprinting:** Порахуйте, скільки receipt-ів приходить на кожен probe, кластеризуйте RTT, щоб визначити OS/client (Android vs iOS vs desktop), і відстежуйте переходи online/offline.
* **G2 – Behavioral monitoring:** Розглядайте високочастотний ряд RTT (≈1 Hz є стабільним) як time-series і визначайте screen on/off, app foreground/background, поїздки vs робочі години тощо.
* **G3 – Resource exhaustion:** Тримайте radios/CPUs кожного пристрою жертви активними, надсилаючи безкінечні silent probes, розряджаючи battery/data і погіршуючи якість VoIP/RTC.

Для опису surface зловживання достатньо двох threat actors:

1. **Creepy companion:** уже має чат із жертвою та зловживає self-reactions, reaction removals або повторними edits/deletes, прив’язаними до наявних message IDs.
2. **Spooky stranger:** реєструє burner account і надсилає reactions із посиланням на message IDs, яких ніколи не існувало в локальній розмові; WhatsApp і Signal усе одно decrypt-ять і acknowledge-ять їх, навіть якщо UI discards state change, тож попередня розмова не потрібна.

## Інструменти для raw protocol access

Покладайтеся на клієнти, які expose-ять underlying E2EE protocol, щоб ви могли craft-ити packets поза обмеженнями UI, задавати довільні `message_id` і логувати точні timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) або [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) дозволяють emit-ити raw `ReactionMessage`, `ProtocolMessage` (edit/delete) і `Receipt` frames, зберігаючи double-ratchet state синхронізованим.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) у поєднанні з [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expose-ить кожен тип повідомлення через CLI/API. Приклад перемикання self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Source Android-клієнта document-ить, як delivery receipts consolidat-яться перед тим, як залишити device, пояснюючи, чому side channel там має negligible bandwidth.
* **Turnkey PoCs:** public projects на кшталт `device-activity-tracker` і `careless-whisper-python` уже automate-ять silent delete/reaction probes і RTT classification. Розглядайте їх як готові reconnaissance helpers, а не як protocol references; важлива частина в тому, що вони підтверджують: атака operationally simple, щойно є raw client access.

Коли custom tooling недоступний, ви все ще можете trigger-ити silent actions з WhatsApp Web або Signal Desktop і sniff-ити encrypted websocket/WebRTC channel, але raw APIs прибирають UI delays і дозволяють invalid operations.

## Creepy companion: silent sampling loop

1. Виберіть будь-яке історичне повідомлення, яке ви авторизували в чаті, щоб жертва ніколи не бачила, як змінюються "reaction" bubbles.
2. Чергуйте між видимим emoji та порожнім reaction payload (encoded as `""` у WhatsApp protobufs або `--remove` у signal-cli). Кожна передача дає device ack, попри відсутність UI delta для жертви.
3. Позначайте час відправлення і прихід кожного delivery receipt. Цикл 1 Hz, як наведений нижче, дає per-device RTT traces безкінечно:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Оскільки WhatsApp/Signal accept-ять необмежену кількість reaction updates, атакувальному ніколи не потрібно post-ити новий chat content або турбуватися про edit windows.

## Spooky stranger: probing довільних номерів телефону

1. Зареєструйте свіжий WhatsApp/Signal account і отримайте public identity keys для цільового номера (це робиться автоматично під час session setup).
2. Створіть reaction/edit/delete packet, який посилається на випадковий `message_id`, якого ніколи не бачили обидві сторони (WhatsApp accept-ить довільні `key.id` GUIDs; Signal використовує millisecond timestamps).
3. Надішліть packet, навіть якщо thread не існує. Пристрої жертви decrypt-ять його, не можуть match-нути base message, discard-ять state change, але все одно acknowledge-ять вхідний ciphertext, надсилаючи device receipts назад атакувальному.
4. Повторюйте безперервно, щоб будувати RTT series, так і не з’являючись у списку чатів жертви.

## Recycling edits and deletes як приховані triggers

* **Repeated deletes:** Після того як повідомлення видалили для всіх один раз, подальші delete packets із тим самим `message_id` не мають UI effect, але кожен пристрій усе одно decrypt-ить і acknowledge-ить їх.
* **Out-of-window operations:** WhatsApp enforce-ить ~60 h delete / ~20 min edit windows у UI; Signal enforce-ить ~48 h. Crafted protocol messages поза цими windows silently ignored на пристрої жертви, але receipts transmitted, тож атакувальний може probe-ити необмежено довго після завершення розмови.
* **Invalid payloads:** Пошкоджені edit bodies або deletes, що посилаються на вже purged messages, викликають ту саму поведінку — decryption plus receipt, zero user-visible artifacts.

## Multi-device amplification & fingerprinting

* Кожен пов’язаний пристрій (телефон, desktop app, browser companion) decrypt-ить probe незалежно і повертає свій власний ack. Підрахунок receipt-ів на кожен probe показує точну кількість пристроїв.
* Якщо пристрій offline, його receipt ставиться в чергу і emit-иться після reconnection. Отже, gaps leak-ять online/offline cycles і навіть commuting schedules (наприклад, desktop receipts зупиняються під час поїздок).
* RTT distributions відрізняються між платформами через OS power management і push wakeups. Кластеризуйте RTT (наприклад, k-means на median/variance features), щоб позначати “Android handset", “iOS handset", “Electron desktop", тощо.
* Оскільки sender має отримати inventory ключів отримувача перед шифруванням, атакувальний також може помітити, коли нові пристрої pair-яться; раптове збільшення кількості пристроїв або новий RTT cluster є сильним індикатором.

## Визначення поведінки за RTT traces

1. Збирайте дані з частотою ≥1 Hz, щоб захопити OS scheduling effects. У WhatsApp на iOS RTT <1 s сильно корелюють із screen-on/foreground, а >1 s — із screen-off/background throttling.
2. Будуйте прості classifiers (thresholding або two-cluster k-means), які позначають кожен RTT як "active" або "idle". Агрегуйте labels у streaks, щоб виводити bedtimes, commutes, work hours або моменти, коли desktop companion активний.
3. Корелюйте одночасні probes до кожного пристрою, щоб бачити, коли користувачі перемикаються з mobile на desktop, коли companions go offline і чи rate limited app через push або persistent socket.

## Визначення location за delivery RTT

Той самий timing primitive можна repurpose-нути, щоб визначити, де саме перебуває отримувач, а не лише чи він активний. Робота `Hope of Delivery` показала, що training на RTT distributions для відомих locations отримувача дозволяє атакувальному пізніше classify-ити location жертви лише за delivery confirmations:

* Побудуйте baseline для тієї самої цілі, коли вона перебуває в кількох відомих місцях (home, office, campus, country A vs country B тощо).
* Для кожного location зберіть багато normal message RTT і витягніть прості features, такі як median, variance або percentile buckets.
* Під час реальної атаки порівняйте нову probe series із натренованими clusters. У статті зазначено, що навіть locations у межах одного міста часто можна розділити, з точністю `>80%` у сценарії з 3 locations.
* Це працює найкраще, коли атакувальний контролює sender environment і probe-ить за схожих мережевих умов, тому що виміряний path включає recipient access network, wake-up latency і messenger infrastructure.

На відміну від тихих reaction/edit/delete атак вище, визначення location не вимагає invalid message IDs або stealthy state-changing packets. Звичайних повідомлень із нормальними delivery confirmations достатньо, тож tradeoff — менша stealth, але ширша придатність для різних messengers.

## Stealthy resource exhaustion

Оскільки кожен silent probe потрібно decrypt-нути і acknowledge-нути, безперервне надсилання reaction toggles, invalid edits або delete-for-everyone packets створює application-layer DoS:

* Примушує radio/modem transmit/receive щосекунди → помітний battery drain, особливо на idle handsets.
* Генерує unmetered upstream/downstream traffic, що витрачає mobile data plans, маскуючись під TLS/WebSocket noise.
* Займає crypto threads і створює jitter у latency-sensitive features (VoIP, video calls), навіть якщо користувач ніколи не бачить сповіщень.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
