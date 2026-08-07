# Атаки на побічні канали квитанцій про доставку в E2EE-месенджерах

{{#include ../banners/hacktricks-training.md}}

Квитанції про доставку є обов'язковими в сучасних E2EE-месенджерах, оскільки клієнтам потрібно знати, коли ciphertext було розшифровано, щоб вони могли відкинути стан ratchet і ephemeral keys. Сервер пересилає непрозорі blobs, тому підтвердження від пристрою (подвійні галочки) надсилаються одержувачем після успішного розшифрування. Вимірювання часу round-trip (RTT) між дією, ініційованою атакувальником, і відповідною квитанцією про доставку відкриває високоточний timing channel, який leak'ає стан пристрою та присутність онлайн і може використовуватися для covert DoS. Розгортання з кількома пристроями за моделлю "client-fanout" посилює leak, оскільки кожен зареєстрований пристрій розшифровує probe і повертає власну квитанцію.<sup>[[1]](#references)</sup>

## Джерела квитанцій про доставку та сигнали, видимі користувачу

Обирайте типи повідомлень, які завжди генерують квитанцію про доставку, але не створюють UI-артефактів на пристрої жертви. У таблиці нижче узагальнено емпірично підтверджену поведінку:<sup>[[1]](#references)</sup>

| Messenger | Дія | Квитанція про доставку | Сповіщення жертви | Примітки |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Текстове повідомлення | ● | ● | Завжди помітне → корисне лише для початкового визначення стану. |
| | Reaction | ● | ◐ (лише якщо реакція на повідомлення жертви) | Власні reactions і їх видалення залишаються непомітними. |
| | Редагування | ● | Залежний від платформи silent push | Вікно редагування ≈20 хв; підтвердження все одно надходить після завершення цього терміну. |
| | Видалення для всіх | ● | ○ | UI дозволяє приблизно 60 год, але пізніші packets все одно підтверджуються. |
| **Signal** | Текстове повідомлення | ● | ● | Ті самі обмеження, що й у WhatsApp. |
| | Reaction | ● | ◐ | Власні reactions невидимі для жертви. |
| | Редагування/видалення | ● | ○ | Сервер застосовує вікно приблизно 48 год і дозволяє до 10 редагувань, але пізні packets все одно підтверджуються. |
| **Threema** | Текстове повідомлення | ● | ● | Квитанції з кількох пристроїв агрегуються, тому для одного probe стає видимим лише один RTT. |

Позначення: ● = завжди, ◐ = умовно, ○ = ніколи. Поведінку UI, залежну від платформи, зазначено в примітках. За потреби вимкніть read receipts, але delivery receipts не можна вимкнути у WhatsApp або Signal.<sup>[[1]](#references)</sup>

## Цілі та моделі атакувальника

* **G1 – Fingerprinting пристроїв:** Підраховувати кількість квитанцій, що надходять для кожного probe, кластеризувати RTT, щоб визначати OS/client (Android, iOS або desktop), і відстежувати переходи онлайн/офлайн.
* **G2 – Behavioural monitoring:** Розглядати високочастотний ряд RTT (стабільно приблизно 1 Гц) як часовий ряд і визначати, чи ввімкнений екран, чи працює застосунок на передньому/задньому плані, години поїздок і роботи тощо.
* **G3 – Resource exhaustion:** Підтримувати радіомодулі/CPU кожного пристрою жертви в активному стані, надсилаючи безкінечні silent probes, розряджаючи батарею, витрачаючи data та погіршуючи якість VoIP/RTC.<sup>[[1]](#references)</sup>

Для опису поверхні зловживань достатньо двох threat actors:<sup>[[1]](#references)</sup>

1. **Creepy companion:** уже має спільний чат із жертвою та зловживає власними reactions, видаленням reactions або повторними редагуваннями/видаленнями, прив'язаними до наявних ID повідомлень.
2. **Spooky stranger:** реєструє burner account і надсилає reactions із посиланнями на ID повідомлень, яких ніколи не існувало в локальній розмові; WhatsApp і Signal усе одно розшифровують і підтверджують їх, хоча UI відкидає зміну стану, тому попередня розмова не потрібна.

## Інструменти для доступу до raw protocol

Використовуйте clients, які надають доступ до базового E2EE protocol, щоб створювати packets поза обмеженнями UI, задавати довільні `message_id` і записувати точні timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) або [Cobalt](https://github.com/Auties00/Cobalt) (орієнтований на mobile) дають змогу надсилати raw `ReactionMessage`, `ProtocolMessage` (edit/delete) і `Receipt` frames, підтримуючи стан double-ratchet синхронізованим.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) у поєднанні з [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) надає доступ до кожного типу повідомлень через CLI/API.<sup>[[5]](#references)[[7]](#references)</sup> Поточний синтаксис `signal-cli` використовує `sendReaction RECIPIENT --target-author --target-timestamp`; залишайте `receive` або `daemon` запущеним, щоб delivery receipts фактично збиралися.<sup>[[6]](#references)</sup> Приклад перемикання власної reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Source Android client документує, як delivery receipts консолідуються перед відправленням із пристрою, пояснюючи, чому side channel тут має negligible bandwidth.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) містить WhatsApp/Signal backends, за замовчуванням використовує silent delete probes і позначає стани `active` та `standby` за допомогою rolling-median threshold (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) — легший WhatsApp-first CLI із `--delay`, `--concurrent`, CSV/Prometheus exporters і виводом, зручним для Grafana.<sup>[[8]](#references)[[9]](#references)</sup> Розглядайте обидва як reconnaissance helpers, а не як protocol references; головний висновок полягає в тому, наскільки мало коду потрібно після отримання доступу до raw client.

Якщо custom tooling недоступний, ви все одно можете запускати silent actions із WhatsApp Web або Signal Desktop і sniff'ити зашифрований websocket/WebRTC channel, але raw APIs прибирають затримки UI та дозволяють invalid operations.

## Creepy companion: цикл silent sampling

1. Виберіть будь-яке історичне повідомлення, автором якого ви були в цьому чаті, щоб жертва ніколи не побачила зміни "reaction" balloons.
2. Чергуйте видимий emoji та порожній reaction payload (кодується як `""` у WhatsApp protobufs або `--remove` у signal-cli). Кожна передача генерує device ack, незважаючи на відсутність UI delta для жертви.
3. Фіксуйте час надсилання та надходження кожної delivery receipt. Цикл із частотою 1 Гц, як у прикладі нижче, безперервно створює RTT traces для кожного пристрою:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Оскільки WhatsApp/Signal приймають необмежену кількість оновлень reactions, атакувальнику ніколи не потрібно публікувати новий chat content або турбуватися про edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: probing довільних номерів телефонів

1. Зареєструйте новий WhatsApp/Signal account і отримайте public identity keys для цільового номера (це автоматично виконується під час session setup).
2. Створіть reaction/edit/delete packet, який посилається на випадковий `message_id`, невідомий обом сторонам (WhatsApp приймає довільні GUID у `key.id`; Signal використовує timestamps у мілісекундах).
3. Надішліть packet, навіть якщо thread не існує. Пристрої жертви розшифрують його, не знайдуть базове повідомлення, відкинуть зміну стану, але все одно підтвердять вхідний ciphertext і надішлють device receipts атакувальнику.
4. Безперервно повторюйте операцію, щоб створити RTT series, ніколи не з'являючись у списку чатів жертви.<sup>[[1]](#references)</sup>

Якщо спочатку потрібно визначити, які номери зареєстровані, або заздалегідь створити inventories пристроїв у масштабі, об'єднайте це з [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), а не вгадуйте випадкові діапазони E.164 вручну.

Опубліковані дослідження contact-discovery показали практичне значення цього підходу: використовуючи точні таблиці phone prefixes і помірні ресурси, дослідники змогли перевірити приблизно `10%` мобільних номерів США у WhatsApp і `100%` у Signal, перш ніж перейти до targeted probing.<sup>[[11]](#references)</sup> На практиці попередня фільтрація активних accounts дає змогу зосередити бюджет silent probes на номерах, які справді розшифрують packets.

У нових збірках WhatsApp також доступний параметр `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Розглядайте його як throughput limiter, а не як виправлення: він переважно ускладнює тривале flooding лише від strangers і не має значення, якщо ви вже є відомим контактом.

## Повторне використання edits і deletes як covert triggers

* **Repeated deletes:** Після того як повідомлення один раз видалено для всіх, наступні delete packets із тим самим `message_id` не впливають на UI, але кожен пристрій усе одно розшифровує та підтверджує їх.
* **Out-of-window operations:** WhatsApp застосовує у UI вікна приблизно 60 год для delete та 20 хв для edit; Signal застосовує приблизно 48 год. Створені protocol messages за межами цих вікон тихо ігноруються на пристрої жертви, але receipts передаються, тому attackers можуть проводити probing необмежено довго після завершення розмови.
* **Invalid payloads:** Некоректні edit bodies або deletes із посиланнями на вже видалені messages викликають таку саму поведінку — decryption плюс receipt і нуль user-visible artefacts.<sup>[[1]](#references)</sup>

## Multi-device amplification і fingerprinting

* Кожен пов'язаний пристрій (телефон, desktop app, browser companion) незалежно розшифровує probe і повертає власний ack. Підрахунок receipts для кожного probe показує точну кількість пристроїв.
* Якщо пристрій офлайн, його receipt ставиться в чергу та надсилається після повторного підключення. Тому gaps leak'ають цикли онлайн/офлайн і навіть розклад поїздок (наприклад, receipts від desktop припиняються під час подорожі).
* RTT distributions відрізняються залежно від платформи через OS power management і push wakeups. Кластеризуйте RTT (наприклад, k-means за ознаками median/variance), щоб позначати “Android handset”, “iOS handset”, “Electron desktop” тощо.
* Оскільки sender має отримати key inventory одержувача перед шифруванням, атакувальник також може відстежувати підключення нових пристроїв; раптове збільшення кількості пристроїв або поява нового RTT cluster є надійним індикатором.<sup>[[1]](#references)</sup>

## Частота sampling, queueing і stacked receipts

* **WhatsApp burst tolerance:** Опубліковані вимірювання показали, що WhatsApp приймав bursts silent reactions зі швидкістю до одного probe кожні `50 ms` без очевидного server-side queueing. Це корисно для коротких calibration bursts, швидкого підрахунку пристроїв або швидкого розгортання drain attack.
* **Signal long-run queueing:** Signal витримував короткі bursts, але починав ставити в чергу тривалий трафік із кількома probes на секунду. Для довготривалого monitoring підтримуйте cadence близько `1 Hz` (або нижче), щоб кожен receipt відображав поточний стан пристрою, а не drain backlog.
* **Reconnect artefacts:** Коли пристрій повертається онлайн, деякі clients пакетно або швидко flush'ать кілька відкладених receipts. Розглядайте такі bursts receipts як маркер переходу стану, а не як незалежні RTT samples, інакше ваш clustering / classifier `active` vs `idle` буде overfit'ити noise reconnect.<sup>[[1]](#references)</sup>

## Виведення поведінки з RTT traces

1. Виконуйте sampling із частотою ≥1 Гц, щоб фіксувати ефекти OS scheduling. Для WhatsApp на iOS RTT <1 с сильно корелює зі screen-on/foreground, а >1 с — зі screen-off/background throttling.
2. Створюйте прості classifiers (thresholding або two-cluster k-means), які позначають кожен RTT як `"active"` або `"idle"`. Об'єднуйте labels у streaks, щоб визначати час сну, поїздки, робочі години або активність desktop companion.
3. Correlate одночасні probes до кожного пристрою, щоб бачити, коли користувачі перемикаються з mobile на desktop, коли companions переходять офлайн і чи rate limited застосунок через push або persistent socket.
4. У реальних мережах не використовуйте один hardcoded threshold `1 s`. Bootstrap'те кожен пристрій коротким warm-up window і підтримуйте rolling baseline (наприклад, `threshold = 0.9 * median RTT`), щоб drift Wi-Fi/cellular не зруйнував ваш classifier.<sup>[[1]](#references)</sup>

## Виведення місцезнаходження за delivery RTT

Той самий timing primitive можна використати для визначення місцезнаходження одержувача, а не лише його активності. Дослідження `Hope of Delivery` показало, що навчання на RTT distributions для відомих місць перебування одержувача дає змогу атакувальнику згодом класифікувати місцезнаходження жертви лише за delivery confirmations:<sup>[[2]](#references)</sup>

* Створіть baseline для тієї самої цілі, коли вона перебуває в кількох відомих місцях (удома, в офісі, на campus, у країні A та країні B тощо).
* Для кожного місця зберіть багато звичайних message RTT і виділіть прості features, такі як median, variance або percentile buckets.
* Під час реальної атаки порівняйте нову probe series із навченими clusters. У статті повідомляється, що часто можна розрізнити навіть місця в одному місті, з точністю `>80%` у сценарії з 3 місцями.
* Найкраще це працює, коли атакувальник контролює sender environment і проводить probes за подібних network conditions, оскільки вимірюваний path включає access network одержувача, wake-up latency та messenger infrastructure.<sup>[[2]](#references)</sup>

На відміну від наведених вище атак із silent reaction/edit/delete, для location inference не потрібні invalid message IDs або stealthy state-changing packets. Достатньо звичайних messages із normal delivery confirmations, тому компромісом є нижча stealth, але ширша застосовність у різних messengers.

## Stealthy resource exhaustion

Оскільки кожен silent probe потрібно розшифрувати та підтвердити, безперервне надсилання reaction toggles, invalid edits або delete-for-everyone packets створює application-layer DoS:<sup>[[1]](#references)</sup>

* Змушує radio/modem щосекунди передавати й приймати дані → помітно розряджає батарею, особливо на idle handsets.
* Генерує unmetered upstream/downstream traffic, який витрачає mobile data plans, маскуючись під TLS/WebSocket noise.
* Завантажує crypto threads і створює jitter у latency-sensitive features (VoIP, video calls), хоча користувач ніколи не бачить notifications.
* У WhatsApp invalid reactions приймають набагато більше даних, ніж можна припустити за звичайним emoji: опубліковані вимірювання виявили server-side acceptance до приблизно `1 MB` на reaction.
* Oversized reactions перестають генерувати надійні delivery receipts, коли body перевищує приблизно `30 bytes`, але все одно пересилаються та обробляються перед discard. Коли потрібні ACKs, використовуйте маленькі reaction bodies; збільшуйте їх лише для pure drain або covert one-way transport.
* Публічні вимірювання досягали приблизно `3.7 MB/s` (`~13.3 GB/h`) traffic жертви в цьому режимі.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
