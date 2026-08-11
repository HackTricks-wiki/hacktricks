# Атаки побічного каналу на квитанції про доставку в E2EE-месенджерах

{{#include ../banners/hacktricks-training.md}}

Квитанції про доставку є обов'язковими в сучасних месенджерах із наскрізним шифруванням (E2EE), оскільки клієнтам потрібно знати, коли ciphertext було розшифровано, щоб вони могли відкинути стан ratchet і ephemeral keys. Сервер пересилає непрозорі blobs, тому підтвердження від пристрою (подвійні позначки) надсилаються одержувачем після успішного розшифрування. Вимірювання часу round-trip (RTT) між дією, ініційованою атакером, і відповідною квитанцією про доставку відкриває високоточний timing channel, який leak’ає стан пристрою, online-присутність і може використовуватися для прихованого DoS. Розгортання з кількома пристроями та "client-fanout" посилюють leak, оскільки кожен зареєстрований пристрій розшифровує probe і повертає власну квитанцію.<sup>[[1]](#references)</sup>

## Джерела квитанцій про доставку та сигнали, видимі користувачу

Обирайте типи повідомлень, які завжди генерують квитанцію про доставку, але не створюють UI-артефактів на пристрої жертви. У таблиці нижче підсумовано емпірично підтверджену поведінку:<sup>[[1]](#references)</sup>

| Месенджер | Дія | Квитанція про доставку | Сповіщення жертви | Примітки |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Текстове повідомлення | ● | ● | Завжди помітне → корисне лише для початкової перевірки стану. |
| | Reaction | ● | ◐ (лише якщо reaction на повідомлення жертви) | Self-reactions і видалення залишаються непомітними. |
| | Редагування | ● | Залежить від платформи, silent push | Вікно редагування ≈20 хв; підтвердження все одно надсилається після його завершення. |
| | Видалення для всіх | ● | ○ | UI дозволяє приблизно 60 год, але пізніші packets все одно підтверджуються. |
| **Signal** | Текстове повідомлення | ● | ● | Ті самі обмеження, що й у WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions невидимі для жертви. |
| | Редагування/видалення | ● | ○ | Сервер застосовує вікно приблизно 48 год і дозволяє до 10 редагувань, але пізні packets все одно підтверджуються. |
| **Threema** | Текстове повідомлення | ● | ● | Квитанції з кількох пристроїв агрегуються, тому для кожного probe стає видимим лише один RTT. |

Позначення: ● = завжди, ◐ = умовно, ○ = ніколи. Поведінку UI, що залежить від платформи, зазначено в рядках. За потреби вимкніть read receipts, але delivery receipts неможливо вимкнути у WhatsApp або Signal.<sup>[[1]](#references)</sup>

## Цілі та моделі атакера

* **G1 – Fingerprinting пристроїв:** Підраховувати, скільки квитанцій надходить для кожного probe, кластеризувати RTT, щоб визначати OS/client (Android проти iOS проти desktop), і відстежувати переходи online/offline.
* **G2 – Behavioural monitoring:** Розглядати високочастотний ряд RTT (≈1 Hz є стабільним) як time-series і визначати, чи ввімкнено екран, чи перебуває застосунок на передньому або задньому плані, години поїздок і роботи тощо.
* **G3 – Resource exhaustion:** Підтримувати радіомодулі/CPU кожного пристрою жертви активними, надсилаючи безкінечні silent probes, розряджаючи батарею, витрачаючи data та погіршуючи якість відеодзвінків.<sup>[[1]](#references)</sup>

Для опису поверхні зловживання достатньо двох threat actors:<sup>[[1]](#references)</sup>

1. **Creepy companion:** уже має спільний чат із жертвою та зловживає self-reactions, видаленням reactions або повторними редагуваннями/видаленнями, прив'язаними до наявних ID повідомлень.
2. **Spooky stranger:** реєструє burner account і надсилає reactions із посиланнями на ID повідомлень, яких ніколи не існувало в локальній розмові; WhatsApp і Signal усе одно розшифровують і підтверджують їх, хоча UI відкидає зміну стану, тому попередня розмова не потрібна.

## Інструменти для доступу до raw protocol

Покладайтеся на клієнти, які відкривають достатній доступ до базового E2EE protocol, щоб створювати підтримувані packets поза обмеженнями UI та записувати точні timestamps; для довільних ID повідомлень потрібно перевіряти кожну реалізацію:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) документує надсилання й отримання delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (неофіційний Java/Kotlin Web і mobile API) документує операції з повідомленнями, зокрема reaction, редагування та видалення. Використовуйте їхні документовані API, а не припускайте, що кожен internal frame доступний.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) надає CLI, JSON-RPC і D-Bus interfaces, тоді як [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) є Java library для взаємодії із Signal.<sup>[[5]](#references)[[7]](#references)</sup> Поточний синтаксис `signal-cli` використовує `sendReaction RECIPIENT --target-author --target-timestamp`; залишайте `receive` або `daemon` запущеним, щоб protocol updates продовжували оброблятися.<sup>[[6]](#references)</sup> Приклад toggle self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Вимірювання в paper Careless Whisper показали, що delivery receipts синхронізуються між пристроями, тому навіть у multi-device setup для кожного повідомлення відкривається лише одна квитанція.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) постачається з WhatsApp/Signal backends, за замовчуванням використовує silent delete probes і позначає `active` проти `standby` за rolling-median threshold (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) — це легший WhatsApp-first CLI з `--delay`, `--concurrent`, CSV/Prometheus exporters і Grafana-friendly output.<sup>[[9]](#references)</sup> Розглядайте обидва як reconnaissance helpers, а не як protocol references; головний висновок полягає в тому, наскільки мало коду потрібно після отримання доступу до raw client.

Коли custom tooling недоступний, official clients або browser developer tools усе ще можуть запускати silent actions і відкривати timing зашифрованого traffic; raw APIs усувають затримки UI та дозволяють invalid operations.<sup>[[1]](#references)</sup>

## Creepy companion: цикл silent sampling

1. Виберіть будь-яке історичне повідомлення, яке ви написали в чаті, щоб жертва ніколи не бачила зміни reaction balloons.
2. Чергуйте видимий emoji та порожній reaction payload (кодується як `""` у WhatsApp protobufs або як `--remove` у signal-cli). Кожна передача генерує device ack, навіть якщо для жертви немає UI delta.
3. Фіксуйте час надсилання та надходження кожної delivery receipt. Цикл із частотою 1 Hz, як наведений нижче, безперервно створює RTT traces для кожного пристрою:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Оскільки WhatsApp/Signal приймають необмежену кількість оновлень reactions, атакеру не потрібно публікувати новий chat content або перейматися edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: probing довільних номерів телефонів

1. Зареєструйте новий WhatsApp/Signal account і отримайте public identity keys для цільового номера (це автоматично виконується під час session setup).
2. Створіть reaction packet, який посилається на випадковий `message_id`, невідомий обом сторонам; paper повідомляє, що WhatsApp і Signal приймають такі reactions і все одно генерують delivery receipts.<sup>[[1]](#references)</sup>
3. Надішліть packet, навіть якщо thread не існує. Пристрої жертви розшифровують його, не знаходять базове повідомлення, відкидають зміну стану, але все одно підтверджують вхідний ciphertext, надсилаючи device receipts назад атакеру.
4. Повторюйте це безперервно, щоб створити RTT series без попередньої розмови або видимого сповіщення.<sup>[[1]](#references)</sup>

Якщо спочатку потрібно визначити, які номери зареєстровані, або заздалегідь зібрати inventories пристроїв у масштабі, поєднайте це з [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), а не вгадуйте випадкові діапазони E.164 вручну.

Опубліковані дослідження contact-discovery показали операційну важливість цього підходу: використовуючи точні таблиці phone-prefix і помірні ресурси, дослідники змогли перевірити приблизно `10%` мобільних номерів США у WhatsApp і `100%` у Signal, перш ніж перейти до цільового probing.<sup>[[11]](#references)</sup> На практиці попередня фільтрація активних accounts дає змогу зосередити бюджет silent probes на номерах, які справді розшифрують packets.

Нові збірки WhatsApp також мають параметр `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Розглядайте його як throughput limiter: tracker documentation зазначає, що WhatsApp блокує high-volume messages від невідомих accounts, але не розкриває threshold, тому це не повністю запобігає probe reactions.<sup>[[8]](#references)</sup>

## Повторне використання edits і deletes як прихованих triggers

* **Repeated deletes:** Після того як повідомлення один раз видалено для всіх, подальші delete packets із тим самим `message_id` не впливають на UI, але кожен пристрій усе одно розшифровує та підтверджує їх.
* **Out-of-window operations:** WhatsApp застосовує у UI вікна приблизно 60 год для delete і 20 хв для edit; Signal застосовує 48 год. Створені protocol messages за межами цих вікон непомітно ігноруються на пристрої жертви, але receipts передаються, тому атакери можуть виконувати probing протягом необмеженого часу після завершення розмови.
* **Invalid payloads:** Paper повідомляє, що invalid messages усе одно можуть підтверджуватися; точна поведінка для malformed bodies або purged IDs залежить від реалізації, тому перед використанням це потрібно перевірити.<sup>[[1]](#references)</sup>

## Multi-device amplification і fingerprinting

* У WhatsApp і Signal кожен associated device (phone, desktop app, browser companion) незалежно розшифровує probe і повертає власний ack. Підрахунок receipts для кожного probe показує точну кількість пристроїв.<sup>[[1]](#references)</sup>
* Якщо пристрій offline, його receipt ставиться в queue і надсилається після reconnect. Тому прогалини leak’ають online/offline cycles і навіть commuting schedules (наприклад, receipts desktop-пристрою припиняються під час поїздки).
* RTT distributions відрізняються залежно від платформи й середовища, оскільки OS, model, client та network conditions впливають на timing. Кластеризуйте RTT (наприклад, k-means за ознаками median/variance), щоб позначати “Android handset”, “iOS handset”, “Electron desktop” тощо.
* Оскільки sender має отримати key inventory одержувача перед шифруванням, атакер також може відстежувати pairing нових пристроїв; раптове збільшення device count або поява нового RTT cluster є сильним індикатором.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing і stacked receipts

* **WhatsApp burst tolerance:** Опубліковані вимірювання показали, що WhatsApp приймав bursts silent reactions зі швидкістю до одного probe кожні `50 ms` без очевидного server-side queueing. Це корисно для коротких calibration bursts, швидкого підрахунку пристроїв або швидкого запуску drain attack.
* **Signal long-run queueing:** Signal витримував короткі bursts, але починав ставити в queue sustained traffic із кількома probes на секунду. Для довготривалого monitoring підтримуйте cadence близько `1 Hz` (або нижче), щоб кожна receipt усе ще відображала поточний стан пристрою, а не drain backlog.
* **Reconnect artefacts:** Коли пристрій повертається online, деякі clients batch’ать або швидко flush’ать кілька delayed receipts. Розглядайте такі bursts receipts як marker переходу стану, а не як незалежні RTT samples, інакше ваш clustering / `active` проти `idle` classifier буде overfit’ити reconnect noise.<sup>[[1]](#references)</sup>

## Виведення поведінки з RTT traces

1. Виконуйте sampling із частотою ≥1 Hz, щоб фіксувати ефекти OS scheduling. У WhatsApp на iOS RTT <1 с сильно корелює з увімкненим екраном/foreground, а RTT >1 с — із вимкненим екраном/background throttling.
2. Створюйте прості classifiers (thresholding або two-cluster k-means), які позначають кожен RTT як "active" або "idle". Об'єднуйте labels у streaks, щоб визначати час сну, поїздки, робочі години або активність desktop companion.
3. Correlate одночасні probes до кожного пристрою, щоб бачити, коли користувачі перемикаються з mobile на desktop, коли companions переходять offline і чи rate limited застосунок через push або persistent socket.
4. У реальних мережах уникайте одного hardcoded threshold `1 s`. Bootstrap кожного пристрою коротким warm-up window і підтримуйте rolling baseline (наприклад, PoC device-activity-tracker використовує `threshold = 0.9 * median RTT`), щоб Wi-Fi/cellular drift не зруйнував ваш classifier.<sup>[[1]](#references)[[8]](#references)</sup>

## Визначення локації за delivery RTT

Той самий timing primitive можна повторно використати для визначення місця перебування одержувача, а не лише його активності. Робота `Hope of Delivery` показала, що training на RTT distributions для відомих локацій одержувача дає атакеру змогу згодом класифікувати локацію жертви лише за delivery confirmations:<sup>[[2]](#references)</sup>

* Створіть baseline для тієї самої цілі, коли вона перебуває в кількох відомих місцях (дім, офіс, кампус, країна A проти країни B тощо).
* Для кожної локації зберіть багато normal message RTT і виділіть прості features, такі як median, variance або percentile buckets.
* Під час реальної атаки порівняйте нову probe series із навченими clusters. Paper повідомляє, що навіть локації в одному місті часто можна розрізнити з точністю `>80%` у сценарії з 3 локаціями.
* Це найкраще працює, коли атакер контролює sender environment і виконує probes за схожих network conditions, оскільки виміряний path включає access network одержувача, wake-up latency та messenger infrastructure.<sup>[[2]](#references)</sup>

На відміну від наведених вище атак із silent reaction/edit/delete, location inference не потребує invalid message IDs або stealthy state-changing packets. Достатньо звичайних повідомлень із normal delivery confirmations, тому компроміс полягає в меншій stealth, але ширшій застосовності в різних месенджерах.

## Stealthy resource exhaustion

Оскільки кожен silent probe потрібно розшифрувати й підтвердити, безперервне надсилання reaction toggles, invalid edits або delete-for-everyone packets створює application-layer DoS:<sup>[[1]](#references)</sup>

* Змушує radio/modem щосекунди передавати й отримувати дані → помітно розряджає батарею, особливо на idle handsets.
* Генерує upstream/downstream traffic, який витрачає mobile data plans і може конкурувати з latency-sensitive features, такими як відеодзвінки.<sup>[[1]](#references)</sup>
* Великі invalid payloads збільшують processing work, але paper повідомляє, що сама cryptography є незначною частиною battery cost.<sup>[[1]](#references)</sup>
* У WhatsApp invalid reactions приймають значно більше даних, ніж передбачає звичайний emoji: опубліковані вимірювання показали server-side acceptance до приблизно `1 MB` на reaction.
* Oversized reactions припиняють генерувати надійні delivery receipts, коли body перевищує приблизно `30 bytes`, але до відкидання все ще пересилаються та обробляються. Коли потрібні ACKs, тримайте reaction bodies малими; збільшуйте їх лише для pure drain або covert one-way transport.
* Public measurements досягли приблизно `3.7 MB/s` (`~13.3 GB/h`) traffic жертви в цьому режимі.

## References

- [1] [Careless Whisper: Експлуатація тихих квитанцій про доставку для моніторингу користувачів у мобільних месенджерах](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Визначення локацій користувачів за мобільними месенджерами](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [Довідкова сторінка signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Як блокувати великі обсяги невідомих повідомлень | Довідковий центр WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Усі номери — американські: масштабне зловживання contact discovery у мобільних месенджерах](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
