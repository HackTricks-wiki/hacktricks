# Side-Channel атаки через підтвердження доставки в E2EE-месенджерах

Підтвердження доставки є обов'язковими в сучасних месенджерах із наскрізним шифруванням (E2EE), оскільки клієнтам потрібно знати, коли ciphertext було розшифровано, щоб вони могли відкинути стан ratchet і ephemeral keys. Сервер пересилає непрозорі blobs, тому підтвердження від пристрою (подвійні позначки) надсилаються отримувачем після успішного розшифрування. Вимірювання round-trip time (RTT) між дією, ініційованою атакувальником, і відповідним підтвердженням доставки відкриває високоточний timing channel, який leak’ить стан пристрою та присутність користувача онлайн і може використовуватися для прихованого DoS. У розгортаннях із кількома пристроями та "client-fanout" leakage посилюється, оскільки кожен зареєстрований пристрій розшифровує probe і повертає власне підтвердження.<sup>[[1]](#references)</sup>

## Джерела підтверджень доставки та сигнали, видимі користувачу

Обирайте типи повідомлень, які завжди генерують підтвердження доставки, але не створюють UI-артефактів на пристрої жертви. У таблиці нижче підсумовано емпірично підтверджену поведінку:<sup>[[1]](#references)</sup>

| Месенджер | Дія | Підтвердження доставки | Сповіщення жертви | Примітки |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Текстове повідомлення | ● | ● | Завжди помітне → корисне лише для початкового визначення стану. |
| | Реакція | ● | ◐ (лише під час реакції на повідомлення жертви) | Власні реакції та їх видалення залишаються непомітними. |
| | Редагування | ● | Залежний від платформи silent push | Вікно редагування ≈20 хв; після завершення терміну підтвердження все одно надсилається. |
| | Видалення для всіх | ● | ○ | UI дозволяє приблизно 60 год, але пізніші пакети все одно підтверджуються. |
| **Signal** | Текстове повідомлення | ● | ● | Ті самі обмеження, що й у WhatsApp. |
| | Реакція | ● | ◐ | Власні реакції невидимі для жертви. |
| | Редагування/видалення | ● | ○ | Сервер застосовує вікно приблизно 48 год і дозволяє до 10 редагувань, але пізні пакети все одно підтверджуються. |
| **Threema** | Текстове повідомлення | ● | ● | Підтвердження від кількох пристроїв агрегуються, тому для кожного probe стає видимим лише один RTT. |

Позначення: ● = завжди, ◐ = умовно, ○ = ніколи. Поведінку UI, що залежить від платформи, зазначено в примітках. За потреби вимкніть підтвердження прочитання, але підтвердження доставки неможливо вимкнути у WhatsApp або Signal.<sup>[[1]](#references)</sup>

## Цілі та моделі атакувальника

* **G1 – Fingerprinting пристроїв:** підраховувати кількість підтверджень, що надходять для кожного probe, групувати RTT, щоб визначати ОС/клієнт (Android, iOS чи desktop), і відстежувати переходи між online/offline.
* **G2 – Моніторинг поведінки:** розглядати високочастотний ряд RTT (≈1 Hz є стабільним) як time-series і визначати, чи ввімкнено екран, чи перебуває застосунок на передньому або задньому плані, години поїздок і роботи тощо.
* **G3 – Виснаження ресурсів:** підтримувати радіомодулі/CPU кожного пристрою жертви в активному стані, надсилаючи нескінченні silent probes, розряджаючи батарею, витрачаючи data та погіршуючи якість відеодзвінків.<sup>[[1]](#references)</sup>

Для опису поверхні зловживань достатньо двох threat actors:<sup>[[1]](#references)</sup>

1. **Creepy companion:** уже має спільний чат із жертвою та зловживає власними реакціями, видаленням реакцій або повторними редагуваннями/видаленнями, пов'язаними з наявними ID повідомлень.
2. **Spooky stranger:** реєструє burner account і надсилає реакції з посиланнями на ID повідомлень, яких ніколи не існувало в локальній розмові; WhatsApp і Signal усе одно розшифровують їх і підтверджують, хоча UI відкидає зміну стану, тому попередня розмова не потрібна.

## Інструменти для доступу до raw protocol

Використовуйте клієнти, які відкривають достатній доступ до базового E2EE-протоколу для створення підтримуваних пакетів поза обмеженнями UI та журналювання точних timestamp; довільні ID повідомлень потрібно перевіряти в кожній реалізації:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) документує надсилання й отримання підтверджень доставки; [Cobalt](https://github.com/Auties00/Cobalt) (неофіційний Java/Kotlin Web і mobile API) документує операції з повідомленнями, зокрема реакції, редагування та видалення. Використовуйте їхні документовані API, а не припускайте, що доступний кожен внутрішній frame.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) надає CLI, JSON-RPC і D-Bus interfaces, а [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) є Java-бібліотекою для взаємодії із Signal.<sup>[[5]](#references)[[7]](#references)</sup> Поточний синтаксис `signal-cli` використовує `sendReaction RECIPIENT --target-author --target-timestamp`; залишайте `receive` або `daemon` запущеним, щоб protocol updates продовжували оброблятися.<sup>[[6]](#references)</sup> Приклад перемикання власної реакції:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Вимірювання в paper Careless Whisper показали, що підтвердження доставки синхронізуються між пристроями, тому навіть у multi-device setup для кожного повідомлення відкривається лише одне підтвердження.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) містить WhatsApp/Signal backends, за замовчуванням використовує silent delete probes і позначає стани `active` та `standby` за rolling-median threshold (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) — легший CLI, орієнтований на WhatsApp, із `--delay`, `--concurrent`, CSV/Prometheus exporters і виводом, зручним для Grafana.<sup>[[9]](#references)</sup> Розглядайте обидва інструменти як допоміжні засоби розвідки, а не як protocol references; головний висновок полягає в тому, наскільки мало коду потрібно після отримання доступу до raw client.

Якщо custom tooling недоступний, офіційні клієнти або browser developer tools усе ще можуть запускати silent actions і відкривати timing зашифрованого traffic; raw APIs усувають затримки UI та дозволяють некоректні операції.<sup>[[1]](#references)</sup>

## Creepy companion: цикл прихованого семплювання

1. Виберіть будь-яке історичне повідомлення, автором якого ви є в цьому чаті, щоб жертва ніколи не бачила зміни "reaction" balloons.
2. Чергуйте видимий emoji та порожній reaction payload (кодується як `""` у WhatsApp protobufs або як `--remove` у signal-cli). Кожна передача генерує device ack, попри відсутність UI delta для жертви.
3. Фіксуйте час надсилання та надходження кожного підтвердження доставки. Цикл із частотою 1 Hz, наприклад наведений нижче, безстроково створює RTT traces для кожного пристрою:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Оскільки WhatsApp/Signal приймають необмежену кількість оновлень реакцій, атакувальнику ніколи не потрібно публікувати новий вміст чату або турбуватися про edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: перевірка довільних номерів телефонів

1. Зареєструйте новий WhatsApp/Signal account і отримайте публічні identity keys цільового номера (це автоматично виконується під час session setup).
2. Створіть reaction packet, який посилається на випадковий `message_id`, невідомий обом сторонам; у paper зазначено, що WhatsApp і Signal приймають такі реакції та все одно генерують підтвердження доставки.<sup>[[1]](#references)</sup>
3. Надішліть packet, навіть якщо thread не існує. Пристрої жертви розшифрують його, не знайдуть базове повідомлення, відкинуть зміну стану, але все одно підтвердять вхідний ciphertext, надіславши device receipts атакувальнику.
4. Повторюйте це безперервно, щоб створити RTT series без попередньої розмови або видимого сповіщення.<sup>[[1]](#references)</sup>

Якщо спочатку потрібно визначити, які номери зареєстровані, або заздалегідь отримати inventory пристроїв у масштабі, поєднайте це з [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), а не перебирайте випадкові діапазони E.164 вручну.

Опубліковані роботи про contact-discovery показали практичне значення цього підходу: використовуючи точні таблиці телефонних префіксів і помірні ресурси, дослідники змогли перевірити приблизно `10%` номерів мобільних телефонів США у WhatsApp і `100%` у Signal, перш ніж перейти до targeted probing.<sup>[[11]](#references)</sup> На практиці попередня фільтрація активних accounts дає змогу зосередити бюджет silent probes на номерах, які справді розшифрують packets.

Нові збірки WhatsApp також містять `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Розглядайте це як обмежувач throughput: документація tracker зазначає, що WhatsApp блокує велику кількість повідомлень від невідомих accounts, але не розкриває threshold, тому це не повністю запобігає probe reactions.<sup>[[8]](#references)</sup>

## Повторне використання редагувань і видалень як прихованих triggers

* **Repeated deletes:** Після одноразового видалення повідомлення для всіх подальші delete packets із тим самим `message_id` не впливають на UI, але кожен пристрій усе одно розшифровує та підтверджує їх.
* **Out-of-window operations:** WhatsApp застосовує у UI вікна приблизно 60 год для видалення та 20 хв для редагування; Signal застосовує вікно приблизно 48 год. Створені protocol messages за межами цих вікон непомітно ігноруються на пристрої жертви, однак receipts передаються, тому атакувальники можуть проводити probing необмежено довго після завершення розмови.
* **Invalid payloads:** У paper зазначено, що некоректні повідомлення все одно можуть підтверджуватися; точна поведінка для malformed bodies або purged IDs залежить від реалізації, тому перед використанням це потрібно перевірити.<sup>[[1]](#references)</sup>

## Multi-device amplification і fingerprinting

* У WhatsApp і Signal кожен пов'язаний пристрій (телефон, desktop app, browser companion) незалежно розшифровує probe і повертає власний ack. Підрахунок receipts для кожного probe розкриває точну кількість пристроїв.<sup>[[1]](#references)</sup>
* Якщо пристрій offline, його receipt ставиться в чергу та надсилається після повторного підключення. Тому проміжки leak’ять цикли online/offline і навіть розклад поїздок (наприклад, receipts із desktop припиняються під час подорожі).
* RTT distributions відрізняються залежно від платформи та середовища, оскільки ОС, модель, клієнт і мережеві умови впливають на timing. Групуйте RTT (наприклад, застосовуючи k-means до ознак median/variance), щоб позначати “Android handset", “iOS handset", “Electron desktop" тощо.
* Оскільки перед шифруванням відправник має отримати key inventory отримувача, атакувальник також може відстежувати підключення нових пристроїв; раптове збільшення кількості пристроїв або поява нового RTT cluster є сильним індикатором.<sup>[[1]](#references)</sup>

## Частота семплювання, черги та stacked receipts

* **WhatsApp burst tolerance:** Опубліковані вимірювання показали, що WhatsApp приймав burst-и silent reactions зі швидкістю до одного probe кожні `50 ms` без очевидної server-side queueing. Це корисно для коротких calibration bursts, швидкого підрахунку пристроїв або швидкого нарощування drain attack.
* **Signal long-run queueing:** Signal витримував короткі bursts, але починав ставити в чергу тривалий traffic із кількома probe за секунду. Для довготривалого моніторингу підтримуйте частоту близько `1 Hz` (або нижче), щоб кожне підтвердження все ще відображало поточний стан пристрою, а не drain backlog.
* **Reconnect artefacts:** Коли пристрій повертається online, деякі клієнти пакетують або швидко flush-ать кілька відкладених receipts. Розглядайте такі burst-и підтверджень як маркер переходу стану, а не як незалежні RTT samples, інакше ваш classifier для clustering / `active` vs `idle` overfit-итиме reconnect noise.<sup>[[1]](#references)</sup>

## Визначення поведінки за RTT traces

1. Семплюйте з частотою ≥1 Hz, щоб фіксувати ефекти scheduling ОС. У WhatsApp на iOS RTT <1 с сильно корелює з увімкненим екраном/foreground, а RTT >1 с — із вимкненим екраном/background throttling.
2. Створюйте прості classifiers (thresholding або two-cluster k-means), які позначають кожен RTT як "active" або "idle". Об'єднуйте позначки в streaks, щоб визначати час сну, поїздки, робочі години або активність desktop companion.
3. Корелюйте одночасні probes до всіх пристроїв, щоб визначати, коли користувачі перемикаються з mobile на desktop, коли companions переходять offline і чи обмежує застосунок rate push або persistent socket.
4. У реальних мережах уникайте одного hardcoded threshold `1 s`. Ініціалізуйте кожен пристрій коротким warm-up window і підтримуйте rolling baseline (наприклад, PoC device-activity-tracker використовує `threshold = 0.9 * median RTT`), щоб зміни Wi-Fi/cellular не зруйнували ваш classifier.<sup>[[1]](#references)[[8]](#references)</sup>

## Визначення місцезнаходження за RTT доставки

Той самий timing primitive можна повторно використати для визначення місця перебування отримувача, а не лише його активності. Робота `Hope of Delivery` показала, що навчання на RTT distributions для відомих місць отримувача дає атакувальнику змогу згодом класифікувати місцезнаходження жертви лише за delivery confirmations:<sup>[[2]](#references)</sup>

* Створіть baseline для тієї самої цілі, поки вона перебуває в кількох відомих місцях (вдома, в офісі, на campus, у країні A та країні B тощо).
* Для кожного місця зберіть багато звичайних message RTT і виділіть прості features, наприклад median, variance або percentile buckets.
* Під час реальної атаки порівнюйте нову probe series із навченими clusters. У paper зазначено, що навіть місця в одному місті часто можна розрізнити, з точністю `>80%` у сценарії з 3 локаціями.
* Найкращі результати досягаються, коли атакувальник контролює середовище відправника та виконує probes за подібних мережевих умов, оскільки вимірюваний шлях охоплює access network отримувача, wake-up latency та messenger infrastructure.<sup>[[2]](#references)</sup>

На відміну від наведених вище атак із silent reaction/edit/delete, для location inference не потрібні invalid message IDs або stealthy state-changing packets. Достатньо звичайних повідомлень із нормальними delivery confirmations, тому компромісом є нижча stealth, але ширша застосовність у різних месенджерах.

## Приховане виснаження ресурсів

Оскільки кожен silent probe потрібно розшифрувати та підтвердити, безперервне надсилання перемикань реакцій, некоректних редагувань або пакетів delete-for-everyone створює application-layer DoS:<sup>[[1]](#references)</sup>

* Змушує radio/modem передавати й отримувати дані щосекунди → помітно розряджає батарею, особливо на idle handsets.
* Генерує upstream/downstream traffic, який витрачає mobile data plans і може конкурувати з функціями, чутливими до latency, наприклад відеодзвінками.<sup>[[1]](#references)</sup>
* Великі invalid payloads збільшують обсяг обробки, але paper повідомляє, що сама cryptography становить незначну частину витрат батареї.<sup>[[1]](#references)</sup>
* У WhatsApp invalid reactions приймають набагато більше даних, ніж можна припустити за звичайним emoji: опубліковані вимірювання виявили server-side acceptance до приблизно `1 MB` на reaction.
* Oversized reactions перестають генерувати надійні delivery receipts, коли body перевищує приблизно `30 bytes`, але все одно пересилаються та обробляються до відкидання. Якщо потрібні ACKs, робіть reaction bodies малими; збільшуйте їх лише коли метою є чисте виснаження або прихований one-way transport.
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
- [10] [Як заблокувати велику кількість повідомлень від невідомих контактів | Довідковий центр WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Усі номери — американські: масштабне зловживання Contact Discovery у мобільних месенджерах](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
