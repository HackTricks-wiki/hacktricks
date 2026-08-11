# Форензика резервних копій iOS (тріаж із фокусом на повідомленнях)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка описує практичні кроки для реконструкції та аналізу резервних копій iOS на наявність ознак доставки 0-click exploit через вкладення в messaging apps. Вона зосереджена на перетворенні хешованої структури резервної копії Apple на зрозумілі шляхи, а потім на переліку та скануванні вкладень у поширених apps.

Цілі:
- Відновити зрозумілі шляхи з Manifest.db
- Перерахувати messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber)
- Визначити шляхи до вкладень, видобути вбудовані об’єкти, де це підтримується (PDF/Images/Fonts), і передати їх structural detectors


## Реконструкція резервної копії iOS

Резервні копії, що зберігаються в MobileSync, використовують хешовані імена файлів, які неможливо зрозуміти безпосередньо. SQLite database Manifest.db зіставляє кожен збережений об’єкт із його логічним шляхом.<sup>[[1]](#references)[[2]](#references)</sup>

Процедура високого рівня:
1) Відкрити Manifest.db і прочитати записи файлів (domain, relativePath, flags, fileID/hash)
2) Відтворити оригінальну ієрархію папок на основі domain + relativePath
3) Скопіювати або створити hardlink для кожного збереженого об’єкта до його реконструйованого шляху

Приклад workflow за допомогою tool, який реалізує цей процес end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Нотатки:
- Розшифровуйте зашифровані backup перед передаванням їх інструменту реконструкції; ElegantBouncer очікує розшифрований backup.<sup>[[2]](#references)[[3]](#references)</sup>
- За можливості зберігайте оригінальні часові мітки/ACL для доказової цінності

### Отримання та розшифрування backup (USB / Finder / libimobiledevice)

- У Finder/Apple Devices/iTunes увімкніть «Encrypt local backup» і створіть новий backup; зашифровані backup можуть містити збережені паролі та дані Health, які відсутні в незашифрованих backup.<sup>[[8]](#references)</sup>
- Кросплатформний варіант: libimobiledevice 1.4.0 містить виправлення для `idevicebackup2`.<sup>[[4]](#references)</sup> Інтерактивно ввімкніть шифрування, а потім примусово створіть повний backup, дотримуючись задокументованого порядку команд, причому цільовий каталог має бути вказаний останнім.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Тріаж на основі IOC за допомогою MVT

Mobile Verification Toolkit від Amnesty може отримати ключ із зашифрованих резервних копій iTunes/Finder і розшифрувати їх, а потім просканувати розшифровану резервну копію за допомогою IOC-файлу STIX2.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
За допомогою `-o` результати у форматі JSON записуються до `/tmp/mvt-results/`; збіги IOC мають суфікс `_detected` і можуть бути співвіднесені зі шляхами до вкладень, відновленими нижче.<sup>[[3]](#references)</sup>

### Загальний аналіз артефактів (iLEAPP)

Для отримання даних часової шкали/метаданих за межами messaging запустіть iLEAPP для raw backup folder; його тип вхідних даних `itunes` підтримує резервні копії iTunes/Finder, а поточні релізи підтримують iOS/iPadOS 11 і новіші версії.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Перелік вкладень у messaging apps

Після реконструкції перелікуйте вкладення для популярних apps. Точна схема залежить від app/версії, але підхід подібний: виконайте запит до messaging database, об’єднайте messages із attachments і визначте paths на диску.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Ключові таблиці: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

Приклади запитів:
```sql
-- List attachments with basic message linkage
SELECT
m.ROWID            AS message_rowid,
a.ROWID            AS attachment_rowid,
a.filename         AS attachment_path,
m.handle_id,
m.date,
m.is_from_me
FROM message m
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;

-- Include chat names via chat_message_join
SELECT
c.display_name,
a.filename AS attachment_path,
m.date
FROM chat c
JOIN chat_message_join cmj ON cmj.chat_id = c.ROWID
JOIN message m ON m.ROWID = cmj.message_id
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;
```
Шляхи до вкладень можуть бути абсолютними або відносними до відновленого дерева в Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Типовий зв’язок: таблиця повідомлень ↔ таблиця медіа/вкладень (назви різняться залежно від версії). Запитайте рядки медіа, щоб отримати шляхи на диску. Belkasoft визначає `ZMEDIALOCALPATH` у `ZWAMEDIAITEM` як розташування медіафайлу; поточна реалізація ElegantBouncer об’єднує `ZWAMEDIAITEM.ZMESSAGE` з `ZWAMESSAGE.Z_PK` і додає префікс `Message/` під час визначення шляху, що починається з `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMEDIAITEM mi
JOIN ZWAMESSAGE m ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Для цього шляху реконструкції ElegantBouncer шлях до медіафайлу, що починається з `Media/`, розгортається в `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; натомість у посібнику Belkasoft описано шлях `Messages/Media/`, тому перевірте backup, перш ніж припускати будь-який із цих варіантів написання.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: база даних повідомлень зашифрована; однак вкладення, кешовані на диску (і мініатюри), зазвичай можна сканувати.<sup>[[2]](#references)</sup>
- Telegram: перевірте каталоги медіафайлів/кешу застосунку; Telegram задокументував bug очищення кешу в iOS app 11.2 на iOS 18.0.1, який позначено як виправлений у 11.3, тому перевірте наявність залишкових файлів.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite містить таблиці повідомлень/вкладень із посиланнями на файли на диску.<sup>[[2]](#references)</sup>

Порада: навіть коли metadata зашифровані, сканування каталогів медіафайлів/кешу все одно виявляє malicious objects.<sup>[[2]](#references)</sup>


## Сканування вкладень на наявність structural exploits

Отримавши шляхи до вкладень, передайте їх у structural detectors, які перевіряють інваріанти file format замість сигнатур. Приклад із ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Виявлення, охоплені structural rules, включають:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): неможливі стани словника JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): конструкції таблиць Huffman із надмірним розміром
- TrueType TRIANGULATION (CVE‑2023‑41990): недокументовані bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: невідповідності між metadata та компонентами stream


## Validation, caveats, and false positives

- Перетворення часу: iMessage у деяких версіях зберігає дати в Apple epochs/units; під час звітування виконуйте відповідне перетворення.<sup>[[2]](#references)</sup>
- Schema drift: SQLite-схеми застосунків з часом змінюються; перевіряйте назви таблиць і стовпців для кожної збірки пристрою
- Рекурсивне вилучення: PDF-файли можуть містити вбудовані JBIG2 streams і fonts; використовуйте parser, який може вилучати та сканувати внутрішні об’єкти
- Хибні спрацювання: structural heuristics є консервативними, але можуть позначати рідкісні пошкоджені, проте безпечні media.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Коли ви не можете отримати зразки, але все одно маєте виявити загрозу](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Проєкт ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Робочий процес MVT iOS backup](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Примітки до випуску libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 порушує очищення cache в iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [Посібник idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Проєкт iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Про зашифровані backups на iPhone, iPad або iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics за допомогою Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [Сканер WhatsApp ElegantBouncer і path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
