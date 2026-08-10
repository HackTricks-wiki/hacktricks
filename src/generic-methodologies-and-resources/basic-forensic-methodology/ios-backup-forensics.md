# Форензика iOS Backup (тріаж із фокусом на повідомленнях)

На цій сторінці описано практичні кроки для відновлення та аналізу iOS backup на ознаки доставки експлойтів 0-click через вкладення в messaging app. Основна увага приділяється перетворенню хешованої структури backup Apple на зрозумілі людині шляхи, а потім переліченню та скануванню вкладень у поширених застосунках.

Цілі:
- Відновити читабельні шляхи з Manifest.db
- Перелічити messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber)
- Визначити шляхи до вкладень, витягнути вбудовані об'єкти, де це підтримується (PDF/Images/Fonts), і передати їх структурним детекторам


## Відновлення iOS backup

Backup, що зберігаються в MobileSync, використовують хешовані імена файлів, які неможливо прочитати безпосередньо. SQLite database Manifest.db зіставляє кожен збережений об'єкт із його логічним шляхом.<sup>[[1]](#references)[[2]](#references)</sup>

Процедура високого рівня:
1) Відкрити Manifest.db і прочитати записи файлів (domain, relativePath, flags, fileID/hash)
2) Відновити початкову ієрархію папок на основі domain + relativePath
3) Скопіювати або створити hardlink для кожного збереженого об'єкта за його відновленим шляхом

Приклад workflow із використанням tool, який реалізує цей процес end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Примітки:
- Розшифровуйте зашифровані резервні копії перед передаванням їх інструменту реконструкції; ElegantBouncer очікує розшифровану резервну копію.<sup>[[2]](#references)[[3]](#references)</sup>
- За можливості зберігайте оригінальні часові мітки/ACL для доказової цінності

### Отримання та розшифрування резервної копії (USB / Finder / libimobiledevice)

- У Finder/Apple Devices/iTunes увімкніть "Encrypt local backup" і створіть нову резервну копію; зашифровані резервні копії можуть містити збережені паролі та дані Health, які незашифровані резервні копії не містять.<sup>[[8]](#references)</sup>
- Кросплатформно: libimobiledevice 1.4.0 містить виправлення для `idevicebackup2`.<sup>[[4]](#references)</sup> Увімкніть шифрування в інтерактивному режимі, потім примусово створіть повну резервну копію, дотримуючись задокументованого порядку команд, а цільовий каталог вкажіть останнім.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Тріаж на основі IOC за допомогою MVT

Mobile Verification Toolkit від Amnesty може отримати ключ із зашифрованих резервних копій iTunes/Finder і розшифрувати їх, а потім просканувати розшифровану резервну копію за допомогою файлу IOC у форматі STIX2.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
За допомогою `-o` результати у форматі JSON записуються в `/tmp/mvt-results/`; збіги IOC використовують суфікс `_detected`, і їх можна зіставити зі шляхами до вкладень, відновленими нижче.<sup>[[3]](#references)</sup>

### Загальний аналіз артефактів (iLEAPP)

Для отримання часової шкали/метаданих, що виходять за межі messaging, запустіть iLEAPP щодо папки з необробленою backup-копією; його тип вхідних даних `itunes` підтримує backup-копії iTunes/Finder, а поточні релізи підтримують iOS/iPadOS 11 і новіші версії.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Перелік вкладень у messaging apps

Після реконструкції перелічіть вкладення для популярних apps. Точна схема залежить від app/version, але підхід подібний: виконайте запит до messaging database, об’єднайте messages із attachments і визначте шляхи на диску.<sup>[[1]](#references)[[2]](#references)</sup>

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
Шляхи до вкладень можуть бути абсолютними або відносними до реконструйованого дерева в Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Типовий зв’язок: таблиця повідомлень ↔ таблиця медіа/вкладень (назви залежать від версії). Виконайте запит до рядків медіа, щоб отримати шляхи на диску. Belkasoft визначає `ZMEDIALOCALPATH` у `ZWAMEDIAITEM` як розташування медіафайлу; поточна реалізація ElegantBouncer об’єднує `ZWAMEDIAITEM.ZMESSAGE` із `ZWAMESSAGE.Z_PK` і додає префікс `Message/` під час визначення шляху, що починається з `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
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
Для шляху реконструкції ElegantBouncer медіашлях, що починається з `Media/`, розгортається в `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; натомість у посібнику Belkasoft описано шлях `Messages/Media/`, тому перевірте backup, перш ніж припускати будь-який із варіантів написання.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: message DB зашифрована; однак attachments, кешовані на диску (і thumbnails), зазвичай можна сканувати.<sup>[[2]](#references)</sup>
- Telegram: перевірте media/cache directories застосунку; Telegram документував bug очищення кешу в iOS app 11.2 на iOS 18.0.1, який було позначено як виправлений у 11.3, тому перевірте залишкові files.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite містить таблиці повідомлень/attachments із references на диску.<sup>[[2]](#references)</sup>

Порада: навіть коли metadata зашифровані, сканування media/cache directories усе одно виявляє malicious objects.<sup>[[2]](#references)</sup>


## Сканування attachments на наявність structural exploits

Отримавши attachment paths, передайте їх у structural detectors, які перевіряють інваріанти file-format замість signatures. Приклад із ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Виявлення, охоплені structural rules, включають:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): неможливі стани словника JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): надмірно великі конструкції таблиць Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): недокументовані bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: невідповідності між metadata та компонентами stream


## Перевірка, застереження та false positives

- Конвертація часу: у деяких версіях iMessage зберігає дати в Apple epochs/units; під час звітування виконуйте належне перетворення.<sup>[[2]](#references)</sup>
- Schema drift: схеми SQLite застосунків з часом змінюються; перевіряйте назви таблиць і стовпців для кожної збірки пристрою
- Рекурсивне extraction: PDF-файли можуть містити вкладені JBIG2 streams і fonts; використовуйте parser, який може витягувати та сканувати внутрішні об’єкти
- False positives: structural heuristics є консервативними, але можуть виявляти рідкісні пошкоджені, проте benign media.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Коли ви не можете отримати зразки, але все одно повинні виявити загрозу](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Проєкт ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Workflow резервного копіювання MVT iOS](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Примітки до випуску libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Оновлення 11.2 порушило очищення cache в iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [Посібник idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Проєкт iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Про зашифровані backup на iPhone, iPad або iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Forensics WhatsApp на iOS за допомогою Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [WhatsApp scanner і path resolver ElegantBouncer](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
