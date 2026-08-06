# Forensics резервних копій iOS (triage, орієнтований на messaging)

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці описано практичні кроки для відновлення та аналізу резервних копій iOS на наявність ознак доставки 0-click exploit через вкладення в messaging apps. Основна увага приділяється перетворенню хешованої структури резервної копії Apple на зрозумілі для людини шляхи, а потім переліченню та скануванню вкладень у поширених apps.

Цілі:
- Відновити зрозумілі шляхи з Manifest.db
- Перелічити messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber)
- Визначити шляхи до вкладень, видобути вбудовані об’єкти (PDF/Images/Fonts) і передати їх structural detectors


## Відновлення резервної копії iOS

Резервні копії, що зберігаються в MobileSync, використовують хешовані імена файлів, які неможливо прочитати безпосередньо. SQLite database Manifest.db зіставляє кожен збережений об’єкт із його логічним шляхом.

Процедура високого рівня:
1) Відкрити Manifest.db і прочитати записи файлів (domain, relativePath, flags, fileID/hash)
2) Відтворити початкову ієрархію папок на основі domain + relativePath
3) Скопіювати або створити hardlink для кожного збереженого об’єкта за його відновленим шляхом

Приклад workflow за допомогою tool, який реалізує цей процес end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Нотатки:
- Обробляйте зашифровані резервні копії, передаючи пароль резервної копії своєму extractor
- За можливості зберігайте оригінальні часові мітки/ACL для доказової цінності

### Отримання та розшифрування резервної копії (USB / Finder / libimobiledevice)

- У macOS/Finder увімкніть "Encrypt local backup" і створіть *свіжу* зашифровану резервну копію, щоб у ній були присутні елементи keychain.
- Кросплатформно: `idevicebackup2` (libimobiledevice ≥1.4.0) підтримує зміни протоколу резервного копіювання iOS 17/18 і виправляє помилки узгодження під час попередніх операцій відновлення/резервного копіювання.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Тріаж на основі IOC за допомогою MVT

Mobile Verification Toolkit від Amnesty (mvt-ios) тепер безпосередньо працює із зашифрованими резервними копіями iTunes/Finder, автоматизуючи розшифрування та зіставлення IOC у випадках використання mercenary spyware.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Результати зберігаються в `mvt-results/` (наприклад, `analytics_detected.json`, `safari_history_detected.json`), і їх можна зіставити зі шляхами до вкладень, відновленими нижче.

### Загальний аналіз артефактів (iLEAPP)

Для отримання даних часової шкали/метаданих поза межами messaging запустіть iLEAPP безпосередньо для папки резервної копії (підтримує схеми iOS 11–17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Перелік вкладень у messaging apps

Після реконструкції виконайте перелік вкладень для популярних apps. Точна schema залежить від app/version, але підхід подібний: виконайте запит до messaging database, об'єднайте messages із attachments і визначте paths на диску.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Ключові таблиці: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
Шляхи до вкладень можуть бути абсолютними або відносними до реконструйованого дерева в Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Типовий зв’язок: таблиця повідомлень ↔ таблиця медіа/вкладень (назви відрізняються залежно від версії). Виконайте запит до рядків медіа, щоб отримати шляхи на диску. У новіших збірках iOS усе ще доступне `ZMEDIALOCALPATH` у `ZWAMEDIAITEM`.
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.Z_PK = m.ZMEDIAITEM
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Шляхи зазвичай ведуть до `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` всередині реконструйованої backup.

### Signal / Telegram / Viber
- Signal: message DB зашифрована; однак attachments, кешовані на диску (та thumbnails), зазвичай можна сканувати
- Telegram: cache залишається в `Library/Caches/` усередині sandbox; збірки iOS 18 мають bugs очищення cache, тому великі залишкові media caches часто є джерелами evidence<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite містить message/attachment tables із посиланнями на диску

Порада: навіть коли metadata зашифрована, сканування media/cache directories усе ще виявляє malicious objects.


## Сканування attachments на наявність structural exploits

Отримавши attachment paths, передайте їх у structural detectors, які перевіряють file-format invariants замість signatures. Приклад із ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Виявлення, охоплені structural rules, включають:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): неможливі стани словника JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): надмірні конструкції таблиць Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): недокументовані опкоди bytecode
- DNG/TIFF CVE‑2025‑43300: невідповідності між metadata та компонентами stream


## Валідація, застереження та false positives

- Конвертація часу: iMessage у деяких версіях зберігає дати в епохах/одиницях Apple; під час звітування виконуйте відповідне перетворення
- Schema drift: SQLite-схеми застосунків із часом змінюються; перевіряйте назви таблиць/стовпців відповідно до build пристрою
- Рекурсивне вилучення: PDF-файли можуть містити вкладені JBIG2 streams і fonts; вилучайте та скануйте внутрішні об’єкти
- False positives: structural heuristics є консервативними, але можуть виявляти рідкісні пошкоджені, проте безпечні media<sup>[[1]](#references)[[2]](#references)</sup>


## Посилання

- [1] [ELEGANTBOUNCER: Коли ви не можете отримати samples, але все одно повинні виявити threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Проєкт ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Workflow резервного копіювання iOS у MVT](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Примітки до release libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 має зламане очищення cache в iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
