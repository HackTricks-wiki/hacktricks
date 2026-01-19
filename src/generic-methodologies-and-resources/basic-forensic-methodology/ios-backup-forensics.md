# Форензика резервних копій iOS (тріаж, орієнтований на месенджери)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка описує практичні кроки з відтворення та аналізу резервних копій iOS для виявлення ознак доставки експлойта 0‑click через вкладення в додатках для обміну повідомленнями. Вона фокусується на перетворенні хешованої структури резервної копії Apple в шляхи, зручні для читання, а також на переліку та скануванні вкладень у поширених додатках.

Цілі:
- Відтворити читабельні шляхи з Manifest.db
- Перелічити бази даних месенджерів (iMessage, WhatsApp, Signal, Telegram, Viber)
- Визначити шляхи вкладень, витягти вкладені об'єкти (PDF/зображення/шрифти) та передати їх у структурні детектори


## Відтворення резервної копії iOS

Резервні копії, що зберігаються у MobileSync, використовують хешовані імена файлів, які нечитабельні для людини. SQLite база даних Manifest.db зіставляє кожен збережений об’єкт з його логічним шляхом.

Загальна процедура:
1) Відкрити Manifest.db і прочитати записи файлів (domain, relativePath, flags, fileID/hash)
2) Відтворити оригінальну ієрархію папок на основі domain + relativePath
3) Скопіювати або створити hardlink для кожного збереженого об’єкта у його відтворений шлях

Приклад робочого процесу з інструментом, який реалізує це end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Примітки:
- Обробляйте зашифровані резервні копії, передаючи пароль резервної копії у ваш екстрактор
- За можливості зберігайте оригінальні часові мітки/ACLs для доказової цінності

### Acquiring & decrypting the backup (USB / Finder / libimobiledevice)

- На macOS/Finder встановіть "Encrypt local backup" і створіть *свіжу* зашифровану резервну копію, щоб елементи keychain були присутні.
- Крос‑платформено: `idevicebackup2` (libimobiledevice ≥1.4.0) розуміє зміни в протоколі резервного копіювання iOS 17/18 і виправляє попередні помилки рукостискання (handshake) під час відновлення/резервного копіювання.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Тріаж на основі IOC за допомогою MVT

Mobile Verification Toolkit (mvt-ios) від Amnesty тепер працює безпосередньо з зашифрованими резервними копіями iTunes/Finder, автоматизуючи розшифрування та зіставлення IOC у випадках mercenary spyware.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Виводи розміщуються в `mvt-results/` (наприклад, analytics_detected.json, safari_history_detected.json) і можуть бути зіставлені з шляхами вкладень, відновленими нижче.

### Загальний парсинг артефактів (iLEAPP)

Для хронології/метаданих поза межами повідомлень, запустіть iLEAPP безпосередньо на папці резервної копії (підтримує схеми iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Перерахування вкладень у месенджерах

Після реконструкції перераховуйте вкладення для популярних додатків. Точна схема залежить від програми/версії, але підхід подібний: виконати запит до бази даних повідомлень, з'єднати messages з attachments і визначити шляхи на диску.

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
Шляхи вкладень можуть бути абсолютними або відносними до реконструйованого дерева під Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Типове зв'язування: таблиця message ↔ таблиця media/attachment (іменування змінюється залежно від версії). Виконуйте запити до рядків media, щоб отримати шляхи на диску. У новіших збірках iOS все ще присутній `ZMEDIALOCALPATH` у `ZWAMEDIAITEM`.
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
Шляхи зазвичай розміщуються під `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` у відтвореній резервній копії.

### Signal / Telegram / Viber
- Signal: база повідомлень шифрована; однак вкладення, закешовані на диску (та мініатюри), зазвичай піддаються скануванню
- Telegram: кеш залишається під `Library/Caches/` всередині sandbox; iOS 18 збірки мають помилки очищення кешу, тому великі залишкові кеші медіа є поширеним джерелом доказів
- Viber: Viber.sqlite містить таблиці повідомлень/вкладень з посиланнями на диску

Порада: навіть коли метадані зашифровані, сканування директорій media/cache все одно виявляє шкідливі об'єкти.


## Scanning attachments for structural exploits

Коли у вас є шляхи до вкладень, передайте їх у структурні детектори, які перевіряють інваріанти формату файлу замість сигнатур. Приклад з ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Виявлення, покриті структурними правилами, включають:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): неможливі стани словника JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): надмірно великі конструкції таблиць Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): недокументовані опкоди байткоду
- DNG/TIFF CVE‑2025‑43300: невідповідності між метаданими та компонентами потоку


## Валідація, застереження та хибні позитиви

- Перетворення часу: iMessage у деяких версіях зберігає дати в Apple epochs/units; під час звітування перетворюйте їх відповідно
- Schema drift: схеми SQLite додатків змінюються з часом; підтверджуйте імена таблиць/стовпців для конкретної збірки пристрою
- Recursive extraction: PDF можуть містити вбудовані потоки JBIG2 та шрифти; витягайте та скануйте вкладені об'єкти
- False positives: структурні евристики є консервативними, але можуть помилково позначати рідкісні некоректні, але безпечні медіафайли


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
