# Форензика резервних копій iOS (триаж, орієнтований на повідомлення)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка описує практичні кроки для відтворення та аналізу резервних копій iOS на предмет ознак доставки 0‑click експлойтів через вкладення в месенджерах. Зосереджено на перетворенні хешованої структури резервної копії Apple у людино‑читабельні шляхи, а також на переліченні та скануванні вкладень у поширених додатках.

Цілі:
- Відновити читабельні шляхи з Manifest.db
- Перерахувати бази даних повідомлень (iMessage, WhatsApp, Signal, Telegram, Viber)
- Розв’язати шляхи вкладень, витягти вбудовані об’єкти (PDF/Images/Fonts) та передати їх у структурні детектори


## Відновлення резервної копії iOS

Резервні копії, що зберігаються в MobileSync, використовують хешовані імена файлів, які не читаються людиною. База даних Manifest.db (SQLite) відображає кожен збережений об'єкт на його логічний шлях.

Загальна процедура:
1) Відкрити Manifest.db і прочитати записи файлів (domain, relativePath, flags, fileID/hash)
2) Відтворити оригінальну структуру папок на основі domain + relativePath
3) Скопіювати або створити hardlink для кожного збереженого об'єкта до його відновленого шляху

Приклад робочого процесу з інструментом, що реалізує це end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Примітки:
- Обробляйте зашифровані резервні копії, передаючи пароль резервної копії вашому екстрактору
- Зберігайте оригінальні часові відмітки/ACLs коли це можливо для доказової цінності


## Перерахування вкладень у додатках обміну повідомленнями

Після реконструкції перераховуйте вкладення для популярних додатків. Конкретна схема залежить від додатка/версії, але підхід схожий: запитуйте базу даних повідомлень, зв'язуйте повідомлення з вкладеннями й визначайте шляхи на диску.

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
Шляхи вкладень можуть бути абсолютними або відносними до відновленого дерева під Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Типове зв'язування: message table ↔ media/attachment table (іменування може відрізнятися залежно від версії). Запитуйте media rows, щоб отримати on‑disk paths.
```sql
SELECT
m.Z_PK          AS message_pk,
mi.ZMEDIALOCALPATH AS media_path,
m.ZMESSAGEDATE  AS message_date
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Adjust table/column names to your app version (ZWAMESSAGE/ZWAMEDIAITEM are common in iOS builds).

### Signal / Telegram / Viber
- Signal: база даних повідомлень (DB) зашифрована; проте вкладення, кешовані на диску (та мініатюри), зазвичай піддаються скануванню
- Telegram: перевіряйте каталоги кешу (photo/video/document caches) і по можливості зіставляйте їх з чатами
- Viber: Viber.sqlite містить таблиці message/attachment з посиланнями на диску

Tip: навіть коли метадані зашифровані, сканування каталогів медіа/кеш (media/cache directories) все ще виявляє шкідливі об'єкти.


## Scanning attachments for structural exploits

Once you have attachment paths, feed them into structural detectors that validate file‑format invariants instead of signatures. Example with ElegantBouncer:
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
- TrueType TRIANGULATION (CVE‑2023‑41990): незадокументовані опкоди bytecode
- DNG/TIFF CVE‑2025‑43300: невідповідності між metadata та компонентами потоку


## Валідація, застереження та помилкові спрацьовування

- Перетворення часу: iMessage зберігає дати в епохах/одиницях Apple у деяких версіях; перетворюйте відповідно під час звітування
- Schema drift: схеми SQLite додатку змінюються з часом; підтверджуйте імена таблиць/стовпців для конкретної збірки пристрою
- Recursive extraction: PDFs можуть містити вбудовані потоки JBIG2 та шрифти; витягуйте та скануйте внутрішні об'єкти
- False positives: структурні евристики є консервативними, але можуть позначати рідкісні пошкоджені, але нешкідливі медіафайли


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
