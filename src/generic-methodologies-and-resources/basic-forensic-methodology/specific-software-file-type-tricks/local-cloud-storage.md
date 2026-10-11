# Локальне хмарне сховище

{{#include ../../../banners/hacktricks-training.md}}

## Емулятори локального сховища та ключі облікових записів

Емулятор Blob, сумісний з Azure і запущений у контейнері, може бути доступний із хоста або через мостову мережу, навіть якщо служба сховища не відкрита для зовнішнього доступу. Перевірте читабельні локальні файли конфігурації та метадані файлів резервних копій на наявність імені облікового запису й ключа, не виводячи ключ під час звичайного переліку даних. [Azurite підтримує власні локальні ключі облікових записів](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [авторизація за Shared Key](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) може надати широкий доступ до даних відповідного облікового запису. Сам факт наявності файла з ключем не підтверджує можливість підвищення привілеїв: перевірте, чи доступна кінцева точка, чи приймаються обліковий запис і ключ та чи містить конкретний blob придатні облікові дані для ідентичності з вищими привілеями. Якщо він містить приватний SSH-ключ, відповідний відкритий ключ також має бути авторизований для цієї ідентичності, а доступ через SSH — дозволений. Захистіть і замініть ключ, щойно підтвердите його витік.

## OneDrive

У Windows папку OneDrive можна знайти в `\Users\<username>\AppData\Local\Microsoft\OneDrive`. А в `logs\Personal` можна знайти файл `SyncDiagnostics.log`, що містить цікаві дані про синхронізовані файли:<sup>[[3]](#references)</sup>

- Розмір у байтах
- Дата створення
- Дата зміни
- Кількість файлів у хмарі
- Кількість файлів у папці
- **CID**: унікальний ідентифікатор користувача OneDrive
- Час створення звіту
- Розмір жорсткого диска ОС

Знайшовши CID, рекомендується **шукати файли, що містять цей ідентифікатор**. Можливо, вдасться знайти файли з назвами _**\<CID>.ini**_ і _**\<CID>.dat**_, які можуть містити цікаву інформацію, наприклад назви файлів, синхронізованих із OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

У Windows основну папку Google Drive можна знайти в `\Users\<username>\AppData\Local\Google\Drive\user_default`\
У цій папці є файл Sync_log.log, у якому реєструються сеанси синхронізації клієнта Google Drive, а також події створення, зміни й видалення файлів.<sup>[[4]](#references)[[6]](#references)</sup>

Файл **`Cloud_graph\Cloud_graph.db`** — це база даних SQLite.<sup>[[6]](#references)</sup> Вона містить таблицю **`cloud_graph_entry`**. У цій таблиці можна знайти **назву** **синхронізованих** **файлів**, час зміни, розмір і контрольну суму MD5 файлів.

У таблиці **`cloud_entry`** пов’язаної бази даних **`snapshot.db`** можуть зберігатися видалені записи з назвами файлів, часовими позначками, розмірами й контрольними сумами.<sup>[[4]](#references)</sup>

У таблиці бази даних **`Sync_config.db`** містяться адреса електронної пошти облікового запису, шлях до спільних папок і версія Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox використовує **бази даних SQLite** для керування файлами.<sup>[[2]](#references)</sup> У цій\
Можна знайти бази даних у таких папках:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Основні бази даних:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Розширення ".dbx" означає, що **бази даних** **зашифровані**. Dropbox використовує **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Щоб краще зрозуміти шифрування, яке використовує Dropbox, прочитайте [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Основна інформація така:<sup>[[1]](#references)</sup>

- **Ентропія**: d114a55212655f74bd772e37e64aee9b
- **Сіль**: 0D638C092E8B82FC452883F95F355B8E
- **Алгоритм**: PBKDF2
- **Ітерації**: 1066

Окрім цієї інформації, для розшифрування баз даних також потрібні:<sup>[[2]](#references)</sup>

- **Зашифрований ключ DPAPI**: його можна знайти в реєстрі за адресою `NTUSER.DAT\Software\Dropbox\ks\client` (експортуйте ці дані у двійковому форматі)
- Вулики **`SYSTEM`** і **`SECURITY`**
- **Головні ключі DPAPI**: їх можна знайти в `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Ім’я користувача** та **пароль** користувача Windows

Далі можна скористатися інструментом [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: далі можна скористатися інструментом DataProtectionDecryptor](<../../../images/image (443).png>)

Якщо все пройде як очікується, інструмент покаже **основний ключ**, який потрібно **використати для відновлення початкового ключа**. Щоб відновити початковий ключ, скористайтеся цим [рецептом cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) і вкажіть основний ключ як «парольну фразу» в рецепті.

Отримане шістнадцяткове значення — це кінцевий ключ, яким шифруються бази даних; їх можна розшифрувати за допомогою:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

База даних **`config.dbx`** містить:

- **Email**: електронна адреса користувача
- **usernamedisplayname**: ім’я користувача
- **dropbox_path**: шлях до папки Dropbox
- **Host_id: Hash** використовується для автентифікації в хмарі. Його можна відкликати лише через вебінтерфейс.
- **Root_ns**: ідентифікатор користувача

База даних **`filecache.db`** містить інформацію про всі файли й папки, синхронізовані з Dropbox. Таблиця `File_journal` містить найкориснішу інформацію:<sup>[[5]](#references)</sup>

- **Server_path**: шлях до файлу на сервері (перед цим шляхом указано `host_id` клієнта).
- **local_sjid**: версія файлу
- **local_mtime**: дата зміни
- **local_ctime**: дата створення

Інші таблиці в цій базі даних містять додаткову цікаву інформацію:

- **block_cache**: hash усіх файлів і папок Dropbox
- **block_ref**: пов’язує hash ID таблиці `block_cache` з ID файлу в таблиці `file_journal`
- **mount_table**: спільні папки Dropbox
- **deleted_fields**: видалені файли Dropbox
- **date_added**

## References

- [1] [Критичний аналіз безпеки програмного забезпечення Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Освіжіть знання про розшифрування Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Криміналістичний аналіз хмарного сховища (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Витік даних у справі NIST CFReDS: відповіді щодо витоку](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Криміналістичний аналіз Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Артефакти використання Google Drive у Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
