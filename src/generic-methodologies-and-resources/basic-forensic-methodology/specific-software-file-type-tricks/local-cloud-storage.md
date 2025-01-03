# Локальне хмарне сховище

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

У Windows ви можете знайти папку OneDrive за адресою `\Users\<username>\AppData\Local\Microsoft\OneDrive`. А всередині `logs\Personal` можна знайти файл `SyncDiagnostics.log`, який містить цікаві дані щодо синхронізованих файлів:

- Розмір у байтах
- Дата створення
- Дата модифікації
- Кількість файлів у хмарі
- Кількість файлів у папці
- **CID**: Унікальний ID користувача OneDrive
- Час генерації звіту
- Розмір жорсткого диска ОС

Якщо ви знайшли CID, рекомендується **шукати файли, що містять цей ID**. Ви можете знайти файли з іменами: _**\<CID>.ini**_ та _**\<CID>.dat**_, які можуть містити цікаву інформацію, таку як назви файлів, синхронізованих з OneDrive.

## Google Drive

У Windows ви можете знайти основну папку Google Drive за адресою `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ця папка містить файл під назвою Sync_log.log з інформацією, такою як адреса електронної пошти облікового запису, імена файлів, часові мітки, MD5 хеші файлів тощо. Навіть видалені файли з'являються в цьому файлі журналу з відповідним MD5.

Файл **`Cloud_graph\Cloud_graph.db`** є базою даних sqlite, яка містить таблицю **`cloud_graph_entry`**. У цій таблиці ви можете знайти **ім'я** **синхронізованих** **файлів**, час модифікації, розмір та MD5 контрольну суму файлів.

Дані таблиці бази даних **`Sync_config.db`** містять адресу електронної пошти облікового запису, шлях до спільних папок та версію Google Drive.

## Dropbox

Dropbox використовує **SQLite бази даних** для управління файлами. У цьому\
Ви можете знайти бази даних у папках:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

А основні бази даних:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Розширення ".dbx" означає, що **бази даних** є **зашифрованими**. Dropbox використовує **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Щоб краще зрозуміти шифрування, яке використовує Dropbox, ви можете прочитати [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Однак основна інформація:

- **Ентропія**: d114a55212655f74bd772e37e64aee9b
- **Сіль**: 0D638C092E8B82FC452883F95F355B8E
- **Алгоритм**: PBKDF2
- **Ітерації**: 1066

Окрім цієї інформації, для розшифрування баз даних вам також знадобиться:

- **зашифрований ключ DPAPI**: Ви можете знайти його в реєстрі за адресою `NTUSER.DAT\Software\Dropbox\ks\client` (експортуйте ці дані у бінарному вигляді)
- **`SYSTEM`** та **`SECURITY`** хіви
- **майстер-ключі DPAPI**: які можна знайти за адресою `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **ім'я користувача** та **пароль** користувача Windows

Тоді ви можете використовувати інструмент [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (443).png>)

Якщо все пройде як очікувалося, інструмент вкаже на **основний ключ**, який вам потрібно **використати для відновлення оригінального**. Щоб відновити оригінал, просто використовуйте цей [рецепт cyber_chef](<https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) ставлячи основний ключ як "пароль" у рецепті.

Отриманий hex є фінальним ключем, використаним для шифрування баз даних, який можна розшифрувати за допомогою:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
База даних **`config.dbx`** містить:

- **Email**: Електронна пошта користувача
- **usernamedisplayname**: Ім'я користувача
- **dropbox_path**: Шлях, де розташована папка dropbox
- **Host_id: Hash** використовується для аутентифікації в хмарі. Його можна відкликати лише з вебу.
- **Root_ns**: Ідентифікатор користувача

База даних **`filecache.db`** містить інформацію про всі файли та папки, синхронізовані з Dropbox. Таблиця `File_journal` є тією, що містить найбільше корисної інформації:

- **Server_path**: Шлях, де файл розташований на сервері (цей шлях передує `host_id` клієнта).
- **local_sjid**: Версія файлу
- **local_mtime**: Дата модифікації
- **local_ctime**: Дата створення

Інші таблиці в цій базі даних містять більш цікаву інформацію:

- **block_cache**: хеш усіх файлів і папок Dropbox
- **block_ref**: Пов'язує хеш ID таблиці `block_cache` з ID файлу в таблиці `file_journal`
- **mount_table**: Спільні папки Dropbox
- **deleted_fields**: Видалені файли Dropbox
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
