# Локальне Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

У Windows папку OneDrive можна знайти за шляхом `\Users\<username>\AppData\Local\Microsoft\OneDrive`. А всередині `logs\Personal` можна знайти файл `SyncDiagnostics.log`, який містить деякі цікаві дані щодо синхронізованих файлів:

- Розмір у байтах
- Дата створення
- Дата зміни
- Кількість файлів у cloud
- Кількість файлів у папці
- **CID**: Унікальний ID користувача OneDrive
- Час створення звіту
- Розмір HD операційної системи

Після знаходження CID рекомендується **шукати файли, що містять цей ID**. Можливо, ви знайдете файли з назвами: _**\<CID>.ini**_ і _**\<CID>.dat**_, які можуть містити цікаву інформацію, наприклад назви файлів, синхронізованих із OneDrive.

## Google Drive

У Windows основну папку Google Drive можна знайти за шляхом `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ця папка містить файл Sync_log.log з такою інформацією, як адреса електронної пошти облікового запису, імена файлів, часові мітки, MD5-хеші файлів тощо. Навіть видалені файли відображаються в цьому log-файлі з відповідним MD5.

Файл **`Cloud_graph\Cloud_graph.db`** є базою даних sqlite, яка містить таблицю **`cloud_graph_entry`**. У цій таблиці можна знайти **назви** **синхронізованих** **файлів**, час зміни, розмір і MD5 checksum файлів.

Дані таблиці бази даних **`Sync_config.db`** містять адресу електронної пошти облікового запису, шлях до спільних папок і версію Google Drive.

## Dropbox

Dropbox використовує **SQLite databases** для керування файлами. У цій\
Ви можете знайти databases у таких папках:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Основними databases є:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Розширення ".dbx" означає, що **databases** **зашифровані**. Dropbox використовує **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Щоб краще зрозуміти шифрування, яке використовує Dropbox, можна прочитати [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Однак основна інформація така:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Окрім цієї інформації, для розшифрування databases вам також потрібні:<sup>[[2]](#references)</sup>

- **Зашифрований ключ DPAPI**: його можна знайти в registry всередині `NTUSER.DAT\Software\Dropbox\ks\client` (експортуйте ці дані як binary)
- Hive **`SYSTEM`** і **`SECURITY`**
- **Master keys DPAPI**: їх можна знайти в `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Username** і **password** користувача Windows

Після цього можна використати tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Після цього можна використати tool DataProtectionDecryptor](<../../../images/image (443).png>)

Якщо все відбувається очікувано, tool покаже **primary key**, який потрібно **використати для відновлення оригінального ключа**. Щоб відновити оригінальний ключ, просто використайте цей [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) і вставте primary key як "passphrase" всередині receipt.

Отриманий hex є фінальним ключем, який використовується для шифрування databases і може бути розшифрований за допомогою:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
База даних **`config.dbx`** містить:

- **Email**: електронна пошта користувача
- **usernamedisplayname**: ім’я користувача
- **dropbox_path**: шлях до розташування папки Dropbox
- **Host_id: Hash**: хеш, що використовується для автентифікації у cloud. Його можна відкликати лише через веб-інтерфейс.
- **Root_ns**: ідентифікатор користувача

База даних **`filecache.db`** містить інформацію про всі файли та папки, синхронізовані з Dropbox. Таблиця `File_journal` містить найбільш корисну інформацію:

- **Server_path**: шлях, де файл розташований на сервері (цьому шляху передує `host_id` клієнта).
- **local_sjid**: версія файлу
- **local_mtime**: дата зміни
- **local_ctime**: дата створення

Інші таблиці в цій базі даних містять додаткову цікаву інформацію:

- **block_cache**: хеш усіх файлів і папок Dropbox
- **block_ref**: пов’язує ідентифікатор хешу з таблиці `block_cache` з ідентифікатором файлу в таблиці `file_journal`
- **mount_table**: спільні папки Dropbox
- **deleted_fields**: видалені файли Dropbox
- **date_added**

## References

- [1] [Критичний аналіз безпеки програмного забезпечення Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Оновлення знань про розшифрування Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
