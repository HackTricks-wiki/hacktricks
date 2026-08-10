# Локальне хмарне сховище

## OneDrive

У Windows папку OneDrive можна знайти в `\Users\<username>\AppData\Local\Microsoft\OneDrive`. А всередині `logs\Personal` можна знайти файл `SyncDiagnostics.log`, який містить деякі цікаві дані щодо синхронізованих файлів:<sup>[[3]](#references)</sup>

- Розмір у байтах
- Дата створення
- Дата модифікації
- Кількість файлів у cloud
- Кількість файлів у папці
- **CID**: Унікальний ідентифікатор користувача OneDrive
- Час створення звіту
- Розмір HD операційної системи

Після знаходження CID рекомендується **шукати файли, що містять цей ID**. Можливо, вам вдасться знайти файли з назвами: _**\<CID>.ini**_ і _**\<CID>.dat**_, які можуть містити цікаву інформацію, наприклад назви файлів, синхронізованих із OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

У Windows основну папку Google Drive можна знайти в `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ця папка містить файл під назвою Sync_log.log, який записує сеанси синхронізації клієнта Google Drive, а також події створення, модифікації та видалення файлів.<sup>[[4]](#references)[[6]](#references)</sup>

Файл **`Cloud_graph\Cloud_graph.db`** є базою даних sqlite.<sup>[[6]](#references)</sup> Він містить таблицю **`cloud_graph_entry`**. У цій таблиці можна знайти **назви** **синхронізованих** **файлів**, час модифікації, розмір і MD5 контрольну суму файлів.

Пов’язана база даних **`snapshot.db`** може зберігати в таблиці **`cloud_entry`** видалені записи з іменами файлів, часовими мітками, розмірами та контрольними сумами.<sup>[[4]](#references)</sup>

Дані таблиці бази даних **`Sync_config.db`** містять адресу електронної пошти облікового запису, шлях до спільних папок і версію Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox використовує **бази даних SQLite** для керування файлами.<sup>[[2]](#references)</sup> У цій\
ви можете знайти бази даних у папках:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Основними базами даних є:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Розширення ".dbx" означає, що **бази даних** є **зашифрованими**. Dropbox використовує **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Щоб краще зрозуміти шифрування, яке використовує Dropbox, можна прочитати [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Однак основна інформація така:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Окрім цієї інформації, для розшифрування баз даних вам усе ще потрібні:<sup>[[2]](#references)</sup>

- **Зашифрований ключ DPAPI**: його можна знайти в реєстрі за шляхом `NTUSER.DAT\Software\Dropbox\ks\client` (експортуйте ці дані як binary)
- Кущі **`SYSTEM`** і **`SECURITY`**
- **Головні ключі DPAPI**: їх можна знайти в `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Ім’я користувача** та **пароль** користувача Windows

Потім можна використати інструмент [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Потім можна використати інструмент DataProtectionDecryptor](<../../../images/image (443).png>)

Якщо все відбувається очікуваним чином, інструмент вкаже **primary key**, який потрібно **використати для відновлення оригінального ключа**. Щоб відновити оригінальний ключ, просто використайте цей [рецепт cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)**, вказавши primary key як "passphrase" у рецепті.

Отриманий hex є фінальним ключем, який використовується для шифрування баз даних; його можна розшифрувати за допомогою:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
База даних **`config.dbx`** містить:

- **Email**: Email користувача
- **usernamedisplayname**: Ім'я користувача
- **dropbox_path**: Шлях до розташування папки Dropbox
- **Host_id: Hash** використовується для автентифікації у хмарі. Його можна відкликати лише через вебінтерфейс.
- **Root_ns**: Ідентифікатор користувача

База даних **`filecache.db`** містить інформацію про всі файли та папки, синхронізовані з Dropbox. Таблиця `File_journal` містить найбільш корисну інформацію:<sup>[[5]](#references)</sup>

- **Server_path**: Шлях, за яким файл розташований на сервері (цьому шляху передує `host_id` клієнта).
- **local_sjid**: Версія файлу
- **local_mtime**: Дата зміни
- **local_ctime**: Дата створення

Інші таблиці в цій базі даних містять додаткову цікаву інформацію:

- **block_cache**: hash усіх файлів і папок Dropbox
- **block_ref**: Пов'язує ідентифікатор hash таблиці `block_cache` з ідентифікатором файлу в таблиці `file_journal`
- **mount_table**: Спільні папки Dropbox
- **deleted_fields**: Видалені файли Dropbox
- **date_added**

## References

- [1] [Критичний аналіз безпеки програмного забезпечення Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Оновлення знань про розшифрування Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Криміналістичний аналіз Cloud Storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Випадок витоку даних NIST CFReDS: відповіді щодо витоку](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Криміналістичний аналіз Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Артефакти використання Google Drive у Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
