# Local Cloud Storage
{{#include /banners/hacktricks-training.md}}


{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

In Windows, you can find the OneDrive folder in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. And inside `logs\Personal` it's possible to find the file `SyncDiagnostics.log` which contains some interesting data regarding the synchronized files:

- Size in bytes
- Creation date
- Modification date
- Number of files in the cloud
- Number of files in the folder
- **CID**: Unique ID of the OneDrive user
- Report generation time
- Size of the HD of the OS

Once you have found the CID it's recommended to **search files containing this ID**. You may be able to find files with the name: _**\<CID>.ini**_ and _**\<CID>.dat**_ that may contain interesting information like the names of files synchronized with OneDrive.

## Google Drive

In Windows, you can find the main Google Drive folder in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
This folder contains a file called Sync_log.log with information like the email address of the account, filenames, timestamps, MD5 hashes of the files, etc. Even deleted files appear in that log file with its corresponding MD5.

The file **`Cloud_graph\Cloud_graph.db`** is a sqlite database which contains the table **`cloud_graph_entry`**. In this table you can find the **name** of the **synchronized** **files**, modified time, size, and the MD5 checksum of the files.

The table data of the database **`Sync_config.db`** contains the email address of the account, the path of the shared folders and the Google Drive version.

## Dropbox

Dropbox uses **SQLite databases** to manage the files. In this\
You can find the databases in the folders:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

And the main databases are:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

The ".dbx" extension means that the **databases** are **encrypted**. Dropbox uses **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

To understand better the encryption that Dropbox uses you can read [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

However, the main information is:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Apart from that information, to decrypt the databases you still need:

- The **encrypted DPAPI key**: You can find it in the registry inside `NTUSER.DAT\Software\Dropbox\ks\client` (export this data as binary)
- The **`SYSTEM`** and **`SECURITY`** hives
- The **DPAPI master keys**: Which can be found in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- The **username** and **password** of the Windows user

Then you can use the tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (443).png>)

If everything goes as expected, the tool will indicate the **primary key** that you need to **use to recover the original one**. To recover the original one, just use this [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) putting the primary key as the "passphrase" inside the receipt.

The resulting hex is the final key used to encrypt the databases which can be decrypted with:

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

The **`config.dbx`** database contains:

- **Email**: The email of the user
- **usernamedisplayname**: The name of the user
- **dropbox_path**: Path where the dropbox folder is located
- **Host_id: Hash** used to authenticate to the cloud. This can only be revoked from the web.
- **Root_ns**: User identifier

The **`filecache.db`** database contains information about all the files and folders synchronized with Dropbox. The table `File_journal` is the one with more useful information:

- **Server_path**: Path where the file is located inside the server (this path is preceded by the `host_id` of the client).
- **local_sjid**: Version of the file
- **local_mtime**: Modification date
- **local_ctime**: Creation date

Other tables inside this database contain more interesting information:

- **block_cache**: hash of all the files and folders of Dropbox
- **block_ref**: Related the hash ID of the table `block_cache` with the file ID in the table `file_journal`
- **mount_table**: Share folders of dropbox
- **deleted_fields**: Dropbox deleted files
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
