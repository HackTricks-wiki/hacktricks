# Local Cloud Storage

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

In Windows, you can find the OneDrive folder in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. And inside `logs\Personal` it's possible to find the file `SyncDiagnostics.log` which contains some interesting data regarding the synchronized files:

* Size in bytes
* Creation date
* Modification date
* Number of files in the cloud
* Number of files in the folder
* **CID**: Unique ID of the OneDrive user
* Report generation time
* Size of the HD of the OS

Once you have found the CID it's recommended to **search files containing this ID**. You may be able to find files with the name: _**\<CID>.ini**_ and _**\<CID>.dat**_ that may contain interesting information like the names of files synchronized with OneDrive.

## Google Drive

In Windows, you can find the main Google Drive folder in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
This folder contains a file called Sync\_log.log with information like the email address of the account, filenames, timestamps, MD5 hashes of the files, etc. Even deleted files appear in that log file with its corresponding MD5.

The file **`Cloud_graph\Cloud_graph.db`** is a sqlite database which contains the table **`cloud_graph_entry`**. In this table you can find the **name** of the **synchronized** **files**, modified time, size, and the MD5 checksum of the files.

The table data of the database **`Sync_config.db`** contains the email address of the account, the path of the shared folders and the Google Drive version.

## Dropbox

Dropbox uses **SQLite databases** to manage the files. In this\
You can find the databases in the folders:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

And the main databases are:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

The ".dbx" extension means that the **databases** are **encrypted**. Dropbox uses **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

To understand better the encryption that Dropbox uses you can read [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

However, the main information is:

* **Entropy**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algorithm**: PBKDF2
* **Iterations**: 1066

Apart from that information, to decrypt the databases you still need:

* The **encrypted DPAPI key**: You can find it in the registry inside `NTUSER.DAT\Software\Dropbox\ks\client` (export this data as binary)
* The **`SYSTEM`** and **`SECURITY`** hives
* The **DPAPI master keys**: Which can be found in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* The **username** and **password** of the Windows user

Then you can use the tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

If everything goes as expected, the tool will indicate the **primary key** that you need to **use to recover the original one**. To recover the original one, just use this [cyber\_chef receipt](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) putting the primary key as the "passphrase" inside the receipt.

The resulting hex is the final key used to encrypt the databases which can be decrypted with:

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

The **`config.dbx`** database contains:

* **Email**: The email of the user
* **usernamedisplayname**: The name of the user
* **dropbox\_path**: Path where the dropbox folder is located
* **Host\_id: Hash** used to authenticate to the cloud. This can only be revoked from the web.
* **Root\_ns**: User identifier

The **`filecache.db`** database contains information about all the files and folders synchronized with Dropbox. The table `File_journal` is the one with more useful information:

* **Server\_path**: Path where the file is located inside the server (this path is preceded by the `host_id` of the client).
* **local\_sjid**: Version of the file
* **local\_mtime**: Modification date
* **local\_ctime**: Creation date

Other tables inside this database contain more interesting information:

* **block\_cache**: hash of all the files and folders of Dropbox
* **block\_ref**: Related the hash ID of the table `block_cache` with the file ID in the table `file_journal`
* **mount\_table**: Share folders of dropbox
* **deleted\_fields**: Dropbox deleted files
* **date\_added**

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
