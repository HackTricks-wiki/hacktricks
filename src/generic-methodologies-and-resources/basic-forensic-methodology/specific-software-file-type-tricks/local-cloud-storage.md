# Plaaslike Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

In Windows kan jy die OneDrive-lêergids vind by `\Users\<username>\AppData\Local\Microsoft\OneDrive`. En binne `logs\Personal` is dit moontlik om die lêer `SyncDiagnostics.log` te vind, wat interessante data oor die gesinchroniseerde lêers bevat:

- Grootte in grepe
- Skeppingsdatum
- Wysigingsdatum
- Aantal lêers in die cloud
- Aantal lêers in die lêergids
- **CID**: Unieke ID van die OneDrive-gebruiker
- Tyd waarop die verslag gegenereer is
- Grootte van die HD van die OS

Sodra jy die CID gevind het, word dit aanbeveel om **na lêers te soek wat hierdie ID bevat**. Jy kan moontlik lêers met die naam _**\<CID>.ini**_ en _**\<CID>.dat**_ vind wat interessante inligting kan bevat, soos die name van lêers wat met OneDrive gesinchroniseer is.

## Google Drive

In Windows kan jy die hoof Google Drive-lêergids vind by `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Hierdie lêergids bevat ’n lêer genaamd Sync_log.log met inligting soos die e-posadres van die rekening, lêername, tydstempels, MD5-hashes van die lêers, ens. Selfs geskrapte lêers verskyn in daardie loglêer met hul ooreenstemmende MD5.

Die lêer **`Cloud_graph\Cloud_graph.db`** is ’n sqlite-databasis wat die tabel **`cloud_graph_entry`** bevat. In hierdie tabel kan jy die **naam** van die **gesinchroniseerde** **lêers**, wysigingstyd, grootte en die MD5-checksum van die lêers vind.

Die tabeldata van die databasis **`Sync_config.db`** bevat die e-posadres van die rekening, die pad van die gedeelde lêergidse en die Google Drive-weergawe.

## Dropbox

Dropbox gebruik **SQLite-databasisse** om die lêers te bestuur. In hierdie\
Jy kan die databasisse in die volgende lêergidse vind:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

En die hoofdatabasisse is:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Die ".dbx"-uitbreiding beteken dat die **databasisse** **geënkripteer** is. Dropbox gebruik **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Om die encryption wat Dropbox gebruik beter te verstaan, kan jy [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) lees.<sup>[[1]](#references)[[2]](#references)</sup>

Die belangrikste inligting is egter:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Afgesien van daardie inligting het jy steeds die volgende nodig om die databasisse te decrypt:<sup>[[2]](#references)</sup>

- Die **geënkripteerde DPAPI-sleutel**: Jy kan dit in die registry vind binne `NTUSER.DAT\Software\Dropbox\ks\client` (voer hierdie data as binary uit)
- Die **`SYSTEM`**- en **`SECURITY`**-hives
- Die **DPAPI master keys**: Dit kan gevind word in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Die **username** en **password** van die Windows-gebruiker

Dan kan jy die tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** gebruik:**

![Google Drive - Dropbox: Dan kan jy die tool DataProtectionDecryptor gebruik](<../../../images/image (443).png>)

As alles soos verwag verloop, sal die tool die **primary key** aandui wat jy moet **gebruik om die oorspronklike een te recover**. Om die oorspronklike een te recover, gebruik eenvoudig hierdie [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) en plaas die primary key as die "passphrase" binne die receipt.

Die resulterende hex is die finale sleutel wat gebruik word om die databasisse te encryp en wat met die volgende gedecrypt kan word:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`**-databasis bevat:

- **Email**: Die gebruiker se e-posadres
- **usernamedisplayname**: Die gebruiker se naam
- **dropbox_path**: Pad waar die Dropbox-lêergids geleë is
- **Host_id: Hash** wat gebruik word om by die cloud te authenticate. Dit kan slegs vanaf die web herroep word.
- **Root_ns**: Gebruikeridentifiseerder

Die **`filecache.db`**-databasis bevat inligting oor al die lêers en vouers wat met Dropbox gesinkroniseer is. Die tabel `File_journal` is die een met die nuttigste inligting:

- **Server_path**: Pad waar die lêer binne die server geleë is (hierdie pad word deur die kliënt se `host_id` voorafgegaan).
- **local_sjid**: Weergawe van die lêer
- **local_mtime**: Wysigingsdatum
- **local_ctime**: Skeppingsdatum

Ander tabelle binne hierdie databasis bevat meer interessante inligting:

- **block_cache**: Hash van al die lêers en vouers van Dropbox
- **block_ref**: Koppel die hash-ID van die tabel `block_cache` aan die lêer-ID in die tabel `file_journal`
- **mount_table**: Gedeelde vouers van Dropbox
- **deleted_fields**: Dropbox se geskrapte lêers
- **date_added**

## Verwysings

- [1] [A critical analysis of Dropbox software security (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Brush up on Dropbox DBX decryption](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
