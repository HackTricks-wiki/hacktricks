# Plaaslike Wolk Berging

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

In Windows kan jy die OneDrive-gids vind in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. En binne `logs\Personal` is dit moontlik om die lêer `SyncDiagnostics.log` te vind wat interessante data bevat rakende die gesinkroniseerde lêers:

- Grootte in bytes
- Skeppingsdatum
- Wysigingsdatum
- Aantal lêers in die wolk
- Aantal lêers in die gids
- **CID**: Unieke ID van die OneDrive-gebruiker
- Verslaggenerasietyd
- Grootte van die HD van die OS

Sodra jy die CID gevind het, word dit aanbeveel om **lêers wat hierdie ID bevat te soek**. Jy mag dalk lêers met die naam: _**\<CID>.ini**_ en _**\<CID>.dat**_ vind wat interessante inligting kan bevat soos die name van lêers wat met OneDrive gesinkroniseer is.

## Google Drive

In Windows kan jy die hoof Google Drive-gids vind in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Hierdie gids bevat 'n lêer genaamd Sync_log.log met inligting soos die e-posadres van die rekening, lêernames, tydstempels, MD5-hashes van die lêers, ens. Selfs verwyderde lêers verskyn in daardie loglêer met die ooreenstemmende MD5.

Die lêer **`Cloud_graph\Cloud_graph.db`** is 'n sqlite-databasis wat die tabel **`cloud_graph_entry`** bevat. In hierdie tabel kan jy die **naam** van die **gesinkroniseerde** **lêers**, gewysigde tyd, grootte, en die MD5 checksum van die lêers vind.

Die tabeldata van die databasis **`Sync_config.db`** bevat die e-posadres van die rekening, die pad van die gedeelde gidse en die Google Drive weergawe.

## Dropbox

Dropbox gebruik **SQLite-databasisse** om die lêers te bestuur. In hierdie\
Jy kan die databasisse in die gidse vind:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

En die hoofdatabasisse is:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Die ".dbx" uitbreiding beteken dat die **databasisse** **versleuteld** is. Dropbox gebruik **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Om die versleuteling wat Dropbox gebruik beter te verstaan, kan jy lees [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Die hoofinligting is egter:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritme**: PBKDF2
- **Herhalings**: 1066

Afgesien van daardie inligting, om die databasisse te ontsleutel het jy steeds nodig:

- Die **versleutelde DPAPI-sleutel**: Jy kan dit in die registrasie vind binne `NTUSER.DAT\Software\Dropbox\ks\client` (eksporteer hierdie data as binêr)
- Die **`SYSTEM`** en **`SECURITY`** hives
- Die **DPAPI meester sleutels**: Wat gevind kan word in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Die **gebruikersnaam** en **wagwoord** van die Windows-gebruiker

Dan kan jy die hulpmiddel [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (448).png>)

As alles volgens verwagting verloop, sal die hulpmiddel die **primêre sleutel** aandui wat jy moet **gebruik om die oorspronklike een te herstel**. Om die oorspronklike een te herstel, gebruik net hierdie [cyber_chef resep](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) en plaas die primêre sleutel as die "wagwoord" binne die resep.

Die resulterende hex is die finale sleutel wat gebruik word om die databasisse te versleutel wat ontsleuteld kan word met:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`** databasis bevat:

- **E-pos**: Die e-pos van die gebruiker
- **usernamedisplayname**: Die naam van die gebruiker
- **dropbox_path**: Pad waar die dropbox-gids geleë is
- **Host_id: Hash** wat gebruik word om aan die wolk te verifieer. Dit kan slegs vanaf die web herroep word.
- **Root_ns**: Gebruikeridentifiseerder

Die **`filecache.db`** databasis bevat inligting oor al die lêers en gidse wat met Dropbox gesinkroniseer is. Die tabel `File_journal` is die een met die meeste nuttige inligting:

- **Server_path**: Pad waar die lêer binne die bediener geleë is (hierdie pad word voorafgegaan deur die `host_id` van die kliënt).
- **local_sjid**: Weergawe van die lêer
- **local_mtime**: Wysigingsdatum
- **local_ctime**: Skeppingsdatum

Ander tabelle binne hierdie databasis bevat meer interessante inligting:

- **block_cache**: hash van al die lêers en gidse van Dropbox
- **block_ref**: Verbind die hash ID van die tabel `block_cache` met die lêer ID in die tabel `file_journal`
- **mount_table**: Deel gidse van dropbox
- **deleted_fields**: Dropbox verwyderde lêers
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
