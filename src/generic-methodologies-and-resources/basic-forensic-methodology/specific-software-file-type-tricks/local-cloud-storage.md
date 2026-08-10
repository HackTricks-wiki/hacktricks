# Plaaslike Cloud Storage

## OneDrive

In Windows kan jy die OneDrive-lêergids vind in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. En binne `logs\Personal` is dit moontlik om die lêer `SyncDiagnostics.log` te vind, wat interessante data oor die gesinchroniseerde lêers bevat:<sup>[[3]](#references)</sup>

- Grootte in grepe
- Skeppingsdatum
- Wysigingsdatum
- Aantal lêers in die cloud
- Aantal lêers in die lêergids
- **CID**: Unieke ID van die OneDrive-gebruiker
- Tydstip van verslaggenerering
- Grootte van die OS se HD

Sodra jy die CID gevind het, word dit aanbeveel om **lêers te soek wat hierdie ID bevat**. Jy kan moontlik lêers met die naam _**\<CID>.ini**_ en _**\<CID>.dat**_ vind wat interessante inligting kan bevat, soos die name van lêers wat met OneDrive gesinchroniseer is.<sup>[[3]](#references)</sup>

## Google Drive

In Windows kan jy die hoof Google Drive-lêergids vind in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Hierdie lêergids bevat ’n lêer genaamd Sync_log.log wat Google Drive-kliëntsinkronisasiesessies en gebeurtenisse vir die skepping, wysiging en verwydering van lêers aanteken.<sup>[[4]](#references)[[6]](#references)</sup>

Die lêer **`Cloud_graph\Cloud_graph.db`** is ’n sqlite-databasis.<sup>[[6]](#references)</sup> Dit bevat die tabel **`cloud_graph_entry`**. In hierdie tabel kan jy die **naam** van die **gesinchroniseerde** **lêers**, gewysigde tyd, grootte en die MD5-checksum van die lêers vind.

Die verwante **`snapshot.db`**-databasis se **`cloud_entry`**-tabel kan verwyderde rekords met lêername, tydstempels, groottes en checksums behou.<sup>[[4]](#references)</sup>

Die tabeldata van die databasis **`Sync_config.db`** bevat die e-posadres van die rekening, die pad van die gedeelde lêergidse en die Google Drive-weergawe.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox gebruik **SQLite-databasisse** om die lêers te bestuur.<sup>[[2]](#references)</sup> In hierdie\
Jy kan die databasisse in die volgende lêergidse vind:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

En die hoofdabasisse is:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Die ".dbx"-uitbreiding beteken dat die **databasisse** **geënkripteer** is. Dropbox gebruik **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Om die enkripsie wat Dropbox gebruik beter te verstaan, kan jy [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) lees.<sup>[[1]](#references)[[2]](#references)</sup>

Die belangrikste inligting is egter:<sup>[[1]](#references)</sup>

- **Entropie**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritme**: PBKDF2
- **Iterasies**: 1066

Afgesien van daardie inligting, het jy steeds die volgende nodig om die databasisse te dekripteer:<sup>[[2]](#references)</sup>

- Die **geënkripteerde DPAPI-sleutel**: Jy kan dit in die register vind binne `NTUSER.DAT\Software\Dropbox\ks\client` (voer hierdie data as binêr uit)
- Die **`SYSTEM`**- en **`SECURITY`**-hives
- Die **DPAPI-hoofsleutels**: Dit kan gevind word in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Die **gebruikersnaam** en **wagwoord** van die Windows-gebruiker

Dan kan jy die hulpmiddel [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** gebruik:**

![Google Drive - Dropbox: Dan kan jy die hulpmiddel DataProtectionDecryptor gebruik](<../../../images/image (443).png>)

As alles verloop soos verwag, sal die hulpmiddel die **primêre sleutel** aandui wat jy moet **gebruik om die oorspronklike een te herstel**. Om die oorspronklike een te herstel, gebruik bloot hierdie [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) en plaas die primêre sleutel as die "passphrase" binne die receipt.

Die resulterende hex is die finale sleutel wat gebruik word om die databasisse te enkripteer, en wat gedekripteer kan word met:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`**-databasis bevat:

- **Email**: Die gebruiker se e-pos
- **usernamedisplayname**: Die gebruiker se naam
- **dropbox_path**: Pad waar die Dropbox-lêergids geleë is
- **Host_id: Hash** wat gebruik word om teen die cloud te authenticate. Dit kan slegs vanaf die web herroep word.
- **Root_ns**: Gebruikeridentifiseerder

Die **`filecache.db`**-databasis bevat inligting oor al die lêers en vouers wat met Dropbox gesinkroniseer is. Die `File_journal`-tabel bevat die nuttigste inligting:<sup>[[5]](#references)</sup>

- **Server_path**: Pad waar die lêer binne die bediener geleë is (hierdie pad word voorafgegaan deur die kliënt se `host_id`).
- **local_sjid**: Weergawe van die lêer
- **local_mtime**: Wysigingsdatum
- **local_ctime**: Skeppingsdatum

Ander tabelle binne hierdie databasis bevat meer interessante inligting:

- **block_cache**: hash van al die lêers en vouers van Dropbox
- **block_ref**: Koppel die hash-ID van die `block_cache`-tabel aan die lêer-ID in die `file_journal`-tabel
- **mount_table**: Gedeelde vouers van Dropbox
- **deleted_fields**: Lêers wat deur Dropbox verwyder is
- **date_added**

## References

- [1] [’n Kritiese ontleding van Dropbox-sagtewaresekuriteit (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Hersien Dropbox DBX-dekripsie](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Forensiese ontleding van Cloud Storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage Case: Antwoorde oor Leakage](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox-forensiese ondersoek](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefakte van Google Drive-gebruik in Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
