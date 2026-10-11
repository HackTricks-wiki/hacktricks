# Plaaslike wolkberging

{{#include ../../../banners/hacktricks-training.md}}

## Plaaslike bergingsemulators en rekeningsleutels

’n Azure-versoenbare Blob-emulator wat in ’n houer loop, kan vanaf sy gasheer- of brugnetwerk bereikbaar wees, selfs wanneer die bergingsdiens nie ekstern blootgestel word nie. Gaan leesbare plaaslike konfigurasie en metadata van rugsteunlêers na vir ’n rekeningnaam en sleutel, sonder om die sleutel tydens roetine-enumerasie te vertoon. [Azurite ondersteun pasgemaakte plaaslike rekeningsleutels](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [Shared Key-magtiging](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) kan breë toegang tot die ooreenstemmende rekening se data verleen. ’n Sleutellêer alleen bewys nie dat voorregte verhoog kan word nie: bevestig dat die eindpunt bereikbaar is, die rekening en sleutel aanvaar word, en die spesifieke blob werklik ’n bruikbare geloofsbrief vir ’n identiteit met hoër voorregte bevat. As dit ’n SSH-private sleutel bevat, moet die ooreenstemmende publieke sleutel ook vir daardie identiteit gemagtig wees, en SSH-toegang moet toegelaat word. Beveilig en roteer ’n sleutel sodra blootstelling bevestig is.

## OneDrive

In Windows kan jy die OneDrive-lêergids vind by `\Users\<username>\AppData\Local\Microsoft\OneDrive`. En binne `logs\Personal` is dit moontlik om die lêer `SyncDiagnostics.log` te vind, wat interessante data oor die gesinchroniseerde lêers bevat:<sup>[[3]](#references)</sup>

- Grootte in grepe
- Skeppingsdatum
- Wysigingsdatum
- Aantal lêers in die wolk
- Aantal lêers in die lêergids
- **CID**: Unieke ID van die OneDrive-gebruiker
- Verslaggenereringstyd
- Grootte van die bedryfstelsel se hardeskyf

Nadat jy die CID gevind het, word dit aanbeveel om **te soek na lêers wat hierdie ID bevat**. Jy kan dalk lêers met die naam _**\<CID>.ini**_ en _**\<CID>.dat**_ vind wat interessante inligting kan bevat, soos die name van lêers wat met OneDrive gesinchroniseer is.<sup>[[3]](#references)</sup>

## Google Drive

In Windows kan jy die hoof-Google Drive-lêergids vind by `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Hierdie lêergids bevat ’n lêer met die naam Sync_log.log, wat Google Drive-kliëntsinkroniseringsessies en lêerskeppings-, wysigings- en uitveegebeurtenisse aanteken.<sup>[[4]](#references)[[6]](#references)</sup>

Die lêer **`Cloud_graph\Cloud_graph.db`** is ’n SQLite-databasis.<sup>[[6]](#references)</sup> Dit bevat die tabel **`cloud_graph_entry`**. In hierdie tabel kan jy die **name** van die **gesinchroniseerde** **lêers**, wysigingstyd, grootte en die MD5-kontrolesom van die lêers vind.

Die verwante **`snapshot.db`**-databasis se **`cloud_entry`**-tabel kan verwyderde rekords met lêername, tydstempels, groottes en kontrolesomme behou.<sup>[[4]](#references)</sup>

Die tabeldata van die databasis **`Sync_config.db`** bevat die rekening se e-posadres, die pad na die gedeelde lêergidse en die Google Drive-weergawe.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox gebruik **SQLite-databasisse** om die lêers te bestuur.<sup>[[2]](#references)</sup> In hierdie\
Jy kan die databasisse in die lêergidse vind:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

En die hoofd databasisse is:

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

- Die **geënkripteerde DPAPI-sleutel**: Jy kan dit in die register vind by `NTUSER.DAT\Software\Dropbox\ks\client` (voer hierdie data as binêr uit)
- Die **`SYSTEM`**- en **`SECURITY`**-korwe
- Die **DPAPI-hoofsleutels**: Dit kan gevind word by `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Die Windows-gebruiker se **gebruikersnaam** en **wagwoord**

Dan kan jy die hulpmiddel [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** gebruik:**

![Google Drive - Dropbox: Dan kan jy die hulpmiddel DataProtectionDecryptor gebruik](<../../../images/image (443).png>)

As alles verloop soos verwag, sal die hulpmiddel die **primêre sleutel** aandui wat jy moet **gebruik om die oorspronklike sleutel te herwin**. Om die oorspronklike sleutel te herwin, gebruik eenvoudig hierdie [cyber_chef-resep](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) en plaas die primêre sleutel as die "passphrase" in die resep.

Die resulterende heksadesimale waarde is die finale sleutel wat gebruik word om die databasisse te enkripteer; hulle kan soos volg gedekripteer word:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

Die **`config.dbx`**-databasis bevat:

- **Email**: Die gebruiker se e-posadres
- **usernamedisplayname**: Die gebruiker se naam
- **dropbox_path**: Pad waar die Dropbox-lêergids geleë is
- **Host_id: Hash** wat gebruik word om by die cloud te staaf. Dit kan slegs vanaf die web herroep word.
- **Root_ns**: Gebruikeridentifiseerder

Die **`filecache.db`**-databasis bevat inligting oor al die lêers en vouers wat met Dropbox gesinkroniseer is. Die tabel `File_journal` bevat die nuttigste inligting:<sup>[[5]](#references)</sup>

- **Server_path**: Pad waar die lêer op die bediener geleë is (hierdie pad word voorafgegaan deur die kliënt se `host_id`).
- **local_sjid**: Lêerweergawe
- **local_mtime**: Wysigingsdatum
- **local_ctime**: Skeppingsdatum

Ander tabelle in hierdie databasis bevat meer interessante inligting:

- **block_cache**: Hashes van al die Dropbox-lêers en -vouers
- **block_ref**: Koppel die hash-ID van die tabel `block_cache` aan die lêer-ID in die tabel `file_journal`
- **mount_table**: Gedeelde Dropbox-vouers
- **deleted_fields**: Dropbox-lêers wat uitgevee is
- **date_added**

## References

- [1] [’n Kritiese ontleding van Dropbox-sagtewaresekuriteit (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Hersien Dropbox DBX-dekripsie](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Forensiese ontleding van cloud-berging (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage-saak: Antwoorde oor Leakage](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox-forensiese ondersoek](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefakte van Google Drive-gebruik in Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
