# Archiviazione cloud locale

{{#include ../../../banners/hacktricks-training.md}}

## Emulatori di archiviazione locale e chiavi dell'account

Un emulatore Blob compatibile con Azure in esecuzione in un container potrebbe essere raggiungibile dal relativo host o dalla rete bridge anche quando il servizio di archiviazione non è esposto all'esterno. Esamina le configurazioni locali leggibili e i metadati dei file di backup per individuare un nome account e una chiave, senza stampare la chiave durante le normali attività di enumerazione. [Azurite supporta chiavi account locali personalizzate](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); l'[autorizzazione Shared Key](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) può concedere ampio accesso ai dati dell'account corrispondente. Il solo fatto di avere un file della chiave non dimostra che sia possibile ottenere privilegi più elevati: verifica che l'endpoint sia raggiungibile, che account e chiave siano accettati e che il blob specifico contenga effettivamente una credenziale utilizzabile per un'identità con privilegi più elevati. Se contiene una chiave privata SSH, anche la chiave pubblica corrispondente deve essere autorizzata per quell'identità e l'accesso SSH deve essere consentito. Proteggi e ruota la chiave una volta confermata l'esposizione.

## OneDrive

In Windows, puoi trovare la cartella OneDrive in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. All'interno di `logs\Personal` è possibile trovare il file `SyncDiagnostics.log`, che contiene dati interessanti sui file sincronizzati:<sup>[[3]](#references)</sup>

- Dimensione in byte
- Data di creazione
- Data di modifica
- Numero di file nel cloud
- Numero di file nella cartella
- **CID**: ID univoco dell'utente OneDrive
- Ora di generazione del report
- Dimensione dell'HD del sistema operativo

Una volta trovato il CID, è consigliabile **cercare i file che contengono questo ID**. Potresti trovare file denominati _**\<CID>.ini**_ e _**\<CID>.dat**_, che potrebbero contenere informazioni interessanti, come i nomi dei file sincronizzati con OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

In Windows, puoi trovare la cartella principale di Google Drive in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Questa cartella contiene un file chiamato Sync_log.log, che registra le sessioni di sincronizzazione del client Google Drive e gli eventi di creazione, modifica ed eliminazione dei file.<sup>[[4]](#references)[[6]](#references)</sup>

Il file **`Cloud_graph\Cloud_graph.db`** è un database SQLite.<sup>[[6]](#references)</sup> Contiene la tabella **`cloud_graph_entry`**. In questa tabella puoi trovare il **nome** dei **file** **sincronizzati**, l'ora di modifica, la dimensione e il checksum MD5 dei file.

La tabella **`cloud_entry`** del database correlato **`snapshot.db`** può conservare record rimossi con nomi di file, timestamp, dimensioni e checksum.<sup>[[4]](#references)</sup>

I dati della tabella del database **`Sync_config.db`** contengono l'indirizzo email dell'account, il percorso delle cartelle condivise e la versione di Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox usa **database SQLite** per gestire i file.<sup>[[2]](#references)</sup> In questa\
Puoi trovare i database nelle cartelle:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

I database principali sono:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

L'estensione ".dbx" indica che i **database** sono **crittografati**. Dropbox usa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Per comprendere meglio la crittografia usata da Dropbox, puoi leggere [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Le informazioni principali sono:<sup>[[1]](#references)</sup>

- **Entropia**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritmo**: PBKDF2
- **Iterazioni**: 1066

Oltre a queste informazioni, per decrittografare i database hai ancora bisogno di:<sup>[[2]](#references)</sup>

- La **chiave DPAPI crittografata**: puoi trovarla nel registro in `NTUSER.DAT\Software\Dropbox\ks\client` (esporta questi dati in formato binario)
- Gli hive **`SYSTEM`** e **`SECURITY`**
- Le **chiavi master DPAPI**: si trovano in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Il **nome utente** e la **password** dell'utente Windows

Puoi quindi usare lo strumento [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: puoi quindi usare lo strumento DataProtectionDecryptor](<../../../images/image (443).png>)

Se tutto procede come previsto, lo strumento indicherà la **chiave primaria** da **usare per recuperare quella originale**. Per recuperare la chiave originale, usa questa [ricetta di cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) inserendo la chiave primaria come "passphrase" nella ricetta.

Il valore esadecimale risultante è la chiave finale usata per crittografare i database, che possono essere decrittografati con:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

The **`config.dbx`** database contiene:

- **Email**: L'indirizzo email dell'utente
- **usernamedisplayname**: Il nome dell'utente
- **dropbox_path**: Percorso in cui si trova la cartella Dropbox
- **Host_id: Hash** utilizzato per autenticarsi al cloud. Può essere revocato solo dal web.
- **Root_ns**: Identificatore dell'utente

Il database **`filecache.db`** contiene informazioni su tutti i file e le cartelle sincronizzati con Dropbox. La tabella `File_journal` contiene le informazioni più utili:<sup>[[5]](#references)</sup>

- **Server_path**: Percorso del file sul server (preceduto dall'`host_id` del client).
- **local_sjid**: Versione del file
- **local_mtime**: Data di modifica
- **local_ctime**: Data di creazione

Altre tabelle di questo database contengono informazioni interessanti:

- **block_cache**: hash di tutti i file e le cartelle di Dropbox
- **block_ref**: associa l'ID hash della tabella `block_cache` all'ID del file nella tabella `file_journal`
- **mount_table**: Cartelle condivise di Dropbox
- **deleted_fields**: File eliminati da Dropbox
- **date_added**

## References

- [1] [Un'analisi critica della sicurezza del software Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Approfondimento sulla decrittografia dei DBX di Dropbox](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Analisi forense del cloud storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Caso di perdita di dati NIST CFReDS: risposte sulla perdita](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Analisi forense di Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefatti dell'utilizzo di Google Drive in Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
