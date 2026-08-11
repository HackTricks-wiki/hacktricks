# Archiviazione cloud locale

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

In Windows, puoi trovare la cartella OneDrive in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E all'interno di `logs\Personal` è possibile trovare il file `SyncDiagnostics.log`, che contiene alcuni dati interessanti riguardo ai file sincronizzati:<sup>[[3]](#references)</sup>

- Dimensione in byte
- Data di creazione
- Data di modifica
- Numero di file nel cloud
- Numero di file nella cartella
- **CID**: ID univoco dell'utente OneDrive
- Ora di generazione del report
- Dimensione dell'HD del sistema operativo

Una volta trovato il CID, è consigliato **cercare i file che contengono questo ID**. Potresti riuscire a trovare file con i nomi: _**\<CID>.ini**_ e _**\<CID>.dat**_, che potrebbero contenere informazioni interessanti come i nomi dei file sincronizzati con OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

In Windows, puoi trovare la cartella principale di Google Drive in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Questa cartella contiene un file chiamato Sync_log.log, che registra le sessioni di sincronizzazione del client Google Drive e gli eventi di creazione, modifica ed eliminazione dei file.<sup>[[4]](#references)[[6]](#references)</sup>

Il file **`Cloud_graph\Cloud_graph.db`** è un database sqlite.<sup>[[6]](#references)</sup> Contiene la tabella **`cloud_graph_entry`**. In questa tabella puoi trovare il **nome** dei **file** **sincronizzati**, l'ora di modifica, la dimensione e il checksum MD5 dei file.

La tabella **`cloud_entry`** del database correlato **`snapshot.db`** può conservare record rimossi con nomi di file, timestamp, dimensioni e checksum.<sup>[[4]](#references)</sup>

I dati della tabella del database **`Sync_config.db`** contengono l'indirizzo email dell'account, il percorso delle cartelle condivise e la versione di Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox utilizza **database SQLite** per gestire i file.<sup>[[2]](#references)</sup> In questo\
Puoi trovare i database nelle cartelle:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

I database principali sono:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

L'estensione ".dbx" indica che i **database** sono **crittografati**. Dropbox utilizza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Per comprendere meglio la crittografia utilizzata da Dropbox, puoi leggere [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Tuttavia, le informazioni principali sono:<sup>[[1]](#references)</sup>

- **Entropia**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritmo**: PBKDF2
- **Iterazioni**: 1066

Oltre a queste informazioni, per decrittografare i database hai ancora bisogno di:<sup>[[2]](#references)</sup>

- La **chiave DPAPI crittografata**: puoi trovarla nel registro, all'interno di `NTUSER.DAT\Software\Dropbox\ks\client` (esporta questi dati come binario)
- Gli hive **`SYSTEM`** e **`SECURITY`**
- Le **chiavi master DPAPI**: che possono essere trovate in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Il **nome utente** e la **password** dell'utente Windows

Puoi quindi utilizzare lo strumento [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Puoi quindi utilizzare lo strumento DataProtectionDecryptor](<../../../images/image (443).png>)

Se tutto procede come previsto, lo strumento indicherà la **chiave primaria** che devi **utilizzare per recuperare quella originale**. Per recuperare quella originale, usa semplicemente questa [ricetta cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) inserendo la chiave primaria come "passphrase" all'interno della ricetta.

Il valore esadecimale risultante è la chiave finale utilizzata per crittografare i database, che possono essere decrittografati con:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Il database **`config.dbx`** contiene:

- **Email**: L'email dell'utente
- **usernamedisplayname**: Il nome dell'utente
- **dropbox_path**: Percorso in cui si trova la cartella Dropbox
- **Host_id: Hash** utilizzato per autenticarsi al cloud. Può essere revocato solo dal web.
- **Root_ns**: Identificatore dell'utente

Il database **`filecache.db`** contiene informazioni su tutti i file e le cartelle sincronizzati con Dropbox. La tabella `File_journal` è quella con le informazioni più utili:<sup>[[5]](#references)</sup>

- **Server_path**: Percorso in cui si trova il file all'interno del server (questo percorso è preceduto dall'`host_id` del client).
- **local_sjid**: Versione del file
- **local_mtime**: Data di modifica
- **local_ctime**: Data di creazione

Altre tabelle all'interno di questo database contengono informazioni più interessanti:

- **block_cache**: Hash di tutti i file e le cartelle di Dropbox
- **block_ref**: Collega l'ID hash della tabella `block_cache` all'ID del file nella tabella `file_journal`
- **mount_table**: Cartelle condivise di Dropbox
- **deleted_fields**: File eliminati di Dropbox
- **date_added**

## References

- [1] [Un'analisi critica della sicurezza del software Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Ripasso della decrittazione DBX di Dropbox](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Analisi forense del Cloud Storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Caso di perdita di dati NIST CFReDS: risposte sulla perdita](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Analisi forense di Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefatti dell'utilizzo di Google Drive in Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
