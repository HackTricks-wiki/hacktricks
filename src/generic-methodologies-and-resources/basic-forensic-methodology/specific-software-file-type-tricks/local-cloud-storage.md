# Archiviazione cloud locale

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

In Windows, puoi trovare la cartella OneDrive in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E all'interno di `logs\Personal` è possibile trovare il file `SyncDiagnostics.log`, che contiene alcuni dati interessanti relativi ai file sincronizzati:

- Dimensione in byte
- Data di creazione
- Data di modifica
- Numero di file nel cloud
- Numero di file nella cartella
- **CID**: ID univoco dell'utente OneDrive
- Ora di generazione del report
- Dimensione dell'HD del sistema operativo

Una volta trovato il CID, è consigliato **cercare i file contenenti questo ID**. Potresti riuscire a trovare file con il nome: _**\<CID>.ini**_ e _**\<CID>.dat**_, che potrebbero contenere informazioni interessanti, come i nomi dei file sincronizzati con OneDrive.

## Google Drive

In Windows, puoi trovare la cartella principale di Google Drive in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Questa cartella contiene un file chiamato Sync_log.log, con informazioni come l'indirizzo email dell'account, i nomi dei file, i timestamp, gli hash MD5 dei file, ecc. Anche i file eliminati compaiono in questo file di log con il relativo MD5.

Il file **`Cloud_graph\Cloud_graph.db`** è un database sqlite che contiene la tabella **`cloud_graph_entry`**. In questa tabella puoi trovare il **nome** dei **file** **sincronizzati**, l'ora di modifica, la dimensione e il checksum MD5 dei file.

I dati della tabella del database **`Sync_config.db`** contengono l'indirizzo email dell'account, il percorso delle cartelle condivise e la versione di Google Drive.

## Dropbox

Dropbox utilizza **database SQLite** per gestire i file. In questa\
Puoi trovare i database nelle cartelle:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

I database principali sono:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

L'estensione ".dbx" indica che i **database** sono **crittografati**. Dropbox utilizza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Per comprendere meglio la crittografia utilizzata da Dropbox, puoi leggere [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Tuttavia, le informazioni principali sono:<sup>[[1]](#references)</sup>

- **Entropia**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritmo**: PBKDF2
- **Iterazioni**: 1066

Oltre a queste informazioni, per decrittografare i database hai ancora bisogno di:<sup>[[2]](#references)</sup>

- La **chiave DPAPI crittografata**: puoi trovarla nel registro all'interno di `NTUSER.DAT\Software\Dropbox\ks\client` (esporta questi dati come binario)
- Gli hive **`SYSTEM`** e **`SECURITY`**
- Le **chiavi master DPAPI**: possono essere trovate in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Il **nome utente** e la **password** dell'utente Windows

Puoi quindi utilizzare lo strumento [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: quindi puoi utilizzare lo strumento DataProtectionDecryptor](<../../../images/image (443).png>)

Se tutto procede come previsto, lo strumento indicherà la **chiave primaria** che devi **utilizzare per recuperare quella originale**. Per recuperare quella originale, usa semplicemente questa [ricetta di cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) inserendo la chiave primaria come "passphrase" all'interno della ricetta.

L'hex risultante è la chiave finale utilizzata per crittografare i database, che possono essere decrittografati con:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Il database **`config.dbx`** contiene:

- **Email**: L'email dell'utente
- **usernamedisplayname**: Il nome dell'utente
- **dropbox_path**: Percorso in cui si trova la cartella Dropbox
- **Host_id: Hash** utilizzato per autenticarsi al cloud. Questo può essere revocato solo dal web.
- **Root_ns**: Identificatore dell'utente

Il database **`filecache.db`** contiene informazioni su tutti i file e le cartelle sincronizzati con Dropbox. La tabella `File_journal` è quella con le informazioni più utili:

- **Server_path**: Percorso in cui si trova il file all'interno del server (questo percorso è preceduto dal `host_id` del client).
- **local_sjid**: Versione del file
- **local_mtime**: Data di modifica
- **local_ctime**: Data di creazione

Altre tabelle all'interno di questo database contengono informazioni più interessanti:

- **block_cache**: hash di tutti i file e le cartelle di Dropbox
- **block_ref**: Collega l'ID hash della tabella `block_cache` all'ID del file nella tabella `file_journal`
- **mount_table**: Cartelle condivise di Dropbox
- **deleted_fields**: File eliminati di Dropbox
- **date_added**

## Riferimenti

- [1] [Un'analisi critica della sicurezza del software Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Ripasso sulla decrittazione di Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
