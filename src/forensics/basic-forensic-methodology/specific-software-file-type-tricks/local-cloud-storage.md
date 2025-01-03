# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

In Windows, puoi trovare la cartella OneDrive in `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E all'interno di `logs\Personal` è possibile trovare il file `SyncDiagnostics.log` che contiene alcuni dati interessanti riguardo ai file sincronizzati:

- Dimensione in byte
- Data di creazione
- Data di modifica
- Numero di file nel cloud
- Numero di file nella cartella
- **CID**: ID univoco dell'utente OneDrive
- Tempo di generazione del report
- Dimensione dell'HD del sistema operativo

Una volta trovato il CID, è consigliato **cercare file contenenti questo ID**. Potresti essere in grado di trovare file con il nome: _**\<CID>.ini**_ e _**\<CID>.dat**_ che potrebbero contenere informazioni interessanti come i nomi dei file sincronizzati con OneDrive.

## Google Drive

In Windows, puoi trovare la cartella principale di Google Drive in `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Questa cartella contiene un file chiamato Sync_log.log con informazioni come l'indirizzo email dell'account, nomi dei file, timestamp, hash MD5 dei file, ecc. Anche i file eliminati appaiono in quel file di log con il corrispondente MD5.

Il file **`Cloud_graph\Cloud_graph.db`** è un database sqlite che contiene la tabella **`cloud_graph_entry`**. In questa tabella puoi trovare il **nome** dei **file sincronizzati**, il tempo di modifica, la dimensione e il checksum MD5 dei file.

I dati della tabella del database **`Sync_config.db`** contengono l'indirizzo email dell'account, il percorso delle cartelle condivise e la versione di Google Drive.

## Dropbox

Dropbox utilizza **database SQLite** per gestire i file. In questo\
Puoi trovare i database nelle cartelle:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

E i database principali sono:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

L'estensione ".dbx" significa che i **database** sono **criptati**. Dropbox utilizza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Per comprendere meglio la crittografia che utilizza Dropbox, puoi leggere [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Tuttavia, le informazioni principali sono:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

A parte queste informazioni, per decriptare i database hai ancora bisogno di:

- La **chiave DPAPI criptata**: Puoi trovarla nel registro all'interno di `NTUSER.DAT\Software\Dropbox\ks\client` (esporta questi dati come binari)
- I rami **`SYSTEM`** e **`SECURITY`**
- Le **chiavi master DPAPI**: Che possono essere trovate in `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Il **nome utente** e la **password** dell'utente Windows

Poi puoi usare lo strumento [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (448).png>)

Se tutto va come previsto, lo strumento indicherà la **chiave primaria** che devi **usare per recuperare quella originale**. Per recuperare quella originale, usa semplicemente questa [ricetta cyber_chef](<https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) mettendo la chiave primaria come "passphrase" all'interno della ricetta.

L'hex risultante è la chiave finale utilizzata per criptare i database che può essere decriptata con:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Il database **`config.dbx`** contiene:

- **Email**: L'email dell'utente
- **usernamedisplayname**: Il nome dell'utente
- **dropbox_path**: Percorso dove si trova la cartella dropbox
- **Host_id: Hash** utilizzato per autenticarsi nel cloud. Questo può essere revocato solo dal web.
- **Root_ns**: Identificatore dell'utente

Il database **`filecache.db`** contiene informazioni su tutti i file e le cartelle sincronizzati con Dropbox. La tabella `File_journal` è quella con più informazioni utili:

- **Server_path**: Percorso dove si trova il file all'interno del server (questo percorso è preceduto dall'`host_id` del client).
- **local_sjid**: Versione del file
- **local_mtime**: Data di modifica
- **local_ctime**: Data di creazione

Altre tabelle all'interno di questo database contengono informazioni più interessanti:

- **block_cache**: hash di tutti i file e le cartelle di Dropbox
- **block_ref**: Collega l'ID hash della tabella `block_cache` con l'ID file nella tabella `file_journal`
- **mount_table**: Cartelle condivise di dropbox
- **deleted_fields**: File eliminati da Dropbox
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
