# Lokaler Cloud-Speicher

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

In Windows befindet sich der OneDrive-Ordner unter `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Und in `logs\Personal` kann man die Datei `SyncDiagnostics.log` finden, die einige interessante Daten zu den synchronisierten Dateien enthält:

- Größe in Bytes
- Erstellungsdatum
- Änderungsdatum
- Anzahl der Dateien in der Cloud
- Anzahl der Dateien im Ordner
- **CID**: Eindeutige ID des OneDrive-Benutzers
- Zeitpunkt der Berichtserstellung
- Größe der HD des Betriebssystems

Sobald du die CID gefunden hast, wird empfohlen, nach **Dateien zu suchen, die diese ID enthalten**. Möglicherweise findest du Dateien mit den Namen: _**\<CID>.ini**_ und _**\<CID>.dat**_, die interessante Informationen enthalten können, beispielsweise die Namen der mit OneDrive synchronisierten Dateien.

## Google Drive

In Windows befindet sich der Hauptordner von Google Drive unter `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Dieser Ordner enthält eine Datei namens Sync_log.log mit Informationen wie der E-Mail-Adresse des Kontos, Dateinamen, Zeitstempeln, MD5-Hashes der Dateien usw. Auch gelöschte Dateien erscheinen mit ihrem entsprechenden MD5 in dieser Logdatei.

Die Datei **`Cloud_graph\Cloud_graph.db`** ist eine sqlite-Datenbank, die die Tabelle **`cloud_graph_entry`** enthält. In dieser Tabelle findest du den **Namen** der **synchronisierten** **Dateien**, den Änderungszeitpunkt, die Größe und die MD5-Prüfsumme der Dateien.

Die Tabellendaten der Datenbank **`Sync_config.db`** enthalten die E-Mail-Adresse des Kontos, den Pfad der freigegebenen Ordner und die Google Drive-Version.

## Dropbox

Dropbox verwendet **SQLite-Datenbanken**, um die Dateien zu verwalten. In diesem\
Du findest die Datenbanken in den Ordnern:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Und die wichtigsten Datenbanken sind:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Die Erweiterung ".dbx" bedeutet, dass die **Datenbanken** **verschlüsselt** sind. Dropbox verwendet **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Um die von Dropbox verwendete Verschlüsselung besser zu verstehen, kannst du [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) lesen.<sup>[[1]](#references)[[2]](#references)</sup>

Die wichtigsten Informationen sind jedoch:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Zusätzlich zu diesen Informationen benötigst du weiterhin Folgendes, um die Datenbanken zu entschlüsseln:<sup>[[2]](#references)</sup>

- Der **verschlüsselte DPAPI-Schlüssel**: Du findest ihn in der Registry unter `NTUSER.DAT\Software\Dropbox\ks\client` (exportiere diese Daten als Binärdaten)
- Die Hives **`SYSTEM`** und **`SECURITY`**
- Die **DPAPI-Masterschlüssel**: Sie befinden sich unter `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Den **Benutzernamen** und das **Passwort** des Windows-Benutzers

Anschließend kannst du das Tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** verwenden:**

![Google Drive - Dropbox: Dann kannst du das Tool DataProtectionDecryptor verwenden](<../../../images/image (443).png>)

Wenn alles wie erwartet funktioniert, zeigt das Tool den **primären Schlüssel** an, den du **verwenden musst, um den ursprünglichen Schlüssel wiederherzustellen**. Um den ursprünglichen Schlüssel wiederherzustellen, verwende einfach dieses [cyber_chef-Rezept](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) und füge den primären Schlüssel als "Passphrase" in das Rezept ein.

Das resultierende Hex ist der endgültige Schlüssel, der zur Verschlüsselung der Datenbanken verwendet wird. Diese können entschlüsselt werden mit:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`**-Datenbank enthält:

- **Email**: Die E-Mail-Adresse des Benutzers
- **usernamedisplayname**: Der Name des Benutzers
- **dropbox_path**: Pfad zum Speicherort des Dropbox-Ordners
- **Host_id: Hash**: Wird zur Authentifizierung bei der Cloud verwendet. Dieser kann nur über das Web widerrufen werden.
- **Root_ns**: Benutzerkennung

Die **`filecache.db`**-Datenbank enthält Informationen über alle mit Dropbox synchronisierten Dateien und Ordner. Die Tabelle `File_journal` enthält die nützlichsten Informationen:

- **Server_path**: Pfad zum Speicherort der Datei auf dem Server (diesem Pfad wird die `host_id` des Clients vorangestellt).
- **local_sjid**: Version der Datei
- **local_mtime**: Änderungsdatum
- **local_ctime**: Erstellungsdatum

Andere Tabellen innerhalb dieser Datenbank enthalten weitere interessante Informationen:

- **block_cache**: Hash aller Dateien und Ordner von Dropbox
- **block_ref**: Verknüpft die Hash-ID der Tabelle `block_cache` mit der Datei-ID in der Tabelle `file_journal`
- **mount_table**: Freigegebene Dropbox-Ordner
- **deleted_fields**: Von Dropbox gelöschte Dateien
- **date_added**

## Referenzen

- [1] [Eine kritische Analyse der Sicherheit der Dropbox-Software (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Auffrischung zur Entschlüsselung von Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
