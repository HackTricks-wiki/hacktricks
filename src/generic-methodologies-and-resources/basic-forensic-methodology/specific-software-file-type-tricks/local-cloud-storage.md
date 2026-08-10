# Lokaler Cloud-Speicher

## OneDrive

Unter Windows befindet sich der OneDrive-Ordner unter `\Users\<username>\AppData\Local\Microsoft\OneDrive`. In `logs\Personal` findet sich außerdem die Datei `SyncDiagnostics.log`, die interessante Daten zu den synchronisierten Dateien enthält:<sup>[[3]](#references)</sup>

- Größe in Bytes
- Erstellungsdatum
- Änderungsdatum
- Anzahl der Dateien in der Cloud
- Anzahl der Dateien im Ordner
- **CID**: Eindeutige ID des OneDrive-Benutzers
- Zeitpunkt der Berichtserstellung
- Größe der HD des Betriebssystems

Sobald du die CID gefunden hast, wird empfohlen, **nach Dateien zu suchen, die diese ID enthalten**. Möglicherweise findest du Dateien mit den Namen _**\<CID>.ini**_ und _**\<CID>.dat**_, die interessante Informationen wie die Namen der mit OneDrive synchronisierten Dateien enthalten können.<sup>[[3]](#references)</sup>

## Google Drive

Unter Windows befindet sich der Hauptordner von Google Drive unter `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Dieser Ordner enthält eine Datei namens Sync_log.log, in der Synchronisierungssitzungen des Google Drive-Clients sowie Ereignisse beim Erstellen, Ändern und Löschen von Dateien aufgezeichnet werden.<sup>[[4]](#references)[[6]](#references)</sup>

Die Datei **`Cloud_graph\Cloud_graph.db`** ist eine sqlite-Datenbank.<sup>[[6]](#references)</sup> Sie enthält die Tabelle **`cloud_graph_entry`**. In dieser Tabelle findest du den **Namen** der **synchronisierten** **Dateien**, den Änderungszeitpunkt, die Größe und die MD5-Prüfsumme der Dateien.

Die Tabelle **`cloud_entry`** der zugehörigen Datenbank **`snapshot.db`** kann entfernte Datensätze mit Dateinamen, Zeitstempeln, Größen und Prüfsummen enthalten.<sup>[[4]](#references)</sup>

Die Tabellendaten der Datenbank **`Sync_config.db`** enthalten die E-Mail-Adresse des Kontos, den Pfad der freigegebenen Ordner und die Google Drive-Version.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox verwendet **SQLite-Datenbanken**, um die Dateien zu verwalten.<sup>[[2]](#references)</sup> In diesem\
Du findest die Datenbanken in den Ordnern:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Die wichtigsten Datenbanken sind:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Die Erweiterung ".dbx" bedeutet, dass die **Datenbanken** **verschlüsselt** sind. Dropbox verwendet **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Um die von Dropbox verwendete Verschlüsselung besser zu verstehen, kannst du [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) lesen.<sup>[[1]](#references)[[2]](#references)</sup>

Die wichtigsten Informationen sind jedoch:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Abgesehen von diesen Informationen benötigst du zum Entschlüsseln der Datenbanken weiterhin:<sup>[[2]](#references)</sup>

- Den **verschlüsselten DPAPI-Schlüssel**: Du findest ihn in der Registry unter `NTUSER.DAT\Software\Dropbox\ks\client` (exportiere diese Daten als Binärdaten)
- Die Hives **`SYSTEM`** und **`SECURITY`**
- Die **DPAPI-Masterschlüssel**: Sie befinden sich unter `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Den **Benutzernamen** und das **Passwort** des Windows-Benutzers

Anschließend kannst du das Tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** verwenden:**

![Google Drive - Dropbox: Anschließend kannst du das Tool DataProtectionDecryptor verwenden](<../../../images/image (443).png>)

Wenn alles wie erwartet funktioniert, zeigt das Tool den **primären Schlüssel** an, den du **zur Wiederherstellung des ursprünglichen Schlüssels verwenden** musst. Um den ursprünglichen Schlüssel wiederherzustellen, verwende einfach dieses [cyber_chef-Rezept](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>), indem du den primären Schlüssel als "Passphrase" in das Rezept einfügst.

Der resultierende Hex-Wert ist der finale Schlüssel, der zur Verschlüsselung der Datenbanken verwendet wird und mit Folgendem entschlüsselt werden kann:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`**-Datenbank enthält:

- **Email**: Die E-Mail-Adresse des Benutzers
- **usernamedisplayname**: Der Name des Benutzers
- **dropbox_path**: Pfad, unter dem sich der Dropbox-Ordner befindet
- **Host_id: Hash** wird zur Authentifizierung bei der Cloud verwendet. Dies kann nur über das Web widerrufen werden.
- **Root_ns**: Benutzerkennung

Die **`filecache.db`**-Datenbank enthält Informationen zu allen mit Dropbox synchronisierten Dateien und Ordnern. Die Tabelle `File_journal` enthält die nützlichsten Informationen:<sup>[[5]](#references)</sup>

- **Server_path**: Pfad, unter dem sich die Datei auf dem Server befindet (diesem Pfad wird die `host_id` des Clients vorangestellt).
- **local_sjid**: Version der Datei
- **local_mtime**: Änderungsdatum
- **local_ctime**: Erstellungsdatum

Andere Tabellen in dieser Datenbank enthalten weitere interessante Informationen:

- **block_cache**: Hash aller Dateien und Ordner von Dropbox
- **block_ref**: Verknüpft die Hash-ID der Tabelle `block_cache` mit der Datei-ID in der Tabelle `file_journal`
- **mount_table**: Freigegebene Dropbox-Ordner
- **deleted_fields**: Gelöschte Dropbox-Dateien
- **date_added**

## References

- [1] [Eine kritische Analyse der Dropbox-Softwaresicherheit (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox-DBX-Verschlüsselung auffrischen](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Forensische Analyse von Cloud Storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage Case: Antworten zur Leakage](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox Forensics](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefakte der Google-Drive-Nutzung unter Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
