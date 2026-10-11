# Lokaler Cloud-Speicher

{{#include ../../../banners/hacktricks-training.md}}

## Lokale Speicheremulatoren und Account-Schlüssel

Ein Azure-kompatibler Blob-Emulator in einem Container kann von seinem Host oder Bridge-Netzwerk aus erreichbar sein, auch wenn der Speicherdienst nicht extern zugänglich ist. Prüfe lesbare lokale Konfigurationen und Metadaten von Backup-Dateien auf einen Account-Namen und -Schlüssel, ohne den Schlüssel bei routinemäßigen Aufzählungen auszugeben. [Azurite unterstützt benutzerdefinierte lokale Account-Schlüssel](https://learn.microsoft.com/en-us/azure/storage/common/storage-azurite); [Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) kann breiten Zugriff auf die Daten des entsprechenden Accounts gewähren. Eine Schlüsseldatei allein belegt keine Rechteausweitung: Bestätige, dass der Endpunkt erreichbar ist, Account und Schlüssel akzeptiert werden und das konkrete Blob tatsächlich ein nutzbares Zugangsmittel für eine Identität mit höheren Berechtigungen enthält. Enthält es einen privaten SSH-Schlüssel, muss auch der zugehörige öffentliche Schlüssel für diese Identität autorisiert sein und SSH-Zugriff erlaubt sein. Schütze und rotiere einen Schlüssel, sobald seine Offenlegung bestätigt ist.

## OneDrive

Unter Windows findest du den OneDrive-Ordner unter `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Im Ordner `logs\Personal` findest du möglicherweise die Datei `SyncDiagnostics.log`, die interessante Daten zu synchronisierten Dateien enthält:<sup>[[3]](#references)</sup>

- Größe in Bytes
- Erstellungsdatum
- Änderungsdatum
- Anzahl der Dateien in der Cloud
- Anzahl der Dateien im Ordner
- **CID**: Eindeutige ID des OneDrive-Benutzers
- Zeitpunkt der Berichtserstellung
- Größe der Festplatte des Betriebssystems

Wenn du die CID gefunden hast, empfiehlt es sich, **nach Dateien zu suchen, die diese ID enthalten**. Möglicherweise findest du Dateien mit den Namen _**\<CID>.ini**_ und _**\<CID>.dat**_, die interessante Informationen enthalten können, etwa die Namen der mit OneDrive synchronisierten Dateien.<sup>[[3]](#references)</sup>

## Google Drive

Unter Windows findest du den Hauptordner von Google Drive unter `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Dieser Ordner enthält eine Datei namens Sync_log.log, in der Google-Drive-Client-Synchronisierungssitzungen sowie Datei-Erstellungs-, Änderungs- und Löschereignisse protokolliert werden.<sup>[[4]](#references)[[6]](#references)</sup>

Die Datei **`Cloud_graph\Cloud_graph.db`** ist eine SQLite-Datenbank.<sup>[[6]](#references)</sup> Sie enthält die Tabelle **`cloud_graph_entry`**. In dieser Tabelle findest du den **Namen** der **synchronisierten** **Dateien**, den Änderungszeitpunkt, die Größe und die MD5-Prüfsumme der Dateien.

Die Tabelle **`cloud_entry`** der zugehörigen Datenbank **`snapshot.db`** kann entfernte Datensätze mit Dateinamen, Zeitstempeln, Größen und Prüfsummen enthalten.<sup>[[4]](#references)</sup>

Die Tabellendaten der Datenbank **`Sync_config.db`** enthalten die E-Mail-Adresse des Accounts, den Pfad der freigegebenen Ordner und die Google-Drive-Version.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox verwendet **SQLite-Datenbanken** zur Verwaltung der Dateien.<sup>[[2]](#references)</sup> In diesem\
Ordner findest du die Datenbanken:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Die wichtigsten Datenbanken sind:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Die Erweiterung „.dbx“ bedeutet, dass die **Datenbanken** **verschlüsselt** sind. Dropbox verwendet **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Eine genauere Beschreibung der von Dropbox verwendeten Verschlüsselung findest du unter [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Die wichtigsten Informationen sind:<sup>[[1]](#references)</sup>

- **Entropie**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithmus**: PBKDF2
- **Iterationen**: 1066

Zusätzlich zu diesen Informationen benötigst du zum Entschlüsseln der Datenbanken noch Folgendes:<sup>[[2]](#references)</sup>

- Den **verschlüsselten DPAPI-Schlüssel**: Du findest ihn in der Registry unter `NTUSER.DAT\Software\Dropbox\ks\client` (exportiere diese Daten als Binärdatei)
- Die **`SYSTEM`**- und **`SECURITY`**-Hives
- Die **DPAPI-Masterschlüssel**: Du findest sie unter `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Den **Benutzernamen** und das **Passwort** des Windows-Benutzers

Anschließend kannst du das Tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** verwenden:**

![Google Drive - Dropbox: Anschließend kannst du das Tool DataProtectionDecryptor verwenden](<../../../images/image (443).png>)

Wenn alles wie erwartet läuft, zeigt das Tool den **Primärschlüssel** an, den du **zur Wiederherstellung des ursprünglichen Schlüssels verwenden musst**. Verwende zum Wiederherstellen des ursprünglichen Schlüssels einfach dieses [cyber_chef-Rezept](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) und gib den Primärschlüssel im Rezept als „passphrase“ ein.

Das resultierende Hex ist der endgültige Schlüssel, mit dem die Datenbanken verschlüsselt sind. Sie können damit entschlüsselt werden:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

Die Datenbank **`config.dbx`** enthält:

- **Email**: Die E-Mail-Adresse des Benutzers
- **usernamedisplayname**: Der Name des Benutzers
- **dropbox_path**: Pfad zum Speicherort des Dropbox-Ordners
- **Host_id: Hash**: Wird zur Authentifizierung bei der Cloud verwendet. Dieser kann nur über das Web widerrufen werden.
- **Root_ns**: Benutzerkennung

Die Datenbank **`filecache.db`** enthält Informationen zu allen mit Dropbox synchronisierten Dateien und Ordnern. Die Tabelle `File_journal` enthält die nützlichsten Informationen:<sup>[[5]](#references)</sup>

- **Server_path**: Pfad zum Speicherort der Datei auf dem Server (diesem Pfad wird die `host_id` des Clients vorangestellt).
- **local_sjid**: Version der Datei
- **local_mtime**: Änderungsdatum
- **local_ctime**: Erstellungsdatum

Andere Tabellen in dieser Datenbank enthalten weitere interessante Informationen:

- **block_cache**: Hashes aller Dropbox-Dateien und -Ordner
- **block_ref**: Verknüpft die Hash-ID aus der Tabelle `block_cache` mit der Datei-ID in der Tabelle `file_journal`
- **mount_table**: Freigegebene Dropbox-Ordner
- **deleted_fields**: Von Dropbox gelöschte Dateien
- **date_added**

## References

- [1] [Eine kritische Analyse der Sicherheit der Dropbox-Software (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox-DBX-Entschlüsselung auffrischen](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Forensische Analyse von Cloud-Speichern (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS-Fall zu Datenlecks: Antworten zum Leak](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox-Forensik](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefakte der Google-Drive-Nutzung unter Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
