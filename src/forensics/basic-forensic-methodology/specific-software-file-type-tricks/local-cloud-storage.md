# Lokaler Cloud-Speicher

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

In Windows finden Sie den OneDrive-Ordner unter `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Und im Inneren von `logs\Personal` ist es möglich, die Datei `SyncDiagnostics.log` zu finden, die einige interessante Daten zu den synchronisierten Dateien enthält:

- Größe in Bytes
- Erstellungsdatum
- Änderungsdatum
- Anzahl der Dateien in der Cloud
- Anzahl der Dateien im Ordner
- **CID**: Eindeutige ID des OneDrive-Benutzers
- Zeit der Berichtserstellung
- Größe der HD des Betriebssystems

Sobald Sie die CID gefunden haben, wird empfohlen, **Dateien mit dieser ID zu suchen**. Möglicherweise finden Sie Dateien mit den Namen: _**\<CID>.ini**_ und _**\<CID>.dat**_, die interessante Informationen wie die Namen der mit OneDrive synchronisierten Dateien enthalten können.

## Google Drive

In Windows finden Sie den Hauptordner von Google Drive unter `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Dieser Ordner enthält eine Datei namens Sync_log.log mit Informationen wie der E-Mail-Adresse des Kontos, Dateinamen, Zeitstempeln, MD5-Hashes der Dateien usw. Selbst gelöschte Dateien erscheinen in dieser Protokolldatei mit ihrem entsprechenden MD5.

Die Datei **`Cloud_graph\Cloud_graph.db`** ist eine SQLite-Datenbank, die die Tabelle **`cloud_graph_entry`** enthält. In dieser Tabelle finden Sie den **Namen** der **synchronisierten** **Dateien**, das Änderungsdatum, die Größe und die MD5-Prüfziffer der Dateien.

Die Tabellendaten der Datenbank **`Sync_config.db`** enthalten die E-Mail-Adresse des Kontos, den Pfad der freigegebenen Ordner und die Google Drive-Version.

## Dropbox

Dropbox verwendet **SQLite-Datenbanken**, um die Dateien zu verwalten. In diesem\
Sie finden die Datenbanken in den Ordnern:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Und die Hauptdatenbanken sind:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Die ".dbx"-Erweiterung bedeutet, dass die **Datenbanken** **verschlüsselt** sind. Dropbox verwendet **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Um die Verschlüsselung, die Dropbox verwendet, besser zu verstehen, können Sie [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) lesen.

Die wichtigsten Informationen sind jedoch:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithmus**: PBKDF2
- **Iterationen**: 1066

Neben diesen Informationen benötigen Sie zur Entschlüsselung der Datenbanken noch:

- Den **verschlüsselten DPAPI-Schlüssel**: Sie finden ihn in der Registrierung unter `NTUSER.DAT\Software\Dropbox\ks\client` (exportieren Sie diese Daten als Binärdatei)
- Die **`SYSTEM`**- und **`SECURITY`**-Hives
- Die **DPAPI-Master-Schlüssel**: Diese finden Sie unter `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Den **Benutzernamen** und das **Passwort** des Windows-Benutzers

Dann können Sie das Tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (448).png>)

Wenn alles wie erwartet verläuft, zeigt das Tool den **primären Schlüssel** an, den Sie **verwenden müssen, um den ursprünglichen wiederherzustellen**. Um den ursprünglichen wiederherzustellen, verwenden Sie einfach dieses [cyber_chef Rezept](<https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) und setzen den primären Schlüssel als "Passphrase" in das Rezept ein.

Das resultierende Hex ist der endgültige Schlüssel, der zur Verschlüsselung der Datenbanken verwendet wird und mit folgendem entschlüsselt werden kann:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Die **`config.dbx`** Datenbank enthält:

- **Email**: Die E-Mail des Benutzers
- **usernamedisplayname**: Der Name des Benutzers
- **dropbox_path**: Pfad, wo der Dropbox-Ordner gespeichert ist
- **Host_id: Hash** verwendet zur Authentifizierung in der Cloud. Dies kann nur über das Web widerrufen werden.
- **Root_ns**: Benutzeridentifikator

Die **`filecache.db`** Datenbank enthält Informationen über alle Dateien und Ordner, die mit Dropbox synchronisiert sind. Die Tabelle `File_journal` enthält die nützlichsten Informationen:

- **Server_path**: Pfad, wo die Datei auf dem Server gespeichert ist (dieser Pfad wird durch die `host_id` des Clients vorangestellt).
- **local_sjid**: Version der Datei
- **local_mtime**: Änderungsdatum
- **local_ctime**: Erstellungsdatum

Andere Tabellen in dieser Datenbank enthalten weitere interessante Informationen:

- **block_cache**: Hash aller Dateien und Ordner von Dropbox
- **block_ref**: Verknüpft die Hash-ID der Tabelle `block_cache` mit der Datei-ID in der Tabelle `file_journal`
- **mount_table**: Freigegebene Ordner von Dropbox
- **deleted_fields**: Gelöschte Dateien von Dropbox
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
