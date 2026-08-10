# Browser-Artefakte

## Browser-Artefakte <a href="#id-3def" id="id-3def"></a>

Browser-Artefakte umfassen verschiedene Arten von Daten, die von Webbrowsern gespeichert werden, etwa Navigationsverlauf, Lesezeichen und Cache-Daten. Diese Artefakte werden in bestimmten Ordnern innerhalb des Betriebssystems gespeichert. Speicherort und Name unterscheiden sich je nach Browser, wobei im Allgemeinen ähnliche Datentypen gespeichert werden.

Hier eine Übersicht der häufigsten Browser-Artefakte:

- **Navigationsverlauf**: Erfasst die Besuche des Benutzers auf Websites und ist nützlich, um Besuche auf schädlichen Websites zu erkennen.
- **Autocomplete-Daten**: Vorschläge auf Grundlage häufiger Suchanfragen, die in Kombination mit dem Navigationsverlauf Erkenntnisse liefern können.
- **Lesezeichen**: Vom Benutzer gespeicherte Websites für den schnellen Zugriff.
- **Extensions und Add-ons**: Vom Benutzer installierte Browser-Extensions oder Add-ons.
- **Cache**: Speichert Webinhalte, z. B. Bilder und JavaScript-Dateien, um die Ladezeiten von Websites zu verbessern, und ist für die forensische Analyse wertvoll.
- **Logins**: Gespeicherte Anmeldedaten.
- **Favicons**: Mit Websites verbundene Symbole, die in Tabs und Lesezeichen angezeigt werden und zusätzliche Informationen über die Besuche des Benutzers liefern können.
- **Browsersitzungen**: Daten zu geöffneten Browsersitzungen.
- **Downloads**: Aufzeichnungen der über den Browser heruntergeladenen Dateien.
- **Formulardaten**: In Webformularen eingegebene Informationen, die für zukünftige Autofill-Vorschläge gespeichert werden.
- **Thumbnails**: Vorschaubilder von Websites.
- **Custom Dictionary.txt**: Vom Benutzer zum Wörterbuch des Browsers hinzugefügte Wörter.

## Firefox

Firefox organisiert Benutzerdaten in Profilen, die abhängig vom Betriebssystem an bestimmten Speicherorten abgelegt werden:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Eine Datei `profiles.ini` in diesen Verzeichnissen listet die Benutzerprofile auf. Die Daten jedes Profils werden in einem Ordner gespeichert, dessen Name in der Variable `Path` innerhalb von `profiles.ini` angegeben ist und der sich im selben Verzeichnis wie `profiles.ini` selbst befindet. Fehlt der Profilordner, wurde er möglicherweise gelöscht.

In jedem Profilordner befinden sich mehrere wichtige Dateien:<sup>[[1]](#references)</sup>

- **places.sqlite**: Speichert Verlauf, Lesezeichen und Downloads. Tools wie [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) unter Windows können auf die Verlaufsdaten zugreifen.
- Verwende spezifische SQL-Abfragen, um Informationen zu Verlauf und Downloads zu extrahieren.
- **bookmarkbackups**: Enthält Sicherungskopien der Lesezeichen.
- **formhistory.sqlite**: Speichert Webformulardaten.
- **handlers.json**: Verwaltet Protokoll-Handler.
- **persdict.dat**: Benutzerdefinierte Wörterbuchwörter.
- **addons.json** und **extensions.sqlite**: Informationen über installierte Add-ons und Extensions.
- **cookies.sqlite**: Speichert Cookies; unter Windows steht zur Untersuchung [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) zur Verfügung.
- **cache2/entries** oder **startupCache**: Cache-Daten, auf die mit Tools wie [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) zugegriffen werden kann.
- **favicons.sqlite**: Speichert Favicons.
- **prefs.js**: Benutzereinstellungen und Präferenzen.
- **downloads.sqlite**: Ältere Download-Datenbank, die inzwischen in places.sqlite integriert ist.
- **thumbnails**: Thumbnails von Websites.
- **logins.json**: Verschlüsselte Anmeldeinformationen.
- **key4.db** oder **key3.db**: Speichert Verschlüsselungsschlüssel zum Schutz sensibler Informationen.

Zusätzlich können die Anti-Phishing-Einstellungen des Browsers überprüft werden, indem in `prefs.js` nach Einträgen mit `browser.safebrowsing` gesucht wird. Diese zeigen an, ob die Safe-Browsing-Funktionen aktiviert oder deaktiviert sind.<sup>[[2]](#references)</sup>

Um zu versuchen, das Masterpasswort zu entschlüsseln, kannst du [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) verwenden.\
Mit dem folgenden Script und Aufruf kannst du eine Passwortdatei zum Brute-Forcen angeben:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Browser-Artefakte - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome speichert Benutzerprofile abhängig vom Betriebssystem an bestimmten Speicherorten:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

In diesen Verzeichnissen befinden sich die meisten Benutzerdaten in den Ordnern **Default/** oder **ChromeDefaultData/**. Die folgenden Dateien enthalten wichtige Daten:<sup>[[1]](#references)</sup>

- **History**: Enthält URLs, Downloads und Suchbegriffe. Unter Windows kann [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) zum Lesen des Verlaufs verwendet werden. Die Spalte „Transition Type“ hat verschiedene Bedeutungen, darunter Benutzerklicks auf Links, eingegebene URLs, Formularübermittlungen und Seitenaktualisierungen.
- **Cookies**: Speichert Cookies. Zur Untersuchung steht [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) zur Verfügung.
- **Cache**: Enthält zwischengespeicherte Daten. Zur Untersuchung können Windows-Benutzer [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) verwenden.

Auf Electron basierende Desktop-Apps (z. B. Discord) verwenden ebenfalls den Chromium Simple Cache und hinterlassen umfangreiche Artefakte auf der Festplatte. Siehe:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Benutzerlesezeichen.
- **Web Data**: Enthält den Formularverlauf.
- **Favicons**: Speichert Website-Favicons.
- **Login Data**: Enthält Anmeldedaten wie Benutzernamen und Passwörter.
- **Current Session**/**Current Tabs**: Daten zur aktuellen Browsersitzung und zu geöffneten Tabs.
- **Last Session**/**Last Tabs**: Informationen zu den Websites, die während der letzten Sitzung vor dem Schließen von Chrome aktiv waren.
- **Extensions**: Verzeichnisse für Browsererweiterungen und Add-ons.
- **Thumbnails**: Speichert Website-Vorschaubilder.
- **Preferences**: Eine sehr informationsreiche Datei, die Einstellungen für Plugins, Erweiterungen, Pop-ups, Benachrichtigungen und mehr enthält.
- **Browser’s built-in anti-phishing**: Um zu überprüfen, ob anti-phishing und Malware-Schutz aktiviert sind, führe `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` aus. Suche in der Ausgabe nach `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **Wiederherstellung von SQLite-DB-Daten**

Wie in den vorherigen Abschnitten zu sehen ist, verwenden sowohl Chrome als auch Firefox **SQLite**-Datenbanken zum Speichern der Daten. Es ist möglich, **gelöschte Einträge mit dem Tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oder** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **wiederherzustellen**.

## **Internet Explorer 11**

Internet Explorer 11 verwaltet seine Daten und Metadaten an verschiedenen Speicherorten. Dies erleichtert die Trennung der gespeicherten Informationen von den zugehörigen Details und damit deren Zugriff und Verwaltung.

### Metadatenspeicherung

Die Metadaten von Internet Explorer werden in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` gespeichert (wobei VX für V01, V16 oder V24 steht). Die zugehörige Datei `V01.log` kann Abweichungen bei den Änderungszeiten gegenüber `WebcacheVX.data` aufweisen, was auf einen Reparaturbedarf mit `esentutl /r V01 /d` hinweist. Diese Metadaten befinden sich in einer ESE-Datenbank und können mit Tools wie photorec beziehungsweise [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) wiederhergestellt und untersucht werden. In der Tabelle **Containers** lässt sich erkennen, in welchen spezifischen Tabellen oder Containern die einzelnen Datensegmente gespeichert sind, einschließlich Cache-Details für andere Microsoft-Tools wie Skype.

### Cache-Untersuchung

Das Tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) ermöglicht die Untersuchung des Caches und benötigt den Speicherort des Ordners für die extrahierten Cache-Daten. Die Cache-Metadaten umfassen Dateiname, Verzeichnis, Zugriffszähler, URL-Ursprung sowie Zeitstempel für die Erstellung, den Zugriff, die Änderung und den Ablauf des Caches.

### Cookie-Verwaltung

Cookies können mit [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) untersucht werden. Die Metadaten umfassen Namen, URLs, Zugriffszähler und verschiedene zeitbezogene Details. Persistente Cookies werden in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gespeichert, während Sitzungscookies im Arbeitsspeicher liegen.

### Download-Details

Download-Metadaten sind über [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) zugänglich. Bestimmte Container enthalten Daten wie URL, Dateityp und Download-Speicherort. Physische Dateien befinden sich unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browserverlauf

Zur Untersuchung des Browserverlaufs kann [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) verwendet werden. Dafür werden der Speicherort der extrahierten Verlaufsdateien und die Konfiguration für Internet Explorer benötigt. Die Metadaten umfassen Änderungs- und Zugriffszeiten sowie Zugriffszähler. Verlaufsdateien befinden sich in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Eingegebene URLs

Eingegebene URLs und deren Nutzungszeiten werden in der Registry unter `NTUSER.DAT` in `Software\Microsoft\InternetExplorer\TypedURLs` und `Software\Microsoft\InternetExplorer\TypedURLsTime` gespeichert. Dabei werden die letzten 50 vom Benutzer eingegebenen URLs und deren letzte Eingabezeiten erfasst.

## Microsoft Edge

Microsoft Edge speichert Benutzerdaten in `%userprofile%\Appdata\Local\Packages`. Die Pfade für verschiedene Datentypen sind:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-Daten werden unter `/Users/$User/Library/Safari` gespeichert. Zu den wichtigsten Dateien gehören:<sup>[[3]](#references)</sup>

- **History.db**: Enthält die Tabellen `history_visits` und `history_items` mit URLs und Zeitstempeln der Besuche. Verwende `sqlite3` für Abfragen.
- **Downloads.plist**: Informationen zu heruntergeladenen Dateien.
- **Bookmarks.plist**: Speichert mit Lesezeichen versehene URLs.
- **TopSites.plist**: Am häufigsten besuchte Websites.
- **Extensions.plist**: Liste der Safari-Browsererweiterungen. Verwende `plutil` oder `pluginkit` zum Abrufen.
- **UserNotificationPermissions.plist**: Domains, die Push-Benachrichtigungen senden dürfen. Verwende `plutil` zum Parsen.
- **LastSession.plist**: Tabs aus der letzten Sitzung. Verwende `plutil` zum Parsen.
- **Browser’s built-in anti-phishing**: Überprüfe dies mit `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Eine Antwort von 1 zeigt an, dass die Funktion aktiv ist.<sup>[[2]](#references)</sup>

## Opera

Die Daten von Opera befinden sich in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` und verwenden für Verlauf und Downloads dasselbe Format wie Chrome.

- **Browser’s built-in anti-phishing**: Überprüfe mit `grep`, ob `fraud_protection_enabled` in der Preferences-Datei auf `true` gesetzt ist.<sup>[[2]](#references)</sup>

Diese Pfade und Befehle sind entscheidend für den Zugriff auf und das Verständnis der von verschiedenen Webbrowsern gespeicherten Browsing-Daten.

## References

- [1] [Forensik von Webbrowsern: Ein Leitfaden zur forensischen Analyse von Webbrowsern](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Teil 3: Systemmanipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting und Analyse von Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
