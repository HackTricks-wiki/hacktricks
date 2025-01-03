# Browser Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Browser Artefakte <a href="#id-3def" id="id-3def"></a>

Browserartefakte umfassen verschiedene Arten von Daten, die von Webbrowsern gespeichert werden, wie z. B. Navigationsverlauf, Lesezeichen und Cache-Daten. Diese Artefakte werden in spezifischen Ordnern innerhalb des Betriebssystems aufbewahrt, die sich in Standort und Namen zwischen den Browsern unterscheiden, jedoch im Allgemeinen ähnliche Datentypen speichern.

Hier ist eine Zusammenfassung der häufigsten Browserartefakte:

- **Navigationsverlauf**: Verfolgt die Besuche des Benutzers auf Websites, nützlich zur Identifizierung von Besuchen auf bösartigen Seiten.
- **Autocomplete-Daten**: Vorschläge basierend auf häufigen Suchen, die Einblicke bieten, wenn sie mit dem Navigationsverlauf kombiniert werden.
- **Lesezeichen**: Von Benutzern gespeicherte Seiten für den schnellen Zugriff.
- **Erweiterungen und Add-ons**: Vom Benutzer installierte Browsererweiterungen oder Add-ons.
- **Cache**: Speichert Webinhalte (z. B. Bilder, JavaScript-Dateien), um die Ladezeiten von Websites zu verbessern, wertvoll für die forensische Analyse.
- **Logins**: Gespeicherte Anmeldeinformationen.
- **Favicons**: Icons, die mit Websites verbunden sind und in Tabs und Lesezeichen erscheinen, nützlich für zusätzliche Informationen zu Benutzerbesuchen.
- **Browser-Sitzungen**: Daten zu offenen Browsersitzungen.
- **Downloads**: Aufzeichnungen von über den Browser heruntergeladenen Dateien.
- **Formulardaten**: Informationen, die in Webformularen eingegeben werden, gespeichert für zukünftige Autofill-Vorschläge.
- **Thumbnails**: Vorschau-Bilder von Websites.
- **Custom Dictionary.txt**: Vom Benutzer zum Wörterbuch des Browsers hinzugefügte Wörter.

## Firefox

Firefox organisiert Benutzerdaten innerhalb von Profilen, die an spezifischen Orten basierend auf dem Betriebssystem gespeichert sind:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Eine `profiles.ini`-Datei innerhalb dieser Verzeichnisse listet die Benutzerprofile auf. Die Daten jedes Profils werden in einem Ordner gespeichert, der im `Path`-Variablen innerhalb von `profiles.ini` benannt ist, der sich im selben Verzeichnis wie `profiles.ini` selbst befindet. Wenn der Ordner eines Profils fehlt, könnte er gelöscht worden sein.

Innerhalb jedes Profilordners finden Sie mehrere wichtige Dateien:

- **places.sqlite**: Speichert Verlauf, Lesezeichen und Downloads. Tools wie [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) auf Windows können auf die Verlaufsdaten zugreifen.
- Verwenden Sie spezifische SQL-Abfragen, um Verlauf und Downloadinformationen zu extrahieren.
- **bookmarkbackups**: Enthält Backups von Lesezeichen.
- **formhistory.sqlite**: Speichert Webformulardaten.
- **handlers.json**: Verwaltet Protokollhandler.
- **persdict.dat**: Benutzerdefinierte Wörter im Wörterbuch.
- **addons.json** und **extensions.sqlite**: Informationen zu installierten Add-ons und Erweiterungen.
- **cookies.sqlite**: Cookie-Speicher, mit [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) verfügbar zur Inspektion auf Windows.
- **cache2/entries** oder **startupCache**: Cache-Daten, zugänglich über Tools wie [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Speichert Favicons.
- **prefs.js**: Benutzereinstellungen und -präferenzen.
- **downloads.sqlite**: Ältere Download-Datenbank, jetzt in places.sqlite integriert.
- **thumbnails**: Website-Thumbnails.
- **logins.json**: Verschlüsselte Anmeldeinformationen.
- **key4.db** oder **key3.db**: Speichert Verschlüsselungsschlüssel zum Schutz sensibler Informationen.

Zusätzlich kann die Überprüfung der Anti-Phishing-Einstellungen des Browsers erfolgen, indem nach `browser.safebrowsing`-Einträgen in `prefs.js` gesucht wird, die anzeigen, ob die Funktionen für sicheres Browsen aktiviert oder deaktiviert sind.

Um das Master-Passwort zu entschlüsseln, können Sie [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) verwenden.\
Mit dem folgenden Skript und Aufruf können Sie eine Passwortdatei zum Brute-Forcen angeben:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome speichert Benutzerprofile an spezifischen Orten, abhängig vom Betriebssystem:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Innerhalb dieser Verzeichnisse sind die meisten Benutzerdaten in den Ordnern **Default/** oder **ChromeDefaultData/** zu finden. Die folgenden Dateien enthalten bedeutende Daten:

- **History**: Enthält URLs, Downloads und Suchbegriffe. Unter Windows kann [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) verwendet werden, um die Historie zu lesen. Die Spalte "Transition Type" hat verschiedene Bedeutungen, einschließlich Benutzerklicks auf Links, eingegebene URLs, Formularübermittlungen und Seitenaktualisierungen.
- **Cookies**: Speichert Cookies. Zur Inspektion steht [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) zur Verfügung.
- **Cache**: Hält zwischengespeicherte Daten. Zur Inspektion können Windows-Benutzer [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) nutzen.
- **Bookmarks**: Benutzer-Lesezeichen.
- **Web Data**: Enthält Formularhistorie.
- **Favicons**: Speichert Website-Favicons.
- **Login Data**: Enthält Anmeldeinformationen wie Benutzernamen und Passwörter.
- **Current Session**/**Current Tabs**: Daten über die aktuelle Browsersitzung und offene Tabs.
- **Last Session**/**Last Tabs**: Informationen über die während der letzten Sitzung aktiven Seiten, bevor Chrome geschlossen wurde.
- **Extensions**: Verzeichnisse für Browsererweiterungen und Add-ons.
- **Thumbnails**: Speichert Website-Thumbnails.
- **Preferences**: Eine informationsreiche Datei, die Einstellungen für Plugins, Erweiterungen, Pop-ups, Benachrichtigungen und mehr enthält.
- **Browser’s built-in anti-phishing**: Um zu überprüfen, ob der Anti-Phishing- und Malware-Schutz aktiviert ist, führen Sie `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` aus. Suchen Sie nach `{"enabled: true,"}` in der Ausgabe.

## **SQLite DB Datenwiederherstellung**

Wie in den vorherigen Abschnitten zu beobachten ist, verwenden sowohl Chrome als auch Firefox **SQLite**-Datenbanken zur Speicherung der Daten. Es ist möglich, **gelöschte Einträge mit dem Tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oder** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **wiederherzustellen**.

## **Internet Explorer 11**

Internet Explorer 11 verwaltet seine Daten und Metadaten an verschiedenen Orten, um die gespeicherten Informationen und deren entsprechende Details für einen einfachen Zugriff und eine einfache Verwaltung zu trennen.

### Metadatenspeicherung

Metadaten für Internet Explorer werden in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` gespeichert (wobei VX V01, V16 oder V24 sein kann). Begleitend dazu könnte die Datei `V01.log` Zeitabweichungen mit `WebcacheVX.data` anzeigen, was auf einen Reparaturbedarf mit `esentutl /r V01 /d` hinweist. Diese Metadaten, die in einer ESE-Datenbank gespeichert sind, können mit Tools wie photorec und [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) wiederhergestellt und inspiziert werden. Innerhalb der **Containers**-Tabelle kann man die spezifischen Tabellen oder Container erkennen, in denen jedes Datensegment gespeichert ist, einschließlich Cache-Details für andere Microsoft-Tools wie Skype.

### Cache-Inspektion

Das Tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) ermöglicht die Inspektion des Caches und erfordert den Speicherort des Ordners zur Extraktion der Cache-Daten. Die Metadaten für den Cache umfassen Dateinamen, Verzeichnis, Zugriffsanzahl, URL-Ursprung und Zeitstempel, die die Erstellung, den Zugriff, die Modifikation und die Ablaufzeiten des Caches anzeigen.

### Cookie-Verwaltung

Cookies können mit [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) erkundet werden, wobei die Metadaten Namen, URLs, Zugriffsanzahl und verschiedene zeitbezogene Details umfassen. Persistente Cookies werden in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gespeichert, während Sitzungscookies im Speicher verbleiben.

### Download-Details

Metadaten zu Downloads sind über [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) zugänglich, wobei spezifische Container Daten wie URL, Dateityp und Downloadort enthalten. Physische Dateien sind unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` zu finden.

### Browserverlauf

Um den Browserverlauf zu überprüfen, kann [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) verwendet werden, wobei der Speicherort der extrahierten Verlaufsdateien und die Konfiguration für Internet Explorer erforderlich sind. Die Metadaten hier umfassen Änderungs- und Zugriffszeiten sowie Zugriffsanzahlen. Verlaufsdateien befinden sich in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Eingetippte URLs

Eingetippte URLs und deren Nutzungszeiten werden im Registrierungseditor unter `NTUSER.DAT` bei `Software\Microsoft\InternetExplorer\TypedURLs` und `Software\Microsoft\InternetExplorer\TypedURLsTime` gespeichert, wobei die letzten 50 vom Benutzer eingegebenen URLs und deren letzte Eingabezeiten verfolgt werden.

## Microsoft Edge

Microsoft Edge speichert Benutzerdaten in `%userprofile%\Appdata\Local\Packages`. Die Pfade für verschiedene Datentypen sind:

- **Profilpfad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Verlauf, Cookies und Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Einstellungen, Lesezeichen und Leseliste**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Letzte aktive Sitzungen**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-Daten werden unter `/Users/$User/Library/Safari` gespeichert. Wichtige Dateien sind:

- **History.db**: Enthält die Tabellen `history_visits` und `history_items` mit URLs und Besuchszeitstempeln. Verwenden Sie `sqlite3`, um Abfragen durchzuführen.
- **Downloads.plist**: Informationen über heruntergeladene Dateien.
- **Bookmarks.plist**: Speichert die Lesezeichen-URLs.
- **TopSites.plist**: Am häufigsten besuchte Seiten.
- **Extensions.plist**: Liste der Safari-Browsererweiterungen. Verwenden Sie `plutil` oder `pluginkit`, um sie abzurufen.
- **UserNotificationPermissions.plist**: Domains, die Benachrichtigungen senden dürfen. Verwenden Sie `plutil`, um sie zu parsen.
- **LastSession.plist**: Tabs aus der letzten Sitzung. Verwenden Sie `plutil`, um sie zu parsen.
- **Browser’s built-in anti-phishing**: Überprüfen Sie mit `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Eine Antwort von 1 zeigt an, dass die Funktion aktiv ist.

## Opera

Die Daten von Opera befinden sich in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` und verwenden das gleiche Format wie Chrome für Verlauf und Downloads.

- **Browser’s built-in anti-phishing**: Überprüfen Sie, ob `fraud_protection_enabled` in der Preferences-Datei auf `true` gesetzt ist, indem Sie `grep` verwenden.

Diese Pfade und Befehle sind entscheidend für den Zugriff auf und das Verständnis der von verschiedenen Webbrowsern gespeicherten Browsing-Daten.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Buch: OS X Incident Response: Scripting and Analysis von Jaron Bradley, Seite 123**

{{#include ../../../banners/hacktricks-training.md}}
