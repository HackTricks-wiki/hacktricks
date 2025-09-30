# Browser-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Browser-Artefakte <a href="#id-3def" id="id-3def"></a>

Browser-Artefakte umfassen verschiedene Datentypen, die von Webbrowsern gespeichert werden, wie Navigationsverlauf, Lesezeichen und Cache-Daten. Diese Artefakte werden in bestimmten Ordnern des Betriebssystems abgelegt, unterscheiden sich in Speicherort und Namen je nach Browser, speichern jedoch im Allgemeinen ähnliche Datentypen.

Hier eine Zusammenfassung der häufigsten Browser-Artefakte:

- **Navigation History**: Verfolgt Besuche des Benutzers auf Websites; nützlich, um Besuche auf bösartigen Seiten zu identifizieren.
- **Autocomplete Data**: Vorschläge basierend auf häufigen Suchen, liefert zusammen mit dem Navigationsverlauf Einblicke.
- **Bookmarks**: Vom Benutzer gespeicherte Seiten für den Schnellzugriff.
- **Extensions and Add-ons**: Vom Benutzer installierte Browser-Erweiterungen oder Add-ons.
- **Cache**: Speichert Webinhalte (z. B. Bilder, JavaScript-Dateien), um Ladezeiten von Websites zu verbessern; wertvoll für die forensische Analyse.
- **Logins**: Gespeicherte Anmeldeinformationen.
- **Favicons**: Mit Websites verknüpfte Symbole, die in Tabs und Lesezeichen erscheinen; nützlich für zusätzliche Hinweise auf Benutzerbesuche.
- **Browser Sessions**: Daten zu geöffneten Browser-Sitzungen.
- **Downloads**: Aufzeichnungen über Dateien, die über den Browser heruntergeladen wurden.
- **Form Data**: In Webformulare eingegebene Informationen, die für zukünftige Autovervollständigungs-Vorschläge gespeichert wurden.
- **Thumbnails**: Vorschaubilder von Websites.
- **Custom Dictionary.txt**: Vom Benutzer dem Browser-Wörterbuch hinzugefügte Wörter.

## Firefox

Firefox organisiert Benutzerdaten innerhalb von Profilen, die je nach Betriebssystem an bestimmten Orten gespeichert sind:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Eine `profiles.ini`-Datei in diesen Verzeichnissen listet die Benutzerprofile auf. Die Daten jedes Profils werden in einem Ordner gespeichert, dessen Name im `Path`-Wert in `profiles.ini` angegeben ist und sich im selben Verzeichnis wie `profiles.ini` befindet. Wenn der Profilordner fehlt, wurde er möglicherweise gelöscht.

Innerhalb jedes Profilordners finden sich mehrere wichtige Dateien:

- **places.sqlite**: Speichert Verlauf, Lesezeichen und Downloads. Tools wie [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) unter Windows können auf die Verlaufsdaten zugreifen.
- Spezielle SQL-Abfragen können verwendet werden, um Verlaufs- und Downloadinformationen zu extrahieren.
- **bookmarkbackups**: Enthält Sicherungen der Lesezeichen.
- **formhistory.sqlite**: Speichert Formulardaten.
- **handlers.json**: Verwaltet Protokoll-Handler.
- **persdict.dat**: Benutzerdefinierte Wörterbuchwörter.
- **addons.json** und **extensions.sqlite**: Informationen zu installierten Add-ons und Erweiterungen.
- **cookies.sqlite**: Cookie-Speicher; zur Inspektion unter Windows steht [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) zur Verfügung.
- **cache2/entries** oder **startupCache**: Cache-Daten, zugänglich über Tools wie [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Speichert Favicons.
- **prefs.js**: Benutzereinstellungen und Präferenzen.
- **downloads.sqlite**: Älteres Download-Datenbankformat, inzwischen in places.sqlite integriert.
- **thumbnails**: Website-Vorschaubilder.
- **logins.json**: Verschlüsselte Anmeldeinformationen.
- **key4.db** oder **key3.db**: Speichert Verschlüsselungsschlüssel zum Schutz sensibler Informationen.

Zusätzlich kann die Antivirus-/Anti-Phishing-Konfiguration des Browsers überprüft werden, indem nach `browser.safebrowsing`-Einträgen in `prefs.js` gesucht wird, was anzeigt, ob Safe-Browsing-Funktionen aktiviert oder deaktiviert sind.

Um zu versuchen, das Master-Passwort zu entschlüsseln, können Sie [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\  
Mit dem folgenden Skript und Aufruf können Sie eine Passwortdatei zum Brute-Force-Angriff angeben:
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

Google Chrome speichert Benutzerprofile an betriebssystemspezifischen Orten:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Innerhalb dieser Verzeichnisse finden sich die meisten Benutzerdaten in den Ordnern **Default/** oder **ChromeDefaultData/**. Die folgenden Dateien enthalten wichtige Daten:

- **History**: Enthält URLs, Downloads und Suchbegriffe. Unter Windows kann [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) zum Auslesen des Verlaufs verwendet werden. Die Spalte "Transition Type" hat verschiedene Bedeutungen, einschließlich Benutzerklicks auf Links, eingegebene URLs, Formularübermittlungen und Seitenneuladungen.
- **Cookies**: Speichert Cookies. Zur Inspektion steht [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) zur Verfügung.
- **Cache**: Enthält zwischengespeicherte Daten. Zur Untersuchung können Windows-Nutzer [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) verwenden.

Electron-basierte Desktop-Apps (z. B. Discord) verwenden ebenfalls Chromium Simple Cache und hinterlassen reichhaltige On-Disk-Artefakte. Siehe:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Benutzer-Lesezeichen.
- **Web Data**: Enthält Formularverläufe.
- **Favicons**: Speichert Website-Favicons.
- **Login Data**: Beinhaltet Anmeldeinformationen wie Benutzernamen und Passwörter.
- **Current Session**/**Current Tabs**: Daten zur aktuellen Browsersitzung und geöffneten Tabs.
- **Last Session**/**Last Tabs**: Informationen zu den Seiten, die während der letzten Sitzung aktiv waren, bevor Chrome geschlossen wurde.
- **Extensions**: Verzeichnisse für Browser-Erweiterungen und Addons.
- **Thumbnails**: Speichert Website-Thumbnails.
- **Preferences**: Eine Datei mit vielen Informationen, einschließlich Einstellungen für Plugins, Erweiterungen, Pop-ups, Benachrichtigungen und mehr.
- **Browser’s built-in anti-phishing**: Um zu prüfen, ob Anti-Phishing und Malware-Schutz aktiviert sind, führe `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` aus. Suche in der Ausgabe nach `{"enabled: true,"}`.

## **SQLite DB Data Recovery**

Wie in den vorherigen Abschnitten zu sehen ist, verwenden sowohl Chrome als auch Firefox **SQLite**-Datenbanken zur Speicherung der Daten. Es ist möglich, **gelöschte Einträge mit dem Tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oder** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **wiederherzustellen**.

## **Internet Explorer 11**

Internet Explorer 11 verwaltet seine Daten und Metadaten an verschiedenen Speicherorten, was dabei hilft, gespeicherte Informationen und die zugehörigen Details getrennt zu halten, um einfachen Zugriff und Management zu ermöglichen.

### Metadata Storage

Metadaten für Internet Explorer werden in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` gespeichert (wobei VX V01, V16 oder V24 sein kann). Begleitend dazu kann die Datei `V01.log` Zeitabweichungen gegenüber `WebcacheVX.data` aufweisen, was auf eine notwendige Reparatur mit `esentutl /r V01 /d` hinweist. Diese Metadaten, untergebracht in einer ESE-Datenbank, können mit Tools wie photorec wiederhergestellt und mit [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) untersucht werden. Innerhalb der **Containers**-Tabelle kann man die spezifischen Tabellen oder Container erkennen, in denen jeder Datenabschnitt gespeichert ist, einschließlich Cache-Details für andere Microsoft-Tools wie Skype.

### Cache Inspection

Das Tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) ermöglicht die Untersuchung des Caches und benötigt den Speicherort des extrahierten Cache-Ordners. Metadaten für den Cache umfassen Dateiname, Verzeichnis, Zugriffsanzahl, Ursprungs-URL und Zeitstempel, die die Erstellung, den Zugriff, die Änderung und das Ablaufdatum des Caches anzeigen.

### Cookies Management

Cookies können mit [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) untersucht werden; die Metadaten umfassen Namen, URLs, Zugriffsanzahlen und verschiedene zeitbezogene Details. Persistente Cookies werden in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gespeichert, während Session-Cookies im Arbeitsspeicher liegen.

### Download Details

Metadaten zu Downloads sind über [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) zugänglich; bestimmte Container enthalten Daten wie URL, Dateityp und Download-Speicherort. Physische Dateien finden sich unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Zur Überprüfung des Browserverlaufs kann [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) verwendet werden; es benötigt den Speicherort der extrahierten Historien-Dateien und die Konfiguration für Internet Explorer. Metadaten hier umfassen Änderungs- und Zugriffszeiten sowie Zugriffsanzahlen. History-Dateien befinden sich in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Eingegebene URLs und deren Nutzungszeiten werden in der Registry unter `NTUSER.DAT` an den Schlüsseln `Software\Microsoft\InternetExplorer\TypedURLs` und `Software\Microsoft\InternetExplorer\TypedURLsTime` gespeichert und verfolgen die letzten 50 vom Benutzer eingegebenen URLs sowie deren letzte Eingabezeiten.

## Microsoft Edge

Microsoft Edge speichert Benutzerdaten in `%userprofile%\Appdata\Local\Packages`. Die Pfade für verschiedene Datentypen sind:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-Daten werden unter `/Users/$User/Library/Safari` gespeichert. Wichtige Dateien umfassen:

- **History.db**: Enthält die Tabellen `history_visits` und `history_items` mit URLs und Besuchszeitstempeln. Verwende `sqlite3` zum Abfragen.
- **Downloads.plist**: Informationen über heruntergeladene Dateien.
- **Bookmarks.plist**: Speichert Lesezeichen-URLs.
- **TopSites.plist**: Am häufigsten besuchte Seiten.
- **Extensions.plist**: Liste der Safari-Browsererweiterungen. Verwende `plutil` oder `pluginkit`, um sie abzurufen.
- **UserNotificationPermissions.plist**: Domains, die Benachrichtigungen senden dürfen. Verwende `plutil` zum Parsen.
- **LastSession.plist**: Tabs aus der letzten Sitzung. Verwende `plutil` zum Parsen.
- **Browser’s built-in anti-phishing**: Prüfe mit `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Eine Antwort von 1 zeigt an, dass die Funktion aktiv ist.

## Opera

Operas Daten liegen in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` und folgen dem Format von Chrome für Verlauf und Downloads.

- **Browser’s built-in anti-phishing**: Überprüfe, ob `fraud_protection_enabled` in der Preferences-Datei mit `grep` auf `true` gesetzt ist.

Diese Pfade und Befehle sind entscheidend, um auf die von verschiedenen Webbrowsern gespeicherten Browsing-Daten zuzugreifen und sie zu verstehen.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Buch: OS X Incident Response: Scripting and Analysis von Jaron Bradley S. 123**


{{#include ../../../banners/hacktricks-training.md}}
