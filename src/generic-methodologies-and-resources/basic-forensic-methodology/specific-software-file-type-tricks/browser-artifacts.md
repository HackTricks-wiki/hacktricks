# Browser-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Browser-Artefakte <a href="#id-3def" id="id-3def"></a>

Browser-Artefakte umfassen verschiedene Arten von Daten, die von Webbrowsern gespeichert werden, beispielsweise Navigationsverlauf, Lesezeichen und Cache-Daten. Diese Artefakte werden in bestimmten Ordnern innerhalb des Betriebssystems gespeichert. Speicherort und Bezeichnung unterscheiden sich je nach Browser, wobei im Allgemeinen ähnliche Datentypen gespeichert werden.

Hier eine Zusammenfassung der häufigsten Browser-Artefakte:

- **Navigationsverlauf**: Zeichnet die Besuche des Benutzers auf Websites auf und ist nützlich, um Besuche auf schädlichen Websites zu identifizieren.
- **Autocomplete-Daten**: Vorschläge auf Grundlage häufiger Suchanfragen, die in Kombination mit dem Navigationsverlauf zusätzliche Einblicke bieten.
- **Lesezeichen**: Vom Benutzer gespeicherte Websites für den schnellen Zugriff.
- **Erweiterungen und Add-ons**: Vom Benutzer installierte Browser-Erweiterungen oder Add-ons.
- **Cache**: Speichert Webinhalte (z. B. Bilder und JavaScript-Dateien), um die Ladezeiten von Websites zu verbessern, und ist für die forensische Analyse wertvoll.
- **Logins**: Gespeicherte Anmeldeinformationen.
- **Favicons**: Mit Websites verknüpfte Symbole, die in Tabs und Lesezeichen angezeigt werden und zusätzliche Informationen über Benutzerbesuche liefern können.
- **Browsersitzungen**: Daten zu geöffneten Browsersitzungen.
- **Downloads**: Aufzeichnungen der über den Browser heruntergeladenen Dateien.
- **Formulardaten**: In Webformulare eingegebene Informationen, die für zukünftige Autofill-Vorschläge gespeichert werden.
- **Thumbnails**: Vorschaubilder von Websites.
- **Custom Dictionary.txt**: Vom Benutzer zum Wörterbuch des Browsers hinzugefügte Wörter.

## Firefox

Firefox organisiert Benutzerdaten in Profilen, die je nach Betriebssystem an bestimmten Speicherorten abgelegt werden:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Eine Datei `profiles.ini` in diesen Verzeichnissen listet die Benutzerprofile auf. Die Daten jedes Profils werden in einem Ordner gespeichert, dessen Name in der Variable `Path` innerhalb von `profiles.ini` angegeben ist und der sich im selben Verzeichnis wie `profiles.ini` befindet. Fehlt der Profilordner, wurde er möglicherweise gelöscht.

In jedem Profilordner befinden sich mehrere wichtige Dateien:<sup>[[1]](#references)</sup>

- **places.sqlite**: Speichert Verlauf, Lesezeichen und Downloads. Tools wie [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) unter Windows können auf die Verlaufsdaten zugreifen.
- Verwende bestimmte SQL-Abfragen, um Informationen zu Verlauf und Downloads zu extrahieren.
- **bookmarkbackups**: Enthält Sicherungskopien von Lesezeichen.
- **formhistory.sqlite**: Speichert Webformular-Daten.
- **handlers.json**: Verwaltet Protokoll-Handler.
- **persdict.dat**: Benutzerdefinierte Wörterbuchwörter.
- **addons.json** und **extensions.sqlite**: Informationen über installierte Add-ons und Erweiterungen.
- **cookies.sqlite**: Speicher für Cookies; unter Windows kann [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) zur Untersuchung verwendet werden.
- **cache2/entries** oder **startupCache**: Cache-Daten, auf die mit Tools wie [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) zugegriffen werden kann.
- **favicons.sqlite**: Speichert Favicons.
- **prefs.js**: Benutzereinstellungen und Präferenzen.
- **downloads.sqlite**: Ältere Download-Datenbank, die inzwischen in places.sqlite integriert wurde.
- **thumbnails**: Website-Thumbnails.
- **logins.json**: Verschlüsselte Anmeldeinformationen.
- **key4.db** oder **key3.db**: Speichert Verschlüsselungsschlüssel zum Schutz sensibler Informationen.

Zusätzlich können die Anti-Phishing-Einstellungen des Browsers überprüft werden, indem in `prefs.js` nach Einträgen von `browser.safebrowsing` gesucht wird. Diese zeigen an, ob die Safe-Browsing-Funktionen aktiviert oder deaktiviert sind.<sup>[[2]](#references)</sup>

Um zu versuchen, das Master-Passwort zu entschlüsseln, kannst du [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) verwenden.\
Mit dem folgenden Script und Aufruf kannst du eine Passwortdatei für Brute-Force-Angriffe angeben:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Browsers Artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome speichert Benutzerprofile abhängig vom Betriebssystem an bestimmten Speicherorten:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

In diesen Verzeichnissen befinden sich die meisten Benutzerdaten in den Ordnern **Default/** oder **ChromeDefaultData/**. Die folgenden Dateien enthalten wichtige Daten:<sup>[[1]](#references)</sup>

- **History**: Enthält URLs, Downloads und Suchbegriffe. Unter Windows kann [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) zum Lesen des Verlaufs verwendet werden. Die Spalte "Transition Type" hat verschiedene Bedeutungen, darunter Benutzerklicks auf Links, eingegebene URLs, Formularübermittlungen und das erneute Laden von Seiten.
- **Cookies**: Speichert Cookies. Zur Untersuchung steht [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) zur Verfügung.
- **Cache**: Enthält zwischengespeicherte Daten. Zur Untersuchung können Windows-Benutzer [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) verwenden.

Auf Electron basierende Desktop-Apps (z. B. Discord) verwenden ebenfalls Chromium Simple Cache und hinterlassen umfangreiche Artefakte auf der Festplatte. Siehe:

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
- **Thumbnails**: Speichert Website-Miniaturansichten.
- **Preferences**: Eine informationsreiche Datei, die unter anderem Einstellungen für Plugins, Erweiterungen, Pop-ups und Benachrichtigungen enthält.
- **Browser’s built-in anti-phishing**: Um zu prüfen, ob Anti-Phishing- und Malware-Schutz aktiviert sind, führe `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` aus. Suche in der Ausgabe nach `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Wie in den vorherigen Abschnitten zu sehen ist, verwenden sowohl Chrome als auch Firefox **SQLite**-Datenbanken zum Speichern der Daten. Es ist möglich, **gelöschte Einträge mit dem Tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oder** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **wiederherzustellen**.

## **Internet Explorer 11**

Internet Explorer 11 verwaltet seine Daten und Metadaten an verschiedenen Speicherorten. Dadurch werden gespeicherte Informationen und die zugehörigen Details getrennt und können einfach abgerufen und verwaltet werden.

### Metadata Storage

Metadaten für Internet Explorer werden in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` gespeichert, wobei VX für V01, V16 oder V24 steht. Die zugehörige Datei `V01.log` kann Abweichungen bei den Änderungszeiten gegenüber `WebcacheVX.data` aufweisen, was auf einen Reparaturbedarf mit `esentutl /r V01 /d` hindeutet. Diese in einer ESE-Datenbank gespeicherten Metadaten können mit Tools wie photorec wiederhergestellt und mit [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) untersucht werden. In der Tabelle **Containers** kann man die spezifischen Tabellen oder Container erkennen, in denen die einzelnen Datensegmente gespeichert sind, einschließlich Cache-Details für andere Microsoft-Tools wie Skype.

### Cache Inspection

Das Tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) ermöglicht die Untersuchung des Caches und benötigt den Speicherort des Ordners, in den die Cache-Daten extrahiert wurden. Zu den Cache-Metadaten gehören Dateiname, Verzeichnis, Zugriffszahl, URL-Ursprung sowie Zeitstempel für die Erstellung, den Zugriff, die Änderung und den Ablauf des Caches.

### Cookies Management

Cookies können mit [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) untersucht werden. Die Metadaten umfassen Namen, URLs, Zugriffszahlen und verschiedene zeitbezogene Details. Persistente Cookies werden in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gespeichert, während Sitzungscookies im Speicher liegen.

### Download Details

Download-Metadaten sind über [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) zugänglich. Bestimmte Container enthalten Daten wie URL, Dateityp und Download-Speicherort. Physische Dateien befinden sich unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Zur Überprüfung des Browserverlaufs kann [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) verwendet werden. Dafür werden der Speicherort der extrahierten Verlaufsdateien und die Konfiguration für Internet Explorer benötigt. Die Metadaten umfassen Änderungs- und Zugriffszeiten sowie Zugriffszahlen. Verlaufsdateien befinden sich in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Eingegebene URLs und ihre Nutzungszeitpunkte werden in der Registry unter `NTUSER.DAT` in `Software\Microsoft\InternetExplorer\TypedURLs` und `Software\Microsoft\InternetExplorer\TypedURLsTime` gespeichert. Dabei werden die letzten 50 vom Benutzer eingegebenen URLs und ihre letzten Eingabezeitpunkte erfasst.

## Microsoft Edge

Microsoft Edge speichert Benutzerdaten in `%userprofile%\Appdata\Local\Packages`. Die Pfade für verschiedene Datentypen sind:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-Daten werden unter `/Users/$User/Library/Safari` gespeichert. Zu den wichtigen Dateien gehören:<sup>[[3]](#references)</sup>

- **History.db**: Enthält die Tabellen `history_visits` und `history_items` mit URLs und Zeitstempeln der Besuche. Verwende `sqlite3` für Abfragen.
- **Downloads.plist**: Informationen zu heruntergeladenen Dateien.
- **Bookmarks.plist**: Speichert mit Lesezeichen versehene URLs.
- **TopSites.plist**: Am häufigsten besuchte Websites.
- **Extensions.plist**: Liste der Safari-Browsererweiterungen. Verwende `plutil` oder `pluginkit` zum Abrufen.
- **UserNotificationPermissions.plist**: Domains, die Push-Benachrichtigungen senden dürfen. Verwende `plutil` zum Parsen.
- **LastSession.plist**: Tabs aus der letzten Sitzung. Verwende `plutil` zum Parsen.
- **Browser’s built-in anti-phishing**: Prüfe dies mit `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Eine Antwort von 1 zeigt an, dass die Funktion aktiv ist.<sup>[[2]](#references)</sup>

## Opera

Die Daten von Opera befinden sich in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` und verwenden für Verlauf und Downloads dasselbe Format wie Chrome.

- **Browser’s built-in anti-phishing**: Überprüfe mit `grep`, ob `fraud_protection_enabled` in der Preferences-Datei auf `true` gesetzt ist.<sup>[[2]](#references)</sup>

Diese Pfade und Befehle sind entscheidend für den Zugriff auf und das Verständnis von Browserdaten, die von verschiedenen Webbrowsern gespeichert werden.

## References

- [1] [Forensik von Webbrowsern: Ein Leitfaden zur forensischen Analyse von Webbrowsern](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Teil 3: Systemmanipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting und Analyse von Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
