# Browser-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Browser-Artefakte <a href="#id-3def" id="id-3def"></a>

Browser-Artefakte umfassen verschiedene Arten von Daten, die von Webbrowsern gespeichert werden, etwa den Navigationsverlauf, Lesezeichen und Cache-Daten. Diese Artefakte werden in bestimmten Ordnern innerhalb des Betriebssystems gespeichert. Speicherort und Bezeichnung unterscheiden sich je nach Browser, die gespeicherten Datentypen sind jedoch im Allgemeinen ähnlich.

Hier eine Zusammenfassung der häufigsten Browser-Artefakte:

- **Navigationsverlauf**: Erfasst die Besuche von Websites durch den Benutzer und ist hilfreich, um Besuche auf bösartigen Websites zu identifizieren.
- **Autovervollständigungsdaten**: Vorschläge auf Grundlage häufiger Suchanfragen, die in Verbindung mit dem Navigationsverlauf zusätzliche Einblicke bieten.
- **Lesezeichen**: Vom Benutzer gespeicherte Websites für den schnellen Zugriff.
- **Erweiterungen und Add-ons**: Vom Benutzer installierte Browser-Erweiterungen oder Add-ons.
- **Cache**: Speichert Webinhalte (z. B. Bilder und JavaScript-Dateien), um die Ladezeiten von Websites zu verkürzen, und ist für forensische Analysen wertvoll.
- **Anmeldedaten**: Gespeicherte Anmeldeinformationen.
- **Favicons**: Websites zugeordnete Symbole, die in Tabs und Lesezeichen angezeigt werden und zusätzliche Informationen zu den Websitebesuchen des Benutzers liefern können.
- **Browsersitzungen**: Daten zu geöffneten Browsersitzungen.
- **Downloads**: Aufzeichnungen der über den Browser heruntergeladenen Dateien.
- **Formulardaten**: In Webformulare eingegebene Informationen, die für künftige Autovervollständigungsvorschläge gespeichert werden.
- **Miniaturansichten**: Vorschaubilder von Websites.
- **Custom Dictionary.txt**: Vom Benutzer zum Browserwörterbuch hinzugefügte Wörter.

## Firefox

Firefox organisiert Benutzerdaten in Profilen, die je nach Betriebssystem an bestimmten Speicherorten abgelegt werden:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Eine Datei `profiles.ini` in diesen Verzeichnissen listet die Benutzerprofile auf. Die Daten jedes Profils werden in einem Ordner gespeichert, dessen Name in der Variable `Path` in `profiles.ini` angegeben ist. Dieser Ordner befindet sich im selben Verzeichnis wie `profiles.ini`. Fehlt der Ordner eines Profils, wurde es möglicherweise gelöscht.

In jedem Profilordner befinden sich mehrere wichtige Dateien:<sup>[[1]](#references)</sup>

- **places.sqlite**: Speichert Verlauf, Lesezeichen und Downloads. Unter Windows können Tools wie [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) auf die Verlaufsdaten zugreifen.
  - Verwenden Sie bestimmte SQL-Abfragen, um Verlaufs- und Downloadinformationen zu extrahieren.
- **bookmarkbackups**: Enthält Sicherungskopien von Lesezeichen.
- **formhistory.sqlite**: Speichert Webformular-Daten.
- **handlers.json**: Verwaltet Protokoll-Handler.
- **persdict.dat**: Benutzerdefinierte Wörterbuchwörter.
- **addons.json** und **extensions.sqlite**: Informationen zu installierten Add-ons und Erweiterungen.
- **cookies.sqlite**: Speichert Cookies. Unter Windows kann die Datei mit [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) untersucht werden.
- **cache2/entries** oder **startupCache**: Cache-Daten, auf die mit Tools wie [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) zugegriffen werden kann.
- **favicons.sqlite**: Speichert Favicons.
- **prefs.js**: Benutzereinstellungen und Präferenzen.
- **downloads.sqlite**: Ältere Download-Datenbank, inzwischen in places.sqlite integriert.
- **thumbnails**: Miniaturansichten von Websites.
- **logins.json**: Verschlüsselte Anmeldeinformationen.
- **key4.db** oder **key3.db**: Speichert Verschlüsselungsschlüssel zum Schutz sensibler Informationen.

Außerdem können Sie die Anti-Phishing-Einstellungen des Browsers prüfen, indem Sie in `prefs.js` nach Einträgen mit `browser.safebrowsing` suchen. Diese zeigen an, ob die Safe-Browsing-Funktionen aktiviert oder deaktiviert sind.<sup>[[2]](#references)</sup>

Um gespeicherte Anmeldedaten aus einem zugänglichen Profil zu entschlüsseln, muss das konfigurierte [Firefox-Hauptpasswort](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins) bereitgestellt oder separat wiederhergestellt werden; das Profil selbst enthält dieses Passwort nicht. Vergewissern Sie sich, dass sich mit den wiederhergestellten Anmeldedaten tatsächlich beim zugehörigen Webkonto anmelden lässt. Für den Nachweis, dass die Anmeldedaten auch für die Unix-Authentifizierung als root akzeptiert werden, ist ein separater Nachweis erforderlich. Gespeicherte Anmeldedaten können Sie mit [firefox_decrypt](https://github.com/unode/firefox_decrypt) überprüfen. Das folgende Beispiel testet mögliche Hauptpasswörter aus einer Passwortdatei:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Browser-Artefakte – Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome speichert Benutzerprofile je nach Betriebssystem an bestimmten Speicherorten:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

In diesen Verzeichnissen befinden sich die meisten Benutzerdaten in den Ordnern **Default/** oder **ChromeDefaultData/**. Die folgenden Dateien enthalten wichtige Daten:<sup>[[1]](#references)</sup>

- **Verlauf**: Enthält URLs, Downloads und Suchbegriffe. Unter Windows lässt sich der Verlauf mit [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) auslesen. Die Spalte „Transition Type“ enthält verschiedene Werte, darunter Klicks auf Links, eingegebene URLs, Formularübermittlungen und Seitenaktualisierungen.
- **Cookies**: Speichert Cookies. Zur Untersuchung steht [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) zur Verfügung.
- **Cache**: Enthält zwischengespeicherte Daten. Windows-Benutzer können den Cache mit [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) untersuchen.

  Desktop-Apps auf Basis von Electron (z. B. Discord) verwenden ebenfalls Chromium Simple Cache und hinterlassen umfangreiche Artefakte auf der Festplatte. Siehe:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Lesezeichen**: Lesezeichen des Benutzers.
- **Web Data**: Enthält den Formularverlauf.
- **Favicons**: Speichert Website-Favicons.
- **Login Data**: Enthält Anmeldedaten wie Benutzernamen und Passwörter.
- **Current Session**/**Current Tabs**: Daten zur aktuellen Browsersitzung und zu geöffneten Tabs.
- **Last Session**/**Last Tabs**: Informationen zu den Websites, die während der letzten Sitzung aktiv waren, bevor Chrome geschlossen wurde.
- **Extensions**: Verzeichnisse für Browsererweiterungen und Add-ons.
- **Thumbnails**: Speichert Website-Miniaturansichten.
- **Preferences**: Eine informationsreiche Datei mit Einstellungen für Plugins, Erweiterungen, Pop-ups, Benachrichtigungen und mehr.
- **Integrierter Phishing-Schutz des Browsers**: Um zu prüfen, ob der Phishing- und Malware-Schutz aktiviert ist, führe `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` aus. Suche in der Ausgabe nach `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

Das Verzeichnis `Local Extension Settings/<extension-id>/` eines Chromium-Profils kann den lokalen Zustand einer Erweiterung enthalten, darunter Schlüsselmaterial eines Passwort-Managers. Passbolt gibt beispielsweise an, dass sein verschlüsselter privater Schlüssel im lokalen Speicher der Browsererweiterung abgelegt wird ([Passbolt-Dokumentation](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/)); über die [Chrome-Erweiterungs-ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) lässt sich das betreffende Verzeichnis bestimmen. Das Vorhandensein des Verzeichnisses allein beweist weder, dass ein Schlüssel vorhanden ist, noch entsperrt es einen Tresor: Der Benutzer benötigt Zugriff auf die Profildaten, einen verwendbaren privaten Schlüssel und eine Passphrase sowie einen autorisierten Wiederherstellungs- oder Authentifizierungspfad zum Server. Ein Tresoreintrag mit dem Passwort eines Betriebssystemkontos erfordert eine separate Überprüfung, ob das Passwort für andere Konten wiederverwendet wird. Bei routinemäßiger Aufzählung sollte nur der Speicherpfad gemeldet werden, ohne die LevelDB-Dateien oder Geheimwerte auszulesen.

## **SQLite-Datenwiederherstellung**

Wie in den vorherigen Abschnitten zu sehen ist, verwenden sowohl Chrome als auch Firefox **SQLite**-Datenbanken zum Speichern von Daten. **Gelöschte Einträge lassen sich mit dem Tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oder** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **wiederherstellen**.

## **Internet Explorer 11**

Internet Explorer 11 verwaltet seine Daten und Metadaten an verschiedenen Speicherorten. Dadurch werden gespeicherte Informationen und die dazugehörigen Details getrennt und lassen sich einfach abrufen und verwalten.

### Metadatenspeicherung

Die Metadaten von Internet Explorer werden unter `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` gespeichert (wobei VX für V01, V16 oder V24 steht). Die zugehörige Datei `V01.log` kann Abweichungen bei den Änderungszeiten gegenüber `WebcacheVX.data` aufweisen. Dies kann auf eine notwendige Reparatur mit `esentutl /r V01 /d` hindeuten. Diese Metadaten befinden sich in einer ESE-Datenbank und lassen sich mit Tools wie photorec wiederherstellen und mit [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) untersuchen. Anhand der Tabelle **Containers** lässt sich feststellen, in welchen Tabellen oder Containern die einzelnen Datensegmente gespeichert sind, einschließlich Cache-Details anderer Microsoft-Tools wie Skype.

### Cache-Untersuchung

Mit dem Tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) lässt sich der Cache untersuchen. Dazu muss der Speicherort des Ordners mit den extrahierten Cache-Daten angegeben werden. Zu den Cache-Metadaten gehören Dateiname, Verzeichnis, Anzahl der Zugriffe, URL-Ursprung sowie Zeitstempel für Erstellung, Zugriff, Änderung und Ablauf des Cache-Eintrags.

### Cookie-Verwaltung

Cookies lassen sich mit [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) untersuchen. Die Metadaten umfassen Namen, URLs, Zugriffszahlen und verschiedene Zeitangaben. Dauerhafte Cookies werden unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gespeichert, während Sitzungscookies im Arbeitsspeicher verbleiben.

### Download-Details

Download-Metadaten lassen sich mit [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) abrufen. Bestimmte Container enthalten Daten wie URL, Dateityp und Download-Speicherort. Die Dateien selbst befinden sich unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browserverlauf

Zum Überprüfen des Browserverlaufs kann [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) verwendet werden. Dazu müssen der Speicherort der extrahierten Verlaufsdateien und die Konfiguration für Internet Explorer angegeben werden. Die Metadaten umfassen Änderungs- und Zugriffszeiten sowie Zugriffszahlen. Die Verlaufsdateien befinden sich unter `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Eingegebene URLs

Eingegebene URLs und ihre Zeitangaben werden in der Registrierung unter `NTUSER.DAT` in den Schlüsseln `Software\Microsoft\InternetExplorer\TypedURLs` und `Software\Microsoft\InternetExplorer\TypedURLsTime` gespeichert. Dort werden die letzten 50 vom Benutzer eingegebenen URLs sowie die jeweiligen Eingabezeitpunkte erfasst.

## Microsoft Edge

Microsoft Edge speichert Benutzerdaten unter `%userprofile%\Appdata\Local\Packages`. Die Speicherorte der verschiedenen Datentypen sind:<sup>[[1]](#references)</sup>

- **Profilpfad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Verlauf, Cookies und Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Einstellungen, Lesezeichen und Leseliste**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Zuletzt aktive Sitzungen**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-Daten werden unter `/Users/$User/Library/Safari` gespeichert. Zu den wichtigen Dateien gehören:<sup>[[3]](#references)</sup>

- **History.db**: Enthält die Tabellen `history_visits` und `history_items` mit URLs und Besuchszeitstempeln. Zum Abfragen kann `sqlite3` verwendet werden.
- **Downloads.plist**: Informationen zu heruntergeladenen Dateien.
- **Bookmarks.plist**: Speichert mit Lesezeichen versehene URLs.
- **TopSites.plist**: Am häufigsten besuchte Websites.
- **Extensions.plist**: Liste der Safari-Browsererweiterungen. Zum Auslesen kann `plutil` oder `pluginkit` verwendet werden.
- **UserNotificationPermissions.plist**: Domains, denen Push-Benachrichtigungen erlaubt sind. Zum Parsen kann `plutil` verwendet werden.
- **LastSession.plist**: Tabs aus der letzten Sitzung. Zum Parsen kann `plutil` verwendet werden.
- **Integrierter Phishing-Schutz des Browsers**: Prüfe den Status mit `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Eine Ausgabe von 1 bedeutet, dass die Funktion aktiv ist.<sup>[[2]](#references)</sup>

## Opera

Operas Daten befinden sich unter `/Users/$USER/Library/Application Support/com.operasoftware.Opera`. Für Verlauf und Downloads wird dasselbe Format wie bei Chrome verwendet.

- **Integrierter Phishing-Schutz des Browsers**: Prüfe mit `grep`, ob `fraud_protection_enabled` in der Datei Preferences auf `true` gesetzt ist.<sup>[[2]](#references)</sup>

Diese Pfade und Befehle sind entscheidend, um auf die von verschiedenen Webbrowsern gespeicherten Browserdaten zuzugreifen und sie zu verstehen.

## References

- [1] [Forensik von Webbrowsern: Ein Leitfaden zur forensischen Analyse von Webbrowsern](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Incident Response unter macOS | Teil 3: Systemmanipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Incident Response unter OS X: Skripting und Analyse von Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
