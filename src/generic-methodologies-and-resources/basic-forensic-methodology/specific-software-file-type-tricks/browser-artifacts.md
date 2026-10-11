# Browser-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Browser-Artefakte <a href="#id-3def" id="id-3def"></a>

Browser-Artefakte umfassen verschiedene Arten von Daten, die von Webbrowsern gespeichert werden, etwa den Navigationsverlauf, Lesezeichen und Cache-Daten. Diese Artefakte werden in bestimmten Ordnern innerhalb des Betriebssystems gespeichert. Speicherort und Name unterscheiden sich je nach Browser, die gespeicherten Datentypen sind jedoch im Allgemeinen ähnlich.

Hier eine Zusammenfassung der häufigsten Browser-Artefakte:

- **Navigationsverlauf**: Zeichnet auf, welche Websites ein Benutzer besucht hat, und hilft dabei, Besuche auf schädlichen Websites zu identifizieren.
- **Autovervollständigungsdaten**: Vorschläge auf Grundlage häufiger Suchanfragen, die in Verbindung mit dem Navigationsverlauf zusätzliche Einblicke bieten.
- **Lesezeichen**: Vom Benutzer gespeicherte Websites für den schnellen Zugriff.
- **Erweiterungen und Add-ons**: Vom Benutzer installierte Browser-Erweiterungen oder Add-ons.
- **Cache**: Speichert Webinhalte (z. B. Bilder und JavaScript-Dateien), um das Laden von Websites zu beschleunigen, und ist für forensische Analysen wertvoll.
- **Anmeldedaten**: Gespeicherte Anmeldeinformationen.
- **Favicons**: Mit Websites verknüpfte Symbole, die in Tabs und Lesezeichen angezeigt werden und zusätzliche Informationen zu Website-Besuchen liefern können.
- **Browsersitzungen**: Daten zu geöffneten Browsersitzungen.
- **Downloads**: Aufzeichnungen der über den Browser heruntergeladenen Dateien.
- **Formulardaten**: In Webformulare eingegebene Informationen, die für künftige Autovervollständigungsvorschläge gespeichert werden.
- **Miniaturansichten**: Vorschaubilder von Websites.
- **Custom Dictionary.txt**: Vom Benutzer zum Browser-Wörterbuch hinzugefügte Wörter.

## Firefox

Firefox organisiert Benutzerdaten in Profilen, die je nach Betriebssystem an bestimmten Speicherorten abgelegt werden:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Eine Datei namens `profiles.ini` in diesen Verzeichnissen listet die Benutzerprofile auf. Die Daten jedes Profils werden in einem Ordner gespeichert, dessen Name in der Variable `Path` in `profiles.ini` angegeben ist. Dieser Ordner befindet sich im selben Verzeichnis wie `profiles.ini`. Fehlt der Ordner eines Profils, wurde es möglicherweise gelöscht.

In jedem Profilordner finden sich mehrere wichtige Dateien:<sup>[[1]](#references)</sup>

- **places.sqlite**: Speichert Verlauf, Lesezeichen und Downloads. Tools wie [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) können unter Windows auf die Verlaufsdaten zugreifen.
  - Verwenden Sie spezifische SQL-Abfragen, um Verlaufs- und Downloadinformationen zu extrahieren.
- **bookmarkbackups**: Enthält Sicherungskopien der Lesezeichen.
- **formhistory.sqlite**: Speichert Webformulardaten.
- **handlers.json**: Verwaltet Protokoll-Handler.
- **persdict.dat**: Benutzerdefinierte Wörterbuchwörter.
- **addons.json** und **extensions.sqlite**: Informationen zu installierten Add-ons und Erweiterungen.
- **cookies.sqlite**: Speichert Cookies. Unter Windows kann die Datei mit [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) untersucht werden.
- **cache2/entries** oder **startupCache**: Cache-Daten, auf die mit Tools wie [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) zugegriffen werden kann.
- **favicons.sqlite**: Speichert Favicons.
- **prefs.js**: Benutzereinstellungen und -präferenzen.
- **downloads.sqlite**: Ältere Download-Datenbank, deren Funktion inzwischen in places.sqlite integriert ist.
- **thumbnails**: Miniaturansichten von Websites.
- **logins.json**: Verschlüsselte Anmeldeinformationen.
- **key4.db** oder **key3.db**: Speichert Verschlüsselungsschlüssel zum Schutz sensibler Informationen.

Außerdem lässt sich prüfen, ob die Safe-Browsing-Funktionen aktiviert oder deaktiviert sind, indem in `prefs.js` nach Einträgen mit `browser.safebrowsing` gesucht wird.<sup>[[2]](#references)</sup>

Um gespeicherte Anmeldedaten aus einem zugänglichen Profil zu entschlüsseln, muss das konfigurierte [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins) angegeben oder separat wiederhergestellt werden; das Profil selbst gibt dieses Passwort nicht preis. Bestätigen Sie, dass sich mit den wiederhergestellten Anmeldedaten beim zugehörigen Webkonto anmelden lässt. Für Root-Zugriff unter Unix ist ein separater Nachweis erforderlich, dass die Anmeldedaten auch von der Unix-Authentifizierung für Root akzeptiert werden. Gespeicherte Anmeldedaten können Sie mit [firefox_decrypt](https://github.com/unode/firefox_decrypt) überprüfen. Das folgende Beispiel testet mögliche Primary Passwords aus einer Passwortdatei:

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

- **History**: Enthält URLs, Downloads und Suchbegriffe. Unter Windows kann [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) zum Lesen des Verlaufs verwendet werden. Die Spalte „Transition Type“ hat verschiedene Bedeutungen, darunter Benutzerklicks auf Links, eingegebene URLs, Formularübermittlungen und Seitenneuladungen.
- **Cookies**: Speichert Cookies. Zur Untersuchung steht [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) zur Verfügung.
- **Cache**: Enthält zwischengespeicherte Daten. Zur Untersuchung können Windows-Benutzer [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) verwenden.

  Desktop-Apps auf Basis von Electron (z. B. Discord) verwenden ebenfalls Chromium Simple Cache und hinterlassen umfangreiche Artefakte auf der Festplatte. Siehe:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Benutzerlesezeichen.
- **Web Data**: Enthält den Formularverlauf.
- **Favicons**: Speichert Website-Favicons.
- **Login Data**: Enthält Anmeldedaten wie Benutzernamen und Passwörter.
- **Current Session**/**Current Tabs**: Daten zur aktuellen Browsersitzung und den geöffneten Tabs.
- **Last Session**/**Last Tabs**: Informationen zu den Websites, die während der letzten Sitzung vor dem Schließen von Chrome aktiv waren.
- **Extensions**: Verzeichnisse für Browser-Extensions und Add-ons.
- **Thumbnails**: Speichert Website-Miniaturansichten.
- **Preferences**: Eine informationsreiche Datei mit Einstellungen für Plugins, Extensions, Pop-ups, Benachrichtigungen und mehr.
- **Integrierter Anti-Phishing-Schutz des Browsers**: Um zu prüfen, ob der Schutz vor Phishing und Malware aktiviert ist, führe `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` aus. Suche in der Ausgabe nach `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

Das Verzeichnis `Local Extension Settings/<extension-id>/` eines Chromium-Profils kann den lokalen Status einer Extension enthalten, darunter Schlüsselmaterial eines Passwortmanagers. Passbolt gibt beispielsweise an, dass sein verschlüsselter privater Schlüssel im lokalen Speicher der Browser-Extension abgelegt wird. Die [Chrome-Extension-ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) identifiziert das entsprechende Verzeichnis. Das bloße Vorhandensein des Verzeichnisses beweist weder, dass ein Schlüssel vorhanden ist, noch entsperrt es einen Vault: Der Benutzer muss Zugriff auf die Profildaten, einen verwendbaren privaten Schlüssel und eine Passphrase sowie einen autorisierten Wiederherstellungs-/Authentifizierungsweg zum Server haben. Bei einem Vault-Eintrag mit dem Passwort eines Betriebssystemkontos muss separat geprüft werden, ob das Konto wiederverwendet wird. Eine routinemäßige Auflistung sollte nur den Speicherpfad melden, ohne die LevelDB-Dateien oder geheime Werte auszulesen.

## **Wiederherstellung von SQLite-DB-Daten**

Wie in den vorherigen Abschnitten zu sehen ist, verwenden sowohl Chrome als auch Firefox **SQLite**-Datenbanken zum Speichern von Daten. **Gelöschte Einträge lassen sich mit dem Tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **oder** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **wiederherstellen**.

## **Internet Explorer 11**

Internet Explorer 11 verwaltet seine Daten und Metadaten an verschiedenen Speicherorten. So lassen sich gespeicherte Informationen und die zugehörigen Details für einen einfachen Zugriff und eine einfache Verwaltung getrennt halten.

### Metadatenspeicherung

Die Metadaten von Internet Explorer werden unter `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` gespeichert (wobei VX für V01, V16 oder V24 steht). Die zugehörige Datei `V01.log` kann eine abweichende Änderungszeit gegenüber `WebcacheVX.data` aufweisen, was auf einen Reparaturbedarf mit `esentutl /r V01 /d` hindeutet. Diese in einer ESE-Datenbank gespeicherten Metadaten lassen sich mit Tools wie photorec wiederherstellen und mit [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) untersuchen. In der Tabelle **Containers** lassen sich die Tabellen oder Container ermitteln, in denen die einzelnen Datensegmente gespeichert sind, einschließlich Cache-Details anderer Microsoft-Tools wie Skype.

### Cache-Untersuchung

Mit dem Tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) lässt sich der Cache untersuchen. Dazu muss der Speicherort des Ordners angegeben werden, in den die Cache-Daten extrahiert wurden. Zu den Cache-Metadaten gehören Dateiname, Verzeichnis, Zugriffszähler, URL-Ursprung und Zeitstempel für Erstellung, Zugriff, Änderung und Ablauf des Cache-Eintrags.

### Cookie-Verwaltung

Cookies lassen sich mit [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) untersuchen. Zu den Metadaten gehören Namen, URLs, Zugriffszähler und verschiedene Zeitangaben. Persistente Cookies werden unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` gespeichert, Sitzungscookies dagegen im Arbeitsspeicher.

### Download-Details

Download-Metadaten können mit [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) abgerufen werden. Bestimmte Container enthalten Daten wie URL, Dateityp und Download-Speicherort. Die Dateien selbst befinden sich unter `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browserverlauf

Zum Überprüfen des Browserverlaufs kann [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) verwendet werden. Dazu müssen der Speicherort der extrahierten Verlaufsdateien und die Konfiguration für Internet Explorer angegeben werden. Zu den Metadaten gehören Änderungs- und Zugriffszeiten sowie Zugriffszähler. Verlaufsdateien befinden sich unter `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Eingegebene URLs

Eingegebene URLs und ihre Eingabezeiten werden in der Registry unter `NTUSER.DAT` in `Software\Microsoft\InternetExplorer\TypedURLs` und `Software\Microsoft\InternetExplorer\TypedURLsTime` gespeichert. Erfasst werden die letzten 50 vom Benutzer eingegebenen URLs und die jeweiligen Eingabezeiten.

## Microsoft Edge

Microsoft Edge speichert Benutzerdaten unter `%userprofile%\Appdata\Local\Packages`. Die Speicherorte für verschiedene Datentypen sind:<sup>[[1]](#references)</sup>

- **Profilpfad**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Verlauf, Cookies und Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Einstellungen, Lesezeichen und Leseliste**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Zuletzt aktive Sitzungen**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari-Daten werden unter `/Users/$User/Library/Safari` gespeichert. Wichtige Dateien sind:<sup>[[3]](#references)</sup>

- **History.db**: Enthält die Tabellen `history_visits` und `history_items` mit URLs und Zeitstempeln der Besuche. Zum Abfragen `sqlite3` verwenden.
- **Downloads.plist**: Informationen zu heruntergeladenen Dateien.
- **Bookmarks.plist**: Speichert als Lesezeichen gespeicherte URLs.
- **TopSites.plist**: Am häufigsten besuchte Websites.
- **Extensions.plist**: Liste der Safari-Browser-Extensions. Zum Abrufen `plutil` oder `pluginkit` verwenden.
- **UserNotificationPermissions.plist**: Domains, denen Push-Benachrichtigungen erlaubt sind. Zum Parsen `plutil` verwenden.
- **LastSession.plist**: Tabs der letzten Sitzung. Zum Parsen `plutil` verwenden.
- **Integrierter Anti-Phishing-Schutz des Browsers**: Mit `defaults read com.apple.Safari WarnAboutFraudulentWebsites` prüfen. Die Antwort 1 bedeutet, dass die Funktion aktiv ist.<sup>[[2]](#references)</sup>

## Opera

Operas Daten befinden sich unter `/Users/$USER/Library/Application Support/com.operasoftware.Opera`. Für Verlauf und Downloads wird dasselbe Format wie bei Chrome verwendet.

- **Integrierter Anti-Phishing-Schutz des Browsers**: Prüfe mit `grep`, ob `fraud_protection_enabled` in der Preferences-Datei auf `true` gesetzt ist.<sup>[[2]](#references)</sup>

Diese Pfade und Befehle sind entscheidend, um auf die von verschiedenen Webbrowsern gespeicherten Browserdaten zuzugreifen und sie zu verstehen.

## References

- [1] [Forensik von Webbrowsern: Ein Leitfaden zur forensischen Analyse von Webbrowsern](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Teil 3: Systemmanipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Skripting und Analyse von Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
