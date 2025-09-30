# Artefakty przeglądarki

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty przeglądarek <a href="#id-3def" id="id-3def"></a>

Artefakty przeglądarek obejmują różne typy danych przechowywanych przez przeglądarki internetowe, takie jak historia nawigacji, zakładki i dane cache. Artefakty te są przechowywane w określonych folderach systemu operacyjnego, różnią się lokalizacją i nazwą w zależności od przeglądarki, lecz zazwyczaj zawierają podobne typy danych.

Poniżej podsumowanie najczęstszych artefaktów przeglądarki:

- **Navigation History**: Śledzi odwiedziny użytkownika na stronach, przydatne do identyfikacji wejść na złośliwe witryny.
- **Autocomplete Data**: Sugestie oparte na częstych wyszukiwaniach, dostarczające wskazówek w połączeniu z historią nawigacji.
- **Bookmarks**: Strony zapisane przez użytkownika do szybkiego dostępu.
- **Extensions and Add-ons**: Rozszerzenia lub dodatki zainstalowane przez użytkownika.
- **Cache**: Przechowuje zawartość sieciową (np. obrazy, pliki JavaScript) w celu przyspieszenia ładowania stron, przydatne w analizie sądowej.
- **Logins**: Zapisane dane logowania.
- **Favicons**: Ikony powiązane ze stronami, widoczne na kartach i w zakładkach, przydatne jako dodatkowa informacja o odwiedzinach użytkownika.
- **Browser Sessions**: Dane związane z otwartymi sesjami przeglądarki.
- **Downloads**: Rejestry plików pobranych przez przeglądarkę.
- **Form Data**: Informacje wpisane w formularze internetowe, zapisywane do przyszłego autouzupełniania.
- **Thumbnails**: Podglądy stron.
- **Custom Dictionary.txt**: Słowa dodane przez użytkownika do słownika przeglądarki.

## Firefox

Firefox organizuje dane użytkownika w profilach, przechowywanych w konkretnych lokalizacjach w zależności od systemu operacyjnego:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Plik `profiles.ini` w tych katalogach zawiera listę profili użytkownika. Dane każdego profilu są przechowywane w folderze nazwanego w zmiennej `Path` w `profiles.ini`, znajdującym się w tym samym katalogu co `profiles.ini`. Jeśli folder profilu nie istnieje, mogło to oznaczać jego usunięcie.

W każdym folderze profilu można znaleźć kilka istotnych plików:

- **places.sqlite**: Przechowuje historię, zakładki i pobrane pliki. Narzędzia takie jak [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) na Windows mogą uzyskać dostęp do danych historii.
- Use specific SQL queries to extract history and downloads information.
- **bookmarkbackups**: Zawiera kopie zapasowe zakładek.
- **formhistory.sqlite**: Przechowuje dane formularzy internetowych.
- **handlers.json**: Zarządza obsługą protokołów.
- **persdict.dat**: Niestandardowe słowa słownika.
- **addons.json** i **extensions.sqlite**: Informacje o zainstalowanych dodatkach i rozszerzeniach.
- **cookies.sqlite**: Przechowywanie cookies, z [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) dostępnym do przeglądu na Windows.
- **cache2/entries** lub **startupCache**: Dane cache, dostępne przez narzędzia takie jak [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Przechowuje favicons.
- **prefs.js**: Ustawienia i preferencje użytkownika.
- **downloads.sqlite**: Starsza baza pobrań, obecnie zintegrowana z `places.sqlite`.
- **thumbnails**: Miniatury stron.
- **logins.json**: Zaszyfrowane informacje o logowaniach.
- **key4.db** lub **key3.db**: Przechowuje klucze szyfrujące do zabezpieczenia informacji wrażliwych.

Dodatkowo, ustawienia anty-phishingowe przeglądarki można sprawdzić, wyszukując wpisy `browser.safebrowsing` w `prefs.js`, co wskazuje czy funkcje bezpiecznego przeglądania są włączone czy wyłączone.

Aby spróbować odszyfrować główne hasło, możesz użyć [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Z poniższym skryptem i wywołaniem możesz podać plik z hasłami do brute force:
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

Google Chrome przechowuje profile użytkowników w określonych lokalizacjach w zależności od systemu operacyjnego:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

W tych katalogach większość danych użytkownika można znaleźć w folderach **Default/** lub **ChromeDefaultData/**. Następujące pliki zawierają istotne dane:

- **History**: Zawiera URL-e, pobrane pliki i słowa kluczowe wyszukiwań. W systemie Windows można użyć [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) do odczytu historii. Kolumna "Transition Type" ma różne znaczenia, m.in. kliknięcia użytkownika w linki, wpisane adresy URL, wysyłanie formularzy i przeładowania stron.
- **Cookies**: Przechowuje cookies. Do analizy dostępne jest narzędzie [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Przechowuje dane w cache. Aby je przejrzeć, użytkownicy Windows mogą skorzystać z [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Aplikacje desktopowe oparte na Electron (np. Discord) również używają Chromium Simple Cache i pozostawiają bogate artefakty na dysku. Zobacz:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Zakładki użytkownika.
- **Web Data**: Zawiera historię formularzy.
- **Favicons**: Przechowuje favikony stron.
- **Login Data**: Zawiera poświadczenia logowania, takie jak nazwy użytkowników i hasła.
- **Current Session**/**Current Tabs**: Dane o bieżącej sesji przeglądania i otwartych kartach.
- **Last Session**/**Last Tabs**: Informacje o stronach aktywnych podczas ostatniej sesji przed zamknięciem Chrome.
- **Extensions**: Katalogi rozszerzeń i dodatków przeglądarki.
- **Thumbnails**: Przechowuje miniatury stron.
- **Preferences**: Plik zawierający wiele informacji, w tym ustawienia wtyczek, rozszerzeń, okienek wyskakujących, powiadomień i inne.
- **Browser’s built-in anti-phishing**: Aby sprawdzić, czy ochrona przed phishingiem i malware jest włączona, uruchom `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Szukaj w wynikach `{"enabled: true,"}`.

## **SQLite DB Data Recovery**

Jak widać w poprzednich sekcjach, zarówno Chrome, jak i Firefox używają baz danych **SQLite** do przechowywania danych. Możliwe jest **odzyskanie usuniętych wpisów przy użyciu narzędzia** [**sqlparse**](https://github.com/padfoot999/sqlparse) **lub** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 przechowuje dane i metadane w różnych lokalizacjach, co ułatwia oddzielenie przechowywanych informacji od odpowiadających im szczegółów, umożliwiając łatwy dostęp i zarządzanie.

### Metadata Storage

Metadane Internet Explorera są przechowywane w %userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data (gdzie VX to V01, V16 lub V24). Towarzyszący plik `V01.log` może wykazywać rozbieżności czasów modyfikacji w stosunku do `WebcacheVX.data`, co wskazuje na konieczność naprawy przy użyciu `esentutl /r V01 /d`. Te metadane, zawarte w bazie ESE, można odzyskać i przeanalizować odpowiednio za pomocą narzędzi takich jak photorec oraz [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). W tabeli **Containers** można rozpoznać konkretne tabele lub kontenery, w których przechowywany jest każdy segment danych, włącznie z informacjami o cache dla innych narzędzi Microsoft, takich jak Skype.

### Cache Inspection

Narzędzie [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) umożliwia przeglądanie cache, wymagając lokalizacji folderu z wyodrębnionymi danymi cache. Metadane cache obejmują nazwę pliku, katalog, liczbę dostępów, źródłowy URL oraz znaczniki czasu wskazujące utworzenie, dostęp, modyfikację i wygaśnięcie cache.

### Cookies Management

Cookies można badać za pomocą [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metadane obejmują nazwy, URL-e, liczbę dostępów oraz różne informacje czasowe. Trwałe cookies są przechowywane w `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, natomiast cookies sesyjne znajdują się w pamięci.

### Download Details

Metadane pobrań są dostępne przez [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), a konkretne kontenery zawierają dane takie jak URL, typ pliku i lokalizacja pobrania. Fizyczne pliki można znaleźć w `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Aby przejrzeć historię przeglądania, można użyć [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), podając lokalizację wyodrębnionych plików historii i konfigurację dla Internet Explorera. Metadane zawierają czasy modyfikacji i dostępu oraz liczbę dostępów. Pliki historii znajdują się w `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Wpisane adresy URL i czasy ich użycia są przechowywane w rejestrze w `NTUSER.DAT` pod kluczami `Software\Microsoft\InternetExplorer\TypedURLs` oraz `Software\Microsoft\InternetExplorer\TypedURLsTime`, śledząc ostatnie 50 wprowadzonych przez użytkownika adresów URL oraz czasy ich ostatniego wprowadzenia.

## Microsoft Edge

Microsoft Edge przechowuje dane użytkownika w `%userprofile%\Appdata\Local\Packages`. Ścieżki do różnych typów danych to:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Dane Safari są przechowywane w `/Users/$User/Library/Safari`. Kluczowe pliki to:

- **History.db**: Zawiera tabele `history_visits` i `history_items` z URL-ami i znacznikami czasu odwiedzin. Użyj `sqlite3` do zapytań.
- **Downloads.plist**: Informacje o pobranych plikach.
- **Bookmarks.plist**: Przechowuje zakładki URL.
- **TopSites.plist**: Najczęściej odwiedzane strony.
- **Extensions.plist**: Lista rozszerzeń Safari. Użyj `plutil` lub `pluginkit`, aby je pobrać.
- **UserNotificationPermissions.plist**: Domeny uprawnione do wysyłania powiadomień. Użyj `plutil` do parsowania.
- **LastSession.plist**: Karty z ostatniej sesji. Użyj `plutil` do parsowania.
- **Browser’s built-in anti-phishing**: Sprawdź używając `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odpowiedź 1 oznacza, że funkcja jest aktywna.

## Opera

Dane Opery znajdują się w `/Users/$USER/Library/Application Support/com.operasoftware.Opera` i korzystają z formatu Chrome dla historii i pobrań.

- **Browser’s built-in anti-phishing**: Zweryfikuj, czy `fraud_protection_enabled` w pliku Preferences jest ustawione na `true` za pomocą `grep`.

Te ścieżki i polecenia są kluczowe do uzyskania dostępu i zrozumienia danych przeglądania przechowywanych przez różne przeglądarki internetowe.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}
