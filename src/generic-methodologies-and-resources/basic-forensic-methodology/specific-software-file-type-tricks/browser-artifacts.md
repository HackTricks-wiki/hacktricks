# Artefakty przeglądarki

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty przeglądarek <a href="#id-3def" id="id-3def"></a>

Artefakty przeglądarek obejmują różne typy danych przechowywanych przez przeglądarki internetowe, takie jak historia nawigacji, zakładki i dane cache. Artefakty te są przechowywane w określonych folderach systemu operacyjnego, których lokalizacja i nazwa różnią się w zależności od przeglądarki, jednak zazwyczaj zawierają podobne typy danych.

Poniżej znajduje się podsumowanie najczęściej spotykanych artefaktów przeglądarek:

- **Historia nawigacji**: Śledzi wizyty użytkownika na stronach internetowych i może pomóc w identyfikacji wizyt na złośliwych stronach.
- **Dane autouzupełniania**: Sugestie oparte na częstych wyszukiwaniach, które w połączeniu z historią nawigacji mogą dostarczyć dodatkowych informacji.
- **Zakładki**: Strony zapisane przez użytkownika w celu szybkiego dostępu.
- **Rozszerzenia i dodatki**: Rozszerzenia lub dodatki przeglądarki zainstalowane przez użytkownika.
- **Cache**: Przechowuje zawartość stron internetowych (np. obrazy i pliki JavaScript), aby przyspieszyć ich ładowanie; jest cenny podczas analizy kryminalistycznej.
- **Loginy**: Przechowywane dane uwierzytelniające.
- **Favikony**: Ikony powiązane ze stronami internetowymi, wyświetlane na kartach i zakładkach, przydatne jako dodatkowe informacje o wizytach użytkownika.
- **Sesje przeglądarki**: Dane związane z otwartymi sesjami przeglądarki.
- **Pobrane pliki**: Rejestry plików pobranych za pośrednictwem przeglądarki.
- **Dane formularzy**: Informacje wprowadzone do formularzy internetowych, zapisywane w celu wyświetlania przyszłych sugestii autouzupełniania.
- **Miniatury**: Obrazy podglądowe stron internetowych.
- **Custom Dictionary.txt**: Słowa dodane przez użytkownika do słownika przeglądarki.

## Firefox

Firefox organizuje dane użytkownika w profilach przechowywanych w określonych lokalizacjach zależnych od systemu operacyjnego:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Plik `profiles.ini` znajdujący się w tych katalogach zawiera listę profili użytkowników. Dane każdego profilu są przechowywane w folderze o nazwie określonej w zmiennej `Path` w pliku `profiles.ini`, znajdującym się w tym samym katalogu co sam plik `profiles.ini`. Jeśli folder profilu nie istnieje, mógł zostać usunięty.

W każdym folderze profilu można znaleźć kilka ważnych plików:<sup>[[1]](#references)</sup>

- **places.sqlite**: Przechowuje historię, zakładki i pobrane pliki. Narzędzia takie jak [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) w systemie Windows mogą uzyskać dostęp do danych historii.
- Użyj konkretnych zapytań SQL, aby wyodrębnić informacje o historii i pobranych plikach.
- **bookmarkbackups**: Zawiera kopie zapasowe zakładek.
- **formhistory.sqlite**: Przechowuje dane formularzy internetowych.
- **handlers.json**: Zarządza handlerami protokołów.
- **persdict.dat**: Zawiera niestandardowe słowa słownika.
- **addons.json** i **extensions.sqlite**: Zawierają informacje o zainstalowanych dodatkach i rozszerzeniach.
- **cookies.sqlite**: Przechowuje cookies; w systemie Windows można je przeglądać za pomocą [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** lub **startupCache**: Zawierają dane cache, dostępne za pomocą narzędzi takich jak [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Przechowuje favikony.
- **prefs.js**: Zawiera ustawienia i preferencje użytkownika.
- **downloads.sqlite**: Starsza baza danych pobranych plików, obecnie zintegrowana z places.sqlite.
- **thumbnails**: Zawiera miniatury stron internetowych.
- **logins.json**: Zawiera zaszyfrowane informacje logowania.
- **key4.db** lub **key3.db**: Przechowuje klucze szyfrowania używane do ochrony poufnych informacji.

Dodatkowo ustawienia anti-phishing przeglądarki można sprawdzić, wyszukując wpisy `browser.safebrowsing` w pliku `prefs.js`, które wskazują, czy funkcje bezpiecznego przeglądania są włączone, czy wyłączone.<sup>[[2]](#references)</sup>

Aby spróbować odszyfrować hasło główne, możesz użyć [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Za pomocą poniższego skryptu i wywołania możesz wskazać plik z hasłami do brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Artefakty przeglądarek - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome przechowuje profile użytkowników w określonych lokalizacjach zależnie od systemu operacyjnego:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

W tych katalogach większość danych użytkownika można znaleźć w folderach **Default/** lub **ChromeDefaultData/**. Następujące pliki zawierają istotne dane:<sup>[[1]](#references)</sup>

- **History**: Zawiera adresy URL, pobrania i słowa kluczowe wyszukiwania. W systemie Windows do odczytu historii można użyć narzędzia [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Kolumna „Transition Type” ma różne znaczenia, w tym kliknięcia użytkownika w linki, wpisane adresy URL, przesłane formularze i ponowne ładowanie stron.
- **Cookies**: Przechowuje cookies. Do inspekcji można użyć narzędzia [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Zawiera dane cache. Użytkownicy systemu Windows mogą użyć narzędzia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Aplikacje desktopowe oparte na Electronie (np. Discord) również używają Chromium Simple Cache i pozostawiają bogate artefakty na dysku. Zobacz:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Zakładki użytkownika.
- **Web Data**: Zawiera historię formularzy.
- **Favicons**: Przechowuje favicons stron internetowych.
- **Login Data**: Zawiera dane logowania, takie jak nazwy użytkowników i hasła.
- **Current Session**/**Current Tabs**: Dane dotyczące bieżącej sesji przeglądania i otwartych kart.
- **Last Session**/**Last Tabs**: Informacje o stronach aktywnych podczas ostatniej sesji przed zamknięciem Chrome.
- **Extensions**: Katalogi rozszerzeń i dodatków przeglądarki.
- **Thumbnails**: Przechowuje miniatury stron internetowych.
- **Preferences**: Plik zawierający wiele informacji, w tym ustawienia pluginów, rozszerzeń, pop-upów, powiadomień i innych elementów.
- **Browser’s built-in anti-phishing**: Aby sprawdzić, czy ochrona anti-phishing i przed malware jest włączona, uruchom `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. W wynikach szukaj `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **Odzyskiwanie danych SQLite DB**

Jak można zauważyć w poprzednich sekcjach, zarówno Chrome, jak i Firefox używają baz danych **SQLite** do przechowywania danych. Możliwe jest **odzyskiwanie usuniętych wpisów za pomocą narzędzia** [**sqlparse**](https://github.com/padfoot999/sqlparse) **lub** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 zarządza swoimi danymi i metadanymi w różnych lokalizacjach, co pomaga oddzielić przechowywane informacje od odpowiadających im szczegółów oraz ułatwia dostęp do nich i zarządzanie nimi.

### Przechowywanie metadanych

Metadane Internet Explorera są przechowywane w `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gdzie VX oznacza V01, V16 lub V24). Towarzyszący mu plik `V01.log` może wykazywać rozbieżności w czasie modyfikacji względem `WebcacheVX.data`, co wskazuje na potrzebę naprawy za pomocą `esentutl /r V01 /d`. Te metadane, przechowywane w bazie ESE, można odzyskać i analizować odpowiednio za pomocą narzędzi photorec oraz [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). W tabeli **Containers** można rozpoznać konkretne tabele lub kontenery, w których przechowywane są poszczególne segmenty danych, w tym szczegóły cache dla innych narzędzi Microsoft, takich jak Skype.

### Inspekcja cache

Narzędzie [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) umożliwia inspekcję cache i wymaga podania lokalizacji folderu, do którego wyodrębniono dane cache. Metadane cache obejmują nazwę pliku, katalog, liczbę dostępów, źródłowy adres URL oraz znaczniki czasu wskazujące czas utworzenia, dostępu, modyfikacji i wygaśnięcia cache.

### Zarządzanie cookies

Cookies można przeglądać za pomocą [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metadane obejmują nazwy, adresy URL, liczbę dostępów i różne informacje związane z czasem. Trwałe cookies są przechowywane w `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, natomiast cookies sesyjne znajdują się w pamięci.

### Szczegóły pobierania

Metadane pobierania są dostępne za pomocą [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), a konkretne kontenery przechowują takie dane jak adres URL, typ pliku i lokalizacja pobierania. Pliki fizyczne można znaleźć w `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia przeglądania

Do przeglądania historii można użyć narzędzia [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), podając lokalizację wyodrębnionych plików historii i konfigurację Internet Explorera. Metadane obejmują tutaj czasy modyfikacji i dostępu oraz liczbę dostępów. Pliki historii znajdują się w `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Wpisywane adresy URL

Wpisywane adresy URL i czasy ich użycia są przechowywane w rejestrze, w `NTUSER.DAT`, pod `Software\Microsoft\InternetExplorer\TypedURLs` oraz `Software\Microsoft\InternetExplorer\TypedURLsTime`. Rejestr śledzi 50 ostatnich adresów URL wprowadzonych przez użytkownika oraz czasy ich ostatniego wpisania.

## Microsoft Edge

Microsoft Edge przechowuje dane użytkownika w `%userprofile%\Appdata\Local\Packages`. Ścieżki dla różnych typów danych to:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Dane Safari są przechowywane w `/Users/$User/Library/Safari`. Najważniejsze pliki to:<sup>[[3]](#references)</sup>

- **History.db**: Zawiera tabele `history_visits` i `history_items` z adresami URL oraz znacznikami czasu odwiedzin. Do wykonywania zapytań użyj `sqlite3`.
- **Downloads.plist**: Informacje o pobranych plikach.
- **Bookmarks.plist**: Przechowuje zapisane adresy URL.
- **TopSites.plist**: Najczęściej odwiedzane strony.
- **Extensions.plist**: Lista rozszerzeń przeglądarki Safari. Do jej pobrania użyj `plutil` lub `pluginkit`.
- **UserNotificationPermissions.plist**: Domeny uprawnione do wysyłania powiadomień push. Do analizy użyj `plutil`.
- **LastSession.plist**: Karty z ostatniej sesji. Do analizy użyj `plutil`.
- **Browser’s built-in anti-phishing**: Sprawdź za pomocą `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odpowiedź 1 oznacza, że funkcja jest aktywna.<sup>[[2]](#references)</sup>

## Opera

Dane Opery znajdują się w `/Users/$USER/Library/Application Support/com.operasoftware.Opera` i używają takiego samego formatu historii oraz pobrań jak Chrome.

- **Browser’s built-in anti-phishing**: Sprawdź, czy `fraud_protection_enabled` w pliku Preferences ma wartość `true`, używając `grep`.<sup>[[2]](#references)</sup>

Te ścieżki i polecenia mają kluczowe znaczenie dla uzyskiwania dostępu do danych przeglądania przechowywanych przez różne przeglądarki internetowe i ich analizy.

## References

- [1] [Forensics przeglądarek internetowych: przewodnik po analizie forensic przeglądarek internetowych](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Incident Response w macOS | Część 3: Manipulacja systemem](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Incident Response w OS X: skrypty i analiza autorstwa Jarona Bradleya](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
