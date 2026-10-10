# Artefakty przeglądarki

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty przeglądarki <a href="#id-3def" id="id-3def"></a>

Artefakty przeglądarki obejmują różne rodzaje danych przechowywanych przez przeglądarki internetowe, takie jak historia nawigacji, zakładki i dane pamięci podręcznej. Artefakty te są przechowywane w określonych folderach systemu operacyjnego, których lokalizacja i nazwa różnią się w zależności od przeglądarki, ale zazwyczaj zawierają podobne rodzaje danych.

Oto podsumowanie najczęstszych artefaktów przeglądarki:

- **Historia nawigacji**: Śledzi strony odwiedzane przez użytkownika, co ułatwia identyfikację wizyt w złośliwych witrynach.
- **Dane autouzupełniania**: Sugestie oparte na częstych wyszukiwaniach, które w połączeniu z historią nawigacji dostarczają dodatkowych informacji.
- **Zakładki**: Witryny zapisane przez użytkownika w celu szybkiego dostępu.
- **Rozszerzenia i dodatki**: Rozszerzenia lub dodatki przeglądarki zainstalowane przez użytkownika.
- **Pamięć podręczna**: Przechowuje zawartość stron internetowych (np. obrazy, pliki JavaScript), aby przyspieszyć ich ładowanie; jest cennym źródłem w analizie kryminalistycznej.
- **Dane logowania**: Zapisane dane logowania.
- **Favikony**: Ikony powiązane z witrynami, wyświetlane na kartach i w zakładkach, przydatne jako dodatkowe źródło informacji o odwiedzanych stronach.
- **Sesje przeglądarki**: Dane dotyczące otwartych sesji przeglądarki.
- **Pobrane pliki**: Zapis informacji o plikach pobranych za pośrednictwem przeglądarki.
- **Dane formularzy**: Informacje wpisane do formularzy internetowych i zapisane w celu wyświetlania przyszłych sugestii autouzupełniania.
- **Miniatury**: Obrazy podglądu witryn.
- **Custom Dictionary.txt**: Słowa dodane przez użytkownika do słownika przeglądarki.

## Firefox

Firefox przechowuje dane użytkownika w profilach, zapisanych w określonych lokalizacjach zależnych od systemu operacyjnego:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Plik `profiles.ini` w tych katalogach zawiera listę profili użytkowników. Dane każdego profilu są przechowywane w folderze, którego nazwa jest określona w zmiennej `Path` w pliku `profiles.ini`. Folder ten znajduje się w tym samym katalogu co sam plik `profiles.ini`. Jeśli folder profilu nie istnieje, mógł zostać usunięty.

W folderze każdego profilu znajduje się kilka ważnych plików:<sup>[[1]](#references)</sup>

- **places.sqlite**: Przechowuje historię, zakładki i pobrane pliki. Narzędzia takie jak [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) w systemie Windows mogą uzyskać dostęp do danych historii.
  - Użyj odpowiednich zapytań SQL, aby wyodrębnić informacje o historii i pobranych plikach.
- **bookmarkbackups**: Zawiera kopie zapasowe zakładek.
- **formhistory.sqlite**: Przechowuje dane formularzy internetowych.
- **handlers.json**: Zarządza programami obsługi protokołów.
- **persdict.dat**: Słowa z niestandardowego słownika.
- **addons.json** i **extensions.sqlite**: Informacje o zainstalowanych dodatkach i rozszerzeniach.
- **cookies.sqlite**: Przechowuje pliki cookie; do ich przeglądania w systemie Windows można użyć narzędzia [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** lub **startupCache**: Dane pamięci podręcznej, dostępne za pomocą narzędzi takich jak [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Przechowuje favikony.
- **prefs.js**: Ustawienia i preferencje użytkownika.
- **downloads.sqlite**: Starsza baza danych pobranych plików, obecnie zintegrowana z plikiem places.sqlite.
- **thumbnails**: Miniatury witryn.
- **logins.json**: Zaszyfrowane informacje o danych logowania.
- **key4.db** lub **key3.db**: Przechowuje klucze szyfrujące chroniące poufne informacje.

Ustawienia ochrony przed phishingiem w przeglądarce można sprawdzić, wyszukując wpisy `browser.safebrowsing` w pliku `prefs.js`. Wskazują one, czy funkcje bezpiecznego przeglądania są włączone, czy wyłączone.<sup>[[2]](#references)</sup>

Aby odszyfrować zapisane dane logowania z dostępnego profilu, należy podać lub osobno odzyskać [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), jeśli została skonfigurowana; profil nie ujawnia tego hasła. Potwierdź, że odzyskane dane logowania umożliwiają uwierzytelnienie na koncie internetowym. Dostęp root w systemie Unix wymaga osobnego potwierdzenia, że dane uwierzytelniające są akceptowane również przez system uwierzytelniania Unix dla użytkownika root. Zapisane dane logowania można przeglądać za pomocą narzędzia [firefox_decrypt](https://github.com/unode/firefox_decrypt). Poniższy przykład testuje potencjalne hasła Primary Password z pliku haseł:

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

Google Chrome przechowuje profile użytkowników w określonych lokalizacjach, zależnie od systemu operacyjnego:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

W tych katalogach większość danych użytkownika znajduje się w folderach **Default/** lub **ChromeDefaultData/**. Poniższe pliki zawierają istotne dane:<sup>[[1]](#references)</sup>

- **History**: Zawiera adresy URL, pobrane pliki i wyszukiwane słowa kluczowe. W systemie Windows do odczytu historii można użyć narzędzia [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Kolumna „Transition Type” ma różne znaczenia, m.in. kliknięcia linków przez użytkownika, wpisane adresy URL, wysłanie formularzy i ponowne załadowanie strony.
- **Cookies**: Przechowuje cookies. Do ich inspekcji służy [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Przechowuje dane w pamięci podręcznej. Użytkownicy Windows mogą ją sprawdzić za pomocą [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Aplikacje desktopowe oparte na Electron (np. Discord) również korzystają z Chromium Simple Cache i pozostawiają bogate artefakty na dysku. Zobacz:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Zakładki użytkownika.
- **Web Data**: Zawiera historię formularzy.
- **Favicons**: Przechowuje ikony witryn.
- **Login Data**: Zawiera dane logowania, takie jak nazwy użytkowników i hasła.
- **Current Session**/**Current Tabs**: Dane o bieżącej sesji przeglądania i otwartych kartach.
- **Last Session**/**Last Tabs**: Informacje o witrynach aktywnych podczas ostatniej sesji przed zamknięciem Chrome.
- **Extensions**: Katalogi rozszerzeń i dodatków przeglądarki.
- **Thumbnails**: Przechowuje miniatury witryn.
- **Preferences**: Plik zawierający wiele informacji, w tym ustawienia wtyczek, rozszerzeń, wyskakujących okienek, powiadomień i nie tylko.
- **Wbudowana ochrona przeglądarki przed phishingiem**: Aby sprawdzić, czy ochrona przed phishingiem i złośliwym oprogramowaniem jest włączona, uruchom `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. W wynikach poszukaj `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

Katalog `Local Extension Settings/<extension-id>/` w profilu Chromium może zawierać lokalny stan rozszerzenia, w tym materiał kluczowy menedżera haseł. Na przykład [Passbolt informuje, że jego zaszyfrowany klucz prywatny jest przechowywany w lokalnej pamięci rozszerzenia przeglądarki](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), a jego [ID rozszerzenia Chrome](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) wskazuje odpowiedni katalog. Sama obecność katalogu nie dowodzi, że znajduje się w nim klucz, ani nie odblokowuje sejfu: użytkownik musi mieć dostęp do danych profilu, użytecznego klucza prywatnego i hasła oraz autoryzowanej ścieżki odzyskiwania lub uwierzytelniania na serwerze. Wpis sejfu zawierający hasło do konta systemu operacyjnego wymaga osobnej weryfikacji ponownego użycia hasła. Rutynowe wyliczanie powinno podawać wyłącznie ścieżkę do pamięci, bez zrzucania plików LevelDB ani wartości sekretów.

## **Odzyskiwanie danych z baz SQLite**

Jak można zauważyć w poprzednich sekcjach, zarówno Chrome, jak i Firefox używają baz danych **SQLite** do przechowywania danych. Można **odzyskać usunięte wpisy za pomocą narzędzia** [**sqlparse**](https://github.com/padfoot999/sqlparse) **lub** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 zarządza swoimi danymi i metadanymi w różnych lokalizacjach, co ułatwia oddzielenie przechowywanych informacji od odpowiadających im szczegółów oraz ich wyszukiwanie i zarządzanie nimi.

### Przechowywanie metadanych

Metadane Internet Explorera są przechowywane w `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gdzie VX to V01, V16 lub V24). Towarzyszący mu plik `V01.log` może wykazywać rozbieżności w czasie modyfikacji względem `WebcacheVX.data`, co wskazuje na potrzebę naprawy za pomocą `esentutl /r V01 /d`. Te metadane, przechowywane w bazie danych ESE, można odzyskać i sprawdzić odpowiednio za pomocą narzędzi photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). W tabeli **Containers** można ustalić konkretne tabele lub kontenery, w których przechowywany jest każdy segment danych, w tym szczegóły pamięci podręcznej innych narzędzi Microsoft, takich jak Skype.

### Inspekcja pamięci podręcznej

Narzędzie [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) umożliwia inspekcję pamięci podręcznej; wymaga podania lokalizacji folderu z wyodrębnionymi danymi pamięci podręcznej. Metadane pamięci podręcznej obejmują nazwę pliku, katalog, liczbę dostępów, źródłowy adres URL oraz znaczniki czasu utworzenia, dostępu, modyfikacji i wygaśnięcia danych.

### Zarządzanie cookies

Cookies można przeglądać za pomocą [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Metadane obejmują nazwy, adresy URL, liczbę dostępów oraz różne informacje o czasie. Trwałe cookies są przechowywane w `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, a cookies sesyjne znajdują się w pamięci.

### Szczegóły pobierania

Metadane pobieranych plików są dostępne za pomocą [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); konkretne kontenery zawierają takie dane jak adres URL, typ pliku i lokalizacja pobrania. Pliki znajdują się w `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia przeglądania

Do przeglądania historii można użyć narzędzia [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html); wymaga ono podania lokalizacji wyodrębnionych plików historii i konfiguracji dla Internet Explorera. Metadane obejmują czas modyfikacji i dostępu oraz liczbę dostępów. Pliki historii znajdują się w `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Wpisane adresy URL

Wpisane adresy URL i czas ich użycia są przechowywane w rejestrze w pliku `NTUSER.DAT` pod ścieżkami `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`. Są tam zapisywane ostatnie 50 adresów URL wprowadzonych przez użytkownika oraz czas ich ostatniego wpisania.

## Microsoft Edge

Microsoft Edge przechowuje dane użytkownika w `%userprofile%\Appdata\Local\Packages`. Ścieżki do różnych typów danych to:<sup>[[1]](#references)</sup>

- **Ścieżka profilu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historia, cookies i pobrane pliki**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ustawienia, zakładki i lista do przeczytania**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Pamięć podręczna**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Ostatnie aktywne sesje**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Dane Safari są przechowywane w `/Users/$User/Library/Safari`. Najważniejsze pliki to:<sup>[[3]](#references)</sup>

- **History.db**: Zawiera tabele `history_visits` i `history_items` z adresami URL i znacznikami czasu odwiedzin. Do wykonywania zapytań użyj `sqlite3`.
- **Downloads.plist**: Informacje o pobranych plikach.
- **Bookmarks.plist**: Przechowuje adresy URL zakładek.
- **TopSites.plist**: Najczęściej odwiedzane witryny.
- **Extensions.plist**: Lista rozszerzeń przeglądarki Safari. Użyj `plutil` lub `pluginkit`, aby ją pobrać.
- **UserNotificationPermissions.plist**: Domeny uprawnione do wysyłania powiadomień push. Użyj `plutil`, aby przeanalizować plik.
- **LastSession.plist**: Karty z ostatniej sesji. Użyj `plutil`, aby przeanalizować plik.
- **Wbudowana ochrona przeglądarki przed phishingiem**: Sprawdź ją za pomocą `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Wartość 1 oznacza, że funkcja jest aktywna.<sup>[[2]](#references)</sup>

## Opera

Dane Opery znajdują się w `/Users/$USER/Library/Application Support/com.operasoftware.Opera`; format historii i pobranych plików jest taki sam jak w Chrome.

- **Wbudowana ochrona przeglądarki przed phishingiem**: Sprawdź za pomocą `grep`, czy wartość `fraud_protection_enabled` w pliku Preferences jest ustawiona na `true`.<sup>[[2]](#references)</sup>

Te ścieżki i polecenia mają kluczowe znaczenie dla uzyskiwania dostępu do danych przeglądania przechowywanych przez różne przeglądarki internetowe i ich analizy.

## References

- [1] [Informatyka śledcza w przeglądarkach internetowych: przewodnik po analizie śledczej przeglądarek internetowych](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Reagowanie na incydenty w macOS | Część 3: Manipulowanie systemem](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Reagowanie na incydenty w OS X: skrypty i analiza autorstwa Jarona Bradleya](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
