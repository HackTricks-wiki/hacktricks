# Artefakty przeglądarki

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty przeglądarki <a href="#id-3def" id="id-3def"></a>

Artefakty przeglądarki obejmują różne rodzaje danych przechowywanych przez przeglądarki internetowe, takie jak historia przeglądania, zakładki i dane pamięci podręcznej. Są one przechowywane w określonych folderach systemu operacyjnego, których lokalizacja i nazwa różnią się w zależności od przeglądarki, ale zazwyczaj zawierają podobne rodzaje danych.

Oto podsumowanie najczęściej spotykanych artefaktów przeglądarki:

- **Historia przeglądania**: Śledzi odwiedzane przez użytkownika witryny, co może pomóc w ustaleniu, czy odwiedzano złośliwe strony.
- **Dane autouzupełniania**: Sugestie oparte na częstych wyszukiwaniach, które w połączeniu z historią przeglądania mogą dostarczyć dodatkowych informacji.
- **Zakładki**: Witryny zapisane przez użytkownika w celu szybkiego dostępu.
- **Rozszerzenia i dodatki**: Rozszerzenia lub dodatki przeglądarki zainstalowane przez użytkownika.
- **Pamięć podręczna**: Przechowuje zawartość stron internetowych (np. obrazy, pliki JavaScript), aby przyspieszyć ich ładowanie; może być przydatna w analizie kryminalistycznej.
- **Loginy**: Zapisane dane logowania.
- **Favikony**: Ikony powiązane z witrynami, wyświetlane na kartach i w zakładkach, które mogą dostarczyć dodatkowych informacji o odwiedzanych stronach.
- **Sesje przeglądarki**: Dane związane z otwartymi sesjami przeglądarki.
- **Pobrane pliki**: Rejestry plików pobranych za pomocą przeglądarki.
- **Dane formularzy**: Informacje wpisane w formularzach internetowych i zapisane w celu wyświetlania przyszłych sugestii autouzupełniania.
- **Miniatury**: Obrazy podglądu witryn.
- **Custom Dictionary.txt**: Słowa dodane przez użytkownika do słownika przeglądarki.

## Firefox

Firefox przechowuje dane użytkownika w profilach znajdujących się w określonych lokalizacjach zależnych od systemu operacyjnego:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Plik `profiles.ini` w tych katalogach zawiera listę profili użytkownika. Dane każdego profilu są przechowywane w folderze o nazwie określonej przez zmienną `Path` w pliku `profiles.ini`, który znajduje się w tym samym katalogu. Jeśli folder profilu nie istnieje, mógł zostać usunięty.

W każdym folderze profilu znajduje się kilka ważnych plików:<sup>[[1]](#references)</sup>

- **places.sqlite**: Przechowuje historię, zakładki i informacje o pobranych plikach. Narzędzia takie jak [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) w systemie Windows mogą uzyskać dostęp do danych historii.
  - Użyj odpowiednich zapytań SQL, aby wyodrębnić informacje o historii i pobranych plikach.
- **bookmarkbackups**: Zawiera kopie zapasowe zakładek.
- **formhistory.sqlite**: Przechowuje dane formularzy internetowych.
- **handlers.json**: Zarządza programami obsługi protokołów.
- **persdict.dat**: Niestandardowe słowa słownika.
- **addons.json** i **extensions.sqlite**: Informacje o zainstalowanych dodatkach i rozszerzeniach.
- **cookies.sqlite**: Przechowuje pliki cookie; w systemie Windows można je przeglądać za pomocą [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** lub **startupCache**: Dane pamięci podręcznej, do których można uzyskać dostęp za pomocą narzędzi takich jak [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Przechowuje favikony.
- **prefs.js**: Ustawienia i preferencje użytkownika.
- **downloads.sqlite**: Starsza baza danych pobranych plików, obecnie zintegrowana z places.sqlite.
- **thumbnails**: Miniatury witryn.
- **logins.json**: Zaszyfrowane informacje logowania.
- **key4.db** lub **key3.db**: Przechowuje klucze szyfrujące chroniące poufne informacje.

Ustawienia ochrony przed phishingiem w przeglądarce można sprawdzić, wyszukując wpisy `browser.safebrowsing` w pliku `prefs.js`, które wskazują, czy funkcje bezpiecznego przeglądania są włączone, czy wyłączone.<sup>[[2]](#references)</sup>

Aby odszyfrować zapisane loginy z dostępnego profilu, należy podać lub osobno odzyskać [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), jeśli została skonfigurowana; profil nie ujawnia tego hasła. Sprawdź, czy odzyskane dane logowania pozwalają uwierzytelnić się na powiązanym koncie internetowym. Dostęp roota w systemie Unix wymaga osobnego potwierdzenia, że dane uwierzytelniające są akceptowane również przez mechanizm uwierzytelniania systemu Unix dla roota. Zapisane loginy można przeglądać za pomocą [firefox_decrypt](https://github.com/unode/firefox_decrypt). Poniższy przykład sprawdza kandydatów na hasło główne z pliku haseł:

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

W tych katalogach większość danych użytkownika można znaleźć w folderach **Default/** lub **ChromeDefaultData/**. Istotne dane znajdują się w następujących plikach:<sup>[[1]](#references)</sup>

- **History**: Zawiera adresy URL, pobrane pliki i wyszukiwane słowa kluczowe. W systemie Windows do odczytu historii można użyć narzędzia [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Kolumna „Transition Type” może przyjmować różne wartości, wskazujące między innymi kliknięcia linków przez użytkownika, wpisane adresy URL, wysłanie formularza i ponowne wczytanie strony.
- **Cookies**: Przechowuje pliki cookie. Do ich przeglądania można użyć narzędzia [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Przechowuje dane w cache. Użytkownicy Windows mogą je przeglądać za pomocą narzędzia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Aplikacje desktopowe oparte na Electron (np. Discord) również używają Chromium Simple Cache i pozostawiają bogate artefakty na dysku. Zobacz:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Zakładki użytkownika.
- **Web Data**: Zawiera historię formularzy.
- **Favicons**: Przechowuje ikony witryn.
- **Login Data**: Zawiera dane logowania, takie jak nazwy użytkowników i hasła.
- **Current Session**/**Current Tabs**: Dane dotyczące bieżącej sesji przeglądania i otwartych kart.
- **Last Session**/**Last Tabs**: Informacje o witrynach aktywnych podczas ostatniej sesji przed zamknięciem Chrome.
- **Extensions**: Katalogi rozszerzeń i dodatków przeglądarki.
- **Thumbnails**: Przechowuje miniatury witryn.
- **Preferences**: Plik zawierający wiele informacji, w tym ustawienia wtyczek, rozszerzeń, wyskakujących okienek, powiadomień i inne.
- **Wbudowana ochrona przeglądarki przed phishingiem**: Aby sprawdzić, czy ochrona przed phishingiem i złośliwym oprogramowaniem jest włączona, uruchom `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. W wynikach poszukaj `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

Katalog `Local Extension Settings/<extension-id>/` w profilu Chromium może zawierać lokalny stan rozszerzenia, w tym materiał klucza używanego przez menedżer haseł. Na przykład [Passbolt informuje, że jego zaszyfrowany klucz prywatny jest przechowywany w lokalnym magazynie rozszerzenia przeglądarki](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), a jego [Chrome extension ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) pozwala wskazać odpowiedni katalog. Sama obecność katalogu nie dowodzi, że znajduje się w nim klucz, ani nie odblokowuje sejfu: użytkownik musi mieć dostęp do danych profilu, użyteczny klucz prywatny i hasło oraz autoryzowaną ścieżkę odzyskiwania lub uwierzytelniania na serwerze. W przypadku elementu sejfu zawierającego hasło do konta systemu operacyjnego konieczna jest osobna weryfikacja ponownego użycia hasła. Rutynowa enumeracja powinna podawać wyłącznie ścieżkę do magazynu, bez zrzucania plików LevelDB ani wartości sekretów.

## **Odzyskiwanie danych z baz SQLite**

Jak widać w poprzednich sekcjach, zarówno Chrome, jak i Firefox używają baz danych **SQLite** do przechowywania danych. Możliwe jest **odzyskanie usuniętych wpisów za pomocą narzędzia** [**sqlparse**](https://github.com/padfoot999/sqlparse) **lub** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 przechowuje swoje dane i metadane w różnych lokalizacjach, co ułatwia oddzielenie zapisanych informacji od powiązanych z nimi szczegółów oraz ich dostępne i uporządkowane zarządzanie.

### Przechowywanie metadanych

Metadane Internet Explorera są przechowywane w `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gdzie VX oznacza V01, V16 lub V24). Towarzyszący mu plik `V01.log` może wskazywać rozbieżności dotyczące czasu modyfikacji względem `WebcacheVX.data`, co może oznaczać konieczność naprawy za pomocą `esentutl /r V01 /d`. Metadane przechowywane w bazie danych ESE można odzyskać i sprawdzić odpowiednio za pomocą narzędzi photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Tabela **Containers** pozwala ustalić, w których tabelach lub kontenerach zapisano poszczególne segmenty danych, w tym szczegóły cache innych narzędzi Microsoft, takich jak Skype.

### Przeglądanie cache

Narzędzie [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) umożliwia przeglądanie cache; wymaga podania lokalizacji folderu, do którego wyodrębniono dane cache. Metadane cache obejmują nazwę pliku, katalog, liczbę dostępów, źródłowy adres URL oraz znaczniki czasu utworzenia, dostępu, modyfikacji i wygaśnięcia wpisu w cache.

### Zarządzanie plikami cookie

Pliki cookie można przeglądać za pomocą narzędzia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Metadane obejmują nazwy, adresy URL, liczbę dostępów i różne informacje dotyczące czasu. Trwałe pliki cookie są przechowywane w `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, a sesyjne znajdują się w pamięci.

### Szczegóły pobierania

Metadane pobranych plików są dostępne za pomocą [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); określone kontenery przechowują takie dane jak adres URL, typ pliku i lokalizacja pobrania. Pliki znajdują się w `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia przeglądania

Do przeglądania historii można użyć narzędzia [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html). Wymaga ono podania lokalizacji wyodrębnionych plików historii i konfiguracji dla Internet Explorera. Metadane obejmują czasy modyfikacji i dostępu oraz liczbę dostępów. Pliki historii znajdują się w `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Wpisane adresy URL

Wpisane adresy URL i czas ich użycia są przechowywane w rejestrze w pliku `NTUSER.DAT`, w lokalizacjach `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`. Rejestr śledzi 50 ostatnich adresów URL wpisanych przez użytkownika oraz czas ich ostatniego wprowadzenia.

## Microsoft Edge

Microsoft Edge przechowuje dane użytkownika w `%userprofile%\Appdata\Local\Packages`. Ścieżki do różnych typów danych to:<sup>[[1]](#references)</sup>

- **Ścieżka profilu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historia, pliki cookie i pobrane pliki**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ustawienia, zakładki i lista do przeczytania**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Ostatnie aktywne sesje**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Dane Safari są przechowywane w `/Users/$User/Library/Safari`. Do najważniejszych plików należą:<sup>[[3]](#references)</sup>

- **History.db**: Zawiera tabele `history_visits` i `history_items` z adresami URL i znacznikami czasu odwiedzin. Do wykonywania zapytań użyj `sqlite3`.
- **Downloads.plist**: Informacje o pobranych plikach.
- **Bookmarks.plist**: Przechowuje zapisane w zakładkach adresy URL.
- **TopSites.plist**: Najczęściej odwiedzane witryny.
- **Extensions.plist**: Lista rozszerzeń przeglądarki Safari. Do ich odczytu użyj `plutil` lub `pluginkit`.
- **UserNotificationPermissions.plist**: Domeny, którym zezwolono na wysyłanie powiadomień push. Do analizy użyj `plutil`.
- **LastSession.plist**: Karty z ostatniej sesji. Do analizy użyj `plutil`.
- **Wbudowana ochrona przeglądarki przed phishingiem**: Sprawdź ją za pomocą `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Wartość 1 oznacza, że funkcja jest aktywna.<sup>[[2]](#references)</sup>

## Opera

Dane Opery znajdują się w `/Users/$USER/Library/Application Support/com.operasoftware.Opera`; format historii i pobranych plików jest taki sam jak w Chrome.

- **Wbudowana ochrona przeglądarki przed phishingiem**: Sprawdź za pomocą `grep`, czy wartość `fraud_protection_enabled` w pliku Preferences jest ustawiona na `true`.<sup>[[2]](#references)</sup>

Te ścieżki i polecenia są niezbędne do uzyskiwania dostępu do danych przeglądania przechowywanych przez różne przeglądarki internetowe i ich analizy.

## References

- [1] [Informatyka śledcza przeglądarek internetowych: przewodnik po analizie śledczej przeglądarek internetowych](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Reagowanie na incydenty w macOS | Część 3: Manipulowanie systemem](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Reagowanie na incydenty w OS X: skrypty i analiza, Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
