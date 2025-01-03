# Artefakty przeglądarki

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty przeglądarek <a href="#id-3def" id="id-3def"></a>

Artefakty przeglądarek obejmują różne typy danych przechowywanych przez przeglądarki internetowe, takie jak historia nawigacji, zakładki i dane pamięci podręcznej. Artefakty te są przechowywane w określonych folderach w systemie operacyjnym, różniących się lokalizacją i nazwą w zależności od przeglądarki, ale ogólnie przechowują podobne typy danych.

Oto podsumowanie najczęstszych artefaktów przeglądarek:

- **Historia nawigacji**: Śledzi wizyty użytkownika na stronach internetowych, przydatna do identyfikacji wizyt na złośliwych stronach.
- **Dane autouzupełniania**: Sugestie oparte na częstych wyszukiwaniach, oferujące wgląd w połączeniu z historią nawigacji.
- **Zakładki**: Strony zapisane przez użytkownika dla szybkiego dostępu.
- **Rozszerzenia i dodatki**: Rozszerzenia przeglądarki lub dodatki zainstalowane przez użytkownika.
- **Pamięć podręczna**: Przechowuje treści internetowe (np. obrazy, pliki JavaScript) w celu poprawy czasu ładowania stron, cenne dla analizy kryminalistycznej.
- **Loginy**: Przechowywane dane logowania.
- **Favikony**: Ikony związane ze stronami internetowymi, pojawiające się w kartach i zakładkach, przydatne do uzyskania dodatkowych informacji o wizytach użytkownika.
- **Sesje przeglądarki**: Dane związane z otwartymi sesjami przeglądarki.
- **Pobrania**: Rejestry plików pobranych przez przeglądarkę.
- **Dane formularzy**: Informacje wprowadzone w formularzach internetowych, zapisane do przyszłych sugestii autouzupełniania.
- **Miniatury**: Obrazy podglądowe stron internetowych.
- **Custom Dictionary.txt**: Słowa dodane przez użytkownika do słownika przeglądarki.

## Firefox

Firefox organizuje dane użytkownika w profilach, przechowywanych w określonych lokalizacjach w zależności od systemu operacyjnego:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Plik `profiles.ini` w tych katalogach zawiera listę profili użytkowników. Dane każdego profilu są przechowywane w folderze nazwanym w zmiennej `Path` w `profiles.ini`, znajdującym się w tym samym katalogu co `profiles.ini`. Jeśli folder profilu jest brakujący, mógł zostać usunięty.

W każdym folderze profilu można znaleźć kilka ważnych plików:

- **places.sqlite**: Przechowuje historię, zakładki i pobrania. Narzędzia takie jak [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) na Windows mogą uzyskać dostęp do danych historii.
- Użyj konkretnych zapytań SQL, aby wyodrębnić informacje o historii i pobraniach.
- **bookmarkbackups**: Zawiera kopie zapasowe zakładek.
- **formhistory.sqlite**: Przechowuje dane formularzy internetowych.
- **handlers.json**: Zarządza obsługą protokołów.
- **persdict.dat**: Słowa ze słownika użytkownika.
- **addons.json** i **extensions.sqlite**: Informacje o zainstalowanych dodatkach i rozszerzeniach.
- **cookies.sqlite**: Przechowywanie ciasteczek, z [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) dostępnym do inspekcji na Windows.
- **cache2/entries** lub **startupCache**: Dane pamięci podręcznej, dostępne za pomocą narzędzi takich jak [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Przechowuje favikony.
- **prefs.js**: Ustawienia i preferencje użytkownika.
- **downloads.sqlite**: Starsza baza danych pobrań, teraz zintegrowana z places.sqlite.
- **thumbnails**: Miniatury stron internetowych.
- **logins.json**: Szyfrowane informacje logowania.
- **key4.db** lub **key3.db**: Przechowuje klucze szyfrujące do zabezpieczania wrażliwych informacji.

Dodatkowo, sprawdzenie ustawień przeglądarki dotyczących ochrony przed phishingiem można przeprowadzić, wyszukując wpisy `browser.safebrowsing` w `prefs.js`, co wskazuje, czy funkcje bezpiecznego przeglądania są włączone czy wyłączone.

Aby spróbować odszyfrować hasło główne, możesz użyć [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Za pomocą poniższego skryptu i wywołania możesz określić plik haseł do brutalnego wymuszenia:
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

- **Historia**: Zawiera adresy URL, pobrania i słowa kluczowe wyszukiwania. Na Windowsie można użyć [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) do odczytania historii. Kolumna "Typ przejścia" ma różne znaczenia, w tym kliknięcia użytkownika w linki, wpisane adresy URL, przesyłanie formularzy i przeładowania stron.
- **Ciasteczka**: Przechowuje ciasteczka. Do inspekcji dostępne jest [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Przechowuje dane w pamięci podręcznej. Aby sprawdzić, użytkownicy Windows mogą skorzystać z [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).
- **Zakładki**: Zakładki użytkownika.
- **Dane sieciowe**: Zawiera historię formularzy.
- **Favikony**: Przechowuje favikony stron internetowych.
- **Dane logowania**: Zawiera dane logowania, takie jak nazwy użytkowników i hasła.
- **Bieżąca sesja**/**Bieżące karty**: Dane o bieżącej sesji przeglądania i otwartych kartach.
- **Ostatnia sesja**/**Ostatnie karty**: Informacje o stronach aktywnych podczas ostatniej sesji przed zamknięciem Chrome.
- **Rozszerzenia**: Katalogi dla rozszerzeń przeglądarki i dodatków.
- **Miniatury**: Przechowuje miniatury stron internetowych.
- **Preferencje**: Plik bogaty w informacje, w tym ustawienia dla wtyczek, rozszerzeń, wyskakujących okienek, powiadomień i innych.
- **Wbudowana ochrona przed phishingiem przeglądarki**: Aby sprawdzić, czy ochrona przed phishingiem i złośliwym oprogramowaniem jest włączona, uruchom `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Szukaj `{"enabled: true,"}` w wynikach.

## **Odzyskiwanie danych z bazy SQLite**

Jak można zauważyć w poprzednich sekcjach, zarówno Chrome, jak i Firefox używają baz danych **SQLite** do przechowywania danych. Możliwe jest **odzyskanie usuniętych wpisów za pomocą narzędzia** [**sqlparse**](https://github.com/padfoot999/sqlparse) **lub** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 zarządza swoimi danymi i metadanymi w różnych lokalizacjach, co ułatwia oddzielanie przechowywanych informacji i ich odpowiadających szczegółów dla łatwego dostępu i zarządzania.

### Przechowywanie metadanych

Metadane dla Internet Explorera są przechowywane w `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gdzie VX to V01, V16 lub V24). Wraz z tym plikiem `V01.log` może pokazywać różnice w czasie modyfikacji w porównaniu do `WebcacheVX.data`, co wskazuje na potrzebę naprawy za pomocą `esentutl /r V01 /d`. Te metadane, przechowywane w bazie danych ESE, można odzyskać i zbadać za pomocą narzędzi takich jak photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). W tabeli **Containers** można dostrzec konkretne tabele lub kontenery, w których przechowywany jest każdy segment danych, w tym szczegóły pamięci podręcznej dla innych narzędzi Microsoftu, takich jak Skype.

### Inspekcja pamięci podręcznej

Narzędzie [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) umożliwia inspekcję pamięci podręcznej, wymagając lokalizacji folderu z danymi pamięci podręcznej. Metadane pamięci podręcznej obejmują nazwę pliku, katalog, liczbę dostępu, pochodzenie URL oraz znaczniki czasowe wskazujące czasy utworzenia, dostępu, modyfikacji i wygaśnięcia pamięci podręcznej.

### Zarządzanie ciasteczkami

Ciasteczka można badać za pomocą [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metadane obejmują nazwy, adresy URL, liczby dostępu i różne szczegóły czasowe. Ciasteczka trwałe są przechowywane w `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, a ciasteczka sesyjne znajdują się w pamięci.

### Szczegóły pobierania

Metadane pobierania są dostępne za pośrednictwem [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), a konkretne kontenery przechowują dane takie jak URL, typ pliku i lokalizacja pobierania. Fizyczne pliki można znaleźć w `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia przeglądania

Aby przeglądać historię przeglądania, można użyć [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), wymagając lokalizacji wyodrębnionych plików historii i konfiguracji dla Internet Explorera. Metadane tutaj obejmują czasy modyfikacji i dostępu, wraz z liczbą dostępu. Pliki historii znajdują się w `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Wpisane adresy URL

Wpisane adresy URL i ich czasy użycia są przechowywane w rejestrze pod `NTUSER.DAT` w `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`, śledząc ostatnie 50 adresów URL wprowadzonych przez użytkownika i ich ostatnie czasy wprowadzenia.

## Microsoft Edge

Microsoft Edge przechowuje dane użytkowników w `%userprofile%\Appdata\Local\Packages`. Ścieżki dla różnych typów danych to:

- **Ścieżka profilu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historia, ciasteczka i pobrania**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ustawienia, zakładki i lista czytania**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Pamięć podręczna**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Ostatnie aktywne sesje**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Dane Safari są przechowywane w `/Users/$User/Library/Safari`. Kluczowe pliki to:

- **History.db**: Zawiera tabele `history_visits` i `history_items` z adresami URL i znacznikami czasu wizyt. Użyj `sqlite3`, aby zapytać.
- **Downloads.plist**: Informacje o pobranych plikach.
- **Bookmarks.plist**: Przechowuje zakładkowane adresy URL.
- **TopSites.plist**: Najczęściej odwiedzane strony.
- **Extensions.plist**: Lista rozszerzeń przeglądarki Safari. Użyj `plutil` lub `pluginkit`, aby je pobrać.
- **UserNotificationPermissions.plist**: Domeny uprawnione do wysyłania powiadomień. Użyj `plutil`, aby je przeanalizować.
- **LastSession.plist**: Karty z ostatniej sesji. Użyj `plutil`, aby je przeanalizować.
- **Wbudowana ochrona przed phishingiem przeglądarki**: Sprawdź, używając `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odpowiedź 1 wskazuje, że funkcja jest aktywna.

## Opera

Dane Opery znajdują się w `/Users/$USER/Library/Application Support/com.operasoftware.Opera` i dzielą format Chrome'a dla historii i pobrań.

- **Wbudowana ochrona przed phishingiem przeglądarki**: Zweryfikuj, sprawdzając, czy `fraud_protection_enabled` w pliku Preferencje jest ustawione na `true` za pomocą `grep`.

Te ścieżki i polecenia są kluczowe dla uzyskania dostępu i zrozumienia danych przeglądania przechowywanych przez różne przeglądarki internetowe.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Książka: OS X Incident Response: Scripting and Analysis By Jaron Bradley str. 123**

{{#include ../../../banners/hacktricks-training.md}}
