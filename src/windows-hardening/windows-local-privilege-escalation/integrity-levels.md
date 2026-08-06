# Poziomy integralności

{{#include ../../banners/hacktricks-training.md}}

## Poziomy integralności

W systemie Windows Vista i nowszych wszystkie chronione elementy mają znacznik **poziomu integralności**. Ta konfiguracja przypisuje głównie plikom i kluczom rejestru poziom integralności „medium”, z wyjątkiem niektórych folderów i plików, które Internet Explorer 7 może zapisywać przy niskim poziomie integralności. Domyślnie procesy uruchamiane przez standardowych użytkowników mają średni poziom integralności, podczas gdy usługi zazwyczaj działają na poziomie integralności systemu. Etykieta wysokiego poziomu integralności chroni katalog główny.

Kluczowa zasada mówi, że obiekty nie mogą być modyfikowane przez procesy o poziomie integralności niższym niż poziom tego obiektu. Dostępne poziomy integralności to:

- **Untrusted**: Ten poziom jest przeznaczony dla procesów z anonimowymi logowaniami. Przykład: Chrome
- **Low**: Używany głównie do interakcji z Internetem, szczególnie w trybie chronionym Internet Explorer, wpływając na powiązane pliki i procesy oraz określone foldery, takie jak **Temporary Internet Folder**. Procesy o niskim poziomie integralności podlegają znacznym ograniczeniom, w tym nie mają dostępu do zapisu w rejestrze i mają ograniczony dostęp do zapisu w profilu użytkownika.
- **Medium**: Domyślny poziom dla większości działań, przypisywany standardowym użytkownikom i obiektom bez określonego poziomu integralności. Nawet członkowie grupy Administrators domyślnie działają na tym poziomie.
- **High**: Zarezerwowany dla administratorów, umożliwiający im modyfikowanie obiektów o niższych poziomach integralności, w tym obiektów znajdujących się na poziomie wysokim.
- **System**: Najwyższy poziom operacyjny dla jądra Windows i podstawowych usług, niedostępny nawet dla administratorów, zapewniający ochronę kluczowych funkcji systemu.
- **Installer**: Unikalny poziom przewyższający wszystkie pozostałe, umożliwiający obiektom na tym poziomie odinstalowanie dowolnego innego obiektu.

Poziom integralności procesu można sprawdzić za pomocą **Process Explorer** z pakietu **Sysinternals**, otwierając **properties** procesu i przechodząc do karty "**Security**":

![Poziomy integralności - Poziomy integralności: Poziom integralności procesu można sprawdzić za pomocą Process Explorer z pakietu Sysinternals, otwierając properties procesu i przechodząc do karty "...](<../../images/image (824).png>)

Możesz także sprawdzić swój **bieżący poziom integralności** za pomocą `whoami /groups`

![Poziomy integralności - Poziomy integralności: Możesz także sprawdzić swój bieżący poziom integralności za pomocą whoami /groups](<../../images/image (325).png>)

### Poziomy integralności w systemie plików

Obiekt w systemie plików może wymagać **minimalnego poziomu integralności**, a jeśli proces nie ma wymaganego poziomu integralności, nie będzie mógł z nim wchodzić w interakcję.\
Na przykład **utwórzmy zwykły plik z konsoli zwykłego użytkownika i sprawdźmy uprawnienia**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Teraz przypiszmy plikowi minimalny poziom integralności **High**. Należy to zrobić z poziomu **konsoli** uruchomionej jako **administrator**, ponieważ **zwykła konsola** będzie działać na poziomie Medium Integrity i **nie będzie mogła** przypisać obiektowi poziomu High Integrity:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
W tym miejscu robi się ciekawie. Widać, że użytkownik `DESKTOP-IDJHTKP\user` ma **FULL privileges** względem pliku (faktycznie to właśnie ten użytkownik utworzył plik), jednak ze względu na zaimplementowany minimalny poziom integralności nie będzie już mógł modyfikować pliku, chyba że działa w ramach High Integrity Level (należy pamiętać, że będzie mógł go odczytać):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Dlatego gdy plik ma określony minimalny poziom integralności, aby go zmodyfikować, musisz działać co najmniej na tym poziomie integralności.**

### Poziomy integralności w plikach binarnych

Utworzyłem kopię `cmd.exe` w `C:\Windows\System32\cmd-low.exe` i ustawiłem dla niej **niski poziom integralności z konsoli administratora:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Teraz, gdy uruchomię `cmd-low.exe`, zostanie on **uruchomiony z niskim poziomem integralności** zamiast ze średnim:

![Poziomy integralności w systemie plików - Poziomy integralności w plikach binarnych: Teraz, gdy uruchomię cmd-low.exe, zostanie on uruchomiony z niskim poziomem integralności zamiast ze średnim](<../../images/image (313).png>)

Jeśli jesteś ciekaw, przypisanie wysokiego poziomu integralności do pliku binarnego (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) nie spowoduje automatycznego uruchomienia go z wysokim poziomem integralności (jeśli wywołasz go ze średniego poziomu integralności — domyślnie — zostanie uruchomiony ze średnim poziomem integralności).

### Poziomy integralności w procesach

Nie wszystkie pliki i foldery mają minimalny poziom integralności, **ale wszystkie procesy są uruchomione z określonym poziomem integralności**. Podobnie jak w przypadku systemu plików, **jeśli proces chce zapisywać dane w innym procesie, musi mieć co najmniej taki sam poziom integralności**. Oznacza to, że proces z niskim poziomem integralności nie może otworzyć uchwytu z pełnym dostępem do procesu ze średnim poziomem integralności.

Ze względu na ograniczenia opisane w tej i poprzedniej sekcji, z punktu widzenia bezpieczeństwa zawsze **zaleca się uruchamianie procesu z możliwie najniższym poziomem integralności**.

{{#include ../../banners/hacktricks-training.md}}
