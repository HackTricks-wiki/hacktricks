# Poziomy integralności

{{#include ../../banners/hacktricks-training.md}}

## Poziomy integralności

W systemie Windows Vista i nowszych wersjach obiekty zabezpieczane mogą mieć etykietę **poziomu integralności**. Większość obiektów jest traktowana jako obiekty o średnim poziomie integralności, natomiast określone lokalizacje przeznaczone dla aplikacji o niskim poziomie integralności mogą być oznaczone jako niskie. Procesy uruchamiane przez standardowych użytkowników zwykle działają ze średnim poziomem integralności, aplikacje uruchomione z podwyższonymi uprawnieniami działają z wysokim poziomem integralności, a wiele usług działa z poziomem integralności systemu.<sup>[[1]](#references)</sup>

Kluczowa zasada mówi, że procesy o niższym poziomie integralności niż poziom obiektu nie mogą modyfikować tego obiektu. Windows stosuje to sprawdzenie Mandatory Integrity Control (MIC) przed oceną listy kontroli dostępu obiektu (DACL). Najczęściej spotykane poziomy to:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Najniższy poziom, reprezentowany przez `SECURITY_MANDATORY_UNTRUSTED_RID`. Przykładowo sandbox Windows przeglądarki Chromium początkowo przypisuje obiektom w sandboxie poziom integralności Low, a następnie po uruchomieniu obniża poziom integralności obiektów rendererów do Untrusted.<sup>[[5]](#references)</sup>
- **Low**: Używany głównie do interakcji z Internetem, szczególnie w Protected Mode przeglądarki Internet Explorer, który obejmuje powiązane pliki i procesy oraz określone foldery, takie jak **Temporary Internet Folder**. Procesy o niskim poziomie integralności podlegają znacznym ograniczeniom, w tym nie mają dostępu do zapisu w rejestrze i mają ograniczony dostęp do zapisu w profilu użytkownika.
- **Medium**: Domyślny poziom dla większości działań, przypisywany standardowym użytkownikom i obiektom bez określonego poziomu integralności. Nawet członkowie grupy Administrators działają domyślnie na tym poziomie.
- **High**: Zarezerwowany dla administratorów, umożliwiający im modyfikowanie obiektów o niższych poziomach integralności, w tym również obiektów na poziomie wysokim.
- **System**: Najwyższy operacyjny poziom dla jądra Windows i podstawowych usług, niedostępny nawet dla administratorów, zapewniający ochronę kluczowych funkcji systemu.

Windows definiuje również wartość poziomu integralności protected-process znajdującą się powyżej poziomu System. **TrustedInstaller** jest jednak tożsamością usługi Windows, a nie oddzielnym poziomem MIC; jego zdolność do modyfikowania chronionych zasobów systemu operacyjnego wynika z uprawnień przyznanych tej tożsamości.

Poziom integralności procesu można uzyskać za pomocą **Process Explorer** z pakietu **Sysinternals**, otwierając właściwości procesu i wyświetlając kartę **Security**:<sup>[[3]](#references)</sup>

![Poziomy integralności - Poziomy integralności: Poziom integralności procesu można uzyskać za pomocą Process Explorer z pakietu Sysinternals, otwierając właściwości procesu i wyświetlając kartę "...](<../../images/image (824).png>)

Możesz również uzyskać swój **bieżący poziom integralności** za pomocą `whoami /groups`:

![Poziomy integralności - Poziomy integralności: Bieżący poziom integralności można również uzyskać za pomocą whoami /groups](<../../images/image (325).png>)

### Poziomy integralności w systemie plików

Obiekt w systemie plików może mieć **minimalne wymaganie dotyczące poziomu integralności**. Proces działający na niższym poziomie podlega zasadom obowiązkowym obiektu, nawet jeśli jego DACL w innych okolicznościach przyznawałaby dostęp. Na przykład utwórz zwykły plik z konsoli standardowego użytkownika i sprawdź jego uprawnienia:<sup>[[1]](#references)[[4]](#references)</sup>
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
Teraz przypisz plikowi minimalny poziom integralności **High**. Należy to zrobić z poziomu **konsoli** uruchomionej jako **administrator**, ponieważ zwykła konsola działa z poziomem integralności Medium i **nie będzie mogła** przypisać obiektowi poziomu integralności High:
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
Użytkownik `DESKTOP-IDJHTKP\user` ma **FULL privileges** do pliku, ponieważ go utworzył. Jednak etykieta mandatory uniemożliwia użytkownikowi modyfikowanie pliku, chyba że proces działa na poziomie High integrity. Użytkownik nadal może go odczytywać, ponieważ wyświetlana polityka mandatory to `(NW)`, czyli no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Dlatego gdy plik ma minimalny poziom integralności, aby go zmodyfikować, musisz działać co najmniej na tym poziomie integralności.**

### Poziomy integralności w plikach binarnych

Poniższy przykład używa kopii `cmd.exe` znajdującej się w `C:\Windows\System32\cmd-low.exe` i przypisuje jej **niski poziom integralności z konsoli administratora**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Teraz, gdy uruchamiam `cmd-low.exe`, będzie on **działać na poziomie niskiej integralności** zamiast na poziomie średnim:

![Poziomy integralności w systemie plików - Poziomy integralności w plikach binarnych: Teraz, gdy uruchamiam cmd-low.exe, będzie on działać na poziomie niskiej integralności zamiast na poziomie średnim](<../../images/image (313).png>)

Przypisanie plikowi binarnemu etykiety wysokiej integralności (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) nie powoduje automatycznego uruchomienia go z wysokim poziomem integralności. Jeśli zostanie wywołany z procesu o średnim poziomie integralności, będzie działać na średnim poziomie integralności, ponieważ nowy proces otrzymuje niższy z poziomów integralności pliku wykonywalnego i procesu wywołującego.<sup>[[1]](#references)</sup>

### Poziomy integralności procesów

Nie wszystkie pliki i foldery mają jawną minimalną etykietę integralności, **ale każdy proces działa na określonym poziomie integralności**. Podobnie jak w przypadku obiektów systemu plików, **proces, który chce uzyskać dostęp do zapisu w innym procesie, musi mieć co najmniej ten sam poziom integralności**. Dlatego proces o niskim poziomie integralności nie może otworzyć procesu o średnim poziomie integralności z pełnym dostępem.<sup>[[1]](#references)</sup>

Ze względu na te ograniczenia najbezpieczniejszym podejściem jest **uruchamianie każdego procesu na najniższym poziomie integralności, który nadal pozwala mu wykonywać zamierzone zadania**.

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Microsoft Learn – Domyślna polityka sandboxa systemu Windows w Chromium](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
