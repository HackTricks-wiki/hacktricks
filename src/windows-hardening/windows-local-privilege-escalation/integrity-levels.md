# Poziomy integralności

{{#include ../../banners/hacktricks-training.md}}

## Poziomy integralności

W systemie Windows Vista i nowszych wersjach obiekty zabezpieczane mogą zawierać etykietę **poziomu integralności**. Większość obiektów jest traktowana jako obiekty o średnim poziomie integralności, natomiast określone lokalizacje przeznaczone dla aplikacji o niskim poziomie integralności mogą być oznaczone jako niskie. Procesy uruchamiane przez standardowych użytkowników zwykle działają na średnim poziomie integralności, podwyższone aplikacje działają na wysokim poziomie integralności, a wiele usług działa na poziomie integralności systemu.<sup>[[1]](#references)</sup>

Kluczowa zasada mówi, że procesy o niższym poziomie integralności niż poziom obiektu nie mogą modyfikować tego obiektu. Windows stosuje to sprawdzenie Mandatory Integrity Control (MIC) przed sprawdzeniem listy uznaniowej kontroli dostępu (DACL) obiektu. Często spotykane poziomy to:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Najniższy poziom, reprezentowany przez `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Nie należy mylić tej etykiety integralności z tożsamością **Anonymous Logon** (`S-1-5-7`); tożsamości uwierzytelniania i etykiety MIC należą do oddzielnych przestrzeni nazw SID. Przykładowo sandbox systemu Chromium dla Windows początkowo przypisuje celom sandboxa poziom integralności Low, a następnie po uruchomieniu obniża poziom celów rendererów do poziomu integralności Untrusted.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Używany głównie do interakcji internetowych, zwłaszcza w trybie Protected Mode przeglądarki Internet Explorer, co wpływa na powiązane pliki i procesy, a także na określone foldery, takie jak **Temporary Internet Folder**. Procesy o niskim poziomie integralności podlegają istotnym ograniczeniom, w tym nie mają dostępu do zapisu w rejestrze i mają ograniczony dostęp do zapisu w profilu użytkownika.
- **Medium**: Domyślny poziom dla większości działań, przypisywany standardowym użytkownikom oraz obiektom bez określonych poziomów integralności. Nawet członkowie grupy Administrators działają domyślnie na tym poziomie.
- **High**: Zarezerwowany dla administratorów, umożliwia im modyfikowanie obiektów o niższych poziomach integralności, w tym obiektów znajdujących się na samym poziomie High.
- **System**: Najwyższy poziom operacyjny dla jądra Windows i podstawowych usług, niedostępny nawet dla administratorów, zapewniający ochronę kluczowych funkcji systemu.

Windows definiuje również wartość integralności chronionego procesu znajdującą się powyżej poziomu System. **TrustedInstaller** jest jednak tożsamością usługi Windows, a nie odrębnym poziomem MIC; możliwość modyfikowania chronionych zasobów systemu operacyjnego wynika z uprawnień przyznanych tej tożsamości.

Nie należy zakładać, że lokalizacja taka jak katalog główny dysku systemowego zawsze ma stałą etykietę integralności High. Sprawdź efektywną DACL oraz wszelkie jawne etykiety obowiązkowe za pomocą `icacls`; obiekt bez etykiety jest traktowany jako Medium przez MIC, natomiast jego DACL i właściciel nadal mogą niezależnie ograniczać dostęp.<sup>[[1]](#references)[[4]](#references)</sup>

Poziom integralności procesu można uzyskać za pomocą **Process Explorer** z pakietu **Sysinternals**, otwierając właściwości procesu i wyświetlając kartę **Security**:<sup>[[3]](#references)</sup>

![Poziomy integralności - Poziomy integralności: Poziom integralności procesu można uzyskać za pomocą Process Explorer z pakietu Sysinternals, otwierając właściwości procesu i wyświetlając kartę „...](<../../images/image (824).png>)

Można również uzyskać **bieżący poziom integralności** za pomocą `whoami /groups`:

![Poziomy integralności - Poziomy integralności: Bieżący poziom integralności można również uzyskać za pomocą whoami /groups](<../../images/image (325).png>)

### Poziomy integralności w systemie plików

Obiekt w systemie plików może mieć **minimalne wymaganie dotyczące poziomu integralności**. Proces działający poniżej tego poziomu podlega zasadom obowiązującym dla obiektu, nawet jeśli jego DACL w innych okolicznościach przyznawałaby dostęp. Na przykład utwórz zwykły plik z konsoli standardowego użytkownika i sprawdź jego uprawnienia:<sup>[[1]](#references)[[4]](#references)</sup>
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
Teraz przypisz plikowi minimalny poziom integralności **High**. Należy to zrobić z poziomu **konsoli** uruchomionej jako **administrator**, ponieważ zwykła konsola działa z poziomem integralności Medium i **nie będzie mieć uprawnień** do przypisania obiektowi poziomu integralności High:
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
Użytkownik `DESKTOP-IDJHTKP\user` ma **PEŁNE uprawnienia** do pliku, ponieważ ten użytkownik go utworzył. Jednak etykieta mandatory uniemożliwia użytkownikowi modyfikowanie pliku, chyba że proces działa z poziomem High integrity. Użytkownik nadal może go odczytać, ponieważ wyświetlana mandatory policy to `(NW)`, czyli no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Dlatego, gdy plik ma minimalny poziom integralności, aby go zmodyfikować, musisz działać co najmniej na tym poziomie integralności.**

### Poziomy integralności w plikach binarnych

Poniższy przykład używa kopii `cmd.exe` w lokalizacji `C:\Windows\System32\cmd-low.exe` i przypisuje jej **poziom integralności Low z konsoli administratora**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Teraz, gdy uruchamiam `cmd-low.exe`, będzie on **działać na poziomie niskiej integralności** zamiast średniego:

![Poziomy integralności w systemie plików - Poziomy integralności w plikach binarnych: Teraz, gdy uruchamiam cmd-low.exe, będzie on działać na poziomie niskiej integralności zamiast średniego](<../../images/image (313).png>)

Przypisanie plikowi binarnemu etykiety wysokiej integralności (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) nie powoduje automatycznego uruchomienia go z wysokim poziomem integralności. Jeśli zostanie wywołany z procesu o średnim poziomie integralności, będzie działać na średnim poziomie integralności, ponieważ nowy proces otrzymuje niższy z poziomów integralności pliku wykonywalnego i procesu wywołującego.<sup>[[1]](#references)</sup>

### Poziomy integralności procesów

Nie wszystkie pliki i foldery mają jawną minimalną etykietę integralności, **ale każdy proces działa na określonym poziomie integralności**. Podobnie jak w przypadku obiektów systemu plików, **proces, który chce uzyskać dostęp do zapisu w innym procesie, musi mieć co najmniej taki sam poziom integralności**. Dlatego proces o niskim poziomie integralności nie może otworzyć procesu o średnim poziomie integralności z pełnym dostępem.<sup>[[1]](#references)</sup>

Ze względu na te ograniczenia najbezpieczniejszym rozwiązaniem jest **uruchamianie każdego procesu z najniższym poziomem integralności, który nadal pozwala mu wykonywać zamierzone zadania**.

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Default Windows sandbox integrity policy](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
