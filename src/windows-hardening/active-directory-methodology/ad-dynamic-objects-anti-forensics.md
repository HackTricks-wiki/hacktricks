# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Jedes Objekt, das mit der auxiliary class **`dynamicObject`** erstellt wurde, erhält **`entryTTL`** (Sekunden-Countdown) und **`msDS-Entry-Time-To-Die`** (absolute Ablaufzeit). Wenn `entryTTL` 0 erreicht, löscht der **Garbage Collector** es ohne tombstone/recycle-bin und entfernt dabei Ersteller-/Zeitstempel, wodurch eine Wiederherstellung blockiert wird.
- **`entryTTL` ist ein operational/constructed attribute**: verlange es explizit in LDAP-Queries. TTL kann entweder durch Aktualisieren von `entryTTL` vor dem Ablauf oder über den LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** erneuert werden.
- TTL-Minimum/-Standard werden in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** erzwungen. Microsoft dokumentiert **86400s** als Standard-TTL und **900s** als Standard-Mindest-TTL; beide unterstützen **1s–1y**. Dynamic objects werden in **Configuration/Schema partitions** nicht unterstützt.
- Es gibt **keine static→dynamic conversion** und nach dem Ablauf keine tombstone-Phase. IR-Teams können sich nicht auf deleted-object controls oder Recycle Bin verlassen; sie müssen das live object/metadata erfassen, bevor GC es entfernt.
- Refresh ist **replica-sensitive**: Wenn TTL zu nah am Ablauf erneuert wird, kann eine andere writable replica oder GC das Objekt lokal trotzdem löschen, bevor der Refresh repliziert wird. Sehr kurze TTLs funktionieren daher am besten, wenn der Angreifer weiß, welcher DC den Abuse bedienen wird, während Verteidiger während der Triage **alle naming contexts / replicas** abfragen sollten.
- Die Löschung kann auf DCs mit kurzer uptime (<24h) um einige Minuten verzögert sein, wodurch ein schmales Response-Fenster bleibt, um attributes abzufragen/zu sichern. Erkennen durch **Alerting auf neue Objekte mit `entryTTL`/`msDS-Entry-Time-To-Die`** und Korrelation mit orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Frage **alle `namingContexts` aus RootDSE** ab, nicht nur den domain NC. Dynamic abuse kann in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) oder in application partitions liegen.
- Solange das Objekt noch lebt, sofort **replication metadata** und alle verknüpften attributes/ACLs auslesen. Nach dem Ablauf bleiben möglicherweise nur **broken `gPLink` values, orphan SIDs oder cached DNS answers** übrig.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ-Umgehung mit sich selbst löschenden Computern

- Das Standard-**`ms-DS-MachineAccountQuota` = 10** erlaubt jedem authentifizierten Benutzer, Computer zu erstellen. Füge bei der Erstellung **`dynamicObject`** hinzu, damit sich der Computer selbst löscht und **den Quotenplatz freigibt**, während Beweise entfernt werden.
- Powermad-Anpassung in **`New-MachineAccount`** (objectClass-Liste):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Wenn die angeforderte TTL **unter `DynamicObjectMinTTL`** liegt, ist je nach Erstellungsweg mit serverseitiger Anpassung oder Ablehnung zu rechnen; in vielen Domains liegt der effektive Mindestwert bei **900s** und der Fallback/Default bleibt **86400s**. ADUC kann **`entryTTL`** ausblenden, aber LDP/LDAP-Abfragen machen es sichtbar.
- Solange das Objekt existiert, können Verteidiger den nicht privilegierten Ersteller weiterhin über **`msDS-CreatorSID`** am Computerobjekt rekonstruieren. Sobald der dynamische Computer abläuft, verschwindet diese Zuordnung mit dem Objekt.

## Stealth Primary Group Membership

- Erstelle eine **dynamic security group** und setze dann die **`primaryGroupID`** eines Benutzers auf die RID dieser Gruppe, um eine effektive Mitgliedschaft zu erhalten, die **nicht in `memberOf` erscheint**, aber in Kerberos/Access Tokens berücksichtigt wird.
- Wenn die TTL abläuft, **löscht** das den Group-Eintrag trotz primary-group delete protection, wodurch der Benutzer eine beschädigte **`primaryGroupID`** behält, die auf eine nicht existierende RID zeigt, und es gibt keinen Tombstone, um nachzuvollziehen, wie das Privileg vergeben wurde.
- Die Darstellung ist vom Tool abhängig: **`Get-ADGroupMember` / `net group`** lösen Mitgliedschaften, die aus der Primary Group stammen, normalerweise auf, während **`memberOf`** und **`Get-ADGroup -Properties member`** das nicht tun. Für weitergehendes **`primaryGroupID`**-Tradecraft siehe [diese andere Seite über DCShadow und PGID abuse](dcshadow.md).
- Für Ziele ohne **AdminSDHolder**-Schutz können Angreifer den dynamic-group-Trick mit einem **DACL deny auf das Lesen von `primaryGroupID`** (oder dem Group-Attribut `member`) kombinieren, um den Link in vielen LDAP/PowerShell-Workflows zu verbergen, noch bevor die Gruppe abläuft.

## AdminSDHolder Orphan-SID Pollution

- Füge ACEs für einen **kurzlebigen dynamic user/group** zu **`CN=AdminSDHolder,CN=System,...`** hinzu. Nach Ablauf der TTL wird die SID in der Template-ACL zu **„Unknown SID“** unauflösbar, und **SDProp (~60 min)** propagiert diese verwaiste SID auf alle geschützten Tier-0-Objekte.
- Forensik verliert die Zuordnung, weil der Principal weg ist (kein Deleted-Object-DN). Achte auf **neue dynamic principals + plötzliche verwaiste SIDs auf AdminSDHolder/privilegierten ACLs**.

## Dynamic GPO Execution mit sich selbst zerstörenden Beweisen

- Erstelle ein **dynamic `groupPolicyContainer`**-Objekt mit einem bösartigen **`gPCFileSysPath`** (z. B. SMB-Share à la GPODDITY) und **verknüpfe es über `gPLink`** mit einer Ziel-OU.
- Clients verarbeiten die Policy und laden Inhalte vom Angreifer-SMB. Wenn die TTL abläuft, verschwindet das GPO-Objekt (und **`gPCFileSysPath`**); übrig bleibt nur eine **defekte `gPLink`**-GUID, wodurch LDAP-Beweise für die ausgeführte Payload entfernt werden.
- Operativ ist das sauberer als klassisches **GPODDITY-style** Cleanup: Statt den ursprünglichen **`gPCFileSysPath`** selbst wiederherzustellen, entfernt AD das bösartige GPC automatisch, sobald der Timer abläuft.

## Ephemeral AD-Integrated DNS Redirection

- AD-DNS-Einträge sind **`dnsNode`**-Objekte in **DomainDnsZones/ForestDnsZones**. Wenn man sie als **dynamic objects** anlegt, ermöglicht das eine temporäre Host-Umleitung (Credential Capture/MITM). Clients cachen die bösartige A/AAAA-Antwort; der Eintrag löscht sich später selbst, sodass die Zone sauber aussieht (DNS Manager braucht eventuell einen Zone-Reload, um die Ansicht zu aktualisieren).
- Detection: auf **jeden DNS-Eintrag mit `dynamicObject`/`entryTTL`** über Replikations-/Event-Logs alarmieren; transiente Einträge tauchen in Standard-DNS-Logs selten auf.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect Delta Sync verlässt sich auf **Tombstones**, um Deletes zu erkennen. Ein **dynamic on-prem user** kann nach Entra ID synchronisiert werden, ablaufen und gelöscht werden, ohne Tombstone—Delta Sync entfernt das Cloud-Konto dann nicht, wodurch ein **verwaister aktiver Entra-User** bleibt, bis ein **Initial-/Full Sync** oder ein manuelles Cloud-Cleanup erzwungen wird.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
