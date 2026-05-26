# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Jedes Objekt, das mit der auxiliary class **`dynamicObject`** erstellt wird, erhält **`entryTTL`** (Sekunden-Countdown) und **`msDS-Entry-Time-To-Die`** (absolutes Ablaufdatum). Wenn `entryTTL` 0 erreicht, löscht der **Garbage Collector** es ohne tombstone/recycle-bin und entfernt Ersteller-/Zeitstempel, wodurch Wiederherstellung verhindert wird.
- **`entryTTL` ist ein operational/constructed attribute**: Fordere es in LDAP-Queries explizit an. TTL kann entweder durch Aktualisieren von `entryTTL` vor Ablauf oder per LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** erneuert werden.
- TTL-Minimum/Default werden in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** erzwungen. Microsoft dokumentiert **86400s** als Standard-TTL und **900s** als Standard-Minimum für gültige TTL; beide unterstützen **1s–1y**. Dynamic objects werden in **Configuration/Schema partitions** nicht unterstützt.
- Es gibt **keine static→dynamic conversion** und nach Ablauf keine tombstone-Phase. IR-Teams können sich nicht auf deleted-object-Kontrollen oder Recycle Bin verlassen; sie müssen das lebende Objekt/Metadata erfassen, bevor GC es entfernt.
- Refresh ist **replica-sensitive**: Wenn TTL zu nah am Ablauf erneuert wird, kann ein anderer writable replica oder GC das Objekt lokal trotzdem löschen, bevor die Erneuerung repliziert. Sehr kurze TTLs funktionieren daher am besten, wenn der Angreifer weiß, welcher DC den abuse bedient; Defender sollten während der Triage **alle naming contexts / replicas** abfragen.
- Löschung kann sich auf DCs mit kurzer uptime (<24h) um einige Minuten verzögern, wodurch ein enges Response-Fenster entsteht, um attributes abzufragen/zu sichern. Erkennen durch **Alerting auf neue Objekte mit `entryTTL`/`msDS-Entry-Time-To-Die`** und Korrelation mit orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Frage **alle `namingContexts` aus RootDSE** ab, nicht nur den domain NC. Dynamic abuse kann in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) oder in application partitions liegen.
- Solange das Objekt noch lebt, sofort **replication metadata** und alle verbundenen attributes/ACLs auslesen. Nach Ablauf bleiben möglicherweise nur **broken `gPLink` values, orphan SIDs oder gecachte DNS-Antworten** übrig.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion mit Self-Deleting Computers

- Standardmäßig erlaubt **`ms-DS-MachineAccountQuota` = 10** jedem authentifizierten Benutzer, Computer zu erstellen. Füge bei der Erstellung `dynamicObject` hinzu, damit sich der Computer selbst löscht und den **Quota-Slot freigibt**, während er Beweise entfernt.
- Powermad-Tweak in `New-MachineAccount` (objectClass-Liste):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Wenn die angeforderte TTL **unter `DynamicObjectMinTTL`** liegt, ist je nach Creation Path mit serverseitiger Anpassung oder Ablehnung zu rechnen; in vielen Domains liegt die effektive Untergrenze bei **900s** und der Fallback/Default bleibt **86400s**. ADUC kann `entryTTL` ausblenden, aber LDP/LDAP-Queries zeigen es.
- Solange das Objekt existiert, können Defender den unprivilegierten Ersteller weiterhin über **`msDS-CreatorSID`** auf dem Computerobjekt ermitteln. Sobald der Dynamic Computer abläuft, verschwindet diese Zuordnung zusammen mit dem Objekt.

## Stealth Primary Group Membership

- Erstelle eine **dynamic security group** und setze dann die **`primaryGroupID`** eines Users auf die RID dieser Gruppe, um effektive Membership zu erhalten, die **nicht in `memberOf` angezeigt wird**, aber in Kerberos/access tokens berücksichtigt wird.
- Das TTL-Ablaufen **löscht die Gruppe trotz primary-group delete protection**, sodass der User mit einer beschädigten `primaryGroupID` auf eine nicht existierende RID verweist und kein Tombstone vorhanden ist, um nachzuvollziehen, wie die Privilege vergeben wurde.
- Das Reporting ist tool-abhängig: **`Get-ADGroupMember` / `net group`** lösen Membership, die aus der Primary Group stammt, meist auf, während **`memberOf`** und **`Get-ADGroup -Properties member`** das nicht tun. Für weitergehendes `primaryGroupID`-Tradecraft siehe [diese andere Seite über DCShadow und PGID abuse](dcshadow.md).
- Für Targets ohne **AdminSDHolder-Schutz** können Angreifer den dynamic-group-Trick mit einem **DACL deny auf das Lesen von `primaryGroupID`** (oder des Gruppen-Attributs `member`) kombinieren, um den Link vor vielen LDAP/PowerShell-Workflows zu verbergen, noch bevor die Gruppe abläuft.

## AdminSDHolder Orphan-SID Pollution

- Füge ACEs für einen **kurzlebigen dynamic user/group** zu **`CN=AdminSDHolder,CN=System,...`** hinzu. Nach TTL-Ablauf wird die SID im Template-ACL **nicht mehr aufgelöst („Unknown SID“) **, und **SDProp (~60 min)** propagiert diese verwaiste SID auf alle geschützten Tier-0-Objekte.
- Forensics verlieren die Zuordnung, weil der Principal verschwunden ist (kein Deleted-Object-DN). Überwache auf **neue dynamic principals + plötzliche orphan SIDs auf AdminSDHolder/privilegierten ACLs**.

## Dynamic GPO Execution mit Self-Destructing Evidence

- Erstelle ein **dynamic `groupPolicyContainer`**-Objekt mit einem bösartigen **`gPCFileSysPath`** (z. B. SMB share à la GPODDITY) und **verknüpfe es über `gPLink`** mit einer Ziel-OU.
- Clients verarbeiten die Policy und laden Inhalt vom Angreifer-SMB. Wenn die TTL abläuft, verschwindet das GPO-Objekt (und `gPCFileSysPath`); übrig bleibt nur eine **defekte `gPLink`**-GUID, wodurch LDAP-Beweise für das ausgeführte Payload entfernt werden.
- Das ist operativ sauberer als klassisches **GPODDITY-style** Cleanup: Statt `gPCFileSysPath` selbst wiederherzustellen, entfernt AD das bösartige GPC automatisch, sobald der Timer abläuft.

## Ephemeral AD-Integrated DNS Redirection

- AD-DNS-Records sind **`dnsNode`**-Objekte in **DomainDnsZones/ForestDnsZones**. Wenn man sie als **dynamic objects** erstellt, ermöglicht das temporäre Host-Redirection (credential capture/MITM). Clients cachen die bösartige A/AAAA-Antwort; der Record löscht sich später selbst, sodass die Zone sauber aussieht (DNS Manager muss eventuell die Zone neu laden, um die Ansicht zu aktualisieren).
- Detection: auf **jeden DNS-Record mit `dynamicObject`/`entryTTL`** über Replikations-/Event-Logs alarmieren; transiente Records erscheinen selten in Standard-DNS-Logs.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync verlässt sich auf **tombstones**, um Deletes zu erkennen. Ein **dynamic on-prem user** kann nach Entra ID synchronisieren, ablaufen und gelöscht werden, ohne Tombstone—delta sync entfernt das Cloud-Konto dann nicht und lässt einen **verwaisten aktiven Entra-User** zurück, bis ein **initial/full sync** oder manuelles Cloud-Cleanup erzwungen wird.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
