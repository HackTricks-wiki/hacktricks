# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanika i podstawy detekcji

- Każdy obiekt utworzony z klasą pomocniczą **`dynamicObject`** otrzymuje **`entryTTL`** (licznik w sekundach) oraz **`msDS-Entry-Time-To-Die`** (absolutny czas wygaśnięcia). Gdy `entryTTL` osiągnie 0, **Garbage Collector usuwa go bez tombstone/recycle-bin**, usuwając dane o twórcy/czasach i blokując odzyskanie.
- **`entryTTL` jest atrybutem operacyjnym/constructed**: zażądaj go jawnie w zapytaniach LDAP. TTL można odświeżyć albo przez aktualizację `entryTTL` przed wygaśnięciem, albo przez LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Min./domyślny TTL są wymuszane w **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft dokumentuje **86400s** jako domyślny TTL i **900s** jako domyślny minimalny prawidłowy TTL; oba wspierają **1s–1y**. Dynamic objects są **unsupported in Configuration/Schema partitions**.
- Nie ma **static→dynamic conversion** i po wygaśnięciu nie ma fazy tombstone. Zespoły IR nie mogą polegać na kontrolach deleted-object ani Recycle Bin; muszą przechwycić żywy obiekt/metadata, zanim GC go usunie.
- Odświeżanie jest **replica-sensitive**: jeśli TTL zostanie odnowiony zbyt blisko wygaśnięcia, inna writable replica lub GC nadal może lokalnie usunąć obiekt, zanim odświeżenie się zreplikuje. Bardzo krótkie TTL działają więc najlepiej, gdy atakujący wie, który DC obsłuży abuse, natomiast obrońcy powinni odpyt ywać **all naming contexts / replicas** podczas triage.
- Usunięcie może opóźnić się o kilka minut na DC z krótkim uptime (<24h), pozostawiając wąskie okno reakcji na odczyt/backup atrybutów. Wykrywaj przez **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** i korelację z orphan SIDs/broken links.

## Szybka enumeracja / Live triage

- Odpytuj **all `namingContexts` from RootDSE**, nie tylko domain NC. Dynamic abuse może występować w **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) albo w application partitions.
- Gdy obiekt nadal żyje, natychmiast zrzutuj **replication metadata** oraz wszelkie linked attributes/ACLs. Po wygaśnięciu mogą zostać tylko **broken `gPLink` values, orphan SIDs, or cached DNS answers**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion with Self-Deleting Computers

- Domyślny **`ms-DS-MachineAccountQuota` = 10** pozwala każdemu uwierzytelnionemu użytkownikowi tworzyć komputery. Dodaj **dynamicObject** podczas tworzenia, aby komputer sam się usuwał i **zwalniał slot quota**, jednocześnie zacierając ślady.
- Tweak Powermad w **`New-MachineAccount`** (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Jeśli żądany TTL jest **poniżej `DynamicObjectMinTTL`**, spodziewaj się dostosowania po stronie serwera albo odrzucenia, zależnie od ścieżki tworzenia; w wielu domenach efektywny floor to **900s**, a fallback/default pozostaje **86400s**. ADUC może ukrywać `entryTTL`, ale zapytania LDP/LDAP ujawniają go.
- Dopóki obiekt istnieje, obrońcy nadal mogą odzyskać nieuprzywilejowanego twórcę z **`msDS-CreatorSID`** na obiekcie komputera. Gdy dynamiczny komputer wygaśnie, to przypisanie znika razem z obiektem.

## Stealth Primary Group Membership

- Utwórz **dynamic security group**, a następnie ustaw użytkownikowi **`primaryGroupID`** na RID tej grupy, aby uzyskać efektywne członkostwo, które **nie pokazuje się w `memberOf`**, ale jest honorowane w Kerberos/access tokens.
- Wygaśnięcie TTL **usuwa grupę mimo ochrony przed usunięciem primary-group**, pozostawiając użytkownika z uszkodzonym `primaryGroupID` wskazującym na nieistniejący RID i bez tombstone, z którego można by wywnioskować, jak przyznano uprawnienie.
- Raportowanie zależy od narzędzia: **`Get-ADGroupMember` / `net group`** zwykle rozpoznają członkostwo wynikające z primary group, podczas gdy **`memberOf`** i **`Get-ADGroup -Properties member`** nie. Szersze tradecraft związane z **`primaryGroupID`** znajdziesz na [tej innej stronie o DCShadow i nadużyciach PGID](dcshadow.md).
- Dla celów niechronionych przez **AdminSDHolder** atakujący mogą połączyć trik z dynamic group z **DACL deny na odczyt `primaryGroupID`** (albo atrybutu `member` grupy), aby ukryć powiązanie przed wieloma workflow LDAP/PowerShell jeszcze przed wygaśnięciem grupy.

## AdminSDHolder Orphan-SID Pollution

- Dodaj ACE dla **krótkotrwałego dynamic user/group** do **`CN=AdminSDHolder,CN=System,...`**. Po wygaśnięciu TTL SID staje się **nierozwiązywalny (“Unknown SID”)** w ACL szablonu, a **SDProp (~60 min)** propaguje ten osierocony SID na wszystkie chronione obiekty Tier-0.
- Forensics tracą atrybucję, ponieważ principal już nie istnieje (brak DN usuniętego obiektu). Monitoruj **nowe dynamic principals + nagłe orphan SIDs na AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Utwórz obiekt **dynamic `groupPolicyContainer`** z złośliwym **`gPCFileSysPath`** (np. SMB share à la GPODDITY) i **powiąż go przez `gPLink`** z docelowym OU.
- Klienci przetwarzają politykę i pobierają zawartość z attacker SMB. Gdy TTL wygaśnie, obiekt GPO (i `gPCFileSysPath`) znika; pozostaje jedynie **uszkodzony `gPLink`** GUID, usuwając LDAP evidence wykonanej payload.
- Operacyjnie jest to czyściejsze niż klasyczne czyszczenie w stylu **GPODDITY**: zamiast samemu przywracać oryginalny `gPCFileSysPath`, AD usuwa malicious GPC automatycznie po wygaśnięciu timera.

## Ephemeral AD-Integrated DNS Redirection

- Rekordy AD DNS to obiekty **`dnsNode`** w **DomainDnsZones/ForestDnsZones**. Tworzenie ich jako **dynamic objects** pozwala na tymczasowe przekierowanie hosta (credential capture/MITM). Klienci buforują złośliwą odpowiedź A/AAAA; rekord później sam się usuwa, więc strefa wygląda na czystą (DNS Manager może wymagać przeładowania strefy, aby odświeżyć widok).
- Detection: alertuj na **dowolny rekord DNS niosący `dynamicObject`/`entryTTL`** przez replication/event logs; przejściowe rekordy rzadko pojawiają się w standardowych logach DNS.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync opiera się na **tombstones** do wykrywania usunięć. **Dynamic on-prem user** może zsynchronizować się do Entra ID, wygasnąć i zostać usunięty bez tombstone — delta sync nie usunie cloud account, pozostawiając **osieroconego aktywnego użytkownika Entra** aż do wymuszenia **initial/full sync** albo ręcznego czyszczenia cloud.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
