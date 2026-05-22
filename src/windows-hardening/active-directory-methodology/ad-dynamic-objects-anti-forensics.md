# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Każdy obiekt utworzony z klasą pomocniczą **`dynamicObject`** dostaje **`entryTTL`** (odliczanie w sekundach) oraz **`msDS-Entry-Time-To-Die`** (absolutny czas wygaśnięcia). Gdy `entryTTL` osiąga 0, **Garbage Collector usuwa go bez tombstone/recycle-bin**, kasując dane o twórcy/czasy i blokując odzyskanie.
- **`entryTTL` jest atrybutem operacyjnym/wyliczanym**: trzeba zażądać go jawnie w zapytaniach LDAP. TTL można odświeżyć albo przez aktualizację `entryTTL` przed wygaśnięciem, albo przez LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Minimalny/domyslny TTL jest egzekwowany w **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft dokumentuje **86400s** jako domyślny TTL oraz **900s** jako domyślny minimalny poprawny TTL; oba wspierają **1s–1y**. Dynamic objects są **nieobsługiwane w partycjach Configuration/Schema**.
- Nie ma **static→dynamic conversion** i po wygaśnięciu nie ma fazy tombstone. Zespoły IR nie mogą polegać na kontrolach dla usuniętych obiektów ani na Recycle Bin; muszą przechwycić żywy obiekt/metadata, zanim GC go usunie.
- Odświeżanie jest **wrażliwe na replikację**: jeśli TTL zostanie odnowiony zbyt blisko wygaśnięcia, inna zapisywalna replika lub GC może nadal lokalnie usunąć obiekt, zanim odświeżenie się zreplikuje. Bardzo krótkie TTL działają więc najlepiej, gdy atakujący wie, który DC obsłuży nadużycie, natomiast obrońcy powinni podczas triage odpytwać **wszystkie naming contexts / repliki**.
- Usunięcie może opóźnić się o kilka minut na DC z krótkim uptime (<24h), zostawiając wąskie okno reakcji na odpytywanie/zrzut atrybutów. Wykrywanie: **alertowanie na nowe obiekty z `entryTTL`/`msDS-Entry-Time-To-Die`** i korelacja z orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Odpytuj **wszystkie `namingContexts` z RootDSE**, nie tylko domain NC. Nadużycie dynamic objects może znajdować się w **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) albo w application partitions.
- Gdy obiekt jest jeszcze żywy, natychmiast zrzutuj **replication metadata** i wszelkie linked attributes/ACLs. Po wygaśnięciu może zostać tylko **broken `gPLink` values, orphan SIDs, lub cached DNS answers**.
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

- Domyślne **`ms-DS-MachineAccountQuota` = 10** pozwala każdemu uwierzytelnionemu użytkownikowi tworzyć komputery. Dodaj `dynamicObject` podczas tworzenia, aby komputer sam się usuwał i **zwalniał slot quota**, jednocześnie zacierając ślady.
- Poprawka Powermad w `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Jeśli żądany TTL jest **poniżej `DynamicObjectMinTTL`**, spodziewaj się dostosowania po stronie serwera albo odrzucenia, zależnie od ścieżki tworzenia; w wielu domenach efektywny próg to **900s**, a fallback/default pozostaje **86400s**. ADUC może ukrywać `entryTTL`, ale zapytania LDP/LDAP ujawniają tę wartość.
- Gdy obiekt istnieje, obrońcy nadal mogą odzyskać nieuprzywilejowanego twórcę z **`msDS-CreatorSID`** na obiekcie komputera. Po wygaśnięciu dynamicznego komputera atrybucja znika razem z obiektem.

## Stealth Primary Group Membership

- Utwórz **dynamic security group**, a następnie ustaw **`primaryGroupID`** użytkownika na RID tej grupy, aby uzyskać skuteczne członkostwo, które **nie pojawia się w `memberOf`**, ale jest respektowane w Kerberos/access tokens.
- Wygaśnięcie TTL **usuwa grupę mimo ochrony przed usunięciem primary-group**, pozostawiając użytkownika z uszkodzonym `primaryGroupID` wskazującym na nieistniejący RID i bez tombstone, który pozwoliłby zbadać, jak nadano uprawnienie.
- Raportowanie zależy od narzędzia: **`Get-ADGroupMember` / `net group`** zwykle rozwiązują członkostwo wynikające z primary-group, podczas gdy **`memberOf`** i **`Get-ADGroup -Properties member`** nie. Dla szerszego tradecraft z `primaryGroupID`, zobacz [tę inną stronę o DCShadow i abuse PGID](dcshadow.md).
- Dla celów **niechronionych przez AdminSDHolder** napastnicy mogą połączyć trik z dynamiczną grupą z **DACL deny na odczyt `primaryGroupID`** (albo atrybutu grupy `member`), aby ukryć powiązanie przed wieloma workflow LDAP/PowerShell nawet przed wygaśnięciem grupy.

## AdminSDHolder Orphan-SID Pollution

- Dodaj ACE dla **krótkotrwałego dynamic user/group** do **`CN=AdminSDHolder,CN=System,...`**. Po wygaśnięciu TTL SID staje się **nierozwiązywalny („Unknown SID”)** w ACL szablonu, a **SDProp (~60 min)** propaguje ten osierocony SID na wszystkie chronione obiekty Tier-0.
- Forensics tracą atrybucję, ponieważ principal znika (brak DN usuniętego obiektu). Monitoruj **nowe dynamic principals + nagłe orphan SIDs na AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Utwórz **dynamic `groupPolicyContainer`** z złośliwym **`gPCFileSysPath`** (np. udział SMB à la GPODDITY) i **podlinkuj go przez `gPLink`** do docelowego OU.
- Klienci przetwarzają politykę i pobierają treść z SMB napastnika. Gdy TTL wygaśnie, obiekt GPO (i `gPCFileSysPath`) znika; pozostaje jedynie **uszkodzony `gPLink`** GUID, usuwając dowody LDAP na wykonany payload.
- Operacyjnie jest to czystsze niż klasyczne sprzątanie w stylu **GPODDITY**: zamiast samodzielnie przywracać oryginalny `gPCFileSysPath`, AD automatycznie usuwa złośliwy GPC po wygaśnięciu timera.

## Ephemeral AD-Integrated DNS Redirection

- Rekordy AD DNS to obiekty **`dnsNode`** w **DomainDnsZones/ForestDnsZones**. Tworzenie ich jako **dynamic objects** pozwala na tymczasowe przekierowanie hosta (credential capture/MITM). Klienci cache'ują złośliwą odpowiedź A/AAAA; rekord później sam się usuwa, więc strefa wygląda na czystą (DNS Manager może wymagać przeładowania strefy, aby odświeżyć widok).
- Detekcja: alarmuj na **dowolny rekord DNS zawierający `dynamicObject`/`entryTTL`** przez replikację/logi zdarzeń; przejściowe rekordy rzadko pojawiają się w standardowych logach DNS.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Delta sync Entra Connect opiera się na **tombstones** do wykrywania usunięć. **Dynamic on-prem user** może zsynchronizować się do Entra ID, wygasnąć i zostać usunięty bez tombstone — delta sync nie usunie konta w chmurze, pozostawiając **osierocone aktywne konto Entra user** aż do wymuszenia **initial/full sync** albo ręcznego cleanup w chmurze.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
