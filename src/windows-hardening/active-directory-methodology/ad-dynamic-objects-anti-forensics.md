# AD Dynamic Objects (dynamicObject) Anty-forensyka

{{#include ../../banners/hacktricks-training.md}}

## Mechanika i podstawy wykrywania

- Każdy obiekt utworzony z pomocniczą klasą **`dynamicObject`** otrzymuje **`entryTTL`** (odliczanie w sekundach) oraz **`msDS-Entry-Time-To-Die`** (absolutny termin wygaśnięcia). Gdy `entryTTL` osiąga 0, **Garbage Collector usuwa go bez tombstone/recycle-bin**, kasując informacje o twórcy/znacznikach czasowych i uniemożliwiając odzyskanie.
- TTL można odświeżyć przez aktualizację `entryTTL`; wartości min/domyślne są wymuszane w **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (obsługuje 1s–1y, choć zwykle domyślnie 86,400s/24h). Dynamic objects są **nieobsługiwane w partycjach Configuration/Schema**.
- Usuwanie może się opóźnić o kilka minut na DCs z krótkim uptime (<24h), dając wąskie okno do zapytania/backupowania atrybutów. Wykrywanie: **alertuj na nowe obiekty zawierające `entryTTL`/`msDS-Entry-Time-To-Die`** i korelację z orphan SIDs/broken links.

## MAQ Evasion with Self-Deleting Computers

- Domyślne **`ms-DS-MachineAccountQuota` = 10** pozwala każdemu uwierzytelnionemu użytkownikowi tworzyć komputery. Dodaj `dynamicObject` podczas tworzenia, aby komputer sam się usunął i **zwolnił slot kwoty** przy jednoczesnym wymazaniu dowodów.
- Powermad modyfikacja w `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Krótki TTL (np. 60s) często nie działa dla zwykłych użytkowników; AD wraca do **`DynamicObjectDefaultTTL`** (przykład: 86,400s). ADUC może ukrywać `entryTTL`, ale zapytania LDP/LDAP ujawnią ten atrybut.

## Ukryte członkostwo w primary group

- Utwórz **dynamiczną grupę zabezpieczeń**, następnie ustaw `primaryGroupID` użytkownika na RID tej grupy, aby uzyskać efektywne członkostwo, które **nie pojawia się w `memberOf`**, ale jest respektowane w Kerberos/access tokens.
- Wygaśnięcie TTL **usuwa grupę pomimo ochrony przed usunięciem primary-group**, pozostawiając użytkownika z uszkodzonym `primaryGroupID` wskazującym na nieistniejący RID i bez tombstone, który pozwoliłby zbadać, jak nadano uprawnienie.

## AdminSDHolder Orphan-SID Pollution

- Dodaj ACEs dla **krótkotrwałego dynamic user/group** do **`CN=AdminSDHolder,CN=System,...`**. Po wygaśnięciu TTL SID staje się **nierozwiązywalny („Unknown SID”)** w template ACL, a **SDProp (~60 min)** propaguje ten osierocony SID do wszystkich chronionych obiektów Tier-0.
- Analiza śledcza traci możliwość przypisania, ponieważ principal zniknął (brak deleted-object DN). Monitoruj **nowe dynamic principals + nagłe orphan SIDs na AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Utwórz **dynamiczny obiekt `groupPolicyContainer`** z złośliwym **`gPCFileSysPath`** (np. SMB share à la GPODDITY) i **połącz go przez `gPLink`** z docelowym OU.
- Klienci przetwarzają politykę i pobierają zawartość z SMB atakującego. Po wygaśnięciu TTL obiekt GPO (i `gPCFileSysPath`) znika; pozostaje tylko **broken `gPLink`** GUID, co usuwa dowody w LDAP dotyczące wykonanego payloadu.

## Ephemeral AD-Integrated DNS Redirection

- Rekordy AD DNS to obiekty **`dnsNode`** w **DomainDnsZones/ForestDnsZones**. Tworzenie ich jako **dynamic objects** pozwala na tymczasowe przekierowanie hosta (credential capture/MITM). Klienci cachują złośliwą odpowiedź A/AAAA; rekord później sam się usuwa, więc strefa wygląda czysto (DNS Manager może wymagać przeładowania strefy, by odświeżyć widok).
- Wykrywanie: alertuj na **dowolny rekord DNS zawierający `dynamicObject`/`entryTTL`** poprzez replication/event logs; przejściowe rekordy rzadko pojawiają się w standardowych logach DNS.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync polega na **tombstones** do wykrywania usunięć. **Dynamic on-prem user** może zsynchronizować do Entra ID, wygasnąć i usunąć bez tombstone — delta sync nie usunie konta w chmurze, pozostawiając **orphaned active Entra user** aż do ręcznego wymuszenia **full sync**.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
