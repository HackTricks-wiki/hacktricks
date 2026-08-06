# Anty-Forensics obiektów AD Dynamic Objects (dynamicObject)

{{#include ../../banners/hacktricks-training.md}}

## Mechanika i podstawy detekcji

- Każdy obiekt utworzony z pomocniczą klasą **`dynamicObject`** zyskuje **`entryTTL`** (odliczanie w sekundach) oraz **`msDS-Entry-Time-To-Die`** (bezwzględny czas wygaśnięcia). Gdy **`entryTTL`** osiągnie wartość 0, **Garbage Collector usuwa obiekt bez tombstone/recycle-bin**, usuwając informacje o twórcy i znacznikach czasu oraz uniemożliwiając odzyskanie.
- **`entryTTL` jest atrybutem operacyjnym/konstruowanym**: należy jawnie zażądać go w zapytaniach LDAP. TTL można odświeżyć przez aktualizację **`entryTTL`** przed wygaśnięciem albo za pomocą LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Minimalne i domyślne wartości TTL są wymuszane w **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft dokumentuje **86400 s** jako domyślny TTL oraz **900 s** jako domyślny minimalny poprawny TTL; obie wartości obsługują zakres **1 s–1 rok**. Dynamic objects są **nieobsługiwane w partycjach Configuration/Schema**.
- Nie istnieje **static→dynamic conversion** ani faza tombstone po wygaśnięciu. Zespoły IR nie mogą polegać na mechanizmach obsługi usuniętych obiektów ani Recycle Bin; muszą przechwycić aktywny obiekt/metadane, zanim GC go usunie.
- Odświeżanie jest **replica-sensitive**: jeśli TTL zostanie odnowiony zbyt blisko czasu wygaśnięcia, inna zapisywalna replika lub GC może nadal lokalnie usunąć obiekt, zanim odświeżenie zostanie zreplikowane. Bardzo krótkie TTL działają więc najlepiej, gdy attacker wie, który DC obsłuży abuse, natomiast defenders powinni odpytywać **wszystkie naming contexts / repliki** podczas triage.
- Usunięcie może opóźnić się o kilka minut na DC z krótkim czasem działania (<24 h), pozostawiając wąskie okno reakcji na odpytywanie/backup atrybutów. Wykrywaj to, **alertując o nowych obiektach zawierających `entryTTL`/`msDS-Entry-Time-To-Die`** i korelując je z osieroconymi SID-ami/uszkodzonymi linkami.<sup>[[1]](#references)</sup>

## Szybka enumeracja / Live Triage

- Odpytuj **wszystkie `namingContexts` z RootDSE**, a nie tylko domain NC. Dynamic abuse może znajdować się w **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) lub w application partitions.
- Gdy obiekt jest nadal aktywny, natychmiast zrzutuj **replication metadata** oraz wszystkie powiązane atrybuty/ACL-e. Po wygaśnięciu mogą pozostać jedynie **uszkodzone wartości `gPLink`, osierocone SID-y lub buforowane odpowiedzi DNS**.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Obejście MAQ za pomocą samousuwających się komputerów

- Domyślne **`ms-DS-MachineAccountQuota` = 10** pozwala każdemu uwierzytelnionemu użytkownikowi tworzyć obiekty komputerów. Dodanie `dynamicObject` podczas tworzenia sprawia, że komputer sam się usunie i zwolni miejsce w limicie, jednocześnie usuwając ślady.
- Modyfikacja Powermad wewnątrz `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Jeśli żądany TTL jest **mniejszy niż `DynamicObjectMinTTL`**, należy oczekiwać korekty po stronie serwera lub odrzucenia, zależnie od ścieżki tworzenia; w wielu domenach efektywnym minimum jest **900 s**, a wartością fallback/default pozostaje **86400 s**. ADUC może ukrywać `entryTTL`, ale zapytania LDP/LDAP go ujawnią.
- Dopóki obiekt istnieje, obrońcy nadal mogą ustalić nieuprzywilejowanego twórcę na podstawie **`msDS-CreatorSID`** obiektu komputera. Po wygaśnięciu dynamicznego komputera ta informacja znika wraz z obiektem.<sup>[[1]](#references)</sup>

## Ukryte członkostwo w grupie podstawowej

- Utwórz **dynamic security group**, a następnie ustaw **`primaryGroupID`** użytkownika na RID tej grupy, aby uzyskać efektywne członkostwo, które **nie pojawia się w `memberOf`**, ale jest uwzględniane w Kerberos/tokenach dostępu.<sup>[[1]](#references)</sup>
- Wygaśnięcie TTL **usuwa grupę pomimo ochrony przed usunięciem grupy podstawowej**, pozostawiając u użytkownika uszkodzone **`primaryGroupID`** wskazujące na nieistniejący RID oraz bez tombstone, który pozwoliłby zbadać, jak przyznano uprawnienie.
- Raportowanie zależy od narzędzia: **`Get-ADGroupMember` / `net group`** zwykle uwzględniają członkostwo wynikające z grupy podstawowej, natomiast **`memberOf`** i **`Get-ADGroup -Properties member`** nie. Więcej informacji o tradecraft związanym z **`primaryGroupID`** znajdziesz na [innej stronie o nadużyciach DCShadow i PGID](dcshadow.md).
- W przypadku celów **niechronionych przez AdminSDHolder** atakujący mogą połączyć trik z dynamiczną grupą z **DACL deny dotyczącym odczytu `primaryGroupID`** (lub atrybutu `member` grupy), aby ukryć powiązanie przed wieloma workflow LDAP/PowerShell jeszcze przed wygaśnięciem grupy.<sup>[[2]](#references)</sup>

## Zanieczyszczanie AdminSDHolder osieroconym SID

- Dodaj ACE dla **krótkotrwałego dynamic user/group** do **`CN=AdminSDHolder,CN=System,...`**. Po wygaśnięciu TTL SID staje się **nierozwiązywalny („Unknown SID”)** w ACL szablonu, a **SDProp (~60 min)** propaguje ten osierocony SID do wszystkich chronionych obiektów Tier-0.
- Forensics tracą możliwość przypisania działania, ponieważ principal znika (brak DN usuniętego obiektu). Monitoruj **nowe dynamic principals + nagłe pojawienie się osieroconych SID-ów w ACL AdminSDHolder/obiektów uprzywilejowanych**.<sup>[[1]](#references)</sup>

## Wykonywanie dynamicznego GPO z samoznikającymi śladami

- Utwórz **dynamiczny obiekt `groupPolicyContainer`** ze złośliwym **`gPCFileSysPath`** (np. udziałem SMB à la GPODDITY) i połącz go przez **`gPLink`** z docelową jednostką OU.
- Klienci przetwarzają policy i pobierają zawartość z SMB atakującego. Po wygaśnięciu TTL obiekt GPO (oraz **`gPCFileSysPath`**) znika; pozostaje tylko **uszkodzony GUID `gPLink`**, usuwając dowody payloadu w LDAP.
- Jest to operacyjnie czystsze niż klasyczne usuwanie śladów w stylu **GPODDITY**: zamiast samodzielnie przywracać pierwotny **`gPCFileSysPath`**, AD automatycznie usuwa złośliwy GPC po wygaśnięciu timera.<sup>[[1]](#references)</sup>

## Efemeryczne przekierowanie DNS zintegrowanego z AD

- Rekordy DNS AD są obiektami **`dnsNode`** w **DomainDnsZones/ForestDnsZones**. Tworzenie ich jako **dynamic objects** umożliwia tymczasowe przekierowanie hostów (credential capture/MITM). Klienci cache'ują złośliwą odpowiedź A/AAAA; rekord później sam się usuwa, więc strefa wygląda na czystą (DNS Manager może wymagać przeładowania strefy, aby odświeżyć widok).
- Wykrywanie: generuj alert dla **każdego rekordu DNS zawierającego `dynamicObject`/`entryTTL`** na podstawie logów replikacji/zdarzeń; efemeryczne rekordy rzadko pojawiają się w standardowych logach DNS.<sup>[[1]](#references)</sup>

## Luka delta-sync w hybrydowym Entra ID (uwaga)

- Delta sync Entra Connect opiera się na **tombstones** do wykrywania usunięć. **Dynamiczny użytkownik on-prem** może zsynchronizować się z Entra ID, wygasnąć i zostać usunięty bez tombstone — delta sync go nie usunie z chmury, pozostawiając **osieroconego aktywnego użytkownika Entra** do czasu wymuszenia **initial/full sync** lub ręcznego czyszczenia w chmurze.<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
