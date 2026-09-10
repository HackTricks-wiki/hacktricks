# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Podstawy działania i wykrywania

- Każdy obiekt utworzony z pomocniczą klasą **`dynamicObject`** otrzymuje **`entryTTL`** (odliczanie w sekundach) oraz **`msDS-Entry-Time-To-Die`** (bezwzględny czas wygaśnięcia). Gdy `entryTTL` osiągnie wartość 0 **i obiekt nie ma potomków**, Garbage Collector usuwa go bez użycia tombstone/recycle-bin, usuwając informacje o twórcy i znacznikach czasu oraz uniemożliwiając odzyskanie.<sup>[[4]](#references)</sup>
- **`entryTTL` jest atrybutem operacyjnym/konstruowanym**: należy żądać go jawnie w zapytaniach LDAP. TTL można odświeżyć przez aktualizację `entryTTL` przed wygaśnięciem lub za pomocą LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Minimalny i domyślny TTL są wartościami AVA obowiązującymi w całym lesie, przechowywanymi w **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` oraz `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft dokumentuje **86400s** jako domyślny TTL oraz **900s** jako domyślny minimalny poprawny TTL; zakres schematu `entryTTL` wynosi **1–31557600s** (od jednej sekundy do jednego roku).<sup>[[3]](#references)</sup> Obiekty dynamiczne są **nieobsługiwane w partycjach Configuration/Schema**.
- Nie istnieje **static→dynamic conversion** ani faza tombstone po wygaśnięciu. Zespoły IR nie mogą polegać na mechanizmach obsługi usuniętych obiektów ani Recycle Bin; muszą przechwycić aktywny obiekt i jego metadane, zanim GC go usunie.
- Odświeżanie jest **zależne od repliki**: jeśli TTL zostanie odnowiony zbyt blisko wygaśnięcia, inna zapisywalna replika lub GC może nadal lokalnie usunąć obiekt, zanim odświeżenie zostanie zreplikowane. Bardzo krótkie TTL-e działają więc najlepiej, gdy attacker zna DC, który obsłuży abuse, natomiast defenders powinni odpytywać **wszystkie naming contexts / repliki** podczas triage.
- Usunięcie może być opóźnione o kilka minut na DC z krótkim czasem działania (<24h), pozostawiając wąskie okno na odpytywanie i backup atrybutów. Wykrywaj to, **alertując na nowe obiekty zawierające `entryTTL`/`msDS-Entry-Time-To-Die`** i korelując je z osieroconymi SID-ami/broken links.<sup>[[1]](#references)</sup>

### Graf wygaśnięcia i przypadki brzegowe czyszczenia referencji

- Każdy potomek obiektu dynamicznego również musi być dynamiczny. Wygasły dynamiczny obiekt nadrzędny jest usuwany przez garbage collector dopiero po tym, jak stanie się liściem; jeśli potomek ma późniejszą wartość `msDS-Entry-Time-To-Die`, DC przesuwa wygaśnięcie obiektu nadrzędnego poza maksymalny czas wygaśnięcia potomków. W rezultacie zapisywalne dynamiczne poddrzewo może **przypiąć/wydłużyć czas życia obiektu nadrzędnego, który wydaje się bliski zniknięcia**: wylicz całe jego poddrzewo i nie używaj zaobserwowanej wartości `entryTTL` obiektu nadrzędnego jako terminu czyszczenia.<sup>[[4]](#references)</sup>
- Czyszczenie po wygaśnięciu jest **świadome istnienia schema-link**. Repliki usuwają wartości atrybutów linkowanych, które odwołują się do usuniętego obiektu dynamicznego, ale zachowują wartości nielinkowane. Należy oczekiwać, że zwykła przynależność forward/back-link zostanie wyczyszczona, podczas gdy referencje typu integer/SID/string, takie jak `primaryGroupID`, SID-y osadzone w `nTSecurityDescriptor` lub tekst `gPLink`, mogą przetrwać jako ślady forensic.<sup>[[4]](#references)</sup>

## Szybka enumeracja / Live Triage

- Odpytuj **wszystkie `namingContexts` z RootDSE**, a nie tylko domenowy NC. Abuse obiektów dynamicznych może występować w **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) lub w application partitions.
- Gdy obiekt jest jeszcze aktywny, natychmiast zrzucaj **replication metadata** oraz wszelkie linked attributes/ACLs. Po wygaśnięciu mogą pozostać jedynie **uszkodzone wartości `gPLink`, osierocone SID-y lub buforowane odpowiedzi DNS**.<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasion MAQ za pomocą samousuwających się komputerów

- Domyślna wartość **`ms-DS-MachineAccountQuota` = 10** pozwala każdemu uwierzytelnionemu użytkownikowi tworzyć komputery. Dodanie `dynamicObject` podczas tworzenia sprawia, że komputer sam się usunie i **zwolni miejsce w limicie**, jednocześnie usuwając ślady.
- Modyfikacja Powermad w `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Jeśli żądany TTL jest **mniejszy niż `DynamicObjectMinTTL`**, należy oczekiwać korekty po stronie serwera lub odrzucenia, zależnie od ścieżki tworzenia; w wielu domenach efektywne minimum wynosi **900 s**, a wartość zapasowa/domyslna nadal wynosi **86400 s**. ADUC może ukrywać `entryTTL`, ale zapytania LDP/LDAP ujawniają tę wartość.
- Gdy obiekt istnieje, obrońcy nadal mogą ustalić nieuwierzytelnionego twórcę na podstawie **`msDS-CreatorSID`** na obiekcie komputera. Po wygaśnięciu dynamicznego komputera ta informacja znika wraz z obiektem.<sup>[[1]](#references)</sup>

## Ukryte członkostwo w Primary Group

- Utwórz **dynamic security group**, a następnie ustaw **`primaryGroupID`** użytkownika na RID tej grupy, aby uzyskać efektywne członkostwo, które **nie jest widoczne w `memberOf`**, ale jest uwzględniane przez Kerberos/tokeny dostępu.<sup>[[1]](#references)</sup>
- Wygaśnięcie TTL **usuwa grupę pomimo ochrony przed usunięciem grupy podstawowej**, pozostawiając użytkownika z uszkodzonym **`primaryGroupID`** wskazującym nieistniejący RID i bez tombstone, który pozwalałby zbadać, jak przyznano uprawnienie.
- Raportowanie zależy od narzędzia: **`Get-ADGroupMember` / `net group`** zwykle uwzględniają członkostwo wynikające z primary group, natomiast **`memberOf`** i **`Get-ADGroup -Properties member`** nie. Więcej informacji o tradecraft związanym z **`primaryGroupID`** znajdziesz na [tej stronie o DCShadow i nadużyciu PGID](dcshadow.md).
- W przypadku celów **niechronionych przez AdminSDHolder** atakujący mogą połączyć technikę dynamicznej grupy z **DACL deny na odczyt `primaryGroupID`** (lub atrybutu `member` grupy), aby ukryć powiązanie przed wieloma procedurami LDAP/PowerShell jeszcze przed wygaśnięciem grupy.<sup>[[2]](#references)</sup>

## Zanieczyszczanie AdminSDHolder osieroconym SID

- Dodaj ACE dla **krótkotrwałego dynamic user/group** do **`CN=AdminSDHolder,CN=System,...`**. Po wygaśnięciu TTL SID staje się **nierozpoznawalny („Unknown SID”)** w ACL szablonu, a **SDProp (~60 min)** propaguje ten osierocony SID do wszystkich chronionych obiektów Tier-0.
- Dochodzenia kryminalistyczne tracą możliwość ustalenia źródła, ponieważ principal już nie istnieje (brak DN usuniętego obiektu). Monitoruj **nowe dynamic principals + nagłe pojawienie się osieroconych SID na listach ACL AdminSDHolder/uprzywilejowanych obiektów**.<sup>[[1]](#references)</sup>

## Wykonywanie dynamicznego GPO z samousuwającymi się śladami

- Utwórz **dynamiczny obiekt `groupPolicyContainer`** ze złośliwym **`gPCFileSysPath`** (np. udziałem SMB à la GPODDITY) i **powiąż go przez `gPLink`** z docelowym OU.
- Klienci przetwarzają policy i pobierają zawartość z SMB atakującego. Po wygaśnięciu TTL obiekt GPO (oraz **`gPCFileSysPath`**) znika; pozostaje tylko **uszkodzony `gPLink`** GUID, usuwając dowody LDAP wykonania payloadu.
- Jest to operacyjnie czystsze niż klasyczne czyszczenie w stylu **GPODDITY**: zamiast samodzielnie przywracać pierwotny **`gPCFileSysPath`**, AD automatycznie usuwa złośliwy GPC po wygaśnięciu timera.<sup>[[1]](#references)</sup> Zobacz [nadużycie ACL persistence](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity), aby poznać szczegóły protokołu i narzędzi, zamiast powielać je tutaj.

## Efemeryczne przekierowanie DNS zintegrowanego z AD

- Rekordy DNS AD są obiektami **`dnsNode`** w **DomainDnsZones/ForestDnsZones**. Tworzenie ich jako **dynamic objects** umożliwia tymczasowe przekierowanie hosta (przechwytywanie poświadczeń/MITM). Klienci buforują złośliwą odpowiedź A/AAAA; rekord później sam się usuwa, dzięki czemu strefa wygląda na czystą (DNS Manager może wymagać ponownego załadowania strefy, aby odświeżyć widok).
- Wykrywanie: generuj alert dla **każdego rekordu DNS zawierającego `dynamicObject`/`entryTTL`** na podstawie logów replikacji/zdarzeń; rekordy tymczasowe rzadko pojawiają się w standardowych logach DNS.<sup>[[1]](#references)</sup>

## Luka delta-sync w hybrydowym Entra ID (uwaga)

- Delta sync Entra Connect opiera się na **tombstones** w celu wykrywania usunięć. **Dynamiczny użytkownik on-prem** może zostać zsynchronizowany z Entra ID, wygasnąć i zostać usunięty bez tombstone — delta sync nie usunie konta w chmurze, pozostawiając **osierocone, aktywne konto użytkownika Entra** do czasu wymuszenia **initial/full sync** lub ręcznego czyszczenia w chmurze.<sup>[[1]](#references)</sup>



## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Configuration of TTL Limits](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: DynamicObject Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
