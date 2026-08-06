# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Основи механіки та виявлення

- Будь-який об’єкт, створений із допоміжним класом **`dynamicObject`**, отримує **`entryTTL`** (зворотний відлік у секундах) і **`msDS-Entry-Time-To-Die`** (абсолютний час завершення дії). Коли **`entryTTL`** досягає 0, **Garbage Collector** видаляє об’єкт без tombstone/recycle-bin, стираючи дані про творця та часові мітки й унеможливлюючи відновлення.
- **`entryTTL` є operational/constructed attribute**: його потрібно явно запитувати в LDAP-запитах. TTL можна оновити або зміною **`entryTTL`** до завершення його дії, або через LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Мінімальне/типове значення TTL задається в **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft документує **86400s** як типовий TTL і **900s** як типове мінімальне допустиме значення TTL; обидва параметри підтримують діапазон **1s–1y**. Dynamic objects **не підтримуються в розділах Configuration/Schema**.
- **static→dynamic conversion** неможливе, а після завершення дії об’єкта немає фази tombstone. IR-команди не можуть покладатися на засоби керування видаленими об’єктами або Recycle Bin; вони мають отримати live object/метадані до того, як GC його видалить.
- Оновлення залежить від replica: якщо TTL поновити надто близько до завершення його дії, інша writable replica або GC все одно можуть локально видалити об’єкт до реплікації оновлення. Тому дуже короткі TTL найкраще працюють, коли attacker знає, який DC обслуговуватиме зловживання, тоді як defenders мають опитувати **all naming contexts / replicas** під час triage.
- На DC із коротким часом роботи (<24h) видалення може затримуватися на кілька хвилин, залишаючи вузьке response window для запиту/резервного копіювання атрибутів. Виявляйте це за допомогою **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** і корелюйте з orphan SIDs/broken links.<sup>[[1]](#references)</sup>

## Швидке перерахування / Live Triage

- Запитуйте **all `namingContexts` from RootDSE**, а не лише domain NC. Dynamic abuse може знаходитися в **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) або в application partitions.
- Поки об’єкт ще існує, негайно збережіть **replication metadata** і всі linked attributes/ACLs. Після завершення дії можуть залишитися лише **broken `gPLink` values, orphan SIDs або cached DNS answers**.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Ухилення від MAQ за допомогою комп’ютерів, що самовидаляються

- Значення **`ms-DS-MachineAccountQuota` = 10** за замовчуванням дозволяє будь-якому authenticated user створювати комп’ютери. Додавання `dynamicObject` під час створення змушує комп’ютер самовидалитися та **звільнити слот квоти**, одночасно стираючи докази.
- Точкова зміна Powermad всередині `New-MachineAccount` (список objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Якщо запитаний TTL **нижчий за `DynamicObjectMinTTL`**, очікуйте server-side коригування або відхилення залежно від способу створення; у багатьох доменах фактичний мінімум становить **900s**, а fallback/default залишається **86400s**. ADUC може приховувати `entryTTL`, але LDP/LDAP-запити його виявляють.
- Поки об’єкт існує, defenders все ще можуть визначити unprivileged creator за **`msDS-CreatorSID`** на об’єкті комп’ютера. Після завершення терміну дії dynamic computer ця атрибуція зникає разом з об’єктом.<sup>[[1]](#references)</sup>

## Приховане членство в Primary Group

- Створіть **dynamic security group**, а потім встановіть **`primaryGroupID`** користувача в RID цієї групи, щоб отримати ефективне членство, яке **не відображається в `memberOf`**, але враховується в Kerberos/access tokens.<sup>[[1]](#references)</sup>
- Завершення TTL **видаляє групу попри захист від видалення primary group**, залишаючи користувача з пошкодженим **`primaryGroupID`**, що вказує на неіснуючий RID, і без tombstone для розслідування способу надання привілею.
- Звітування залежить від tool: **`Get-ADGroupMember` / `net group`** зазвичай визначають membership, отримане через primary group, тоді як **`memberOf`** і **`Get-ADGroup -Properties member`** цього не роблять. Щодо ширшого tradecraft для **`primaryGroupID`** дивіться [цю іншу сторінку про DCShadow і зловживання PGID](dcshadow.md).
- Для цілей, **не захищених AdminSDHolder**, attackers можуть поєднати trick із dynamic group та **DACL deny на читання `primaryGroupID`** (або атрибута `member` групи), щоб приховати зв’язок від багатьох LDAP/PowerShell workflows ще до завершення терміну дії групи.<sup>[[2]](#references)</sup>

## Забруднення AdminSDHolder осиротілими SID

- Додайте ACE для **short-lived dynamic user/group** до **`CN=AdminSDHolder,CN=System,...`**. Після завершення TTL SID стає **невизначуваним (“Unknown SID”)** у template ACL, а **SDProp (~60 min)** поширює цей orphan SID на всі захищені об’єкти Tier-0.
- Forensics втрачає атрибуцію, оскільки principal більше не існує (відсутній DN видаленого об’єкта). Відстежуйте **нові dynamic principals + раптові orphan SIDs в AdminSDHolder/privileged ACLs**.<sup>[[1]](#references)</sup>

## Виконання Dynamic GPO із самознищенням доказів

- Створіть **dynamic `groupPolicyContainer`** object зі шкідливим **`gPCFileSysPath`** (наприклад, SMB share на кшталт GPODDITY) і зв’яжіть його через **`gPLink`** із цільовим OU.
- Clients обробляють policy та отримують content з attacker SMB. Після завершення TTL об’єкт GPO (і **`gPCFileSysPath`**) зникає; залишається лише **broken `gPLink`** GUID, що усуває LDAP-докази виконаного payload.
- Це операційно чистіше за класичне очищення у стилі **GPODDITY**: замість того щоб самостійно відновлювати оригінальний `gPCFileSysPath`, AD автоматично видаляє шкідливий GPC після завершення таймера.<sup>[[1]](#references)</sup>

## Тимчасове перенаправлення AD-Integrated DNS

- DNS-записи AD є об’єктами **`dnsNode`** у **DomainDnsZones/ForestDnsZones**. Створення їх як **dynamic objects** дозволяє тимчасово перенаправляти hosts (credential capture/MITM). Clients кешують шкідливу A/AAAA-відповідь; згодом запис самовидаляється, тому zone виглядає чистою (для оновлення view у DNS Manager може знадобитися перезавантаження zone).
- Detection: створюйте alert для **будь-якого DNS-запису, що містить `dynamicObject`/`entryTTL`**, через replication/event logs; transient records рідко з’являються у стандартних DNS logs.<sup>[[1]](#references)</sup>

## Прогалина Delta-Sync у Hybrid Entra ID (примітка)

- Entra Connect delta sync покладається на **tombstones** для виявлення видалень. **Dynamic on-prem user** може синхронізуватися з Entra ID, завершити термін дії та видалитися без tombstone — delta sync не видалить cloud account, залишивши **orphaned active Entra user**, доки не буде виконано **initial/full sync** або примусове manual cloud cleanup.<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
