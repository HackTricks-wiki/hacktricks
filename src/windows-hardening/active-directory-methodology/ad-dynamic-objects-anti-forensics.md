# AD Dynamic Objects (dynamicObject): антифорензика

{{#include ../../banners/hacktricks-training.md}}

## Основи механіки та виявлення

- Будь-який об'єкт, створений із допоміжним класом **`dynamicObject`**, отримує **`entryTTL`** (зворотний відлік у секундах) і **`msDS-Entry-Time-To-Die`** (абсолютний час завершення дії). Коли значення `entryTTL` досягає 0 **і об'єкт не має нащадків**, Garbage Collector видаляє його без tombstone/recycle-bin, стираючи дані про створювача та часові мітки й унеможливлюючи відновлення.<sup>[[4]](#references)</sup>
- **`entryTTL` є operational/constructed атрибутом**: явно запитуйте його в LDAP-запитах. TTL можна оновити шляхом зміни `entryTTL` до завершення дії або через LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Мінімальне та стандартне значення TTL є AVA для всього forest у **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` і `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft документує **86400s** як стандартний TTL і **900s** як стандартний мінімальний допустимий TTL; діапазон схеми `entryTTL` становить **1–31557600s** (від однієї секунди до одного року).<sup>[[3]](#references)</sup> Dynamic objects **не підтримуються в розділах Configuration/Schema**.
- **Перетворення static→dynamic відсутнє**, як і фаза tombstone після завершення дії. IR-команди не можуть покладатися на засоби контролю видалених об'єктів або Recycle Bin; вони мають зібрати live-об'єкт і його метадані до того, як GC його видалить.
- Refresh є **залежним від replica**: якщо TTL поновити надто близько до завершення дії, інша writable replica або GC все ще може локально видалити об'єкт до реплікації оновлення. Тому дуже короткі TTL найкраще працюють, коли attacker знає, який DC обслуговуватиме зловживання, а defenders мають опитувати **всі naming contexts / replicas** під час triage.
- Видалення на DC із коротким часом роботи (<24h) може затримуватися на кілька хвилин, залишаючи вузьке response window для запиту/резервного копіювання атрибутів. Виявляйте це за допомогою **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** і корелюйте з orphan SID/broken links.<sup>[[1]](#references)</sup>

### Граф завершення дії та крайні випадки очищення посилань

- Кожен нащадок dynamic object має сам бути dynamic. Прострочений dynamic parent видаляється garbage collector лише після того, як стає leaf; якщо нащадок має пізніше значення `msDS-Entry-Time-To-Die`, DC пересуває час завершення дії parent за максимальний час завершення дії нащадків. Отже, writable dynamic subtree може **закріпити/продовжити існування parent, який, здається, ось-ось зникне**: перераховуйте все його subtree і не використовуйте спостережуване `entryTTL` parent як крайній термін очищення.<sup>[[4]](#references)</sup>
- Очищення після завершення дії є **schema-link-aware**. Replicas видаляють значення linked attributes, які посилаються на видалений dynamic object, але зберігають nonlinked values. Очікуйте очищення звичайних forward/back-link membership, тоді як цілочислові/SID/рядкові посилання, як-от `primaryGroupID`, SID, вбудовані в `nTSecurityDescriptor`, або текст `gPLink`, можуть зберегтися як forensic residue.<sup>[[4]](#references)</sup>

## Швидке перерахування / Live Triage

- Запитуйте **всі `namingContexts` із RootDSE**, а не лише domain NC. Dynamic abuse може знаходитися в **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) або в application partitions.
- Поки об'єкт ще існує, негайно збережіть **replication metadata** і всі linked attributes/ACLs. Після завершення дії можуть залишитися лише **broken `gPLink` values, orphan SIDs або cached DNS answers**.<sup>[[1]](#references)</sup>
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
## Обхід MAQ за допомогою комп’ютерів із самовидаленням

- Значення **`ms-DS-MachineAccountQuota` = 10** за замовчуванням дає будь-якому автентифікованому користувачу змогу створювати комп’ютери. Додавання `dynamicObject` під час створення змушує комп’ютер самовидалитися та **звільнити слот квоти**, одночасно стираючи докази.
- Налаштування Powermad усередині `New-MachineAccount` (список objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Якщо запитаний TTL **нижчий за `DynamicObjectMinTTL`**, очікуйте коригування або відхилення на стороні сервера залежно від способу створення; у багатьох доменах фактичний мінімум становить **900 с**, а fallback/default залишається **86400 с**. ADUC може приховувати `entryTTL`, але запити через LDP/LDAP його показують.
- Поки об’єкт існує, defenders усе ще можуть визначити непривілейованого творця за **`msDS-CreatorSID`** на об’єкті комп’ютера. Після завершення терміну дії dynamic computer ця атрибуція зникає разом з об’єктом.<sup>[[1]](#references)</sup>

## Приховане членство в Primary Group

- Створіть **dynamic security group**, а потім встановіть **`primaryGroupID`** користувача на RID цієї групи, щоб отримати ефективне членство, яке **не відображається в `memberOf`**, але враховується в Kerberos/access tokens.<sup>[[1]](#references)</sup>
- Після завершення TTL група **видаляється попри захист від видалення primary group**, залишаючи користувача з пошкодженим **`primaryGroupID`**, що вказує на неіснуючий RID, і без tombstone для розслідування способу надання привілею.
- Звітування залежить від інструмента: **`Get-ADGroupMember` / `net group`** зазвичай враховують членство, отримане через primary group, тоді як **`memberOf`** і **`Get-ADGroup -Properties member`** — ні. Щодо ширшого tradecraft для **`primaryGroupID`** див. [цю іншу сторінку про DCShadow і зловживання PGID](dcshadow.md).
- Для цілей, **не захищених AdminSDHolder**, attackers можуть поєднати трюк із dynamic group із **DACL deny на читання `primaryGroupID`** (або атрибута `member` групи), щоб приховати зв’язок від багатьох LDAP/PowerShell workflows ще до завершення терміну дії групи.<sup>[[2]](#references)</sup>

## Забруднення AdminSDHolder осиротілими SID

- Додайте ACE для **короткоживучого dynamic user/group** до **`CN=AdminSDHolder,CN=System,...`**. Після завершення TTL SID стає **невирішуваним (“Unknown SID”)** у template ACL, а **SDProp (~60 хв)** поширює цей orphan SID на всі захищені Tier-0 objects.
- Forensics втрачає атрибуцію, оскільки principal зникає (deleted-object DN відсутній). Відстежуйте **нові dynamic principals + раптові orphan SID в AdminSDHolder/privileged ACL**.<sup>[[1]](#references)</sup>

## Виконання Dynamic GPO із самознищенням доказів

- Створіть **dynamic `groupPolicyContainer` object** зі шкідливим **`gPCFileSysPath`** (наприклад, SMB share на кшталт GPODDITY) і **зв’яжіть його через `gPLink`** із цільовим OU.
- Клієнти обробляють policy та завантажують вміст із attacker SMB. Після завершення TTL GPO object (і **`gPCFileSysPath`**) зникає; залишається лише **зламаний `gPLink`** GUID, що усуває LDAP-докази виконаного payload.
- Операційно це чистіше за класичне очищення **GPODDITY-style**: замість самостійного відновлення початкового `gPCFileSysPath` AD автоматично видаляє шкідливий GPC після завершення таймера.<sup>[[1]](#references)</sup> Див. [зловживання ACL persistence](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity), щоб ознайомитися з деталями протоколу та tooling, а не дублювати їх тут.

## Тимчасове перенаправлення AD-Integrated DNS

- DNS-записи AD є об’єктами **`dnsNode`** у **DomainDnsZones/ForestDnsZones**. Створення їх як **dynamic objects** дає змогу тимчасово перенаправляти hosts (credential capture/MITM). Клієнти кешують шкідливу A/AAAA-відповідь; згодом запис самовидаляється, тому zone виглядає чистою (для оновлення подання DNS Manager може знадобитися перезавантаження zone).
- Виявлення: створіть alert для **будь-якого DNS-запису, що містить `dynamicObject`/`entryTTL`**, через replication/event logs; transient records рідко з’являються у стандартних DNS logs.<sup>[[1]](#references)</sup>

## Прогалина Hybrid Entra ID Delta-Sync (примітка)

- Entra Connect delta sync покладається на **tombstones** для виявлення видалень. **Dynamic on-prem user** може синхронізуватися з Entra ID, завершити термін дії та бути видаленим без tombstone — delta sync не видалить cloud account, залишивши **orphaned active Entra user**, доки не буде виконано **initial/full sync** або примусово не проведено manual cloud cleanup.<sup>[[1]](#references)</sup>



## References

- [1] [Dynamic Objects в Active Directory: прихована загроза](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Пригоди з поведінкою, звітуванням і exploitation Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Налаштування обмежень TTL](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: Вимоги DynamicObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
