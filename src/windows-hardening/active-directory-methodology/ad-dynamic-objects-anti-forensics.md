# AD Dynamic Objects (dynamicObject) Антифорензика

{{#include ../../banners/hacktricks-training.md}}

## Механіка та основи виявлення

- Будь-який об'єкт, створений з допоміжного класу **`dynamicObject`**, отримує **`entryTTL`** (відлік у секундах) та **`msDS-Entry-Time-To-Die`** (абсолютний час закінчення). Коли `entryTTL` досягає 0, **Garbage Collector видаляє його без tombstone/recycle-bin**, стираючи інформацію про творця/мітки часу і унеможливлюючи відновлення.
- TTL можна оновити, змінюючи `entryTTL`; мінімум/за замовчуванням примусово задаються в **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (підтримує 1s–1y, але зазвичай за замовчуванням 86,400s/24h). Динамічні об'єкти **не підтримуються в Configuration/Schema partitions**.
- Видалення може відставати на кілька хвилин на DC з коротким часом роботи (<24h), що дає вузьке вікно для опитування/бекапу атрибутів. Виявляйте шляхом **тригерів на нові об'єкти, що несуть `entryTTL`/`msDS-Entry-Time-To-Die`**, і корелюйте з орфанними SID/битими посиланнями.

## MAQ Evasion with Self-Deleting Computers

- За замовчуванням **`ms-DS-MachineAccountQuota` = 10** дозволяє будь-якому автентифікованому користувачу створювати комп'ютери. Додайте `dynamicObject` під час створення, щоб комп'ютер самовидалився і **звільнив слот квоти**, одночасно витираючи докази.
- Powermad tweak всередині `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Короткий TTL (наприклад, 60s) часто не спрацьовує для стандартних користувачів; AD повертається до **`DynamicObjectDefaultTTL`** (приклад: 86,400s). ADUC може приховувати `entryTTL`, але LDP/LDAP запити його покажуть.

## Stealth Primary Group Membership

- Створіть **dynamic security group**, потім встановіть `primaryGroupID` користувача на RID тієї групи, щоб отримати ефективне членство, яке **не показується в `memberOf`**, але враховується в Kerberos/токенах доступу.
- При завершенні TTL **група видаляється незважаючи на захист від видалення primary-group**, залишаючи користувача з пошкодженим `primaryGroupID`, що вказує на неіснуючий RID, і без tombstone для аналізу, як було надано привілеї.

## AdminSDHolder Orphan-SID Pollution

- Додайте ACE для **короткотривалого dynamic user/group** в **`CN=AdminSDHolder,CN=System,...`**. Після закінчення TTL SID стає **нерозв'язуваним (“Unknown SID”)** в шаблонному ACL, а **SDProp (~60 min)** поширює цей орфанний SID по всіх захищених Tier-0 об'єктах.
- Форензика втрачає атрибуцію, оскільки принципал зник (немає deleted-object DN). Моніторте **нові dynamic principals + раптові орфанні SID в AdminSDHolder/привілейованих ACL**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Створіть **dynamic `groupPolicyContainer`** об'єкт з шкідливим **`gPCFileSysPath`** (наприклад, SMB share à la GPODDITY) та **зв'яжіть його через `gPLink`** з цільовим OU.
- Клієнти обробляють політику й тягнуть контент з attacker SMB. Коли TTL спливає, GPO-об'єкт (та `gPCFileSysPath`) зникає; залишається лише **битий `gPLink`** GUID, що прибирає LDAP-доказ виконаного payload.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS записи — це **`dnsNode`** об'єкти в **DomainDnsZones/ForestDnsZones**. Створення їх як **dynamic objects** дозволяє тимчасово перенаправляти хости (credential capture/MITM). Клієнти кешують шкідливу A/AAAA відповідь; пізніше запис самовидаляється й зона виглядає чистою (DNS Manager може потребувати перезавантаження зони для оновлення вигляду).
- Виявлення: сповіщайте про **будь-який DNS record, що несе `dynamicObject`/`entryTTL`**, через replication/event logs; транзитні записи рідко з'являються в стандартних DNS логах.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync покладається на **tombstones** для виявлення видалень. **dynamic on-prem user** може синхронізуватися в Entra ID, сплинути й видалитися без tombstone — delta sync не видалить cloud-акаунт, залишаючи **orphaned active Entra user** доки не буде вручну запущено **full sync**.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
