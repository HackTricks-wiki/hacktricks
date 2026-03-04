# AD Dynamic Objects (dynamicObject) Анти-форензика

{{#include ../../banners/hacktricks-training.md}}

## Механіка та основи виявлення

- Будь-який об'єкт, створений з допоміжним класом **`dynamicObject`**, отримує **`entryTTL`** (відлік у секундах) та **`msDS-Entry-Time-To-Die`** (абсолютний час закінчення). Коли `entryTTL` досягає 0, **Garbage Collector видаляє його без tombstone/recycle-bin**, стираючи інформацію про творця/мітки часу й унеможливлюючи відновлення.
- TTL можна оновити, змінивши `entryTTL`; мінімум/значення за замовчуванням контролюються в **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (підтримує від 1s–1y, але зазвичай за замовчуванням 86,400s/24h). Dynamic objects are **unsupported in Configuration/Schema partitions**.
- Видалення може затримуватись на кілька хвилин на DC з коротким часом роботи (<24h), залишаючи вузьке вікно для опитування/резервного копіювання атрибутів. Виявляйте шляхом **сповіщення про нові об'єкти, що містять `entryTTL`/`msDS-Entry-Time-To-Die`**, та кореляції з сиротними SID/пошкодженими посиланнями.

## MAQ Evasion with Self-Deleting Computers

- За замовчуванням **`ms-DS-MachineAccountQuota` = 10** дозволяє будь-якому автентифікованому користувачеві створювати комп'ютери. Додайте `dynamicObject` під час створення, щоб комп'ютер самовидалився і **звільнив слот квоти**, одночасно витираючи докази.
- Powermad tweak всередині `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Короткий TTL (наприклад, 60s) часто не спрацьовує для стандартних користувачів; AD повертається до **`DynamicObjectDefaultTTL`** (наприклад: 86,400s). ADUC може приховувати `entryTTL`, але запити LDP/LDAP його показують.

## Stealth Primary Group Membership

- Створіть **dynamic security group**, потім встановіть для користувача **`primaryGroupID`** на RID цієї групи, щоб отримати ефективне членство, яке **не відображається в `memberOf`**, але враховується в Kerberos/токенах доступу.
- По закінченню TTL **група видаляється незважаючи на захист від видалення primary-group**, залишаючи користувача з пошкодженим `primaryGroupID`, що вказує на неіснуючий RID, і без tombstone, щоб дослідити, як було надано привілей.

## AdminSDHolder Orphan-SID Pollution

- Додайте ACEs для **короткоживучого dynamic user/group** до **`CN=AdminSDHolder,CN=System,...`**. Після закінчення TTL SID стає **unresolvable (“Unknown SID”)** у шаблонному ACL, а **SDProp (~60 min)** поширює цей сиротливий SID по всіх захищених Tier-0 об'єктах.
- Форензика втрачає атрибуцію, оскільки принципал зник (немає deleted-object DN). Слідкуйте за **новими dynamic principals + раптовими orphan SIDs на AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Створіть **dynamic `groupPolicyContainer`** об'єкт з шкідливим **`gPCFileSysPath`** (наприклад, SMB share à la GPODDITY) та **зв'яжіть його через `gPLink`** з цільовим OU.
- Клієнти застосовують політику і завантажують вміст з attacker SMB. Коли TTL спливає, об'єкт GPO (і `gPCFileSysPath`) зникає; залишається лише **broken `gPLink`** GUID, що видаляє LDAP-докази виконаного payload.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS-записи є об'єктами **`dnsNode`** у **DomainDnsZones/ForestDnsZones**. Створення їх як **dynamic objects** дозволяє тимчасове перенаправлення хоста (credential capture/MITM). Клієнти кешують шкідливу A/AAAA відповідь; запис пізніше самовидаляється, тож зона виглядає чистою (DNS Manager може потребувати перезавантаження зони для оновлення вигляду).
- Виявлення: сповіщення про **будь-який DNS запис, що містить `dynamicObject`/`entryTTL`** через replication/event logs; тимчасові записи рідко з'являються у стандартних DNS логах.

## Hybrid Entra ID Delta-Sync Gap (Примітка)

- Entra Connect delta sync покладається на **tombstones** для виявлення видалень. **Dynamic on-prem user** може синхронізуватися до Entra ID, сплинути й видалитися без tombstone — delta sync не видалить хмарний акаунт, залишивши **orphaned active Entra user** поки не буде примусово виконано ручний **full sync**.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
