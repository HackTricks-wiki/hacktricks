# Зовнішній домен лісу - односторонній (вихідний)

{{#include ../../banners/hacktricks-training.md}}

У цьому сценарії **ваш домен** надає **привілеї** суб'єктам з **іншого домену/лісу**.

## Перерахування

### Вихідна довіра
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
Якщо у вас доступний модуль AD, безпосередньо перевірте також **Trusted Domain Object (TDO)**. Це надасть вам необроблені дані довіри, отримані через LDAP, які надалі знадобляться під час визначення, чи є простішим шляхом **FSP/group abuse** або **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Також слід визначити, де саме іноземним principals із `CN=ForeignSecurityPrincipals` було надано доступ. Типові варіанти:

- **Local admin** на сервері/DC у вашому поточному домені
- Членство в **custom domain group**, яка має ACL над користувачами/комп’ютерами/GPO
- Права на зміну **computer objects**, що згодом можуть перетворитися на [RBCD](resource-based-constrained-delegation.md), якщо конфігурація trust це дозволяє

## Trust Account Attack

Коли one-way trust створюється від domain/forest **B** до domain/forest **A** (**B trusts A**), у **A** створюється **trust account** для **B**. У поданні outbound-trust домену **A** це корисно, оскільки після компрометації **B** (сторони, що довіряє) ви можете dump-нути секрет trust там і автентифікуватися назад у **A** як `B$`.<sup>[[1]](#references)</sup>

Критично важливо розуміти, що пароль і матеріали Kerberos для цього trust account можна витягнути з Domain Controller у **trusting** домені за допомогою:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Це працює, оскільки обліковий запис довіри, створений у **довіреному** домені, є увімкненим суб'єктом, який зрештою отримує базові права звичайного користувача домену в цьому домені. Цього часто достатньо, щоб почати перерахування LDAP, запитувати квитки та знайти наступний шлях ескалації.<sup>[[1]](#references)</sup>

У сценарії, де `ext.local` є **доменом, що довіряє**, а `root.local` — **довіреним доменом**, усередині `root.local` створюється обліковий запис користувача з іменем `EXT$`. Вивантаження ключів довіри з `ext.local` розкриває облікові дані, які можна використовувати як `root.local\EXT$` проти `root.local`:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Після цього використайте отриманий ключ **RC4**, щоб автентифікуватися як `root.local\EXT$` у `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Потім перераховуйте довірений домен як цей principal, наприклад виконавши Kerberoasting високопріоритетного SPN у `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### З Linux

Якщо ви отримали ключ облікового запису довіри **RC4**, та сама ідея працює з Linux за допомогою Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Якщо **RC4** не приймається, використайте резервний варіант: відновлений **cleartext password** (або похідні **AES** keys) і повторно застосуйте стандартні workflow [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) та [Kerberoast](kerberoast.md) із цього foothold.

### Важливі нюанси key material

Не плутайте **trust keys** і **trust-account credentials**:<sup>[[1]](#references)</sup>

- В односторонньому trust обидві сторони зберігають **TDO**, але фактичний **`EXT$` user account існує лише у trusted domain**.
- Поточний пароль trust-account відображається в trust secret TDO (`NewPassword` / current trust key).
- **RC4** trust key — найпростіший артефакт для повторного використання з `asktgt` як trust account; у стандартних конфігураціях це зазвичай робочий enctype, оскільки trust account часто має порожнє значення `msDS-SupportedEncryptionTypes`.
- Якщо ви розглядаєте **AES trust keys**, пам’ятайте, що вони не взаємозамінні з AES keys trust-account, оскільки salts відрізняються.

Тому для техніки на цій сторінці надавайте перевагу або отриманому **RC4** material, або відновленому **cleartext** password.<sup>[[1]](#references)</sup>

### Отримання cleartext trust password

У попередньому flow замість **cleartext password** використовувався trust hash (який також **dumped by mimikatz**).<sup>[[1]](#references)</sup>

Cleartext password можна отримати, перетворивши \[ CLEAR ] output від mimikatz із hexadecimal і видаливши null bytes `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Отримання cleartext trust password: Cleartext password можна отримати, перетворивши output ( CLEAR ) від mimikatz із hexadecimal і видаливши null...](<../../images/image (938).png>)

Іноді під час створення trust користувач має ввести для нього password. У цій демонстрації key є початковим trust password, тому він придатний для читання людиною. Після ротації key (за замовчуванням кожні 30 днів) cleartext зазвичай перестає бути придатним для читання людиною, але технічно залишається придатним для використання.<sup>[[1]](#references)</sup>

Cleartext password можна використати для виконання звичайної authentication як trust account — як альтернативу отриманню TGT із Kerberos secret key trust account. Тут виконується запит до `root.local` з `ext.local` щодо членів `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Отримання cleartext trust password: Cleartext password можна використати для виконання звичайної authentication як trust account — як альтернативу отриманню TGT...](<../../images/image (792).png>)

### Практичні обмеження

> [!WARNING]
> Trust accounts — незручні principals. Interactive logons, такі як **RUNAS / console / RDP**, не є очікуваним шляхом, а спроби **NTLM** authentication можуть завершитися помилкою `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Натомість плануйте **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Примітка щодо persistence / cleanup

Якщо defenders зрозуміють, що trusting domain було скомпрометовано, їм слід виконати ротацію trust secret **на обох сторонах** за допомогою `netdom trust ... /resetOneSide ...`. З погляду operator це важливо, оскільки **manual reset негайно робить недійсним старий trust material**, тоді як звичайна ротація trust-password зберігає поточні/попередні значення протягом rollover.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Посилання

- [1] [SID filter як межа безпеки між доменами? (Частина 7) – Атака на обліковий запис довіри – від довірчого до довіреного](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [Відновлення лісу AD – Скидання пароля довіри](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
