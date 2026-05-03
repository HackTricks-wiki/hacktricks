# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Нещодавні збірки Windows запровадили **SMB client support for alternative TCP ports**. Цю можливість можна використати, щоб перетворити **local NTLM authentication** на **SYSTEM local privilege escalation**, коли attacker може:

1. Відкрити SMB connection до listener під контролем attacker на **non-445 port**
2. Утримувати це TCP connection alive
3. Coerce **privileged local client** звернутися до **same SMB share path**
4. Relay отриману **local NTLM authentication** назад до реальної SMB service машини

Це primitive, на якому базується **CVE-2026-24294**, patched у **March 2026**.

## Why it works

Старіший CMTI / serialized-SPN reflection trick описано тут:

{{#ref}}
../ntlm/README.md
{{#endref}}

Цей новіший варіант **не** потребує marshalled hostname. Натомість він зловживає двома SMB client behaviours:

- **Alternative port support** на **Windows 11 24H2** і **Windows Server 2025**, доступний користувачам через `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, де кілька authenticated sessions можуть використовувати одне й те саме TCP connection

Це означає, що low-privileged user може спочатку створити TCP connection від SMB client до attacker SMB server на високому порту, а потім coerce privileged service звернутися до **exact same UNC path**. Якщо Windows вирішить reuse existing TCP connection, privileged NTLM exchange буде надіслано через transport під контролем attacker і його можна буде relay до local SMB server.

## Preconditions

- Target supports SMB alternative ports:
- **Windows 11 24H2** or later
- **Windows Server 2025** or later
- Attacker can run a local or remote SMB server on a chosen high port
- Attacker can coerce a privileged service to access a UNC path
- Privileged authentication must be **NTLM local authentication**
- Target must be relayable:
- Synacktiv reported it worked by default on **Windows Server 2025**
- Their chain did **not** work on **Windows 11 24H2** because outbound SMB signing is enforced there by default

## Userland and internals

From the command line the feature looks simple:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Програмно, client використовує `WNetAddConnection4W` з недокументованими `lpUseOptions` data. Важливий option — `TraP` (transport parameters), який зрештою потрапляє до kernel SMB client через FSCTL і парситься `mrxsmb`.

Важливі практичні примітки:

- **UNC syntax все ще не має port field**
- **`net use` є per-logon-session**
- Bypass все ще працює, тому що **TCP connection і SMB session — це separate objects**
- Повторне використання **same share path** є mandatory, якщо exploit залежить від того, що SMB client повторно використовує раніше створене TCP connection

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Запустіть SMB server на high port і змусьте Windows connect to it:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Сервер може прийняти будь-яку пару облікових даних, яку ви контролюєте, наприклад `user:user`. Мета цього кроку — ще не privilege escalation, а лише змусити Windows SMB client відкрити та утримувати повторно використовуване TCP-з’єднання з вашим listener.

### 2. Спровокувати привілейований сервіс до того ж UNC path

Використайте coercion primitive, наприклад **PetitPotam**, проти **того ж самого** шляху `\\192.168.56.3\share`. Якщо примушений client привілейований і цільова назва є локальною (`localhost` або local IP/host), Windows виконує **NTLM local authentication**.

Оскільки TCP-з’єднання повторно використовується, цей привілейований NTLM exchange йде до SMB service атакувальника замість того, щоб напряму піти до реального local SMB server.

### 3. Relay привілейовану authentication назад до local SMB

Керований атакувальником SMB service пересилає привілейований NTLM exchange до `ntlmrelayx.py`, який relays його до реального SMB listener на машині та отримує session як `NT AUTHORITY\SYSTEM`.

Типові інструменти з public writeup:

- `smbserver.py` на custom port для прийому привілейованої auth через повторно використане TCP-з’єднання
- `ntlmrelayx.py` для relay захопленого NTLM до local SMB
- `PetitPotam.exe` або інший coercion primitive, щоб примусити привілейовану authentication

## Operator notes

- Це **local privilege escalation** technique, а не загальний remote relay trick
- Керований атакувальником SMB service має обробити привілейовану authentication на **тому самому TCP-з’єднанні**, яке спочатку було використане для mount share
- Якщо примушений access потрапляє до **іншого share path**, Windows може встановити інше connection і ланцюжок зламається
- Вимоги SMB signing можуть зупинити relay навіть тоді, коли arbitrary-port step працює
- Якщо у вас є лише Kerberos material або ви не можете примусити local NTLM, цей exact variant недостатній

## Detection and hardening

- Застосуйте патч для **CVE-2026-24294** з **March 2026 Patch Tuesday**
- Відстежуйте `net use` або `New-SmbMapping`, що використовують **non-default SMB ports**
- Сповіщайте про незвичний outbound SMB із workstations або servers на **high TCP ports**
- Перевіряйте coercion opportunities, такі як тригери **EFSRPC / PetitPotam-style**
- Увімкніть SMB signing, де це можливо; Synacktiv зазначає, що це заблокувало їхній relay на Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
