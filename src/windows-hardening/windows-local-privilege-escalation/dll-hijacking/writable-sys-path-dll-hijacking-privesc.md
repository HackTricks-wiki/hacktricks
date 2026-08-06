# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Якщо ви виявили, що можете **писати в папку System Path** (зверніть увагу: це не працюватиме, якщо ви можете писати в папку User Path), можливо, ви зможете **підвищити привілеї** в системі.

Для цього можна використати **Dll Hijacking**, під час якого ви будете **перехоплювати бібліотеку, що завантажується** службою або процесом із **вищими привілеями**, ніж у вас. Оскільки ця служба завантажує Dll, якої, ймовірно, взагалі немає в усій системі, вона спробує завантажити її з System Path, до якого ви маєте доступ на запис.

Докладніше про **what is Dll Hijackig** дивіться:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Пошук відсутньої Dll

Спочатку потрібно **ідентифікувати процес**, який працює з **вищими привілеями**, ніж у вас, і намагається **завантажити Dll із System Path**, до якого ви маєте доступ на запис.

Пам’ятайте, що ця техніка залежить від запису **Machine/System PATH**, а не лише від вашого **User PATH**. Тому перш ніж витрачати час на Procmon, варто перелічити записи **Machine PATH** і перевірити, до яких із них можна отримати доступ на запис:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Проблема в цих випадках полягає в тому, що, ймовірно, ці процеси вже запущені. Щоб визначити, яких Dll бракує службам, потрібно запустити procmon якомога швидше (до завантаження процесів). Отже, щоб знайти відсутні .dll, виконайте такі дії:

- **Створіть** папку `C:\privesc_hijacking` і додайте шлях `C:\privesc_hijacking` до **змінної середовища System Path**. Це можна зробити **вручну** або за допомогою **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Запустіть **`procmon`** і перейдіть до **`Options`** --> **`Enable boot logging`**, потім натисніть **`OK`** у запиті.
- Потім **перезавантажте комп’ютер**. Після перезапуску комп’ютера **`procmon`** почне **записувати** події якомога швидше.
- Після того як **Windows** **запуститься, знову виконайте `procmon`**. Він повідомить, що вже працював, і **запитає, чи хочете ви зберегти** події у файл. Відповідайте **так** і **збережіть події у файл**.
- **Після** того як **файл** буде **створено**, закрийте відкрите вікно **`procmon`** і **відкрийте файл подій**.
- Додайте ці **фільтри**, і ви знайдете всі DLL, які деякі **процеси намагалися завантажити** з доступної для запису папки System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging потрібен лише для служб, які запускаються надто рано**, щоб спостерігати за ними іншим способом. Якщо ви можете **запустити цільову службу/програму на вимогу** (наприклад, взаємодіючи з її COM-інтерфейсом, перезапустивши службу або повторно запустивши заплановане завдання), зазвичай швидше залишити звичайний захват Procmon із такими фільтрами, як **`Path contains .dll`**, **`Result is NAME NOT FOUND`** і **`Path begins with <writable_machine_path>`**.

### Пропущені DLL

Під час запуску цього на безкоштовній **віртуальній (vmware) машині з Windows 11** я отримав такі результати:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

У цьому випадку файли .exe не мають користі, тому ігноруйте їх; пропущені DLL були такими:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Після цього я знайшов цей цікавий допис у блозі, де також пояснюється, як [**зловживати WptsExtensions.dll для privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Саме це ми **зараз і зробимо**.<sup>[[3]](#references)</sup>

### Інші кандидати, які варто перевірити

`WptsExtensions.dll` є хорошим прикладом, але це не єдина повторювана **phantom DLL**, яка трапляється у привілейованих службах. Сучасні правила полювання та публічні каталоги hijacking і досі відстежують такі назви:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Класичний кандидат із рівнем **SYSTEM** у клієнтських системах. Добре працює, коли доступний для запису каталог знаходиться в **Machine PATH**, а служба перевіряє наявність DLL під час запуску. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Цікавий варіант у **серверних редакціях**, оскільки служба працює як **SYSTEM** і в деяких збірках може бути **запущена на вимогу звичайним користувачем**, що робить цей варіант кращим за випадки, які потребують лише перезавантаження. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Зазвичай спочатку надає **`NT AUTHORITY\LOCAL SERVICE`**. Цього часто достатньо, оскільки токен має **`SeImpersonatePrivilege`**, тому його можна поєднати з [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Сприймайте ці назви як **підказки для первинної перевірки**, а не як гарантований результат: усе залежить від **SKU/збірки**, і Microsoft може змінювати поведінку між випусками. Головний висновок полягає в тому, що потрібно шукати **відсутні DLL у привілейованих службах, які проходять через Machine PATH**, особливо якщо службу можна **повторно запустити без перезавантаження**.

### Експлуатація

Отже, щоб **підвищити привілеї**, ми виконаємо hijacking бібліотеки **WptsExtensions.dll**. Маючи **шлях** та **назву**, нам потрібно лише **створити шкідливу DLL**.

Ви можете [**спробувати використати будь-який із цих прикладів**](#creating-and-compiling-dlls). Можна запускати такі payloads: отримати rev shell, додати користувача, виконати beacon...

> [!WARNING]
> Зверніть увагу, що **не всі служби запускаються** від імені **`NT AUTHORITY\SYSTEM`**; деякі також запускаються від імені **`NT AUTHORITY\LOCAL SERVICE`**, який має **менше привілеїв**, тому ви **не зможете створити нового користувача**, використовуючи його дозволи.\
> Однак цей користувач має привілей **`seImpersonate`**, тому ви можете скористатися[ **potato suite для підвищення привілеїв**](../roguepotato-and-printspoofer.md). Отже, у цьому випадку rev shell є кращим варіантом, ніж спроба створити користувача.

На момент написання статті служба **Task Scheduler** працює від імені **Nt AUTHORITY\SYSTEM**.

Створивши **шкідливу DLL** (_у моєму випадку я використав x64 rev shell і отримав shell, але defender завершив його роботу, оскільки він був створений за допомогою msfvenom_), збережіть її в доступному для запису System Path під назвою **WptsExtensions.dll** і **перезавантажте** комп’ютер (або перезапустіть службу, або зробіть усе необхідне для повторного запуску відповідної служби/програми).

Коли службу буде перезапущено, **DLL має бути завантажена та виконана** (ви можете **повторно використати** прийом із **procmon**, щоб перевірити, чи **бібліотеку було завантажено очікуваним чином**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
