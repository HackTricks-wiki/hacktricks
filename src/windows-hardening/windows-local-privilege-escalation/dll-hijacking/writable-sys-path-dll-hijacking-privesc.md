# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Якщо ви можете **записувати до каталогу в загальносистемному `PATH`** (а не лише у вашому користувацькому `PATH`), ви можете отримати можливість **підвищити привілеї** в системі.

Цим можна зловживати через **DLL hijacking**, коли сервіс або процес із вищими привілеями намагається завантажити DLL, якої немає в попередніх місцях пошуку, і зрештою виконує пошук у доступному для запису каталозі системного `PATH`.

Доступний для запису запис Machine `PATH` є лише **примітивом**, а не доказом виконання коду. Для неупакованої програми, яка використовує стандартний порядок пошуку, `PATH` перевіряється після перенаправлення, API sets, SxS, списку завантажених модулів, KnownDLLs, каталогів програми та Windows, а також поточного каталогу. Повний шлях або політика `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` можуть повністю виключити `PATH`.<sup>[[4]](#references)</sup>

Докладніше про **DLL hijacking** дивіться тут:

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Пошук відсутньої DLL

Спочатку **визначте процес**, що працює з **вищими привілеями** та намагається **завантажити DLL із доступного для запису каталогу системного `PATH`**.

Пам’ятайте, що ця техніка залежить від запису Machine/System PATH, а не лише від вашого **User PATH**. Тому перед тим, як витрачати час на Procmon, варто перелічити записи **Machine PATH** і перевірити, до яких із них є доступ на запис:<sup>[[1]](#references)</sup>
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
Текст ACL може вводити в оману, оскільки на результат впливають членство в групах, ACE із забороною та успадковані дозволи. Під час авторизованого тестування probe create/delete перевіряє **ефективний доступ поточного token** (це intrusive дія, яка може генерувати сповіщення):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Підтвердьте фактичний `PATH` цільового процесу

Machine `PATH`, прочитаний із реєстру, є даними конфігурації; loader використовує блок environment **цільового процесу**. Кожен процес має власний блок environment, і дочірній процес зазвичай успадковує копію environment свого батьківського процесу. Отже, довготривалий service може зберігати старе значення, а service, запущений із custom environment, може відрізнятися від значення, видимого у вашій shell. Вважайте спостереження Procmon щодо точного directory цільовим PID достовірним джерелом; після зміни `PATH` у lab перезапустіть відповідне дерево процесів або виконайте reboot, перш ніж робити висновок, що lookup не відбувається.<sup>[[5]](#references)</sup>

Проблема в таких випадках полягає в тому, що ці процеси, імовірно, уже запущені. Щоб визначити DLL, які services намагаються завантажити, але не можуть, запустіть Procmon якомога раніше (до запуску процесів), а потім:

> [!WARNING]
> Додавання user-writable directory до Machine `PATH` **створює вразливу умову**. Виконуйте це лише в ізольованій research VM, щоб виявити, які privileged processes звертаються до `PATH`; на assessed host відстежуйте наявний writable entry, не змінюючи system configuration.<sup>[[1]](#references)</sup>

- **Створіть** folder `C:\privesc_hijacking` і додайте path `C:\privesc_hijacking` до **System Path env variable**. Це можна зробити **вручну** або за допомогою **PS**:
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
- Запустіть **`procmon`**, перейдіть до **`Options`** --> **`Enable boot logging`** і натисніть **`OK`** у запиті.
- Потім **перезавантажте комп'ютер**. Після перезапуску комп'ютера **`procmon`** почне **записувати** події якнайшвидше.
- Коли **Windows** буде **запущено, виконайте `procmon`** ще раз. Він повідомить, що вже працював, і **запитає, чи хочете ви зберегти** події у файл. Виберіть **так** і **збережіть події у файл**.
- **Після** створення **файлу** закрийте відкрите вікно **`procmon`** і **відкрийте файл подій**.
- Додайте ці **фільтри**, щоб знайти всі DLL, які **процес намагався завантажити** з доступної для запису папки System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging потрібен лише для служб, які запускаються надто рано**, щоб спостерігати за ними іншим способом. Якщо ви можете **запустити цільову службу/програму за потреби** (наприклад, взаємодіючи з її COM-інтерфейсом, перезапустивши службу або повторно запустивши заплановане завдання), зазвичай швидше виконати звичайний запис у Procmon із такими фільтрами, як **`Path contains .dll`**, **`Result is NAME NOT FOUND`** і **`Path begins with <writable_machine_path>`**.

### Пропущені DLL

Під час запуску цього на безкоштовній **віртуальній (vmware) машині з Windows 11** я отримав такі результати:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

У цьому випадку проігноруйте результати `.exe`. Запити відсутніх DLL надходили від:

| Служба                         | Dll                | CMD line                                                             |
| ------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

У наведеному далі прикладі використовується техніка, описана у цій статті про [**зловживання `WptsExtensions.dll` для підвищення привілеїв**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Інші кандидати, які варто перевірити

`WptsExtensions.dll` є хорошим прикладом, але це не єдина повторювана **phantom DLL**, яка трапляється у привілейованих службах. Сучасні правила пошуку та публічні каталоги hijack також відстежують такі імена:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Класичний кандидат для **SYSTEM** у клієнтських системах. Добре підходить, коли доступний для запису каталог міститься в **Machine PATH**, а служба перевіряє DLL під час запуску. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Цікавий варіант у **server editions**, оскільки служба працює як **SYSTEM** і в деяких збірках може бути **запущена за потреби звичайним користувачем**, що робить цей варіант кращим за випадки, які потребують лише перезавантаження. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Зазвичай спочатку надає **`NT AUTHORITY\LOCAL SERVICE`**. Цього часто все ще достатньо, оскільки токен має **`SeImpersonatePrivilege`**, тож його можна об'єднати з [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Розглядайте ці імена як **підказки для triage**, а не як гарантований результат: вони **залежать від SKU/збірки**, і Microsoft може змінювати поведінку між випусками. Важливо шукати **відсутні DLL у привілейованих службах, які проходять через Machine PATH**, особливо якщо службу можна **повторно запустити без перезавантаження**.

### Перевірка кандидата перед weaponizing

Події `NAME NOT FOUND` самі по собі недостатньо. Перш ніж розміщувати payload, перевірте весь ланцюжок:<sup>[[1]](#references)[[4]](#references)</sup>

1. Подія належить очікуваним **PID, командному рядку, обліковому запису служби та рівню цілісності**, а відсутній шлях є точним доступним для запису каталогом Machine `PATH`.
2. Для того самого базового імені DLL жоден попередній каталог не повертає `SUCCESS`, а модуль не забезпечується списком завантажених модулів, KnownDLLs, redirection або SxS manifest.
3. Запит повторюється, коли низькопривілейований користувач виконує передбачений trigger. Пошук, що виконується лише під час завантаження, придатний для використання, але з операційної точки зору значно гірший за варіант із запуском за потреби.
4. Архітектура payload відповідає процесу. Якщо програма пізніше розв'язує exports, створіть proxy для легітимної DLL або експортуйте очікувані symbols; див. [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Спочатку використайте нешкідливу canary DLL, яка записує PID, ідентичність і timestamp. У Procmon вимагайте успішний **`Load Image`** із розміщеного шляху, а не припускайте, що попередній запит до файлу спричинив виконання.

### Експлуатація

Щоб **підвищити привілеї**, виконайте hijack **`WptsExtensions.dll`**. Коли **шлях** та **ім'я** відомі, згенеруйте malicious DLL.

Ви можете [**спробувати використати будь-який із цих прикладів**](README.md#creating-and-compiling-dlls). Можна виконати такі payloads: отримати rev shell, додати користувача, виконати beacon...

> [!WARNING]
> Зверніть увагу, що **не всі служби працюють** як **`NT AUTHORITY\SYSTEM`**. Деякі працюють як **`NT AUTHORITY\LOCAL SERVICE`**, що має **менше привілеїв**, тому зловживання однією з таких служб може не дозволити створити нового користувача.\
> Однак цей обліковий запис має право користувача **`SeImpersonatePrivilege`**, тож ви можете використати [**Potato suite для підвищення привілеїв**](../roguepotato-and-printspoofer.md). У цьому випадку reverse shell є кращим варіантом, ніж спроба створити користувача.

Служба **Task Scheduler** зазвичай працює як **`NT AUTHORITY\SYSTEM`**, але перевірте фактичне розгортання й не визначайте ідентичність виконання лише за назвою служби:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Після **генерації malicious Dll** (_у моєму випадку я використав x64 rev shell і отримав shell у відповідь, але defender завершив його, оскільки він походив із msfvenom_), збережіть його у доступному для запису System Path під назвою **WptsExtensions.dll** і **перезапустіть** комп'ютер (або перезапустіть service чи зробіть усе необхідне, щоб повторно запустити відповідний service/program).

Коли service буде перезапущено, **DLL має бути завантажена та виконана** (ви можете **повторно використати** прийом із **Procmon**, щоб перевірити, чи **library було завантажено належним чином**).

> [!NOTE]
> Сплануйте cleanup перед запуском. Service може зберігати DLL у memory та блокувати файл, доки не зупиниться; для `WptsExtensions.dll` зупинка Task Scheduler потребує elevated rights. Після отримання потрібного context безпечно зупиніть target, видаліть payload і відновіть будь-яку зміну `PATH`, зроблену лише для lab.<sup>[[1]](#references)</sup>

### Remediation / detection

Видаліть слабкі дозволи на запис із кожної директорії Machine `PATH` і видаліть застарілі entries. Developers мають завантажувати trusted libraries за повним шляхом або обмежувати resolution за допомогою `SetDefaultDllDirectories` / search flags для `LoadLibraryEx`. Defenders можуть корелювати зміни Machine `PATH` із privileged processes, які завантажують DLL із non-system директорій, доступних для запису користувачами.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (сподіваюся) — пояснення](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Підозрілий DLL, завантажений для persistence або privilege escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking — Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Порядок пошуку dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
