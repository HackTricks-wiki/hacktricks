# Записуваний системний PATH +DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Якщо ви можете **записувати до каталогу в загальносистемному `PATH`** (а не лише у своєму `PATH` користувача), ви можете отримати можливість **підвищити привілеї** в системі.

Цим можна зловживати через **DLL hijacking**, коли служба або процес із вищими привілеями намагається завантажити DLL, якої немає в попередніх місцях пошуку, і зрештою здійснює пошук у записуваному каталозі системного `PATH`.

Додаткову інформацію про **DLL hijacking** дивіться тут:


{{#ref}}
./
{{#endref}}

## Privesc через DLL Hijacking

### Пошук відсутньої DLL

Спочатку **визначте процес**, який працює з **вищими привілеями** та намагається **завантажити DLL із записуваного каталогу системного `PATH`**.

Пам’ятайте, що ця техніка залежить від запису **Machine/System PATH**, а не лише від вашого **User PATH**. Тому перш ніж витрачати час на Procmon, варто перелічити записи **Machine PATH** і перевірити, до яких із них можна записувати:<sup>[[1]](#references)</sup>
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
Проблема в таких випадках полягає в тому, що ці процеси, ймовірно, уже запущені. Щоб визначити DLL, які служби намагаються завантажити, але не можуть, запустіть Procmon якомога раніше (до запуску процесів), а потім:

- **Створіть** папку `C:\privesc_hijacking` і додайте шлях `C:\privesc_hijacking` до **змінної System Path**. Це можна зробити **вручну** або за допомогою **PS**:
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
- Запустіть **`procmon`** і перейдіть до **`Options`** --> **`Enable boot logging`**, після чого натисніть **`OK`** у запиті.
- Потім **перезавантажте комп’ютер**. Після перезапуску комп’ютера **`procmon`** почне **записувати** події якомога швидше.
- Коли **Windows** буде **запущено, виконайте `procmon`** знову. Він повідомить, що вже працював, і **запитає, чи хочете ви зберегти** події у файл. Виберіть **так** і **збережіть події у файл**.
- **Після** створення **файлу** закрийте відкрите вікно **`procmon`** і **відкрийте файл подій**.
- Додайте ці **фільтри**, щоб знайти всі DLL, які **процес намагався завантажити** з доступної для запису теки System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging потрібен лише для служб, які запускаються надто рано**, щоб спостерігати за ними іншим способом. Якщо ви можете **запустити цільову службу/програму на вимогу** (наприклад, взаємодіючи з її COM-інтерфейсом, перезапустивши службу або повторно запустивши заплановане завдання), зазвичай швидше виконати звичайний capture у Procmon із такими фільтрами, як **`Path contains .dll`**, **`Result is NAME NOT FOUND`** і **`Path begins with <writable_machine_path>`**.

### Пропущені DLL

Під час запуску цього в безкоштовній **віртуальній машині (vmware) з Windows 11** я отримав такі результати:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

У цьому випадку проігноруйте результати для `.exe`. Запити відсутніх DLL надходили від:

| Служба                         | Dll                | CMD line                                                             |
| ----------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

У наступному прикладі використовується техніка, описана в цій статті про [**зловживання `WptsExtensions.dll` для підвищення привілеїв**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Інші кандидати, які варто перевірити

`WptsExtensions.dll` — хороший приклад, але це не єдина повторювана **phantom DLL**, яка трапляється у привілейованих службах. Сучасні правила hunting і загальнодоступні каталоги hijack досі відстежують такі назви:<sup>[[2]](#references)</sup>

| Служба / Сценарій | Відсутня DLL | Примітки |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Класичний кандидат для **SYSTEM** у клієнтських системах. Добре працює, коли доступна для запису директорія міститься в **Machine PATH**, а служба шукає DLL під час запуску. |
| NetMan у Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Цікавий варіант у **серверних редакціях**, оскільки служба працює від імені **SYSTEM** і в деяких збірках може бути **запущена на вимогу звичайним користувачем**, що робить її кращою за випадки, які потребують лише перезавантаження. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Зазвичай спочатку надає **`NT AUTHORITY\LOCAL SERVICE`**. Цього часто достатньо, оскільки токен має **`SeImpersonatePrivilege`**, тому можна поєднати це з [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Розглядайте ці назви як **підказки для triage**, а не як гарантований результат: вони **залежать від SKU/збірки**, і Microsoft може змінювати поведінку між релізами. Головний висновок полягає в тому, що потрібно шукати **відсутні DLL у привілейованих службах, які проходять через Machine PATH**, особливо якщо службу можна **повторно запустити без перезавантаження**.

### Експлуатація

Щоб **підвищити привілеї**, виконайте hijack **`WptsExtensions.dll`**. Коли **шлях** і **назва** відомі, згенеруйте шкідливу DLL.

Ви можете [**спробувати використати будь-який із цих прикладів**](#creating-and-compiling-dlls). Можна запускати payloads, наприклад: отримати rev shell, додати користувача, виконати beacon...

> [!WARNING]
> Зверніть увагу, що **не всі служби працюють** від імені **`NT AUTHORITY\SYSTEM`**. Деякі працюють від імені **`NT AUTHORITY\LOCAL SERVICE`**, який має **менше привілеїв**, тому зловживання однією з таких служб може не дозволити створити нового користувача.\
> Однак цей обліковий запис має право користувача **`SeImpersonatePrivilege`**, тому можна скористатися [**набором Potato для підвищення привілеїв**](../roguepotato-and-printspoofer.md). У цьому випадку reverse shell є кращим варіантом, ніж спроба створити користувача.

На момент написання матеріалу служба **Task Scheduler** працює від імені **Nt AUTHORITY\SYSTEM**.

Після **генерації шкідливої DLL** (_у моєму випадку я використав x64 rev shell і отримав shell, але defender завершив його, оскільки він походив із msfvenom_) збережіть її в доступному для запису System Path під назвою **WptsExtensions.dll** і **перезавантажте** комп’ютер (або перезапустіть службу чи зробіть усе необхідне для повторного запуску відповідної служби/програми).

Коли службу буде перезапущено, **dll має бути завантажена та виконана** (можна **повторно використати** прийом із **procmon**, щоб перевірити, чи **бібліотеку завантажено очікуваним чином**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
