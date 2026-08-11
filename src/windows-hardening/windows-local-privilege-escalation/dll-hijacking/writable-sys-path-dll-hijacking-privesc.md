# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Якщо ви можете **записувати до каталогу в загальносистемному `PATH`** (а не лише у вашому користувацькому `PATH`), ви можете отримати можливість **підвищити привілеї** в системі.

Цим можна зловживати через **DLL hijacking**, коли більш привілейований сервіс або процес намагається завантажити DLL, якої немає в попередніх місцях пошуку, і зрештою шукає її в доступному для запису каталозі системного `PATH`.

Докладніше про **DLL hijacking** дивіться:


{{#ref}}
./
{{#endref}}

## Підвищення привілеїв за допомогою Dll Hijacking

### Пошук відсутньої DLL

Спочатку **визначте процес**, який працює з **вищими привілеями** та намагається **завантажити DLL із доступного для запису каталогу системного `PATH`**.

Пам’ятайте, що ця техніка залежить від запису **Machine/System PATH**, а не лише від вашого **User PATH**. Тому перш ніж витрачати час на Procmon, варто перелічити записи **Machine PATH** і перевірити, до яких із них є доступ для запису:<sup>[[1]](#references)</sup>
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

- **Створіть** папку `C:\privesc_hijacking` і додайте шлях `C:\privesc_hijacking` до **системної змінної середовища Path**. Це можна зробити **вручну** або за допомогою **PS**:
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
- Потім **перезавантажте комп’ютер**. Після перезапуску комп’ютера **`procmon`** одразу почне **записувати** події.
- Після **запуску Windows знову виконайте `procmon`**. Він повідомить, що вже працював, і **запитає, чи хочете ви зберегти** події у файл. Виберіть **так** і **збережіть події у файл**.
- **Після** створення **файлу** закрийте відкрите вікно **`procmon`** і **відкрийте файл подій**.
- Додайте такі **фільтри**, щоб знайти всі DLL, які **процес намагався завантажити** з доступної для запису папки System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging потрібен лише для служб, які запускаються надто рано**, щоб спостерігати за ними іншим способом. Якщо ви можете **запустити цільову службу або програму на вимогу** (наприклад, взаємодіючи з її COM-інтерфейсом, перезапустивши службу або повторно запустивши заплановане завдання), зазвичай швидше виконати звичайне захоплення в Procmon із такими фільтрами, як **`Path contains .dll`**, **`Result is NAME NOT FOUND`** і **`Path begins with <writable_machine_path>`**.

### Пропущені DLL

Запустивши це на безкоштовній **віртуальній (vmware) машині з Windows 11**, я отримав такі результати:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

У цьому випадку проігноруйте результати `.exe`. Запити відсутніх DLL надходили від:

| Служба                         | DLL                | Рядок CMD                                                           |
| ------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Планувальник завдань (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Служба політики діагностики (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

У наступному прикладі використовується техніка, описана в цій статті про [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Інші кандидати, які варто перевірити

`WptsExtensions.dll` — хороший приклад, але це не єдина recurring **phantom DLL**, яка з’являється у привілейованих службах. Сучасні правила пошуку та публічні каталоги hijack і надалі відстежують такі імена:<sup>[[2]](#references)</sup>

| Служба / сценарій | Відсутня DLL | Примітки |
| --- | --- | --- |
| Планувальник завдань (`Schedule`) | `WptsExtensions.dll` | Класичний кандидат із привілеями **SYSTEM** у клієнтських системах. Добре підходить, коли доступний для запису каталог міститься в **Machine PATH**, а служба перевіряє наявність DLL під час запуску. |
| NetMan у Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Цікавий варіант у **серверних редакціях**, оскільки служба працює від імені **SYSTEM** і в деяких збірках може бути **запущена на вимогу звичайним користувачем**, що робить цей випадок кращим за сценарії, які потребують лише перезавантаження. |
| Служба Connected Devices Platform (`CDPSvc`) | `cdpsgshims.dll` | Зазвичай спочатку надає **`NT AUTHORITY\LOCAL SERVICE`**. Цього часто достатньо, оскільки токен має **`SeImpersonatePrivilege`**, тож його можна поєднати з [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Розглядайте ці імена як **підказки для перевірки**, а не як гарантований результат: вони **залежать від SKU та збірки**, і Microsoft може змінювати поведінку між випусками. Головний висновок полягає в тому, що потрібно шукати **відсутні DLL у привілейованих службах, які проходять через Machine PATH**, особливо якщо службу можна **повторно запустити без перезавантаження**.

### Експлуатація

Щоб **підвищити привілеї**, виконайте hijack **`WptsExtensions.dll`**. Коли **шлях** та **ім’я** відомі, створіть шкідливу DLL.

Ви можете [**try to use any of these examples**](#creating-and-compiling-dlls). Можна виконати такі payloads: отримати rev shell, додати користувача, запустити beacon тощо.

> [!WARNING]
> Зверніть увагу, що **не всі служби працюють** від імені **`NT AUTHORITY\SYSTEM`**. Деякі працюють від імені **`NT AUTHORITY\LOCAL SERVICE`**, який має **менше привілеїв**, тому зловживання однією з таких служб може не дозволити створити нового користувача.\
> Однак цей обліковий запис має право користувача **`SeImpersonatePrivilege`**, тож для **підвищення привілеїв можна використати Potato suite**](../roguepotato-and-printspoofer.md). У цьому випадку reverse shell є кращим варіантом, ніж спроба створити користувача.

На момент написання цієї статті служба **Task Scheduler** працює від імені **Nt AUTHORITY\SYSTEM**.

Створивши **шкідливу DLL** (_у моєму випадку я використав x64 rev shell і отримав shell, але defender завершив його, оскільки він був створений за допомогою msfvenom_), збережіть її у доступному для запису System Path під іменем **WptsExtensions.dll** і **перезавантажте** комп’ютер (або перезапустіть службу чи зробіть усе необхідне, щоб повторно запустити відповідну службу/програму).

Коли службу буде перезапущено, **DLL має завантажитися та виконатися** (можна **повторно використати** прийом із **procmon**, щоб перевірити, чи **бібліотеку завантажено належним чином**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
