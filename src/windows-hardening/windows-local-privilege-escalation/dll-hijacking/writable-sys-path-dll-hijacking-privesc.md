# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Якщо ви виявили, що можете **записувати в папку System Path** (зверніть увагу, що це не спрацює, якщо ви можете записувати лише в User Path), то ймовірно ви можете **підвищити привілеї** в системі.

Для цього можна зловживати **Dll Hijacking**, коли ви збираєтеся **перехопити бібліотеку, що завантажується** сервісом або процесом з **більшими привілеями**, ніж у вас, і оскільки цей сервіс завантажує Dll, який, ймовірно, взагалі не існує в системі, він спробує завантажити його з System Path, в який ви можете писати.

Більше інформації про **what is Dll Hijackig** дивіться:


{{#ref}}
./
{{#endref}}

## Privesc за допомогою Dll Hijacking

### Пошук відсутнього Dll

Перше, що вам потрібно — це **виявити процес**, що працює з **більшими привілеями**, ніж у вас, і який намагається **завантажити Dll зі System Path**, в який ви можете записувати.

Проблема в таких випадках полягає в тому, що ці процеси, ймовірно, вже запущені. Щоб знайти, яких .dll бракує службам, потрібно запустити procmon якомога раніше (до того, як процеси будуть завантажені). Отже, щоб знайти відсутні .dll, зробіть:

- **Create** папку `C:\privesc_hijacking` і додайте шлях `C:\privesc_hijacking` до **System Path env variable**. Можна зробити це **вручну** або за допомогою **PS**:
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
- Запустіть **`procmon`** і перейдіть у **`Options`** --> **`Enable boot logging`**, натисніть **`OK`** у запиті.
- Потім **перезавантажте** систему. Коли комп'ютер перезапуститься, **procmon** почне **записувати** події якомога швидше.
- Після завантаження **Windows** знову **запустіть `procmon`** — воно повідомить, що працювало під час завантаження і запитає, чи зберегти події у файл. Скажіть **yes** і **збережіть події у файл**.
- **Після** створення **файлу** закрийте відкрите вікно **`procmon`** і **відкрийте файл подій**.
- Додайте ці **фільтри** — ви знайдете всі Dll, які якийсь **процес намагався завантажити** з доступної для запису папки System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Missed Dlls

Запустивши це на безкоштовній віртуальній машині (vmware) з **Windows 11**, я отримав такі результати:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

У цьому випадку `.exe` марні, тож ігноруйте їх — пропущені DLL походили з:

| Служба                          | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Після цього я знайшов цікавий блог, який також пояснює, як [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Саме це **ми робитимемо зараз**.

### Exploitation

Отже, щоб **ескалювати привілеї**, ми плануємо перехопити бібліотеку **WptsExtensions.dll**. Маючи **шлях** і **ім'я**, нам лишається **згенерувати шкідливу dll**.

You can [**try to use any of these examples**](#creating-and-compiling-dlls). Ви можете запускати payload'и, наприклад: отримати rev shell, додати користувача, виконати beacon...

> [!WARNING]
> Зверніть увагу, що **не всі служби запускаються** від імені **`NT AUTHORITY\SYSTEM`** — деякі працюють під **`NT AUTHORITY\LOCAL SERVICE`**, який має **менше привілеїв**, і ви **не зможете створити нового користувача**, аби зловживати його правами.\
> Однак цей користувач має привілейію **`seImpersonate`**, тож ви можете скористатися [ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Отже, у цьому випадку rev shell — кращий варіант, ніж спроба створити користувача.

На момент написання служба **Task Scheduler** запускається від імені **Nt AUTHORITY\SYSTEM**.

Після того, як шкідлива Dll згенерована (в моєму випадку я використав x64 rev shell і отримав shell назад, але defender вбив процес, бо payload був з msfvenom), збережіть її у доступному для запису System Path під іменем **WptsExtensions.dll** і **перезавантажте** комп'ютер (або перезапустіть службу чи зробіть будь-що, щоб знову запустити уражену службу/програму).

Коли служба перезапуститься, **dll повинна бути завантажена і виконана** (ви можете **знову скористатися** трюком з **procmon**, щоб перевірити, чи бібліотека була завантажена, як очікувалося).

{{#include ../../../banners/hacktricks-training.md}}
