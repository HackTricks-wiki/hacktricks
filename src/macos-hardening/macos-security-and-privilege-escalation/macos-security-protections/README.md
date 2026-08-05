# Protezioni di sicurezza di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper viene solitamente utilizzato per riferirsi alla combinazione di **Quarantine + Gatekeeper + XProtect**, 3 moduli di sicurezza di macOS che tenteranno di **impedire agli utenti di eseguire software potenzialmente dannoso scaricato**.

Maggiori informazioni in:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Limitazioni dei processi

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **limita le applicazioni** eseguite all'interno della sandbox alle **azioni consentite specificate nel profilo Sandbox** con cui viene eseguita l'app. Questo aiuta a garantire che **l'applicazione acceda esclusivamente alle risorse previste**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** è un framework di sicurezza. È progettato per **gestire i permessi** delle applicazioni, regolando specificamente il loro accesso alle funzionalità sensibili. Ciò include elementi come **servizi di localizzazione, contatti, foto, microfono, fotocamera, accessibilità e accesso completo al disco**. TCC garantisce che le app possano accedere a queste funzionalità solo dopo aver ottenuto il consenso esplicito dell'utente, rafforzando così la privacy e il controllo sui dati personali.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Le launch constraints in macOS sono una funzionalità di sicurezza che **regola l'avvio dei processi**, definendo **chi può avviare** un processo, **come** e **da dove**. Introdotte in macOS Ventura, classificano i binari di sistema in categorie di constraint all'interno di una **trust cache**. Ogni binario eseguibile dispone di **regole** per il proprio **avvio**, incluse constraint **self**, **parent** e **responsible**. Estese alle app di terze parti come constraint di **Environment** in macOS Sonoma, queste funzionalità aiutano a mitigare i potenziali exploit del sistema regolando le condizioni di avvio dei processi.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Il Malware Removal Tool (MRT) è un'altra componente dell'infrastruttura di sicurezza di macOS. Come suggerisce il nome, la funzione principale di MRT è **rimuovere malware noto dai sistemi infetti**.

Una volta rilevato il malware su un Mac (da XProtect o con altri mezzi), MRT può essere utilizzato per **rimuovere automaticamente il malware**. MRT opera silenziosamente in background e in genere viene eseguito ogni volta che il sistema viene aggiornato o quando viene scaricata una nuova definizione di malware (sembra che le regole che MRT utilizza per rilevare il malware siano contenute nel binario).

Sebbene XProtect e MRT facciano entrambi parte delle misure di sicurezza di macOS, svolgono funzioni diverse:

- **XProtect** è uno strumento preventivo. **Controlla i file mentre vengono scaricati** (tramite determinate applicazioni) e, se rileva tipi di malware noti, **impedisce l'apertura del file**, evitando così che il malware infetti il sistema.
- **MRT**, invece, è uno **strumento reattivo**. Opera dopo che il malware è stato rilevato su un sistema, con l'obiettivo di rimuovere il software dannoso e ripulire il sistema.

L'applicazione MRT si trova in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestione dei task in background

**macOS** ora **avvisa** ogni volta che uno strumento utilizza una **tecnica nota per mantenere l'esecuzione del codice** (come Login Items, Daemons...), in modo che l'utente sappia meglio **quale software mantiene la persistenza**.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Questo viene eseguito con un **daemon** situato in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` e l'**agent** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[1]</sup>

Il modo in cui **`backgroundtaskmanagementd`** sa che qualcosa è installato in una cartella persistente consiste nell'**ottenere gli FSEvents** e creare alcuni **handler** per gestirli.<sup>[1]</sup>

Inoltre, esiste un file plist che contiene le **applicazioni note** che usano frequentemente la persistenza, mantenuto da Apple e situato in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumerazione

È possibile **enumerare tutti** gli elementi in background configurati utilizzando lo strumento CLI di Apple:<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Inoltre, è anche possibile elencare queste informazioni con [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Queste informazioni vengono archiviate in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** e Terminal necessita di FDA.<sup>[2]</sup>

### Manomissione di BTM

Quando viene rilevata una nuova persistence, viene generato un evento di tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Pertanto, qualsiasi metodo per **impedire** l'invio di questo **evento** o per **impedire all'agent di avvisare** l'utente aiuterà un attacker a _**bypassare**_ BTM.<sup>[1]</sup>

- **Reset del database**: l'esecuzione del comando seguente resetterà il database (dovrebbe ricostruirlo da zero); tuttavia, per qualche motivo, dopo averlo eseguito, **nessuna nuova persistence verrà segnalata finché il sistema non verrà riavviato**.<sup>[1]</sup>
- Sono necessari i privilegi di **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Arrestare l'Agent**: È possibile inviare un segnale di arresto all'agent, in modo che **non avvisi l'utente** quando vengono rilevati nuovi elementi.<sup>[1]</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**: Se il **processo che ha creato la persistenza termina subito dopo**, il daemon tenterà di **ottenere informazioni** al riguardo, **fallirà** e **non sarà in grado di inviare l'evento** che indica che un nuovo elemento sta ottenendo la persistenza.<sup>[1]</sup>

## Riferimenti

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
