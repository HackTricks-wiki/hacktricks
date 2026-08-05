# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati i valori importanti nella memoria di un gioco in esecuzione e modificarli.\
Quando lo scarichi e lo avvii, ti verrà presentato un **tutorial** su come utilizzare lo strumento. Se vuoi imparare a usare lo strumento, è altamente consigliato completarlo.<sup>[[3]](#references)</sup>

## Che cosa stai cercando?

![Cheat Engine - Che cosa stai cercando?: Che cosa stai cercando?](<../../images/image (762).png>)

Questo strumento è molto utile per trovare **dove viene memorizzato un valore** (solitamente un numero) nella memoria di un programma.\
**Solitamente i numeri** vengono memorizzati nel formato **4bytes**, ma puoi trovarli anche nei formati **double** o **float**, oppure potresti voler cercare qualcosa di **diverso da un numero**. Per questo motivo devi assicurarti di **selezionare** ciò che vuoi **cercare**:

![Cheat Engine - Che cosa stai cercando?: Solitamente i numeri vengono memorizzati nel formato 4bytes, ma puoi trovarli anche nei formati double o float, oppure potresti voler cercare qualcosa...](<../../images/image (324).png>)

Puoi anche indicare **diversi** tipi di **ricerca**:

![Cheat Engine - Che cosa stai cercando?: Puoi anche indicare diversi tipi di ricerca](<../../images/image (311).png>)

Puoi anche selezionare la casella per **fermare il gioco durante la scansione della memoria**:

![Cheat Engine - Che cosa stai cercando?: Puoi anche selezionare la casella per fermare il gioco durante la scansione della memoria](<../../images/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ puoi impostare diverse **hotkeys** per scopi differenti, come **fermare** il **gioco** (cosa piuttosto utile se a un certo punto vuoi eseguire una scansione della memoria). Sono disponibili anche altre opzioni:

![Che cosa stai cercando? - Hotkeys: In Edit -- Settings -- Hotkeys puoi impostare diverse hotkeys per scopi differenti, come fermare il gioco (cosa piuttosto utile se a un certo punto...](<../../images/image (864).png>)

## Modifica del valore

Dopo aver **trovato** dove si trova il **valore** che stai **cercando** (maggiori informazioni nei passaggi seguenti), puoi **modificarlo** facendo doppio clic su di esso e poi doppio clic sul suo valore:

![Hotkeys - Modifica del valore: Dopo aver trovato dove si trova il valore che stai cercando (maggiori informazioni nei passaggi seguenti), puoi modificarlo facendo doppio clic su di esso e poi doppio clic...](<../../images/image (563).png>)

Infine, **seleziona la casella** per applicare la modifica alla memoria:

![Hotkeys - Modifica del valore: Infine, seleziona la casella per applicare la modifica alla memoria](<../../images/image (385).png>)

La **modifica** alla **memoria** verrà **applicata** immediatamente (nota che, finché il gioco non utilizza nuovamente questo valore, il valore **non verrà aggiornato nel gioco**).

## Ricerca del valore

Supponiamo quindi che esista un valore importante (come la vita del tuo utente) che vuoi aumentare e che tu stia cercando questo valore nella memoria.

### Tramite una modifica nota

Supponendo che tu stia cercando il valore 100, **esegui una scansione** cercando quel valore e trovi molte corrispondenze:

![Ricerca del valore - Tramite una modifica nota: Supponendo che tu stia cercando il valore 100, esegui una scansione cercando quel valore e trovi molte corrispondenze](<../../images/image (108).png>)

Poi fai qualcosa in modo che il **valore cambi**, **fermi** il gioco ed **esegui una** **nuova scansione**:

![Ricerca del valore - Tramite una modifica nota: Poi fai qualcosa in modo che il valore cambi, fermi il gioco ed esegui una nuova scansione](<../../images/image (684).png>)

Cheat Engine cercherà i **valori** che sono **passati da 100 al nuovo valore**. Congratulazioni, hai **trovato** l'**indirizzo** del valore che stavi cercando e ora puoi modificarlo.\
_Se sono ancora presenti diversi valori, esegui nuovamente un'azione per modificare quel valore ed esegui un'altra "next scan" per filtrare gli indirizzi._

### Valore sconosciuto, modifica nota

Nello scenario in cui **non conosci il valore**, ma sai **come farlo cambiare** (e persino l'entità della modifica), puoi cercare il tuo numero.

Inizia eseguendo una scansione di tipo "**Unknown initial value**":

![Tramite una modifica nota - Valore sconosciuto, modifica nota: Inizia quindi eseguendo una scansione di tipo " Unknown initial value "](<../../images/image (890).png>)

Poi fai cambiare il valore, indica **come** è **cambiato il valore** (nel mio caso è diminuito di 1) ed esegui una **nuova scansione**:

![Tramite una modifica nota - Valore sconosciuto, modifica nota: Poi fai cambiare il valore, indica come è cambiato il valore (nel mio caso è diminuito di 1) ed esegui una nuova scansione](<../../images/image (371).png>)

Ti verranno mostrati **tutti i valori modificati nel modo selezionato**:

![Tramite una modifica nota - Valore sconosciuto, modifica nota: Ti verranno mostrati tutti i valori modificati nel modo selezionato](<../../images/image (569).png>)

Dopo aver trovato il valore, puoi modificarlo.

Nota che esistono **molte modifiche possibili** e puoi eseguire questi **passaggi tutte le volte che vuoi** per filtrare i risultati:

![Tramite una modifica nota - Valore sconosciuto, modifica nota: Nota che esistono molte modifiche possibili e puoi eseguire questi passaggi tutte le volte che vuoi per filtrare i risultati](<../../images/image (574).png>)

### Indirizzo casuale della memoria - Individuare il codice

Finora abbiamo imparato a trovare un indirizzo che memorizza un valore, ma è molto probabile che, nelle **diverse esecuzioni del gioco, quell'indirizzo si trovi in posizioni diverse della memoria**. Vediamo quindi come trovare sempre quell'indirizzo.

Usando alcuni dei trucchi menzionati, trova l'indirizzo in cui il gioco attuale sta memorizzando il valore importante. Poi (ferma il gioco, se vuoi) fai **clic con il tasto destro** sull'**indirizzo** trovato e seleziona "**Find out what accesses this address**" oppure "**Find out what writes to this address**":

![Valore sconosciuto, modifica nota - Indirizzo casuale della memoria - Individuare il codice: Usando alcuni dei trucchi menzionati, trova l'indirizzo in cui il gioco attuale sta memorizzando il valore importante. Poi...](<../../images/image (1067).png>)

La **prima opzione** è utile per sapere quali **parti** del **codice** stanno **utilizzando** questo **indirizzo** (utile anche per altre attività, come **sapere dove puoi modificare il codice** del gioco).\
La **seconda opzione** è più **specifica** e sarà più utile in questo caso, poiché ci interessa sapere **da dove viene scritto questo valore**.

Dopo aver selezionato una di queste opzioni, il **debugger** verrà **collegato** al programma e apparirà una nuova **finestra vuota**. Ora **gioca** e **modifica** quel **valore** (senza riavviare il gioco). La **finestra** dovrebbe essere **riempita** con gli **indirizzi** che stanno **modificando** il **valore**:

![Valore sconosciuto, modifica nota - Indirizzo casuale della memoria - Individuare il codice: Dopo aver selezionato una di queste opzioni, il debugger verrà collegato al programma e apparirà una nuova finestra vuota...](<../../images/image (91).png>)

Ora che hai trovato l'indirizzo che modifica il valore, puoi **modificare il codice a tuo piacimento** (Cheat Engine consente di modificarlo rapidamente inserendo dei NOP):

![Valore sconosciuto, modifica nota - Indirizzo casuale della memoria - Individuare il codice: Ora che hai trovato l'indirizzo che modifica il valore, puoi modificare il codice a tuo piacimento (Cheat Engine...](<../../images/image (1057).png>)

Ora puoi modificarlo in modo che il codice non influenzi il tuo numero oppure lo influenzi sempre in modo positivo.

### Indirizzo casuale della memoria - Individuare il pointer

Seguendo i passaggi precedenti, trova dove si trova il valore che ti interessa. Poi, usando "**Find out what writes to this address**", scopri quale indirizzo scrive questo valore e fai doppio clic su di esso per ottenere la vista disassembly:

![Indirizzo casuale della memoria - Individuare il codice - Indirizzo casuale della memoria - Individuare il pointer: Seguendo i passaggi precedenti, trova dove si trova il valore che ti interessa. Poi, usando " Find out...](<../../images/image (1039).png>)

Esegui quindi una nuova scansione **cercando il valore esadecimale compreso tra "\[]"** (il valore di $edx in questo caso):

![Indirizzo casuale della memoria - Individuare il codice - Indirizzo casuale della memoria - Individuare il pointer: Esegui quindi una nuova scansione cercando il valore esadecimale compreso tra " ()" (il valore di $edx in questo caso)](<../../images/image (994).png>)

(_Se ne compaiono diversi, solitamente è necessario scegliere quello con l'indirizzo più piccolo_)\
Ora abbiamo **trovato il pointer che modificherà il valore che ci interessa**.

Fai clic su "**Add Address Manually**":

![Indirizzo casuale della memoria - Individuare il codice - Indirizzo casuale della memoria - Individuare il pointer: Fai clic su " Add Address Manually "](<../../images/image (990).png>)

Ora fai clic sulla casella di controllo "Pointer" e aggiungi l'indirizzo trovato nella casella di testo (in questo scenario, l'indirizzo trovato nell'immagine precedente era "Tutorial-i386.exe"+2426B0):

![Indirizzo casuale della memoria - Individuare il codice - Indirizzo casuale della memoria - Individuare il pointer: Ora fai clic sulla casella di controllo "Pointer" e aggiungi l'indirizzo trovato nella casella di testo (in questo scenario,...](<../../images/image (392).png>)

(Nota come il primo "Address" venga popolato automaticamente con l'indirizzo del pointer inserito)

Fai clic su OK e verrà creato un nuovo pointer:

![Indirizzo casuale della memoria - Individuare il codice - Indirizzo casuale della memoria - Individuare il pointer: Fai clic su OK e verrà creato un nuovo pointer](<../../images/image (308).png>)

Ora, ogni volta che modifichi quel valore, **modifichi il valore importante anche se l'indirizzo della memoria in cui si trova il valore è diverso.**

### Code Injection

La Code injection è una tecnica in cui inietti una porzione di codice nel processo target e poi reindirizzi l'esecuzione del codice in modo che passi attraverso il codice scritto da te (ad esempio, assegnandoti punti invece di sottrarli).

Immagina quindi di aver trovato l'indirizzo che sottrae 1 alla vita del tuo player:

![Indirizzo casuale della memoria - Individuare il pointer - Code Injection: Immagina quindi di aver trovato l'indirizzo che sottrae 1 alla vita del tuo player](<../../images/image (203).png>)

Fai clic su Show disassembler per ottenere il **codice disassemblato**.\
Poi premi **CTRL+a** per aprire la finestra Auto assemble e seleziona _**Template --> Code Injection**_

![Indirizzo casuale della memoria - Individuare il pointer - Code Injection: Poi premi CTRL+a per aprire la finestra Auto assemble e seleziona Template -- Code Injection](<../../images/image (902).png>)

Inserisci **l'indirizzo dell'istruzione che vuoi modificare** (solitamente viene compilato automaticamente):

![Indirizzo casuale della memoria - Individuare il pointer - Code Injection: Inserisci l'indirizzo dell'istruzione che vuoi modificare (solitamente viene compilato automaticamente)](<../../images/image (744).png>)

Verrà generato un template:

![Indirizzo casuale della memoria - Individuare il pointer - Code Injection: Verrà generato un template](<../../images/image (944).png>)

Inserisci quindi il nuovo assembly code nella sezione "**newmem**" e rimuovi il codice originale dalla sezione "**originalcode**" se non vuoi che venga eseguito**.** In questo esempio, il codice iniettato aggiungerà 2 punti invece di sottrarne 1:

![Indirizzo casuale della memoria - Individuare il pointer - Code Injection: Inserisci quindi il nuovo assembly code nella sezione " newmem " e rimuovi il codice originale dalla sezione " originalcode " se non vuoi...](<../../images/image (521).png>)

**Fai clic su execute e così via e il tuo codice dovrebbe essere iniettato nel programma, modificando il comportamento della funzionalità!**

## Funzionalità avanzate di Cheat Engine 7.x (2023-2025)

Cheat Engine ha continuato a evolversi dalla versione 7.0 e sono state aggiunte diverse funzionalità di qualità della vita e di *offensive-reversing*, estremamente utili durante l'analisi di software moderni (e non solo dei giochi!). Di seguito trovi una **guida operativa molto condensata** alle aggiunte che probabilmente utilizzerai più spesso durante il lavoro di red-team/CTF.<sup>[[1]](#references)</sup>

### Miglioramenti di Pointer Scanner 2
* `Pointers must end with specific offsets` e il nuovo slider **Deviation** (≥7.4) riducono notevolmente i falsi positivi quando ripeti la scansione dopo un aggiornamento. Usalo insieme al confronto multi-mappa (`.PTR` → *Compare results with other saved pointer map*) per ottenere un **base-pointer resiliente singolo** in pochi minuti.
* Scorciatoia per il filtro massivo: dopo la prima scansione premi `Ctrl+A → Space` per selezionare tutto, poi `Ctrl+I` (invert) per deselezionare gli indirizzi che non hanno superato la nuova scansione.

### Ultimap 3 – Tracciamento Intel PT
*Dalla versione 7.5, il vecchio Ultimap è stato reimplementato utilizzando **Intel Processor-Trace (IPT)***. Ciò significa che ora puoi registrare *ogni branch eseguito dal target* **senza eseguire single-stepping** (solo in user-mode; non attiverà la maggior parte degli anti-debug gadget).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Dopo alcuni secondi interrompi la cattura e **fai clic con il pulsante destro → Save execution list to file**. Combina gli indirizzi dei branch con una sessione `Find out what addresses this instruction accesses` per individuare molto rapidamente gli hotspot ad alta frequenza della logica di gioco.

### Template per `jmp` a 1 byte / auto-patch
La versione 7.5 ha introdotto uno stub JMP *a un byte* (0xEB) che installa un handler SEH e inserisce un INT3 nella posizione originale. Viene generato automaticamente quando usi **Auto Assembler → Template → Code Injection** su istruzioni che non possono essere patchate con un salto relativo di 5 byte. Questo consente di creare hook “stretti” all'interno di routine packed o con vincoli di dimensione.

### Stealth a livello kernel con DBVM (AMD e Intel)
*DBVM* è l'hypervisor Type-2 integrato di CE. Le build recenti hanno finalmente aggiunto il supporto AMD-V/SVM, quindi puoi eseguire `Driver → Load DBVM` su host Ryzen/EPYC. DBVM consente di:
1. Creare hardware breakpoints invisibili ai controlli Ring-3/anti-debug.
2. Leggere/scrivere regioni di memoria kernel pageable o protette anche quando il driver user-mode è disabilitato.
3. Eseguire bypass di timing attack senza VM-EXIT (ad esempio interrogare `rdtsc` dall'hypervisor).

**Suggerimento:** DBVM si rifiuterà di caricarsi quando HVCI/Memory-Integrity è abilitato su Windows 11 → disabilitalo oppure avvia una VM dedicata come host.

### Debugging remoto / cross-platform con **ceserver**
CE ora include una riscrittura completa di *ceserver* e può connettersi tramite TCP a target **Linux, Android, macOS e iOS**. Un fork popolare integra *Frida* per combinare l'instrumentation dinamica con la GUI di CE: è ideale quando devi patchare giochi Unity o Unreal in esecuzione su uno smartphone:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Per il bridge Frida, consulta `bb33bb/frida-ceserver` su GitHub.<sup>[[2]](#references)</sup>

### Altri elementi degni di nota
* **Patch Scanner** (MemView → Tools) – rileva modifiche inattese al codice nelle sezioni eseguibili; utile per la malware analysis.
* **Structure Dissector 2** – trascina un indirizzo → `Ctrl+D`, quindi *Guess fields* per valutare automaticamente le C-structures.
* **.NET & Mono Dissector** – supporto migliorato per i giochi Unity; consente di chiamare direttamente i metodi dalla CE Lua console.
* **Big-Endian custom types** – scansione/modifica con ordine dei byte invertito (utile per gli emulatori di console e i buffer dei network packet).
* **Autosave & tabs** per le finestre AutoAssembler/Lua, oltre a `reassemble()` per la riscrittura di istruzioni su più righe.

### Note su installazione e OPSEC (2024-2025)
* L'installer ufficiale include **ad-offers** di InnoSetup (`RAV`, ecc.). **Fai sempre clic su *Decline*** *oppure compila dal source* per evitare PUP. Gli AV continueranno comunque a segnalare `cheatengine.exe` come *HackTool*, comportamento previsto.
* I moderni driver anti-cheat (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) rilevano la window class di CE anche quando viene rinominata. Esegui la tua copia per il reversing **all'interno di una VM disposable** oppure dopo aver disabilitato il network play.
* Se ti serve solo l'accesso user-mode, scegli **`Settings → Extra → Kernel mode debug = off`** per evitare di caricare il driver unsigned di CE, che potrebbe causare un BSOD su Windows 11 24H2 con Secure-Boot disabilitato.

---

## Riferimenti

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine tutorial, completalo per imparare a iniziare a usare Cheat Engine

{{#include ../../banners/hacktricks-training.md}}
