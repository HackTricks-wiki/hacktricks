# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati i valori importanti nella memoria di un gioco in esecuzione e modificarli.\
Quando lo scarichi e lo avvii, ti viene presentato un **tutorial** su come usare lo strumento. Se vuoi imparare a usare lo strumento, è altamente consigliato completarlo.

## Che cosa stai cercando?

![Cheat Engine - Che cosa stai cercando?: Che cosa stai cercando?](<../../images/image (762).png>)

Questo strumento è molto utile per trovare **dove viene memorizzato un valore** (solitamente un numero) **nella memoria** di un programma.\
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

Infine, **selezionando la casella** per applicare la modifica nella memoria:

![Hotkeys - Modifica del valore: Infine, selezionando la casella per applicare la modifica nella memoria](<../../images/image (385).png>)

La **modifica** alla **memoria** verrà **applicata** immediatamente (nota che, finché il gioco non utilizzerà nuovamente questo valore, il valore **non verrà aggiornato nel gioco**).

## Ricerca del valore

Supponiamo quindi che esista un valore importante (come la vita del tuo personaggio) che vuoi aumentare e che tu stia cercando questo valore nella memoria.

### Attraverso una modifica nota

Supponendo che tu stia cercando il valore 100, **esegui una scansione** cercando quel valore e trovi molte corrispondenze:

![Ricerca del valore - Attraverso una modifica nota: Supponendo che tu stia cercando il valore 100, esegui una scansione cercando quel valore e trovi molte corrispondenze](<../../images/image (108).png>)

Poi fai qualcosa in modo che il **valore cambi**, quindi **fermi** il gioco ed **esegui una** **scansione successiva**:

![Ricerca del valore - Attraverso una modifica nota: Poi fai qualcosa in modo che il valore cambi, quindi fermi il gioco ed esegui una scansione successiva](<../../images/image (684).png>)

Cheat Engine cercherà i **valori** che sono **passati da 100 al nuovo valore**. Congratulazioni, hai **trovato** l'**indirizzo** del valore che stavi cercando e ora puoi modificarlo.\
_Se sono ancora presenti diversi valori, fai qualcosa per modificare nuovamente quel valore ed esegui un'altra "scansione successiva" per filtrare gli indirizzi._

### Valore sconosciuto, modifica nota

Nello scenario in cui **non conosci il valore**, ma sai **come farlo cambiare** (e persino l'entità della modifica), puoi cercare il tuo numero.

Inizia eseguendo una scansione di tipo "**Unknown initial value**":

![Attraverso una modifica nota - Valore sconosciuto, modifica nota: Inizia eseguendo una scansione di tipo " Unknown initial value "](<../../images/image (890).png>)

Poi fai cambiare il valore, indica **come** è **cambiato il valore** (nel mio caso è diminuito di 1) ed esegui una **scansione successiva**:

![Attraverso una modifica nota - Valore sconosciuto, modifica nota: Poi fai cambiare il valore, indica come è cambiato il valore (nel mio caso è diminuito di 1) ed esegui una scansione successiva](<../../images/image (371).png>)

Ti verranno mostrati **tutti i valori modificati nel modo selezionato**:

![Attraverso una modifica nota - Valore sconosciuto, modifica nota: Ti verranno mostrati tutti i valori modificati nel modo selezionato](<../../images/image (569).png>)

Dopo aver trovato il valore, puoi modificarlo.

Nota che esistono **molte modifiche possibili** e puoi eseguire questi **passaggi tutte le volte che vuoi** per filtrare i risultati:

![Attraverso una modifica nota - Valore sconosciuto, modifica nota: Nota che esistono molte modifiche possibili e puoi eseguire questi passaggi tutte le volte che vuoi per filtrare i risultati](<../../images/image (574).png>)

### Indirizzo di memoria casuale - Trovare il codice

Finora abbiamo imparato a trovare un indirizzo che memorizza un valore, ma è molto probabile che in **esecuzioni diverse del gioco quell'indirizzo si trovi in posizioni diverse della memoria**. Vediamo quindi come trovare sempre quell'indirizzo.

Usando alcuni dei trucchi menzionati, trova l'indirizzo in cui il gioco attuale memorizza il valore importante. Poi (ferma il gioco, se vuoi) fai **clic con il pulsante destro** sull'**indirizzo** trovato e seleziona "**Find out what accesses this address**" oppure "**Find out what writes to this address**":

![Valore sconosciuto, modifica nota - Indirizzo di memoria casuale - Trovare il codice: Usando alcuni dei trucchi menzionati, trova l'indirizzo in cui il gioco attuale memorizza il valore importante. Poi...](<../../images/image (1067).png>)

La **prima opzione** è utile per sapere quali **parti** del **codice** stanno **usando** questo **indirizzo** (utile anche per altre cose, come **sapere dove puoi modificare il codice** del gioco).\
La **seconda opzione** è più **specifica** e sarà più utile in questo caso, poiché ci interessa sapere **da dove viene scritto questo valore**.

Dopo aver selezionato una di queste opzioni, il **debugger** verrà **collegato** al programma e apparirà una nuova **finestra vuota**. Ora **gioca** e **modifica** quel **valore** (senza riavviare il gioco). La **finestra** dovrebbe **riempirsi** con gli **indirizzi** che stanno **modificando** il **valore**:

![Valore sconosciuto, modifica nota - Indirizzo di memoria casuale - Trovare il codice: Dopo aver selezionato una di queste opzioni, il debugger verrà collegato al programma e apparirà una nuova finestra vuota...](<../../images/image (91).png>)

Ora che hai trovato l'indirizzo che modifica il valore, puoi **modificare il codice come preferisci** (Cheat Engine consente di modificarlo rapidamente inserendo NOP):

![Valore sconosciuto, modifica nota - Indirizzo di memoria casuale - Trovare il codice: Ora che hai trovato l'indirizzo che modifica il valore, puoi modificare il codice come preferisci (Cheat Engine...](<../../images/image (1057).png>)

Ora puoi modificarlo in modo che il codice non influisca sul tuo numero oppure lo modifichi sempre in modo positivo.

### Indirizzo di memoria casuale - Trovare il puntatore

Seguendo i passaggi precedenti, trova dove si trova il valore che ti interessa. Poi, usando "**Find out what writes to this address**", scopri quale indirizzo scrive questo valore e fai doppio clic su di esso per visualizzare la vista disassembly:

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Seguendo i passaggi precedenti, trova dove si trova il valore che ti interessa. Poi, usando " Find out...](<../../images/image (1039).png>)

Esegui quindi una nuova scansione **cercando il valore esadecimale tra "\[]"** (in questo caso, il valore di $edx):

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Esegui quindi una nuova scansione cercando il valore esadecimale tra " ()" (in questo caso, il valore di $edx)](<../../images/image (994).png>)

(_Se ne compaiono diversi, solitamente ti serve quello con l'indirizzo più piccolo_)\
Ora abbiamo **trovato il puntatore che modificherà il valore a cui siamo interessati**.

Fai clic su "**Add Address Manually**":

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Fai clic su " Add Address Manually "](<../../images/image (990).png>)

Ora fai clic sulla casella "Pointer" e inserisci l'indirizzo trovato nella casella di testo (in questo scenario, l'indirizzo trovato nell'immagine precedente era "Tutorial-i386.exe"+2426B0):

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Ora fai clic sulla casella "Pointer" e inserisci l'indirizzo trovato nella casella di testo (in questo scenario,...](<../../images/image (392).png>)

(Nota come il primo "Address" venga popolato automaticamente con l'indirizzo del puntatore inserito)

Fai clic su OK e verrà creato un nuovo puntatore:

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Fai clic su OK e verrà creato un nuovo puntatore](<../../images/image (308).png>)

Ora, ogni volta che modifichi quel valore, **modifichi il valore importante anche se l'indirizzo di memoria in cui si trova il valore è diverso.**

### Code Injection

La Code injection è una tecnica in cui si inietta una porzione di codice nel processo bersaglio e poi si reindirizza l'esecuzione del codice affinché passi dal codice scritto da te (ad esempio, facendoti ottenere punti invece di perderli).

Immagina quindi di aver trovato l'indirizzo che sottrae 1 alla vita del tuo personaggio:

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Immagina quindi di aver trovato l'indirizzo che sottrae 1 alla vita del tuo personaggio](<../../images/image (203).png>)

Fai clic su Show disassembler per ottenere il **codice disassemblato**.\
Poi premi **CTRL+a** per aprire la finestra Auto assemble e seleziona _**Template --> Code Injection**_

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Poi premi CTRL+a per aprire la finestra Auto assemble e seleziona Template -- Code Injection](<../../images/image (902).png>)

Inserisci **l'indirizzo dell'istruzione che vuoi modificare** (di solito viene compilato automaticamente):

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Inserisci l'indirizzo dell'istruzione che vuoi modificare (di solito viene compilato automaticamente)](<../../images/image (744).png>)

Verrà generato un template:

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Verrà generato un template](<../../images/image (944).png>)

Inserisci quindi il tuo nuovo codice assembly nella sezione "**newmem**" e rimuovi il codice originale da "**originalcode**" se non vuoi che venga eseguito**.** In questo esempio, il codice iniettato aggiungerà 2 punti invece di sottrarne 1:

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Inserisci quindi il tuo nuovo codice assembly nella sezione " newmem " e rimuovi il codice originale da " originalcode " se non...](<../../images/image (521).png>)

**Fai clic su execute e così via: il tuo codice dovrebbe essere iniettato nel programma, modificando il comportamento della funzionalità!**

## Funzionalità avanzate di Cheat Engine 7.x (2023-2025)

Cheat Engine ha continuato a evolversi dalla versione 7.0 e sono state aggiunte diverse funzionalità di qualità della vita e di *offensive-reversing*, estremamente utili durante l'analisi di software moderni (e non solo giochi!). Di seguito trovi una **guida pratica molto condensata** alle aggiunte che probabilmente utilizzerai più spesso durante il lavoro di red-team/CTF.<sup>[[1]](#references)</sup>

### Miglioramenti del Pointer Scanner 2
* `Pointers must end with specific offsets` e il nuovo slider **Deviation** (≥7.4) riducono notevolmente i falsi positivi quando esegui una nuova scansione dopo un aggiornamento. Usalo insieme al confronto multi-mappa (`.PTR` → *Compare results with other saved pointer map*) per ottenere un **singolo base-pointer resiliente** in pochi minuti.
* Scorciatoia per il filtro massivo: dopo la prima scansione premi `Ctrl+A → Space` per selezionare tutto, quindi `Ctrl+I` (inverti) per deselezionare gli indirizzi che non hanno superato la nuova scansione.

### Ultimap 3 – Tracciamento Intel PT
*Dalla versione 7.5, il vecchio Ultimap è stato reimplementato utilizzando **Intel Processor-Trace (IPT)**.* Ciò significa che ora puoi registrare *ogni branch eseguito dal bersaglio* **senza eseguire single-stepping** (solo in user-mode; non attiverà la maggior parte degli anti-debug gadget).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Dopo alcuni secondi interrompi la cattura e fai **clic destro → Save execution list to file**. Combina gli indirizzi dei branch con una sessione `Find out what addresses this instruction accesses` per individuare molto rapidamente gli hotspot ad alta frequenza della logica di gioco.

### Template `jmp` da 1 byte / auto-patch
La versione 7.5 ha introdotto uno stub JMP *one-byte* (0xEB) che installa un gestore SEH e inserisce un INT3 nella posizione originale. Viene generato automaticamente quando utilizzi **Auto Assembler → Template → Code Injection** su istruzioni che non possono essere patchate con un salto relativo di 5 byte. Questo consente di creare hook “stretti” all’interno di routine packed o con vincoli di dimensione.<sup>[[1]](#references)</sup>

### Stealth a livello kernel con DBVM (AMD e Intel)
*DBVM* è l’hypervisor Type-2 integrato in CE. Le build recenti hanno finalmente aggiunto il supporto AMD-V/SVM, consentendo di eseguire `Driver → Load DBVM` su host Ryzen/EPYC. DBVM consente di:
1. Creare hardware breakpoint invisibili ai controlli Ring-3/anti-debug.
2. Leggere/scrivere regioni di memoria kernel pageable o protette anche quando il driver user-mode è disabilitato.
3. Eseguire bypass di timing attack senza VM-EXIT (ad esempio interrogare `rdtsc` dall’hypervisor).

**Suggerimento:** DBVM rifiuterà di caricarsi quando HVCI/Memory-Integrity è abilitato su Windows 11 → disabilitalo oppure avvia una VM-host dedicata.

### Debugging remoto / cross-platform con **ceserver**
CE ora include una riscrittura completa di *ceserver* e può collegarsi tramite TCP a target **Linux, Android, macOS e iOS**. Un fork popolare integra *Frida* per combinare la dynamic instrumentation con la GUI di CE: ideale quando devi patchare giochi Unity o Unreal in esecuzione su un telefono:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Per il bridge Frida, consulta `bb33bb/frida-ceserver` su GitHub.<sup>[[1]](#references)[[2]](#references)</sup>

### Altri strumenti degni di nota
* **Patch Scanner** (MemView → Tools) – rileva modifiche al codice inattese nelle sezioni eseguibili; utile per l'analisi del malware.
* **Structure Dissector 2** – trascina un indirizzo → `Ctrl+D`, quindi *Guess fields* per valutare automaticamente le C-structures.
* **.NET & Mono Dissector** – supporto migliorato per i giochi Unity; chiama i metodi direttamente dalla console Lua di CE.
* **Big-Endian custom types** – scansione/modifica con ordine dei byte invertito (utile per gli emulatori di console e i buffer dei network packet).
* **Autosave & tabs** per le finestre AutoAssembler/Lua, oltre a `reassemble()` per la riscrittura di istruzioni su più righe.<sup>[[1]](#references)</sup>

### Note di installazione e OPSEC (2024-2025)
* L'installer ufficiale è accompagnato da **ad-offers** di InnoSetup (`RAV`, ecc.). **Clicca sempre su *Decline*** *oppure compila dal source* per evitare PUP. Gli antivirus continueranno comunque a segnalare `cheatengine.exe` come *HackTool*, comportamento previsto.
* I moderni driver anti-cheat (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) rilevano la window class di CE anche quando viene rinominata. Esegui la tua copia per il reversing **all'interno di una VM usa e getta** oppure dopo aver disabilitato il network play.
* Se ti serve soltanto l'accesso user-mode, scegli **`Settings → Extra → Kernel mode debug = off`** per evitare di caricare il driver non firmato di CE, che potrebbe causare un BSOD su Windows 11 24H2 con Secure-Boot.

---

## Riferimenti

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
