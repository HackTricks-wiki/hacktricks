# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove sono salvati nella memoria di un gioco in esecuzione i valori importanti e modificarli.\
Quando lo scarichi e lo esegui, ti viene presentato un **tutorial** su come usare lo strumento. Se vuoi imparare a usare lo strumento, è altamente consigliato completarlo.

## Cosa stai cercando?

![Cheat Engine - Cosa stai cercando?: Cosa stai cercando?](<../../images/image (762).png>)

Questo strumento è molto utile per trovare **dove è memorizzato un valore** (solitamente un numero) nella memoria di un programma.\
**Solitamente i numeri** sono memorizzati nel formato **4bytes**, ma puoi anche trovarli nei formati **double** o **float**, oppure potresti voler cercare qualcosa di **diverso da un numero**. Per questo motivo devi assicurarti di **selezionare** ciò che vuoi **cercare**:

![Cheat Engine - Cosa stai cercando?: Solitamente i numeri sono memorizzati nel formato 4bytes, ma puoi anche trovarli nei formati double o float, oppure potresti voler cercare qualcosa...](<../../images/image (324).png>)

Puoi anche indicare **diversi** tipi di **ricerca**:

![Cheat Engine - Cosa stai cercando?: Puoi anche indicare diversi tipi di ricerca](<../../images/image (311).png>)

Puoi anche selezionare la casella per **fermare il gioco durante la scansione della memoria**:

![Cheat Engine - Cosa stai cercando?: Puoi anche selezionare la casella per fermare il gioco durante la scansione della memoria](<../../images/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ puoi impostare diverse **hotkeys** per scopi differenti, come **fermare** il **gioco** (cosa piuttosto utile se a un certo punto vuoi scansionare la memoria). Sono disponibili anche altre opzioni:

![Cosa stai cercando? - Hotkeys: In Edit -- Settings -- Hotkeys puoi impostare diverse hotkeys per scopi differenti, come fermare il gioco (cosa piuttosto utile se a un certo punto...](<../../images/image (864).png>)

## Modificare il valore

Dopo aver **trovato** dove si trova il **valore** che stai **cercando** (maggiori informazioni nei passaggi successivi), puoi **modificarlo** facendo doppio clic su di esso e poi doppio clic sul suo valore:

![Hotkeys - Modificare il valore: Dopo aver trovato dove si trova il valore che stai cercando (maggiori informazioni nei passaggi successivi), puoi modificarlo facendo doppio clic su di esso e poi doppio clic...](<../../images/image (563).png>)

Infine, **seleziona la casella** per applicare la modifica nella memoria:

![Hotkeys - Modificare il valore: Infine, seleziona la casella per applicare la modifica nella memoria](<../../images/image (385).png>)

La **modifica** alla **memoria** verrà **applicata** immediatamente (nota che, finché il gioco non utilizza nuovamente questo valore, il valore **non verrà aggiornato nel gioco**).

## Cercare il valore

Supponiamo quindi che esista un valore importante (come la vita del tuo personaggio) che vuoi aumentare e che tu stia cercando questo valore nella memoria.

### Attraverso una modifica nota

Supponendo che tu stia cercando il valore 100, **esegui una scansione** cercando quel valore e trovi molte corrispondenze:

![Cercare il valore - Attraverso una modifica nota: Supponendo che tu stia cercando il valore 100, esegui una scansione cercando quel valore e trovi molte corrispondenze](<../../images/image (108).png>)

Poi fai qualcosa affinché il **valore cambi**, **fermi** il gioco ed **esegui una scansione successiva**:

![Cercare il valore - Attraverso una modifica nota: Poi fai qualcosa affinché il valore cambi, fermi il gioco ed esegui una scansione successiva](<../../images/image (684).png>)

Cheat Engine cercherà i **valori** che sono **passati da 100 al nuovo valore**. Congratulazioni, hai **trovato** l'**indirizzo** del valore che stavi cercando e ora puoi modificarlo.\
_Se sono ancora presenti diversi valori, modifica nuovamente quel valore ed esegui un'altra "scansione successiva" per filtrare gli indirizzi._

### Valore sconosciuto, modifica nota

Nello scenario in cui **non conosci il valore**, ma sai **come farlo cambiare** (e persino l'entità della modifica), puoi cercare il tuo numero.

Inizia quindi eseguendo una scansione di tipo "**Unknown initial value**":

![Attraverso una modifica nota - Valore sconosciuto, modifica nota: Inizia quindi eseguendo una scansione di tipo " Unknown initial value "](<../../images/image (890).png>)

Poi fai cambiare il valore, indica **come** è **cambiato** il **valore** (nel mio caso è diminuito di 1) ed esegui una **scansione successiva**:

![Attraverso una modifica nota - Valore sconosciuto, modifica nota: Poi fai cambiare il valore, indica come è cambiato il valore (nel mio caso è diminuito di 1) ed esegui una scansione successiva](<../../images/image (371).png>)

Ti verranno presentati **tutti i valori modificati nel modo selezionato**:

![Attraverso una modifica nota - Valore sconosciuto, modifica nota: Ti verranno presentati tutti i valori modificati nel modo selezionato](<../../images/image (569).png>)

Una volta trovato il valore, puoi modificarlo.

Nota che esistono **molte modifiche possibili** e puoi eseguire questi **passaggi tutte le volte che vuoi** per filtrare i risultati:

![Attraverso una modifica nota - Valore sconosciuto, modifica nota: Nota che esistono molte modifiche possibili e puoi eseguire questi passaggi tutte le volte che vuoi per filtrare i risultati](<../../images/image (574).png>)

### Indirizzo di memoria casuale - Trovare il codice

Finora abbiamo imparato a trovare un indirizzo che memorizza un valore, ma è molto probabile che in **esecuzioni diverse del gioco quell'indirizzo si trovi in posizioni diverse della memoria**. Vediamo quindi come trovare sempre quell'indirizzo.

Usando alcuni dei trucchi menzionati, trova l'indirizzo in cui il gioco corrente memorizza il valore importante. Poi (ferma il gioco, se vuoi) fai **clic con il tasto destro** sull'**indirizzo** trovato e seleziona "**Find out what accesses this address**" oppure "**Find out what writes to this address**":

![Valore sconosciuto, modifica nota - Indirizzo di memoria casuale - Trovare il codice: Usando alcuni dei trucchi menzionati, trova l'indirizzo in cui il gioco corrente memorizza il valore importante. Poi...](<../../images/image (1067).png>)

La **prima opzione** è utile per sapere quali **parti** del **codice** stanno **usando** questo **indirizzo** (ed è utile per altre operazioni, come **sapere dove puoi modificare il codice** del gioco).\
La **seconda opzione** è più **specifica** e sarà più utile in questo caso, poiché ci interessa sapere **da dove viene scritto questo valore**.

Dopo aver selezionato una di queste opzioni, il **debugger** verrà **collegato** al programma e apparirà una nuova **finestra vuota**. Ora **gioca** e **modifica** quel **valore** (senza riavviare il gioco). La **finestra** dovrebbe essere **riempita** con gli **indirizzi** che stanno **modificando** il **valore**:

![Valore sconosciuto, modifica nota - Indirizzo di memoria casuale - Trovare il codice: Dopo aver selezionato una di queste opzioni, il debugger verrà collegato al programma e apparirà una nuova finestra vuota...](<../../images/image (91).png>)

Ora che hai trovato l'indirizzo che modifica il valore, puoi **modificare il codice come preferisci** (Cheat Engine consente di modificarlo rapidamente per usare NOP):

![Valore sconosciuto, modifica nota - Indirizzo di memoria casuale - Trovare il codice: Ora che hai trovato l'indirizzo che modifica il valore, puoi modificare il codice come preferisci (Cheat Engine...](<../../images/image (1057).png>)

Puoi quindi modificarlo in modo che il codice non influisca sul tuo numero oppure lo modifichi sempre in modo positivo.

### Indirizzo di memoria casuale - Trovare il puntatore

Seguendo i passaggi precedenti, trova dove si trova il valore che ti interessa. Poi, usando "**Find out what writes to this address**", scopri quale indirizzo scrive questo valore e fai doppio clic su di esso per visualizzare la disassembly:

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Seguendo i passaggi precedenti, trova dove si trova il valore che ti interessa. Poi, usando " Find out...](<../../images/image (1039).png>)

Poi esegui una nuova scansione **cercando il valore esadecimale tra "\[]"** (in questo caso, il valore di $edx):

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Poi esegui una nuova scansione cercando il valore esadecimale tra " ()" (in questo caso, il valore di $edx)](<../../images/image (994).png>)

(_Se ne appaiono diversi, di solito devi scegliere quello con l'indirizzo più piccolo_)\
Ora abbiamo **trovato il puntatore che modificherà il valore che ci interessa**.

Fai clic su "**Add Address Manually**":

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Fai clic su " Add Address Manually "](<../../images/image (990).png>)

Ora fai clic sulla casella di controllo "Pointer" e aggiungi l'indirizzo trovato nella casella di testo (in questo scenario, l'indirizzo trovato nell'immagine precedente era "Tutorial-i386.exe"+2426B0):

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Ora fai clic sulla casella di controllo "Pointer" e aggiungi l'indirizzo trovato nella casella di testo (in questo scenario,...](<../../images/image (392).png>)

(Nota come il primo "Address" venga compilato automaticamente a partire dall'indirizzo del puntatore inserito)

Fai clic su OK e verrà creato un nuovo puntatore:

![Indirizzo di memoria casuale - Trovare il codice - Indirizzo di memoria casuale - Trovare il puntatore: Fai clic su OK e verrà creato un nuovo puntatore](<../../images/image (308).png>)

Ora, ogni volta che modifichi quel valore, **modifichi il valore importante anche se l'indirizzo di memoria in cui si trova il valore è diverso.**

### Code Injection

Code injection è una tecnica in cui si inietta una porzione di codice nel processo target e poi si reindirizza l'esecuzione del codice affinché passi dal proprio codice (ad esempio, assegnandoti punti invece di sottrarli).

Supponiamo quindi che tu abbia trovato l'indirizzo che sottrae 1 alla vita del tuo giocatore:

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Supponiamo quindi che tu abbia trovato l'indirizzo che sottrae 1 alla vita del tuo giocatore](<../../images/image (203).png>)

Fai clic su Show disassembler per ottenere il **codice disassemblato**.\
Poi premi **CTRL+a** per aprire la finestra Auto assemble e seleziona _**Template --> Code Injection**_

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Poi premi CTRL+a per aprire la finestra Auto assemble e seleziona Template -- Code Injection](<../../images/image (902).png>)

Inserisci l'**indirizzo dell'istruzione che vuoi modificare** (di solito viene compilato automaticamente):

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Inserisci l'indirizzo dell'istruzione che vuoi modificare (di solito viene compilato automaticamente)](<../../images/image (744).png>)

Verrà generato un template:

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Verrà generato un template](<../../images/image (944).png>)

Inserisci quindi il tuo nuovo codice assembly nella sezione "**newmem**" e rimuovi il codice originale da "**originalcode**" se non vuoi che venga eseguito**.** In questo esempio, il codice iniettato aggiungerà 2 punti invece di sottrarne 1:

![Indirizzo di memoria casuale - Trovare il puntatore - Code Injection: Inserisci quindi il tuo nuovo codice assembly nella sezione " newmem " e rimuovi il codice originale da " originalcode " se non...](<../../images/image (521).png>)

**Fai clic su execute e così via: il tuo codice dovrebbe essere iniettato nel programma, modificando il comportamento della funzionalità!**

## Iniezione di codice sicura rispetto alla rilocazione con firme AOB

Uno script che esegue hook su `game.exe+123456` può smettere di funzionare dopo ASLR o un aggiornamento del software. Una **firma Array of Bytes (AOB)** trova l'istruzione a partire dal codice macchina circostante. Usa `aobscanmodule` per limitare la ricerca a un modulo. Rendi la firma abbastanza lunga da restituire una sola corrispondenza. Usa i wildcard per i byte di rilocazione, gli indirizzi e gli altri byte che potrebbero cambiare. Non usare wildcard per l'intera istruzione che devi ripristinare.<sup>[[4]](#references)</sup>

In Memory View, seleziona l'istruzione e usa **Tools → Auto Assemble → Template → AOB Injection**. Il blocco `[DISABLE]` generato è importante. Deve ripristinare ogni byte sovrascritto e liberare l'allocazione.<sup>[[4]](#references)</sup>

<details>
<summary>Skeleton minimo di iniezione AOB x64</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Prima di abilitare lo script, verifica questi punti:

1. L'AOB restituisce **un** indirizzo. Se ne restituisce di più, aggiungi istruzioni stabili su entrambi i lati.
2. Il jump sostituisce istruzioni complete. Non dividere mai un'istruzione.
3. La code cave allocata è raggiungibile dal jump generato. Su x64, un'allocazione distante potrebbe richiedere un jump di 14 byte.
4. Il codice iniettato preserva registri, flag e allineamento dello stack previsti dalla funzione originale.
5. Il blocco di disabilitazione ripristina gli stessi byte originali. Prova più volte l'abilitazione e la disabilitazione prima di salvare la tabella.

## Workflow affidabile per i puntatori

Un puntatore trovato in un'esecuzione è solo un candidato. Crea mappe dei puntatori in diverse esecuzioni pulite e ripeti la scansione confrontandole con tutte. Riavvia il target tra le acquisizioni, in modo che ASLR e le allocazioni dell'heap cambino. Preferisci percorsi la cui base sia un modulo o un altro simbolo stabile. Rifiuta i percorsi che funzionano solo con un determinato salvataggio, livello o istanza dell'oggetto.

Il filtro **il puntatore deve terminare con offset specifici** e la relativa opzione di deviazione possono mantenere percorsi utili quando un campo vicino cambia tra le build. La release 7.5 ha aggiunto anche questo controllo della deviazione. È un filtro, non una prova che una catena di puntatori sia stabile.<sup>[[1]](#references)</sup>

Quando una struttura cambia troppo spesso per la scansione dei puntatori, esegui l'hook sull'istruzione che vi accede. Acquisisci il puntatore all'oggetto attivo da un registro e inseriscilo in un simbolo allocato. Questo è spesso più affidabile per gli elenchi di entità e gli oggetti gestiti.

## Tracciare il codice invece di scansionare i valori

Usa **Find out what writes to this address** quando il valore viene modificato direttamente. Usa **Find out what accesses this address** quando ti serve l'oggetto proprietario o quando la scrittura avviene tramite dati copiati. Attiva una sola azione nel target. Poi confronta il numero di occorrenze e lo stato dei registri.

**Ultimap 2** usa Intel Processor Trace sulle CPU Intel supportate. Registra il flusso di controllo eseguito con meno interruzioni rispetto all'esecuzione passo-passo di ogni istruzione. Filtra il codice eseguito durante l'azione di interesse e rimuovi quello eseguito anche durante un'acquisizione a riposo. Intel PT non è una funzionalità stealth. Il target può comunque rilevare il tracing, le variazioni nei tempi o Cheat Engine stesso.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 ha aggiunto anche un'interfaccia Intel PT fornita da Windows. La modalità Ultimap basata su DBVM e la modalità Intel PT hanno requisiti hardware e del sistema operativo diversi. Non dare per scontato che una CPU compatibile con DBVM supporti Intel PT.<sup>[[1]](#references)</sup>

## Selezione del debugger e dei breakpoint

Scegli il debugger meno invasivo che funzioni:

- **Windows debugger** è semplice, ma crea normali eventi di debug. I controlli anti-debugging possono rilevarlo.
- **VEH debugger** gestisce i breakpoint tramite un gestore delle eccezioni vettorizzate. Evita alcuni controlli di base del debugger, ma non è invisibile.
- **Hardware breakpoints** non modificano i byte dell'istruzione, ma x86/x64 offre solo un numero limitato di slot nei registri di debug.
- **Software breakpoints** sostituiscono un byte con `INT3`. Sono facili da rilevare e possono entrare in conflitto con i controlli di integrità.
- **DBVM debugger** sposta alcune operazioni al di sotto del guest OS. Dispone di privilegi molto maggiori e può causare il crash dell'host se configurato in modo errato.

Cheat Engine 7.5 può usare un jump di un byte basato su un gestore delle eccezioni e `INT3` quando non c'è spazio sufficiente per un normale jump relativo. Trattalo come un software breakpoint. Verifica il flusso delle eccezioni e non dare per scontato che aggiri i controlli anti-tamper.<sup>[[1]](#references)</sup>

DBVM è un hypervisor, non un interruttore generale per l'invisibilità. Usalo solo in un laboratorio usa e getta. Non esporre la sua interfaccia di controllo a codice non attendibile. I prodotti kernel anti-cheat ed endpoint possono comunque rilevare il driver, lo stato dell'hypervisor o la memoria modificata.

## Runtime gestiti e funzionalità recenti della versione 7.6/7.7

Per i target Mono, IL2CPP, .NET e Java, quando disponibile, preferisci i metadata del runtime alle scansioni alla cieca. Apri **Mono → Activate mono features** o la finestra corrispondente con le informazioni del runtime. Individua prima la classe, il campo o il metodo. Poi usa il disassemblato nativo quando il metodo gestito viene compilato JIT.

La linea 7.6 ha aggiunto `AOBSCANEX` per le signature limitate alla memoria eseguibile, un'interfaccia debugger `gdbserver`, l'ispezione dei metadata Java, un'enumerazione IL2CPP più veloce e un'opzione di pointer scan che ignora il byte superiore del puntatore usato dal memory tagging ARM. La linea 7.7 ha aggiunto build native Linux, `HOOK`/`UNHOOK`, `aobscanfunction`, una ricerca migliorata dei metodi Mono generici, un supporto migliorato per le strutture PDB e una dissection di base delle strutture di Unreal Engine.<sup>[[3]](#references)</sup>

Queste aggiunte abilitano un workflow utile:

1. Risolvi un metodo gestito o un campo statico dai metadata.
2. Traccia o disassembla il codice nativo prodotto per quel metodo.
3. Usa `AOBSCANEX` o `aobscanfunction` per individuare una signature eseguibile stabile.
4. Genera un hook reversibile. Conserva le istruzioni originali e convalida il percorso di disabilitazione.
5. Ricontrolla la signature dopo ogni aggiornamento del target. Una corrispondenza riuscita non garantisce che la logica circostante abbia ancora lo stesso significato.

## Target remoti con `ceserver`

`ceserver` espone l'enumerazione dei processi, l'accesso alla memoria e il debugging alla GUI di Cheat Engine. Le build ufficiali supportano Linux e Android. Esegui sul target l'architettura corrispondente e connettiti tramite la scheda **Network**. Su Android, inoltrare la porta predefinita evita di esporla sulla rete:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
Il bridge di terze parti `frida-ceserver` può fornire un'interfaccia compatibile con Cheat Engine per target iOS. Non è il `ceserver` ufficiale e le operazioni supportate possono differire.<sup>[[2]](#references)</sup>

Presupponi che il protocollo conceda un accesso a livello di debugger. Associalo al loopback oppure posizionalo dietro un tunnel SSH/ADB. Non esporre mai la porta TCP 52736 a una rete non attendibile. Arresta il server al termine della sessione.

## Sicurezza operativa

Collegati solo a software di tua proprietà o per cui disponi dell'autorizzazione al test. Non eseguire Cheat Engine insieme a un gioco online o a un endpoint di produzione. Le scritture in memoria, il codice iniettato, i drivers e DBVM possono causare il crash o la corruzione del target.<sup>[[3]](#references)</sup>

Scarica le build dal sito ufficiale oppure compila il source pubblicato. I prodotti di sicurezza classificano spesso i memory editor, i debugger e i relativi drivers come hack tools. Non disabilitare globalmente la protezione dell'host. Utilizza una VM dedicata o un host di laboratorio e verifica l'artifact prima di eseguirlo.<sup>[[3]](#references)</sup>



## References

- [1] [Note di rilascio di Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [Bridge frida-ceserver per target remoti](https://github.com/gmh5225/frida-ceserver)
- [3] [News ufficiali sulle release di Cheat Engine](https://www.cheatengine.org/)
- [4] [Wiki di Cheat Engine: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
