# Rootkit del kernel di Windows e DKOM

{{#include ../../banners/hacktricks-training.md}}

## Ambito

Un impianto post-compromissione può caricare un driver kernel firmato come servizio ed esporre un piano di controllo in modalità utente tramite `IRP_MJ_DEVICE_CONTROL`. La firma del driver stabilisce soltanto che Windows accetta l’immagine; non rende sicuri l’autorizzazione IOCTL, le operazioni sulla memoria, le callback o gli hook. Un rootkit analizzato usava tre handler durante il normale funzionamento, ma esponeva decine di primitive aggiuntive per la post-exploitation: perciò il reverse engineering deve coprire l’intero dispatcher, non solo le richieste osservate in una traccia del malware.<sup>[[1]](#references)</sup>

## Triage di driver firmati e IOCTL

Inizia da `DriverEntry`, registra gli oggetti dispositivo e i collegamenti simbolici DOS, individua la routine `MajorFunction[IRP_MJ_DEVICE_CONTROL]` e mappa ogni confronto o voce di tabella che porta a un handler. Confronta i nomi aperti dal codice in modalità utente con quelli effettivamente creati dal driver: in una catena osservata veniva aperto `\\.\msagent`, mentre il driver creava `\Device\ToolTool` e `\DosDevices\ToolTool`. Questa discrepanza può indicare un altro sample/configurazione, una logica di setup mancante o un’incoerenza nell’analisi.<sup>[[1]](#references)</sup>

Decodifica ogni codice di controllo prima di ricostruirne la struttura di input.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Questi tre codici si decodificano come `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` e `METHOD_BUFFERED`. Questo **non** dimostra che un chiamante non privilegiato possa raggiungerli: esamina anche la DACL del dispositivo, la routine di dispatch per create/open, i controlli del chiamante per ogni richiesta, le lunghezze dei buffer previste, i puntatori incorporati, la gestione del ciclo di vita dei PID e se l'handler si fida di un PID o flag fornito dal chiamante.<sup>[[1]](#references)</sup>

Quando l'implant usa solo un sottoinsieme dei comandi, raggruppa gli handler rimanenti per primitive invece di considerarli codice morto. Un singolo driver multifunzione ha esposto tutte le seguenti categorie:<sup>[[1]](#references)</sup>

- **Controllo/configurazione:** attivare o disattivare lo stato del rootkit; aggiungere, rimuovere, interrogare o cancellare percorsi, processi e indirizzi C2 protetti.
- **Manipolazione dei processi:** terminare un PID, smappare la sua immagine, iniettare con `NtCreateThreadEx`, nascondere/ripristinare processi o moduli utente e rimuovere la protezione PPL.
- **Manipolazione del kernel:** scollegare un driver caricato, enumerare/disabilitare/ripristinare callback di notifica, mappare manualmente un altro driver e scrivere a un indirizzo kernel arbitrario.
- **Manipolazione degli oggetti:** eliminare/decifrare file e creare o modificare valori del registro.

## Mapping manuale nel kernel tramite un driver firmato vulnerabile

Un driver firmato con operazioni di lettura/scrittura della memoria kernel può fungere da loader per un'immagine driver non firmata, senza chiedere a Windows di caricare quell'immagine come un driver normale.<sup>[[2]](#references)[[7]](#references)</sup> L'esempio LocalStranger apre un dispositivo `\\.\WinNotify` esistente; il suo codice sorgente non mostra che un utente non privilegiato possa installare, avviare o aprire il driver su un host qualsiasi.<sup>[[2]](#references)[[3]](#references)</sup> Il mapper riceve il percorso di un'immagine, interroga la base del kernel caricato e usa gli IOCTL di lettura/scrittura della memoria virtuale del dispositivo.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Per trasformare l'accesso in lettura/scrittura in una chiamata kernel, il mapper legge un valore immediato della PTE base da `MmGetVirtualForPhysical` e percorre le voci di paging che coprono `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> Il calcolo della PTE è `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; il codice controlla anche la presenza di una PDE per una large page.<sup>[[5]](#references)[[7]](#references)</sup> Rende temporaneamente scrivibile la voce che copre l'indirizzo, sostituisce l'entry della syscall con un salto alla funzione kernel desiderata, richiama lo stub `NtAddAtom` in user mode e poi ripristina sia i byte originali sia la voce della pagina.<sup>[[6]](#references)</sup>

Il mapper usa questo percorso di chiamata per `ExAllocatePool`, mappa nell'immagine le sezioni PE, gli import e le rilocazioni, scrive il contenuto nell'allocazione e chiama il suo entry point.<sup>[[7]](#references)[[8]](#references)</sup> Questa implementazione accetta solo immagini PE x64 rilocabili; inoltre, la lettura della PTE base presuppone un layout fisso `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Considerala dipendente dalla build, non un bypass KASLR indipendente né una prova che HVCI o PatchGuard consentano il mapping.<sup>[[5]](#references)[[8]](#references)</sup> Per un uso di kernel R/W basato solo sui dati, vedi il [furto del token SYSTEM](arbitrary-kernel-rw-token-theft.md).

## Esenzioni per processi attendibili

Un modello utile consiste in un IOCTL che registra un PID insieme a un flag **trusted**. La stessa verifica di attendibilità viene poi usata dai filtri per file, registro, processi e thread: gli strumenti non attendibili ricevono risultati di enumerazione filtrati, diritti di handle ridotti o `STATUS_ACCESS_DENIED`, mentre l'implant può continuare ad aggiornare i propri oggetti nascosti. Consideralo un confine di autorizzazione e verifica come vengono autenticati e sincronizzati gli elementi e come vengono rimossi dopo l'uscita del processo o il riutilizzo del PID.<sup>[[1]](#references)</sup>

I rootkit possono memorizzare i criteri in valori `REG_MULTI_SZ` e compilare in alberi AVL gli elenchi di file, directory, chiavi del registro, valori del registro, immagini ignorate, immagini protette e immagini nascoste. Durante l'analisi, traccia ogni lettore e scrittore di questi alberi condivisi: collega la configurazione del registro, gli IOCTL, le callback e la logica di filtraggio anche quando i nomi delle funzioni sono stati rimossi.<sup>[[1]](#references)</sup>

## Nascondere processi e moduli tramite DKOM

### `EPROCESS.ActiveProcessLinks`

Gli offset di `ActiveProcessLinks` variano a seconda della build di Windows. Un rootkit compatibile con più versioni può provare gli offset noti e poi scansionare `EPROCESS` alla ricerca di una `LIST_ENTRY` coerente, i cui vicini puntino di nuovo all'elemento candidato. Memorizza l'offset trovato, nasconde un processo ricollegando i campi `Flink`/`Blink` dei suoi vicini e conserva lo stato per ricollegare in seguito l'elemento. Il processo continua a funzionare, ma scompare dagli enumeratori che percorrono l'elenco dei processi attivi.<sup>[[1]](#references)</sup>

Questo è **DKOM**, non una terminazione. Il rilevamento dovrebbe confrontare i risultati basati sugli elenchi con prove indipendenti, come scansioni di pool/oggetti, proprietà dei thread, tabelle degli handle, artefatti dello scheduler e ispezione della memoria kernel. Un processo visibile in una scansione ma assente dall'elenco canonico è più significativo di una sola delle due viste.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

La primitiva equivalente per nascondere un modulo individua l'elemento di destinazione in `PsLoadedModuleList` e modifica i puntatori `Flink`/`Blink` adiacenti. Il driver rimane mappato ed eseguibile, ma le query sui moduli basate sugli elenchi non lo mostrano. Confronta l'elenco del loader con le mappature kernel eseguibili, i tag del pool, gli oggetti dispositivo/driver, le chiavi dei servizi, gli indirizzi delle callback e i puntatori di dispatch che puntano al di fuori di un'immagine elencata.<sup>[[1]](#references)</sup>

## Protezione e occultamento basati su callback

Un rootkit può combinare framework di callback documentati con DKOM e hook:<sup>[[1]](#references)</sup>

- Gli handler di pre-operazione `ObRegisterCallbacks` per `PsProcessType` e `PsThreadType` rimuovono i diritti usati per terminare, accedere alla memoria virtuale, duplicare o manipolare thread quando un chiamante non attendibile apre una risorsa protetta. Registra l'altitudine della callback e risolvi ogni indirizzo di callback fino al modulo proprietario.
- `PsSetCreateProcessNotifyRoutineEx` e `PsSetLoadImageNotifyRoutine` mantengono lo stato dei processi protetti/ignorati/nascosti man mano che vengono creati processi e caricate immagini; una scansione iniziale dei processi può recuperare gli oggetti esistenti prima della registrazione.
- Un minifilter del filesystem nega l'accesso ai percorsi configurati. Un'implementazione insolita può creare la chiave `Instances`, scegliere dinamicamente un'altitudine e incrementarla/riprovare quando `FltRegisterFilter` segnala una collisione.
- Una routine `CmRegisterCallbackEx` può sopprimere i nomi protetti durante l'enumerazione e negare le operazioni dirette di apertura, rinomina, impostazione o eliminazione, esentando i processi attendibili registrati.

Metti in correlazione le registrazioni di `ObRegisterCallbacks`, le altitudini delle callback del registro, l'output di `fltmc filters`, le chiavi `Instances` dei servizi e gli indirizzi delle callback. Se gli strumenti normali vengono filtrati, esamina queste strutture da un'immagine di memoria offline o usando un altro livello di acquisizione attendibile.<sup>[[1]](#references)</sup>

## Filtraggio dei risultati di Nsiproxy

L'occultamento della rete può prendere di mira `\Driver\Nsiproxy`: ottenere l'oggetto driver con `ObReferenceObjectByName`, salvare un puntatore a un handler, sostituirlo con un wrapper e rimuovere i record IPv4 restituiti che corrispondono a un elenco C2 gestito tramite IOCTL, prima che raggiungano user mode. Le applicazioni che usano i dati NSI filtrati potrebbero non mostrare più la connessione, anche se il traffico è ancora presente.<sup>[[1]](#references)</sup>

Confronta le viste delle connessioni dell'host con le acquisizioni di pacchetti, la telemetria WFP/ETW e gli oggetti di rete in memoria kernel. Esamina anche i puntatori di dispatch/handler di `Nsiproxy` e verifica che ciascuno punti all'interno del modulo firmato previsto; un puntatore a una mappatura non elencata può collegare il filtraggio della rete al DKOM di `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Checklist di indagine

Il segnale più forte è la discordanza tra i livelli, non un singolo nome di file o hash. Metti in correlazione:<sup>[[1]](#references)</sup>

1. La creazione di un servizio kernel e un driver firmato il cui certificato, publisher o percorso non sono coerenti con il prodotto installato.
2. La creazione dei dispositivi, i collegamenti DOS e il traffico IOCTL, compresi i nomi dei dispositivi in user mode e kernel mode che non corrispondono.
3. Una richiesta di registrazione di un PID, seguita dall'impossibilità per altri processi di aprire, enumerare, modificare o eliminare gli stessi oggetti.
4. Callback di oggetti/registro/processi/immagini, istanze di minifilter e hook i cui indirizzi non appartengono a un driver normalmente enumerato.
5. Le differenze tra gli inventari di processi, moduli, callback e rete basati su elenchi e quelli basati su scansioni.

## References

- [1] [Kaspersky Securelist - HoneyMyte migliora CoolClient con un rootkit firmato per il kernel di Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [README di LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Inizializzazione del driver LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Riga di comando del mapper LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Risoluzione degli export kernel e della PTE base in LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Trampoline per chiamate kernel di LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Allocazione del mapper e chiamata dell'entry point in LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [Mapping PE di LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Contesto kernel e syscall di LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Wrapper IOCTL per la memoria virtuale di LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
