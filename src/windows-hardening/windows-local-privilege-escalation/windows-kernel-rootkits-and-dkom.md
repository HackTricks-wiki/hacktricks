# Windows Kernel Rootkits e DKOM

{{#include ../../banners/hacktricks-training.md}}

## Ambito

Un implant post-compromise può caricare un kernel driver firmato come servizio ed esporre un control plane user-mode tramite `IRP_MJ_DEVICE_CONTROL`. La firma del driver stabilisce solo che Windows accetta l'immagine; non rende sicure l'autorizzazione degli IOCTL, le operazioni di memoria, le callback o gli hook. Un rootkit analizzato utilizzava tre handler durante il normale funzionamento, ma esponeva dozzine di primitive aggiuntive di post-exploitation, quindi il reverse engineering deve coprire il dispatcher completo anziché solo le richieste osservate in una traccia malware.<sup>[[1]](#references)</sup>

## Triage di signed-driver e IOCTL

Inizia da `DriverEntry`, registra gli oggetti device e i link simbolici DOS, individua la routine `MajorFunction[IRP_MJ_DEVICE_CONTROL]` e mappa ogni confronto/voce della tabella che raggiunge un handler. Confronta i nomi aperti dal user mode con quelli effettivamente creati dal driver: una catena osservata apriva `\\.\msagent`, mentre il suo driver creava `\Device\ToolTool` e `\DosDevices\ToolTool`. Questa discrepanza può identificare un altro sample/configuration, una logica di setup mancante o un'incoerenza nell'analisi.<sup>[[1]](#references)</sup>

Decodifica ogni control code prima di ricostruire la sua struttura di input.<sup>[[1]](#references)</sup>
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
Questi tre codici vengono decodificati come `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` e `METHOD_BUFFERED`. Questo **non** dimostra che un caller non privilegiato possa raggiungerli: esamina anche la DACL del device, la gestione di create/open, i controlli del caller per ogni richiesta, le lunghezze dei buffer previste, i puntatori incorporati, la gestione del ciclo di vita dei PID e se l'handler si fida di un PID o flag fornito dal caller.<sup>[[1]](#references)</sup>

Quando l'implant usa solo un sottoinsieme dei comandi, raggruppa gli handler rimanenti per primitive invece di liquidarli come dead code. Un singolo driver multifunzione ha esposto tutte le seguenti classi:<sup>[[1]](#references)</sup>

- **Control/configuration:** attivare o disattivare lo stato del rootkit; aggiungere, rimuovere, interrogare o cancellare path, processi e indirizzi C2 protetti.
- **Process manipulation:** terminare un PID, eseguire l'unmap della sua image, effettuare injection con `NtCreateThreadEx`, nascondere/ripristinare processi o moduli user, e rimuovere la protezione PPL.
- **Kernel manipulation:** scollegare un driver caricato, enumerare/disabilitare/ripristinare notification callbacks, eseguire il manual mapping di un altro driver e scrivere a un indirizzo kernel arbitrario.
- **Object manipulation:** eliminare/decrittografare file e creare o modificare valori del registry.

## Trusted-process exemptions

Un pattern di progettazione utile è un IOCTL che registra un PID insieme a un flag **trusted**. La stessa ricerca della fiducia viene quindi consultata dai filtri di file, registry, processi e thread: gli strumenti non trusted ricevono risultati di enumerazione filtrati, diritti ridotti sugli handle o `STATUS_ACCESS_DENIED`, mentre l'implant può continuare ad aggiornare i propri oggetti nascosti. Tratta questo come un confine di autorizzazione e verifica come le entry vengono autenticate, sincronizzate e rimosse dopo l'uscita del processo o il riutilizzo del PID.<sup>[[1]](#references)</sup>

I rootkit possono memorizzare la policy in valori `REG_MULTI_SZ` e compilare gli elenchi di file, directory, registry key, registry value, ignored image, protected image e hidden image in alberi AVL. Durante l'analisi, traccia ogni reader e writer di questi alberi condivisi; questo collega la configurazione del registry, gli IOCTL, le callback e la logica di filtering anche quando i nomi delle funzioni sono stati rimossi.<sup>[[1]](#references)</sup>

## DKOM process and module hiding

### `EPROCESS.ActiveProcessLinks`

Gli offset di `ActiveProcessLinks` variano in base alla build di Windows. Un rootkit version-tolerant può testare candidati noti e quindi scansionare `EPROCESS` alla ricerca di una `LIST_ENTRY` autocoerente i cui neighbor puntino nuovamente al candidato. Conserva l'offset individuato, nasconde un processo ricollegando i `Flink`/`Blink` dei suoi neighbor e preserva lo stato per ricollegare successivamente l'entry. Il processo continua a essere eseguito, ma scompare dagli enumerator che percorrono la active-process list.<sup>[[1]](#references)</sup>

Questo è **DKOM**, non una terminazione. Il rilevamento dovrebbe confrontare i risultati basati sulle list con prove indipendenti, come scansioni di pool/object, ownership dei thread, handle table, artefatti dello scheduler e ispezione della memoria kernel. Un processo visibile a una scansione ma assente dalla lista canonica è più significativo di una delle due viste considerata singolarmente.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

La primitive equivalente per nascondere un modulo individua la entry target in `PsLoadedModuleList` e modifica i puntatori `Flink`/`Blink` adiacenti. Il driver rimane mappato ed eseguibile, ma le query dei moduli basate sulle list lo omettono. Confronta la loader list con i mapping kernel eseguibili, i pool tag, gli oggetti device/driver, le service key, gli indirizzi delle callback e i dispatch pointer che puntano al di fuori di un'image elencata.<sup>[[1]](#references)</sup>

## Callback-based protection and cloaking

Un rootkit può combinare callback framework documentati con DKOM e hook:<sup>[[1]](#references)</sup>

- Gli handler pre-operation di `ObRegisterCallbacks` per `PsProcessType` e `PsThreadType` rimuovono i diritti usati per la terminazione, l'accesso alla VM, la duplicazione o la manipolazione dei thread quando un caller non trusted apre un target protetto. Registra l'altitude della callback e risolvi ogni indirizzo di callback nel modulo proprietario.
- `PsSetCreateProcessNotifyRoutineEx` e `PsSetLoadImageNotifyRoutine` mantengono lo stato dei processi protetti/ignorati/nascosti quando processi e image vengono visualizzati; una process walk eseguita una sola volta può completare gli oggetti esistenti prima della registrazione.
- Un filesystem minifilter nega l'accesso ai path configurati. Un'implementazione insolita può creare la propria key `Instances`, scegliere dinamicamente un'altitude e incrementarla/riprovare quando `FltRegisterFilter` segnala una collisione.
- Una routine `CmRegisterCallbackEx` può sopprimere i nomi protetti dall'enumeration e negare operazioni dirette di open, rename, set o delete, esentando i processi trusted registrati.

Correla le registrazioni di `ObRegisterCallbacks`, le altitude delle registry callback, l'output di `fltmc filters`, le key `Instances` dei service e gli indirizzi delle callback. Se gli strumenti normali vengono filtrati, ispeziona queste strutture da un'immagine della memoria offline o da un altro trusted acquisition layer.<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Il network concealment può prendere di mira `\Driver\Nsiproxy`: ottenere il driver object con `ObReferenceObjectByName`, salvare un handler pointer, sostituirlo con un wrapper e rimuovere i record IPv4 restituiti che corrispondono a una lista C2 gestita tramite IOCTL prima che vengano ricevuti dall'user mode. Le applicazioni basate sui dati NSI filtrati potrebbero non visualizzare più la connessione, anche se il traffico esiste ancora.<sup>[[1]](#references)</sup>

Confronta le viste delle connessioni dell'host con la packet capture, la telemetria WFP/ETW e gli oggetti di rete nella memoria kernel. Ispeziona anche i dispatch/handler pointer di `Nsiproxy` e verifica che ciascuno si risolva all'interno del modulo signed previsto; un puntatore verso un mapping non elencato può collegare il network filtering al DKOM di `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Investigation checklist

Il segnale più forte è il disaccordo tra i layer, non un singolo filename o hash. Correla:<sup>[[1]](#references)</sup>

1. La creazione di kernel service e un driver signed il cui certificato, publisher o path non è coerente con il prodotto installato.
2. La creazione di device, i link DOS e il traffico IOCTL, inclusi i nomi dei device user mode e kernel non corrispondenti.
3. Una richiesta di registrazione di un PID seguita da errori, da parte di altri processi, nell'aprire, enumerare, modificare o eliminare gli stessi oggetti.
4. Callback di object/registry/process/image, istanze di minifilter e hook i cui indirizzi non appartengono a un driver normalmente enumerato.
5. Differenze tra gli inventari di processi, moduli, callback e network basati su list e quelli basati su scan.

## References

- [1] [Kaspersky Securelist - HoneyMyte potenzia CoolClient con un rootkit del kernel Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
