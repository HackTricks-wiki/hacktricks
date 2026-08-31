# Sfruttamento di una Race Condition del Kernel tramite Slow Paths dell'Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Perché ampliare la race window è importante

Molti LPE del kernel Windows seguono il pattern classico `check_state(); NtOpenX("name"); privileged_action();`. Sull'hardware moderno, un `NtOpenEvent`/`NtOpenSection` cold risolve un nome breve in ~2 µs, lasciando pochissimo tempo per modificare lo stato verificato prima che venga eseguita l'azione privilegiata. Forzando deliberatamente la ricerca nell'Object Manager Namespace (OMNS) del passaggio 2 a durare decine di microsecondi, l'attaccante ottiene tempo sufficiente per vincere in modo consistente race altrimenti inaffidabili senza dover effettuare migliaia di tentativi.<sup>[[1]](#references)</sup>

## Internals della ricerca dell'Object Manager in breve

* **Struttura OMNS** – I nomi come `\BaseNamedObjects\Foo` vengono risolti directory per directory. Ogni componente richiede al kernel di trovare/aprire una *Object Directory* e confrontare stringhe Unicode. I symbolic link (ad esempio, le lettere delle unità) possono essere attraversati durante il percorso.
* **Limite di `UNICODE_STRING`** – I percorsi OM sono contenuti in una `UNICODE_STRING` il cui `Length` è un valore a 16 bit. Il limite assoluto è di 65 535 byte (32 767 codepoint UTF-16). Con prefissi come `\BaseNamedObjects\`, un attaccante controlla comunque ≈32 000 caratteri.
* **Prerequisiti dell'attaccante** – Qualsiasi utente può creare oggetti all'interno di directory scrivibili come `\BaseNamedObjects`. Quando il codice vulnerabile utilizza un nome al loro interno o segue un symbolic link che conduce lì, l'attaccante controlla le performance della ricerca senza privilegi speciali.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Singolo componente massimo

Il costo della risoluzione di un componente è approssimativamente lineare rispetto alla sua lunghezza, perché il kernel deve eseguire un confronto Unicode con ogni voce nella directory padre. La creazione di un evento con un nome lungo 32 kB aumenta immediatamente la latenza di `NtOpenEvent` da ~2 µs a ~35 µs su Windows 11 24H2 (testbed Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Note pratiche*

- Puoi raggiungere il limite di lunghezza usando qualsiasi named kernel object (eventi, sezioni, semafori…).
- I symbolic link o i reparse point possono puntare da un breve nome “victim” a questo componente gigantesco, in modo che lo slowdown venga applicato in modo trasparente.
- Poiché tutto risiede in namespace scrivibili dall'utente, il payload funziona da un livello standard di integrità utente.<sup>[[1]](#references)</sup>

## Primitiva di slowdown n. 2 – Directory ricorsive profonde

Una variante più aggressiva alloca una catena di migliaia di directory (`\BaseNamedObjects\A\A\...\X`). Ogni passaggio attiva la logica di risoluzione delle directory (controlli ACL, ricerche hash, conteggio dei riferimenti), quindi la latenza per livello è maggiore rispetto a un singolo confronto di stringhe. Con circa 16 000 livelli (limitati dalla stessa dimensione di `UNICODE_STRING`), le misurazioni empiriche superano la soglia di 35 µs raggiunta dai singoli componenti di grandi dimensioni.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Suggerimenti:

* Alterna il carattere per livello (`A/B/C/...`) se la directory padre inizia a rifiutare i duplicati.
* Mantieni un array di handle per poter eliminare la catena in modo pulito dopo l'exploitation ed evitare di contaminare il namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Directory shadow, collisioni hash e symlink reparses (minuti invece di microsecondi)

Le directory dell'Object Manager supportano le **shadow directories** (lookup di fallback) e tabelle hash suddivise in bucket per le entry. Sfrutta entrambe, insieme al limite di 64 componenti per il reparse dei symbolic link, per moltiplicare il rallentamento senza superare la lunghezza di `UNICODE_STRING`:

1. Crea due directory sotto `\BaseNamedObjects`, ad esempio `A` (shadow) e `A\A` (target). Crea la seconda usando la prima come shadow directory (`NtCreateDirectoryObjectEx`), in modo che i lookup mancanti in `A` ricadano su `A\A`.
2. Riempi ogni directory con migliaia di **nomi collidenti** che finiscono nello stesso bucket hash (ad esempio, variando le cifre finali mantenendo invariato il valore di `RtlHashUnicodeString`). I lookup degenerano quindi in scansioni lineari O(n) all'interno di una singola directory.
3. Costruisci una catena di circa 63 **symbolic link dell'Object Manager** che effettuino ripetutamente il reparse nel lungo suffisso `A\A\…`, consumando il budget di reparse. Ogni reparse riavvia il parsing dall'inizio, moltiplicando il costo delle collisioni.
4. Il lookup del componente finale (`...\\0`) richiede ora **minuti** su Windows 11 quando sono presenti 16.000 collisioni per directory, offrendo una vittoria praticamente garantita nella race per kernel LPE one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Perché è importante*: Un rallentamento della durata di diversi minuti trasforma gli LPE basati su race condition da exploit one-shot in exploit deterministici.<sup>[[1]](#references)</sup>

### Note sul retest del 2025 e tooling pronto all'uso

- James Forshaw ha ripubblicato la tecnica con timing aggiornati su Windows 11 24H2 (ARM64). Le aperture baseline restano di ~2 µs; un componente da 32 kB porta questo valore a ~35 µs, mentre shadow-dir + collision + catene di 63 reparse raggiungono ancora ~3 minuti, confermando che le primitive sopravvivono alle build attuali. Il codice sorgente e il perf harness si trovano nel post aggiornato di Project Zero.<sup>[[1]](#references)</sup>
- Puoi scriptare la configurazione usando il bundle pubblico `symboliclink-testing-tools`: `CreateObjectDirectory.exe` per creare la coppia shadow/target e `NativeSymlink.exe` in un loop per generare la catena a 63 hop. Questo evita di scrivere manualmente wrapper `NtCreate*` e mantiene coerenti gli ACL.<sup>[[2]](#references)</sup>

## Misurare la race window

Integra un harness rapido nel tuo exploit per misurare quanto diventa ampia la window sull'hardware della vittima. Lo snippet seguente apre l'oggetto target `iterations` volte e restituisce il costo medio per apertura usando `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
I risultati confluiscono direttamente nella tua strategia di orchestrazione della race (ad esempio, il numero di thread worker necessari, gli intervalli di sleep e quanto presto devi modificare lo stato condiviso).

## Workflow di exploitation

1. **Individua l'apertura vulnerabile** – Traccia il percorso del kernel (tramite simboli, ETW, hypervisor tracing o reversing) finché non trovi una chiamata `NtOpen*`/`ObOpenObjectByName` che attraversa un nome controllato dall'attacker o un symbolic link in una directory scrivibile dall'utente.
2. **Sostituisci quel nome con un percorso lento**
- Crea il componente lungo o la catena di directory sotto `\BaseNamedObjects` (o un'altra radice OM scrivibile).
- Crea un symbolic link in modo che il nome previsto dal kernel ora venga risolto nel percorso lento. Puoi indirizzare la directory lookup del driver vulnerabile verso la tua struttura senza toccare il target originale.
3. **Attiva la race**
- Il thread A (victim) esegue il codice vulnerabile e si blocca durante la slow lookup.
- Il thread B (attacker) modifica lo stato protetto (ad esempio, sostituisce un file handle, riscrive un symbolic link o modifica la sicurezza dell'object) mentre il thread A è occupato.
- Quando il thread A riprende ed esegue l'azione privilegiata, osserva uno stato obsoleto ed esegue l'operazione controllata dall'attacker.
4. **Esegui il cleanup** – Elimina la catena di directory e i symbolic link per evitare di lasciare artefatti sospetti o di interrompere utenti legittimi dell'IPC.<sup>[[1]](#references)</sup>

## Catena applicata: placeholder mutabili di Cloud Files + switching del percorso dell'Object Manager

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), pubblicato come bypass per RoguePlanet (CVE-2026-50656), dimostra un pattern di exploitation più ampio: fare in modo che uno scanner privilegiato classifichi una rappresentazione di un file logico, quindi modificare sia i suoi byte sia la risoluzione del namespace prima che la remediation la utilizzi. Il PoC combina una TOCTOU di hydration di Cloud Files, un fallback a una shadow directory dell'Object Manager, la cattura di nomi generati da CLFS e un link a una administrative share locale per trasformare il cleanup di Defender in una scrittura di una DLL protetta.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Sostituisci il contenuto tramite la hydration di Cloud Files

Registra una directory scrivibile dall'attacker come sync root di Cloud Files, collega una callback `CF_CALLBACK_TYPE_FETCH_DATA` e crea un placeholder la cui dimensione dichiarata corrisponda a un detection trigger deterministico come lo ZIP EICAR. Il primo fetch restituisce il trigger e modifica lo stato della callback; i fetch successivi restituiscono il payload. Dopo che lo scanner ha classificato la prima rappresentazione, ottieni la transfer key e riavvia la hydration con metadata delle dimensioni del payload, quindi forza la hydration fino a EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
Il confine di sicurezza viene meno se scan, verdict e remediation fanno riferimento solo a un pathname o a un'identità segnaposto: nessuno dei due garantisce che una successiva hydration restituisca i byte che sono stati ispezionati.<sup>[[4]](#references)</sup>

### 2. Cambiare un percorso invariabile tramite un fallback shadow-directory

Create una directory Object Manager di destinazione e una seconda directory con `NtCreateDirectoryObjectEx`, passando l'handle della destinazione come shadow/fallback directory. Inserite una voce `WD_SCAN` con lo stesso nome in entrambi i livelli di risoluzione: la voce visibile punta alla directory di lavoro normale, mentre la voce di fallback punta a `\CLFS\??\<working-directory>`. Fornite a Defender solo il percorso invariabile riportato di seguito; eliminando il link visibile mentre l'operazione è attiva, la stessa stringa ricade nella voce basata su CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Questo è distinto dall’utilizzo di shadow directories solo per rallentare la ricerca: l’attaccante modifica il **significato** di un percorso precedentemente accettato senza modificarne la stringa.<sup>[[4]](#references)</sup>

### 3. Acquisire il nome generato e installare un link specifico per il filename

Monitora la working directory con `ReadDirectoryChangesW`. Alla prima `FILE_ACTION_ADDED`, rimuovi il link visibile `WD_SCAN` per attivare la ricerca di fallback. Acquisisci il secondo filename generato, apri il file correlato a CLFS e blocca l’intervallo `0..MAXLONGLONG` con `LockFileEx`. Mentre l’operazione privilegiata è sospesa, sostituisci `WD_SCAN` nella directory visibile con una directory di Object Manager reale e crea un symbolic link figlio denominato in base al filename osservato (il PoC ne rimuove gli ultimi quattro caratteri). Indirizzalo alla destinazione protetta tramite SMB locale:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Il processo senza privilegi non può scrivere direttamente quella destinazione, ma il contesto SYSTEM di Defender può attraversare la condivisione amministrativa loopback. Combinare l'osservazione dei nomi generati con un collegamento di Object Manager specifico per il nome del file evita di dover prevedere in anticipo l'artefatto di remediation.<sup>[[4]](#references)</sup>

### 4. Stabilizzare la race di cleanup e attivare un loader privilegiato

Prima della scansione, il PoC memorizza un PE valido (`ntdll.dll`) nell'alternate data stream NTFS `:stream` del placeholder. Dopo che il redirection ha creato il file base protetto, apre `phoneinfo.dll:stream` con accesso di esecuzione e mantiene attiva una mapping `PAGE_EXECUTE_READ | SEC_IMAGE` mentre il cleanup riprende; gli oggetti file/section attivi limitano l'eliminazione o la sostituzione durante la race finale. La hydration riavviata restituisce ora la payload DLL anziché EICAR, quindi il file base protetto contiene codice controllato dall'attaccante.<sup>[[4]](#references)</sup>

Una protected write viene quindi convertita in esecuzione SYSTEM posizionando un `Report.wer` creato ad hoc sotto `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` e invocando `\Microsoft\Windows\Windows Error Reporting\QueueReporting` tramite l'API COM del Task Scheduler. In questa chain, l'elaborazione WER privilegiata carica il `C:\Windows\System32\phoneinfo.dll` piantato; una connessione named-pipe viene utilizzata come segnale di esecuzione della payload.<sup>[[4]](#references)</sup>

### Pivot di rilevamento

Le correlazioni utili sono più specifiche di qualsiasi singolo nome temporaneo e coprono tutte le transizioni di namespace nella chain:<sup>[[4]](#references)</sup>

- Un provider Cloud Files registrato di recente seguito dal rilevamento di EICAR e da `CF_OPERATION_TYPE_RESTART_HYDRATION` sullo stesso placeholder.
- Percorsi di Object Manager contenenti `WD_TARGET_*`, `WD_SHADOW_*` o `WD_SCAN`, in particolare un percorso di scansione sotto `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Creazione di un file CLFS seguita da un lock esclusivo sull'intero file e dall'accesso loopback a `\\127.0.0.1\C$\Windows\System32\*.dll` da parte di un processo di sicurezza privilegiato.
- Creazione di una DLL in System32 insieme a un NTFS ADS, seguita dal mapping `SEC_IMAGE` dello stream.
- Una voce della coda WER creata dall'attaccante seguita da un'esecuzione manuale insolita di `\Microsoft\Windows\Windows Error Reporting\QueueReporting` e dal caricamento dell'immagine della DLL piantata.

## Considerazioni operative

- **Combinare le primitive** – È possibile usare un nome lungo *per livello* in una chain di directory per ottenere una latenza ancora maggiore, fino a esaurire la dimensione di `UNICODE_STRING`.
- **Bug one-shot** – La finestra ampliata (da decine di microsecondi a minuti) rende realistici i bug “single trigger” se abbinati al pinning dell'affinità CPU o alla preemption assistita dall'hypervisor.
- **Effetti collaterali** – Il rallentamento interessa solo il percorso malevolo, quindi le prestazioni complessive del sistema restano inalterate; i defender lo noteranno raramente, a meno che non monitorino la crescita del namespace.
- **Cleanup** – Mantieni gli handle per ogni directory/oggetto creato, così da poter chiamare successivamente `NtMakeTemporaryObject`/`NtClose`. In caso contrario, chain di directory non limitate potrebbero persistere tra i riavvii.
- **Race del file system** – Se il percorso vulnerabile alla fine viene risolto tramite NTFS, puoi applicare un Oplock (ad esempio `SetOpLock.exe` dello stesso toolkit) al file sottostante mentre è in esecuzione il rallentamento OM, bloccando il consumer per ulteriori millisecondi senza modificare il grafo OM.<sup>[[2]](#references)</sup>

## Note difensive

- Il codice del kernel che si basa su oggetti denominati dovrebbe convalidare nuovamente lo stato sensibile alla sicurezza *dopo* l'apertura, oppure acquisire un riferimento prima del controllo (colmando la falla TOCTOU).
- Applica limiti superiori alla profondità/lunghezza dei percorsi OM prima di dereferenziare i nomi controllati dall'utente. Rifiutare i nomi eccessivamente lunghi costringe gli attaccanti a tornare alla finestra di microsecondi.
- Strumenta la crescita del namespace di Object Manager (ETW `Microsoft-Windows-Kernel-Object`) per rilevare chain sospette composte da migliaia di componenti sotto `\BaseNamedObjects`.

## References

- [1] [Project Zero – Tecniche di exploitation di Windows: vincere le race condition con le ricerche dei percorsi](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/strumenti per il testing dei symbolic link](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
