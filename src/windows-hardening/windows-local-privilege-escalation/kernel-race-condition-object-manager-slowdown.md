# Sfruttamento di una Race Condition del Kernel tramite gli Slow Path dell'Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Perché ampliare la race window è importante

Molti LPE del kernel Windows seguono lo schema classico `check_state(); NtOpenX("name"); privileged_action();`. Sull'hardware moderno, un `NtOpenEvent`/`NtOpenSection` cold risolve un nome breve in ~2 µs, lasciando pochissimo tempo per modificare lo stato verificato prima che venga eseguita l'azione privilegiata. Forzando deliberatamente la ricerca nel namespace dell'Object Manager (OMNS) del passaggio 2 a durare decine di microsecondi, l'attaccante ottiene tempo sufficiente per vincere in modo consistente race altrimenti inaffidabili senza dover effettuare migliaia di tentativi.<sup>[[1]](#references)</sup>

## Internals della ricerca dell'Object Manager in breve

* **Struttura dell'OMNS** – I nomi come `\BaseNamedObjects\Foo` vengono risolti directory per directory. Ogni componente richiede al kernel di trovare/aprire una *Object Directory* e confrontare stringhe Unicode. I symbolic link (ad esempio, le lettere delle unità) possono essere attraversati durante il percorso.
* **Limite di `UNICODE_STRING`** – I percorsi OM sono contenuti in una `UNICODE_STRING`, il cui `Length` è un valore a 16 bit. Il limite assoluto è di 65 535 byte (32 767 codepoint UTF-16). Con prefissi come `\BaseNamedObjects\`, un attaccante controlla comunque circa 32 000 caratteri.
* **Prerequisiti dell'attaccante** – Qualsiasi utente può creare oggetti all'interno di directory scrivibili come `\BaseNamedObjects`. Quando il codice vulnerabile utilizza un nome al loro interno o segue un symbolic link che conduce lì, l'attaccante controlla le prestazioni della ricerca senza privilegi speciali.<sup>[[1]](#references)</sup>

## Primitive di rallentamento n. 1 – Singolo componente massimo

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

- È possibile raggiungere il limite di lunghezza usando qualsiasi named kernel object (eventi, sezioni, semafori…).
- I symbolic link o i reparse point possono puntare da un breve nome “victim” a questo componente enorme, in modo che il rallentamento venga applicato in modo trasparente.
- Poiché tutto risiede in namespace scrivibili dall'utente, il payload funziona da un livello di integrità utente standard.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Directory ricorsive profonde

Una variante più aggressiva alloca una catena di migliaia di directory (`\BaseNamedObjects\A\A\...\X`). Ogni passaggio attiva la logica di risoluzione delle directory (controlli ACL, ricerche hash, conteggio dei riferimenti), quindi la latenza per livello è superiore a quella di un singolo confronto di stringhe. Con circa 16.000 livelli (limitati dalla stessa dimensione di `UNICODE_STRING`), i tempi misurati superano la soglia di 35 µs raggiunta dai componenti singoli molto lunghi.
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
* Mantieni un array di handle per poter eliminare la catena in modo pulito dopo l'exploitation ed evitare di inquinare il namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuti invece di microsecondi)

Le directory dell'Object Manager supportano le **shadow directories** (lookup di fallback) e tabelle hash suddivise in bucket per le entry. Abusa di entrambe, oltre al limite di 64 componenti per il reparse delle symbolic link, per moltiplicare il rallentamento senza superare la lunghezza di `UNICODE_STRING`:

1. Crea due directory sotto `\BaseNamedObjects`, ad esempio `A` (shadow) e `A\A` (target). Crea la seconda usando la prima come shadow directory (`NtCreateDirectoryObjectEx`), in modo che i lookup mancanti in `A` passino a `A\A`.
2. Riempi ogni directory con migliaia di **nomi colliding** che finiscono nello stesso hash bucket (ad esempio, variando le cifre finali mantenendo invariato il valore di `RtlHashUnicodeString`). I lookup degenerano quindi in scansioni lineari O(n) all'interno di una singola directory.
3. Costruisci una catena di circa 63 **symbolic link dell'Object Manager** che eseguono ripetutamente il reparse nel lungo suffisso `A\A\…`, consumando il budget di reparse. Ogni reparse riavvia il parsing dall'inizio, moltiplicando il costo delle collisioni.
4. Il lookup del componente finale (`...\\0`) richiede ora **minuti** su Windows 11 quando sono presenti 16.000 collisioni per directory, offrendo una race win praticamente garantita per kernel LPE one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Perché è importante*: Un rallentamento della durata di alcuni minuti trasforma le LPE basate su race eseguibili una sola volta in exploit deterministici.<sup>[[1]](#references)</sup>

### Note del retest del 2025 e tooling pronto all'uso

- James Forshaw ha ripubblicato la tecnica con timing aggiornati su Windows 11 24H2 (ARM64). Le aperture baseline restano di circa 2 µs; un componente da 32 kB le porta a circa 35 µs, mentre shadow-dir + collision + catene di 63 reparse raggiungono ancora circa 3 minuti, confermando che le primitive sopravvivono nelle build attuali. Il codice sorgente e il perf harness si trovano nel post aggiornato di Project Zero.<sup>[[1]](#references)</sup>
- Puoi automatizzare la configurazione usando il bundle pubblico `symboliclink-testing-tools`: `CreateObjectDirectory.exe` per creare la coppia shadow/target e `NativeSymlink.exe` in un loop per generare la catena di 63 hop. Questo evita di scrivere wrapper `NtCreate*` manualmente e mantiene coerenti le ACL.<sup>[[2]](#references)</sup>

## Misurare la tua finestra della race

Integra un harness rapido nel tuo exploit per misurare quanto diventa grande la finestra sull'hardware della vittima. Lo snippet seguente apre l'oggetto target `iterations` volte e restituisce il costo medio per apertura usando `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
I risultati confluiscono direttamente nella strategia di orchestrazione della race (ad es., numero di thread worker necessari, intervalli di sleep e quanto presto è necessario modificare lo stato condiviso).

## Workflow di exploitation

1. **Individuare l'open vulnerabile** – Tracciare il percorso del kernel (tramite simboli, ETW, hypervisor tracing o reversing) fino a trovare una chiamata `NtOpen*`/`ObOpenObjectByName` che percorre un nome controllato dall'attaccante o un symbolic link in una directory scrivibile dall'utente.
2. **Sostituire quel nome con un percorso lento**
- Creare il long component o la catena di directory sotto `\BaseNamedObjects` (o un'altra radice OM scrivibile).
- Creare un symbolic link in modo che il nome previsto dal kernel punti ora al percorso lento. È possibile indirizzare la directory lookup del driver vulnerabile verso la propria struttura senza modificare il target originale.
3. **Attivare la race**
- Il thread A (vittima) esegue il codice vulnerabile e si blocca durante la slow lookup.
- Il thread B (attaccante) modifica lo stato protetto (ad es., sostituisce un file handle, riscrive un symbolic link o modifica la object security) mentre il thread A è occupato.
- Quando il thread A riprende l'esecuzione ed esegue l'azione privilegiata, osserva uno stato obsoleto ed esegue l'operazione controllata dall'attaccante.
4. **Eseguire la pulizia** – Eliminare la catena di directory e i symbolic link per evitare di lasciare artefatti sospetti o interrompere utenti IPC legittimi.<sup>[[1]](#references)</sup>

## Catena applicata: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), pubblicato come bypass per RoguePlanet (CVE-2026-50656), dimostra un pattern di exploitation più ampio: fare in modo che uno scanner privilegiato classifichi una rappresentazione di un file logico, quindi modificare sia i suoi byte sia la namespace resolution prima che la remediation lo utilizzi. Il PoC combina una Cloud Files hydration TOCTOU, un Object Manager shadow-directory fallback, la cattura di nomi generati da CLFS e un local administrative-share link per trasformare la pulizia di Defender in una protected DLL write.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Sostituire il contenuto tramite Cloud Files hydration

Registrare una directory scrivibile dall'attaccante come Cloud Files sync root, collegare una callback `CF_CALLBACK_TYPE_FETCH_DATA` e creare un placeholder la cui dimensione dichiarata corrisponda a un detection trigger deterministico come lo ZIP di EICAR. Il primo fetch restituisce il trigger e modifica lo stato della callback; i fetch successivi restituiscono il payload. Dopo che lo scanner ha classificato la prima rappresentazione, ottenere la transfer key e riavviare la hydration con metadata delle dimensioni del payload, quindi forzare la hydration fino a EOF.<sup>[[4]](#references)</sup>
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
Il confine di sicurezza fallisce se scan, verdict e remediation fanno riferimento solo a un pathname o a un'identità placeholder: nessuno dei due garantisce che una successiva hydration restituisca i byte che sono stati ispezionati.<sup>[[4]](#references)</sup>

### 2. Cambiare un invariant path tramite uno shadow-directory fallback

Crea una directory Object Manager di destinazione e una seconda directory con `NtCreateDirectoryObjectEx`, passando l'handle della destinazione come shadow/fallback directory. Inserisci una voce `WD_SCAN` con lo stesso nome in entrambi i livelli di risoluzione: la voce visibile punta alla normale directory di lavoro, mentre la voce di fallback punta a `\CLFS\??\<working-directory>`. Fornisci a Defender solo l'invariant path riportato di seguito; eliminare il link visibile mentre l'operazione è attiva fa sì che la stessa stringa ricada nella voce supportata da CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Questo è distinto dall'uso di shadow directories esclusivamente per rallentare la ricerca: l'attacker modifica il **significato** di un path precedentemente accettato senza modificarne la stringa.<sup>[[4]](#references)</sup>

### 3. Acquisisci il nome generato e installa un link specifico per il filename

Monitora la working directory con `ReadDirectoryChangesW`. Alla prima `FILE_ACTION_ADDED`, rimuovi il link visibile `WD_SCAN` per attivare il fallback lookup. Acquisisci il secondo filename generato, apri il file correlato a CLFS e blocca l'intervallo `0..MAXLONGLONG` con `LockFileEx`. Mentre l'operazione privilegiata è bloccata, sostituisci `WD_SCAN` nella directory visibile con una directory di Object Manager reale e crea un symbolic link figlio denominato in base al filename osservato (il PoC ne rimuove gli ultimi quattro caratteri). Puntalo alla destinazione protetta tramite SMB locale:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Il processo senza privilegi non può scrivere direttamente quella destinazione, ma il contesto SYSTEM di Defender può attraversare la condivisione amministrativa loopback. Combinare l'osservazione dei nomi generati con un collegamento Object Manager specifico per il filename evita di dover prevedere in anticipo l'artefatto di remediation.<sup>[[4]](#references)</sup>

### 4. Stabilizzare la cleanup race e attivare un privileged loader

Prima della scansione, il PoC memorizza una PE valida (`ntdll.dll`) nell'NTFS alternate data stream `:stream` del placeholder. Dopo che il redirect crea il file base protetto, apre `phoneinfo.dll:stream` con accesso di esecuzione e mantiene attiva una mapping `PAGE_EXECUTE_READ | SEC_IMAGE` mentre la cleanup riprende; gli oggetti file/section attivi limitano l'eliminazione o la sostituzione durante la race finale. La hydration riavviata restituisce ora la payload DLL invece di EICAR, quindi il file base protetto contiene codice controllato dall'attacker.<sup>[[4]](#references)</sup>

Una write protetta viene quindi convertita in esecuzione SYSTEM collocando un `Report.wer` appositamente costruito sotto `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` e invocando `\Microsoft\Windows\Windows Error Reporting\QueueReporting` tramite la Task Scheduler COM API. In questa chain, l'elaborazione WER privilegiata carica la `C:\Windows\System32\phoneinfo.dll` inserita dall'attacker; una connessione named-pipe viene usata come segnale di esecuzione della payload.<sup>[[4]](#references)</sup>

### Detection pivots

Le correlazioni utili sono più specifiche di qualsiasi singolo filename temporaneo e coprono tutte le transizioni di namespace nella chain:<sup>[[4]](#references)</sup>

- Un provider Cloud Files registrato di recente seguito dal rilevamento di EICAR e da `CF_OPERATION_TYPE_RESTART_HYDRATION` sullo stesso placeholder.
- Percorsi Object Manager contenenti `WD_TARGET_*`, `WD_SHADOW_*` o `WD_SCAN`, in particolare un percorso di scansione sotto `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Creazione di un file CLFS seguita da un exclusive whole-file lock e dall'accesso loopback a `\\127.0.0.1\C$\Windows\System32\*.dll` da parte di un security process privilegiato.
- Creazione di una DLL in System32 insieme a un NTFS ADS, seguita da una mapping `SEC_IMAGE` dello stream.
- Una voce WER queue creata dall'attacker seguita da un'esecuzione manuale insolita di `\Microsoft\Windows\Windows Error Reporting\QueueReporting` e dal caricamento dell'immagine della DLL inserita.

## Chain applicata: switch del mount-point regolato da oplock contro la remediation privilegiata

Un pattern LPE riutilizzabile compare quando uno scanner privilegiato controlla un file controllato dall'attacker e in seguito lo sottopone a remediation riaprendo il **pathname** invece di continuare tramite handle validati. FalconFlank è un esempio pubblico rivolto al workflow di rimozione delle macro Office di CrowdStrike Falcon; il repository dichiara test su Windows 11 25H2 e Windows Server 2025 con la policy rilevante abilitata, ma non pubblica CVE, intervallo delle build interessate, advisory del vendor o stato delle patch, quindi la claim specifica sul prodotto deve essere considerata non verificata e dipendente dalla build.<sup>[[5]](#references)[[6]](#references)</sup>

### Struttura della race

1. Costruire un tree scrivibile il cui nome relativo finale sia utile nella destinazione prevista. L'esempio usa `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, ma inizialmente scrive un documento con macro OLE, non una PE DLL, in `bcrypt.dll`. Il rilevamento basato sul contenuto attiva la remediation mentre il basename controllato dall'attacker viene preservato per il side-load successivo.<sup>[[5]](#references)</sup>
2. Aprire le directory con condivisione ampia e `FILE_OPEN_REPARSE_POINT`, quindi richiedere un oplock RH asincrono sul trigger con `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` e `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Attendere l'evento overlapped e usare il suo completamento come indicatore per lo switch del path. Una notifica di oplock-break RH è indicativa, non dimostra che ogni operazione conflittuale sia bloccata; l'exploitability dipende quindi ancora dall'esatta sequenza di open/remediation della vittima.<sup>[[5]](#references)[[7]](#references)</sup>
3. Dopo il break, rimuovere la leaf directory con `FileDispositionInformationEx` (information class 64) usando i flag di eliminazione e semantica POSIX, chiudere il relativo handle e applicare un `IO_REPARSE_TAG_MOUNT_POINT` al parent ora vuoto con `FSCTL_SET_REPARSE_POINT_EX`. Il mount point reindirizza il suffisso invariato verso un tree protetto come `\\SystemRoot\\System32\\WindowsPowerShell`; l'impostazione di un reparse point fallisce se la directory non è vuota, spiegando il precedente passaggio di eliminazione.<sup>[[5]](#references)[[8]](#references)</sup>
4. Riprendere il workflow privilegiato. Se risolve nuovamente la stringa senza dimostrare che la directory chain e l'oggetto finale siano gli stessi precedentemente ispezionati, lo stesso pathname logico ora raggiunge la directory protetta scelta dall'attacker. Nell'esempio, il successo viene testato riaprendo `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` in lettura/scrittura dal processo originale; ciò distingue la write primitive confused-deputy dalla successiva fase di code execution.<sup>[[5]](#references)</sup>
5. Sostituire il file risultante con la DLL reale e attivare un loader privilegiato. Il PoC usa `CreateTransaction` + `CreateFileTransacted`, tronca il file, mappa la sostituzione delle dimensioni della DLL, copia la PE ed esegue il commit; TxF associa l'handle del file e le successive operazioni basate su handle alla transaction, ma costituisce un meccanismo di sostituzione post-race, non l'origine del fallimento del privilege boundary.<sup>[[5]](#references)[[9]](#references)</sup>
6. Infine, eseguire un scheduled task privilegiato esistente il cui executable cerca il filename adiacente inserito. FalconFlank invoca `\\Microsoft\\Windows\\Application Experience\\MareBackup`, attende che la DLL si connetta a `\\??\\pipe\\FALCONFLANK` e poi elimina il file inserito. Non assumere un token risultante specifico basandosi solo sul nome del task: verificare il processo avviato, il module path, l'integrity level e il token sulla build testata.<sup>[[5]](#references)</sup>

La domanda centrale dell'audit non è quindi «il service valida il path di input originale?», ma «ogni mutazione privilegiata rimane associata agli stessi oggetti file e directory aperti che sono stati validati?». Mantenere gli handle tra check e use, aprire gli oggetti figli in relazione a un handle di directory trusted, rifiutare tag reparse inattesi e rivalidare l'identità del file prima della mutazione chiudono questa classe di bug di pathname-substitution.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection e triage del PoC

Una detection ad alto segnale correla la transizione del namespace con il consumer privilegiato: un header OLE sotto un basename DLL in un tree temporaneo con nome GUID, un oplock break, la rimozione in stile POSIX della leaf directory, la creazione di un mount point che punta a una directory Windows protetta e la creazione o modifica dello stesso basename sotto quella destinazione. Per l'esempio pubblico, aggiungere `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, l'esecuzione manuale di `MareBackup` e la named pipe `FALCONFLANK` come pivot più ristretti; nessuno di questi è sufficiente da solo.<sup>[[5]](#references)</sup>

Quando si riproduce il PoC, tenere conto di tre difetti di affidabilità nel source pubblicato: chiama `FlushFileBuffers` con il puntatore all'array di byte incorporato invece dell'handle del file, controlla un `HRESULT` obsoleto dopo `GetFolder`, `GetTask` e `Run`, e usa retry/wait loop senza limite per l'eliminazione della directory, la creazione del reparse, l'evento oplock e la connessione alla pipe.<sup>[[5]](#references)</sup>

## Considerazioni operative

- **Combinare le primitive** – È possibile usare un nome lungo *per livello* in una directory chain per ottenere una latenza ancora maggiore, fino a esaurire la dimensione di `UNICODE_STRING`.
- **Bug one-shot** – La finestra ampliata (da decine di microsecondi a minuti) rende realistici i bug “single trigger” se associati al pinning della CPU o alla preemption assistita dall'hypervisor.
- **Effetti collaterali** – Il rallentamento interessa solo il path malevolo, quindi le prestazioni complessive del sistema rimangono inalterate; i defender lo noteranno raramente, a meno che non monitorino la crescita del namespace.
- **Cleanup** – Mantenere gli handle per ogni directory/oggetto creato, così da poter chiamare `NtMakeTemporaryObject`/`NtClose` in seguito. In caso contrario, directory chain senza limite potrebbero persistere tra i reboot.
- **File-system races** – Se il path vulnerabile alla fine viene risolto tramite NTFS, è possibile sovrapporre un Oplock (ad esempio `SetOpLock.exe` dallo stesso toolkit) sul file di backing mentre è in esecuzione l'OM slowdown, congelando il consumer per ulteriori millisecondi senza modificare il grafo OM.<sup>[[2]](#references)</sup>

## Note difensive

- Il codice kernel che si basa su named objects dovrebbe rivalidare lo stato sensibile alla sicurezza *dopo* l'open, oppure acquisire un reference prima del check, chiudendo la finestra TOCTOU.
- Applicare limiti superiori alla profondità/lunghezza del path OM prima di dereferenziare nomi controllati dall'utente. Rifiutare nomi eccessivamente lunghi costringe gli attacker a tornare nella finestra dei microsecondi.
- Strumentare la crescita del namespace dell'Object Manager (ETW `Microsoft-Windows-Kernel-Object`) per rilevare chain sospette composte da migliaia di componenti sotto `\BaseNamedObjects`.

## References

- [1] [Project Zero – Tecniche di exploitation di Windows: vincere le race condition con i path lookup](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Come usare Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
