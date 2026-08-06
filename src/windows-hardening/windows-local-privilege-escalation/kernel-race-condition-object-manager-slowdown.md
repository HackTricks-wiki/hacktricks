# Exploitation di una Race Condition nel Kernel tramite gli Slow Path dell'Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Perché è importante estendere la race window

Molti LPE nel kernel di Windows seguono il pattern classico `check_state(); NtOpenX("name"); privileged_action();`. Su hardware moderno, un `NtOpenEvent`/`NtOpenSection` a freddo risolve un nome breve in circa 2 µs, lasciando pochissimo tempo per modificare lo stato verificato prima che venga eseguita l'azione privilegiata. Forzando deliberatamente la lookup dell'Object Manager Namespace (OMNS) nello step 2 a durare decine di microsecondi, l'attacker ottiene tempo sufficiente per vincere in modo consistente race altrimenti inaffidabili senza dover effettuare migliaia di tentativi.<sup>[[1]](#references)</sup>

## Internals della lookup dell'Object Manager in breve

* **Struttura dell'OMNS** – I nomi come `\BaseNamedObjects\Foo` vengono risolti directory per directory. Ogni componente induce il kernel a trovare/aprire una *Object Directory* e a confrontare stringhe Unicode. I symbolic link (ad esempio, le lettere delle unità) possono essere attraversati durante il percorso.
* **Limite di `UNICODE_STRING`** – I percorsi OM sono contenuti in una `UNICODE_STRING` il cui `Length` è un valore a 16 bit. Il limite assoluto è di 65 535 byte (32 767 codepoint UTF-16). Con prefissi come `\BaseNamedObjects\`, l'attacker controlla comunque circa 32 000 caratteri.
* **Prerequisiti dell'attacker** – Qualsiasi utente può creare oggetti all'interno di directory scrivibili come `\BaseNamedObjects`. Quando il codice vulnerabile utilizza un nome al loro interno o segue un symbolic link che vi conduce, l'attacker controlla le prestazioni della lookup senza privilegi speciali.<sup>[[1]](#references)</sup>

## Primitive di slowdown #1 – Singolo componente massimo

Il costo della risoluzione di un componente è approssimativamente lineare rispetto alla sua lunghezza, perché il kernel deve eseguire un confronto Unicode con ogni voce nella directory padre. La creazione di un event con un nome lungo 32 kB aumenta immediatamente la latenza di `NtOpenEvent` da circa 2 µs a circa 35 µs su Windows 11 24H2 (testbed Snapdragon X Elite).
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
- I symbolic link o i reparse point possono puntare da un breve nome “victim” a questo componente gigante, in modo che il rallentamento venga applicato in modo trasparente.
- Poiché tutto risiede in namespace scrivibili dall’utente, il payload funziona da un livello standard di integrità utente.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Directory ricorsive profonde

Una variante più aggressiva alloca una catena di migliaia di directory (`\BaseNamedObjects\A\A\...\X`). Ogni passaggio attiva la logica di risoluzione delle directory (controlli ACL, ricerche hash, conteggio dei riferimenti), quindi la latenza per livello è superiore a quella di un singolo confronto di stringhe. Con circa 16 000 livelli (limitati dalla stessa dimensione di `UNICODE_STRING`), i tempi empirici superano la soglia dei 35 µs raggiunta dai componenti singoli di grandi dimensioni.
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
* Mantieni un array di handle per poter eliminare la catena in modo pulito dopo l'exploitation, evitando di inquinare il namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuti invece di microsecondi)

Le directory dell'Object Manager supportano le **shadow directories** (ricerche di fallback) e tabelle hash suddivise in bucket per le entry. Abusa di entrambe, insieme al limite di 64 componenti per i reparse delle symbolic link, per moltiplicare il rallentamento senza superare la lunghezza di `UNICODE_STRING`:

1. Crea due directory sotto `\BaseNamedObjects`, ad esempio `A` (shadow) e `A\A` (target). Crea la seconda usando la prima come shadow directory (`NtCreateDirectoryObjectEx`), in modo che le ricerche mancanti in `A` ricadano su `A\A`.
2. Riempi ogni directory con migliaia di **colliding names** che finiscono nello stesso hash bucket (ad esempio, variando le cifre finali mantenendo invariato il valore di `RtlHashUnicodeString`). Le ricerche ora degenerano in scansioni lineari O(n) all'interno di una singola directory.
3. Costruisci una catena di circa 63 **object manager symbolic links** che eseguono ripetutamente il reparse nel lungo suffisso `A\A\…`, consumando il reparse budget. Ogni reparse riavvia il parsing dall'inizio, moltiplicando il costo delle collisioni.
4. La ricerca del componente finale (`...\\0`) ora richiede **minuti** su Windows 11 quando sono presenti 16 000 collisioni per directory, offrendo una vittoria praticamente garantita nella race per kernel LPE one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Perché è importante*: Un rallentamento della durata di alcuni minuti trasforma gli LPE basati su race eseguiti una sola volta in exploit deterministici.<sup>[[1]](#references)</sup>

### Note sul retest del 2025 e tooling pronto all'uso

- James Forshaw ha ripubblicato la tecnica con timing aggiornati su Windows 11 24H2 (ARM64). Le aperture baseline restano di circa 2 µs; un componente da 32 kB porta questo valore a circa 35 µs, mentre shadow-dir + collision + catene con 63 reparse raggiungono ancora circa 3 minuti, confermando che le primitive sono ancora presenti nelle build attuali. Il codice sorgente e il perf harness si trovano nel post aggiornato di Project Zero.<sup>[[1]](#references)</sup>
- Puoi scriptare la configurazione usando il bundle pubblico `symboliclink-testing-tools`: `CreateObjectDirectory.exe` per creare la coppia shadow/target e `NativeSymlink.exe` in un loop per generare la catena di 63 hop. Questo evita di scrivere manualmente wrapper `NtCreate*` e mantiene coerenti gli ACL.<sup>[[2]](#references)</sup>

## Misurare la race window

Integra un semplice harness nel tuo exploit per misurare quanto diventa grande la window sull'hardware della vittima. Lo snippet seguente apre l'oggetto target `iterations` volte e restituisce il costo medio per apertura usando `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
I risultati confluiscono direttamente nella tua strategia di orchestrazione della race (ad esempio, il numero di worker thread necessari, gli intervalli di sleep e quanto presto devi modificare lo stato condiviso).

## Workflow di exploitation

1. **Individua l'apertura vulnerabile** – Segui il percorso del kernel (tramite simboli, tracing ETW, tracing dell'hypervisor o reversing) finché trovi una chiamata `NtOpen*`/`ObOpenObjectByName` che attraversa un nome controllato dall'attaccante o un symbolic link in una directory scrivibile dall'utente.
2. **Sostituisci quel nome con un slow path**
- Crea il componente lungo o la catena di directory sotto `\BaseNamedObjects` (o un'altra root OM scrivibile).
- Crea un symbolic link in modo che il nome atteso dal kernel venga ora risolto verso lo slow path. Puoi indirizzare la directory lookup del driver vulnerabile verso la tua struttura senza modificare il target originale.
3. **Attiva la race**
- Il Thread A (victim) esegue il codice vulnerabile e si blocca all'interno della slow lookup.
- Il Thread B (attacker) modifica lo stato protetto (ad esempio, scambia un file handle, riscrive un symbolic link o modifica la sicurezza dell'oggetto) mentre il Thread A è occupato.
- Quando il Thread A riprende l'esecuzione ed esegue l'azione privilegiata, osserva uno stato obsoleto ed esegue l'operazione controllata dall'attaccante.
4. **Esegui il cleanup** – Elimina la catena di directory e i symbolic link per evitare di lasciare artefatti sospetti o interrompere utenti IPC legittimi.<sup>[[1]](#references)</sup>

## Considerazioni operative

- **Combina le primitive** – Puoi usare un nome lungo *per ogni livello* di una catena di directory per ottenere una latenza ancora maggiore, fino a esaurire la dimensione di `UNICODE_STRING`.
- **Bug one-shot** – La finestra ampliata (da decine di microsecondi a minuti) rende realistici i bug “single trigger” se abbinati al CPU affinity pinning o alla preemption assistita dall'hypervisor.
- **Effetti collaterali** – Lo slowdown interessa solo il path malevolo, quindi le prestazioni complessive del sistema rimangono inalterate; i defender lo noteranno raramente, a meno che non monitorino la crescita del namespace.
- **Cleanup** – Mantieni gli handle di ogni directory/oggetto creato, in modo da poter chiamare `NtMakeTemporaryObject`/`NtClose` in seguito. In caso contrario, le catene di directory senza limiti potrebbero persistere dopo i reboot.
- **Race del file system** – Se il path vulnerabile viene infine risolto tramite NTFS, puoi applicare un Oplock (ad esempio, `SetOpLock.exe` dello stesso toolkit) al file di supporto mentre è in esecuzione lo slowdown dell'OM, bloccando il consumer per ulteriori millisecondi senza modificare il grafo OM.<sup>[[2]](#references)</sup>

## Note difensive

- Il codice del kernel che si basa su oggetti denominati dovrebbe rivalidare lo stato sensibile alla sicurezza *dopo* l'open, oppure acquisire un reference prima del check (chiudendo la finestra TOCTOU).
- Imposta limiti superiori sulla profondità/lunghezza del path OM prima di dereferenziare i nomi controllati dall'utente. Rifiutare nomi eccessivamente lunghi costringe gli attacker a tornare nella finestra dei microsecondi.
- Strumenta la crescita del namespace dell'object manager (ETW `Microsoft-Windows-Kernel-Object`) per rilevare catene sospette composte da migliaia di componenti sotto `\BaseNamedObjects`.

## References

- [1] [Project Zero – Tecniche di Exploitation di Windows: vincere le race condition con le path lookup](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
