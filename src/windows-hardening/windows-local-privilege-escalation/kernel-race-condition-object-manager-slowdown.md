# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Perché allargare la finestra temporale della race è importante

Molti Windows kernel LPE seguono lo schema classico `check_state(); NtOpenX("name"); privileged_action();`. Su hardware moderno una cold `NtOpenEvent`/`NtOpenSection` risolve un nome breve in ~2 µs, lasciando quasi zero tempo per cambiare lo stato verificato prima che l'azione protetta avvenga. Forzando deliberatamente la lookup del Object Manager Namespace (OMNS) nel passo 2 a durare decine di microsecondi, l'attaccante guadagna tempo sufficiente per vincere in modo consistente race altrimenti instabili senza bisogno di migliaia di tentativi.

## Object Manager lookup internals in a nutshell

* **Struttura OMNS** – I nomi come `\BaseNamedObjects\Foo` vengono risolti directory per directory. Ogni componente fa sì che il kernel trovi/apra un *Object Directory* e confronti stringhe Unicode. Possono essere attraversati anche collegamenti simbolici (es., lettere di unità) lungo il percorso.
* **UNICODE_STRING limit** – I percorsi OM sono contenuti in un `UNICODE_STRING` il cui `Length` è un valore a 16 bit. Il limite assoluto è 65 535 byte (32 767 codepoint UTF-16). Con prefissi come `\BaseNamedObjects\`, un attaccante controlla ancora ≈32 000 caratteri.
* **Prerequisiti per l'attaccante** – Qualsiasi utente può creare oggetti sotto directory scrivibili come `\BaseNamedObjects`. Quando il codice vulnerabile usa un nome al loro interno, o segue un collegamento simbolico che vi conduce, l'attaccante controlla le prestazioni della lookup senza privilegi speciali.

## Slowdown primitive #1 – Single maximal component

Il costo per risolvere un componente è approssimativamente lineare rispetto alla sua lunghezza perché il kernel deve eseguire un confronto Unicode contro ogni voce nella directory padre. Creare un event con un nome lungo 32 kB aumenta immediatamente la latenza di `NtOpenEvent` da ~2 µs a ~35 µs su Windows 11 24H2 (testbed Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Note pratiche*

- Puoi raggiungere il limite di lunghezza usando qualsiasi named kernel object (events, sections, semaphores…).
- Symbolic links o reparse points possono puntare un breve nome “victim” verso questo giant component in modo che il rallentamento venga applicato in modo trasparente.
- Poiché tutto risiede in user-writable namespaces, il payload funziona da un standard user integrity level.

## Slowdown primitive #2 – Directory ricorsive profonde

Una variante più aggressiva alloca una catena di migliaia di directory (`\BaseNamedObjects\A\A\...\X`). Ogni hop attiva la directory resolution logic (ACL checks, hash lookups, reference counting), quindi la latenza per livello è maggiore rispetto a una singola string compare. Con ~16 000 livelli (limitati dallo stesso `UNICODE_STRING`), i tempi empirici superano la barriera dei 35 µs raggiunta da singoli componenti lunghi.
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
Consigli:

* Alterna il carattere per livello (`A/B/C/...`) se la directory padre inizia a rifiutare duplicati.
* Mantieni un handle array in modo da poter cancellare la catena in modo pulito dopo l'exploitation per evitare di inquinare il namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuti invece di microsecondi)

Object directories supportano **shadow directories** (fallback lookups) e bucketed hash tables per le entries. Abusa di entrambi più il limite di 64 componenti per lo symbolic-link reparse per moltiplicare lo slowdown senza superare la lunghezza di `UNICODE_STRING`:

1. Crea due directory sotto `\BaseNamedObjects`, p.es. `A` (shadow) e `A\A` (target). Crea la seconda usando la prima come shadow directory (`NtCreateDirectoryObjectEx`), così le lookup mancanti in `A` ricadono in `A\A`.
2. Riempi ciascuna directory con migliaia di **colliding names** che finiscono nello stesso hash bucket (es., variando le cifre finali mantenendo lo stesso valore `RtlHashUnicodeString`). Le lookup ora degradano a scansioni lineari O(n) all'interno di una singola directory.
3. Costruisci una catena di ~63 **object manager symbolic links** che ripetutamente effettuano un reparse sul lungo suffisso `A\A\…`, consumando il budget di reparse. Ogni reparse riavvia il parsing dall'inizio, moltiplicando il costo delle collisioni.
4. La lookup dell'ultimo componente (`...\\0`) ora impiega **minuti** su Windows 11 quando sono presenti 16 000 collisioni per directory, offrendo una vittoria di race praticamente garantita per one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Perché è importante*: Un rallentamento di diversi minuti trasforma i one-shot race-based LPEs in exploit deterministici.

## Misurare la tua race window

Incorpora un rapido harness all'interno del tuo exploit per misurare quanto diventa grande la window sull'hardware della vittima. Il frammento qui sotto apre l'oggetto target `iterations` volte e restituisce il costo medio per apertura usando `QueryPerformanceCounter`.
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
I risultati si riflettono direttamente nella tua race orchestration strategy (es.: numero di worker threads necessari, intervalli di sleep, quanto presto devi flipare lo shared state).

## Exploitation workflow

1. **Individuare l'open vulnerabile** – Traccia il percorso kernel (tramite simboli, ETW, hypervisor tracing o reversing) fino a trovare una chiamata `NtOpen*`/`ObOpenObjectByName` che percorre un nome controllato dall'attaccante o un symbolic link in una directory scrivibile dall'utente.
2. **Sostituire quel nome con un slow path**
- Crea il componente lungo o la catena di directory sotto `\BaseNamedObjects` (o un altro OM root scrivibile).
- Crea un symbolic link in modo che il nome che il kernel si aspetta risolva ora nel slow path. Puoi puntare la directory lookup del driver vulnerabile alla tua struttura senza toccare il target originale.
3. **Innescare la race**
- Thread A (vittima) esegue il codice vulnerabile e si blocca all'interno dello slow lookup.
- Thread B (attaccante) flips lo guarded state (es.: scambia un file handle, riscrive un symbolic link, toggla la object security) mentre Thread A è occupato.
- Quando Thread A riprende e esegue l'azione privilegiata, osserva uno stato stale e compie l'operazione controllata dall'attaccante.
4. **Pulizia** – Elimina la catena di directory e i symbolic link per evitare di lasciare artefatti sospetti o di interrompere utenti IPC legittimi.

## Considerazioni operative

- **Combine primitives** – Puoi usare un nome lungo *per level* in una catena di directory per ottenere una latenza ancora maggiore fino a esaurire la dimensione di `UNICODE_STRING`.
- **One-shot bugs** – La finestra espansa (da decine di microsecondi a minuti) rende realistici i bug “single trigger” quando combinati con CPU affinity pinning o preemption assistita dall'hypervisor.
- **Side effects** – Lo slowdown colpisce solo il malicious path, quindi le prestazioni complessive del sistema rimangono invariate; i defenders noteranno raramente a meno che non monitorino la crescita del namespace.
- **Cleanup** – Tieni gli handle per ogni directory/oggetto che crei così puoi chiamare `NtMakeTemporaryObject`/`NtClose` in seguito. Catene di directory senza limiti possono persistere attraverso reboot altrimenti.

## Note difensive

- Il codice kernel che si basa su named objects dovrebbe ri-validare lo stato sensibile alla sicurezza *dopo* l'open, o prendere un reference prima del check (chiudendo la TOCTOU gap).
- Applica limiti superiori sulla profondità/lunghezza del percorso OM prima di dereferenziare nomi controllati dall'utente. Rifiutare nomi eccessivamente lunghi costringe gli attacker nella finestra dei microsecondi.
- Monitora la crescita del namespace dell'object manager (ETW `Microsoft-Windows-Kernel-Object`) per rilevare catene sospette di migliaia di componenti sotto `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
