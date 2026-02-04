# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Perché allargare la race window conta

Molti LPE del kernel di Windows seguono il classico pattern `check_state(); NtOpenX("name"); privileged_action();`. Su hardware moderno una chiamata a freddo `NtOpenEvent`/`NtOpenSection` risolve un nome breve in ~2 µs, lasciando quasi nessun tempo per modificare lo stato verificato prima che l'azione privilegiata avvenga. Forzando deliberatamente la lookup dell'Object Manager Namespace (OMNS) al passo 2 affinché impieghi decine di microsecondi, l'attaccante ottiene abbastanza tempo per vincere in modo consistente race altrimenti instabili senza necessitare migliaia di tentativi.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Nomi come `\BaseNamedObjects\Foo` vengono risolti directory per directory. Ogni componente fa sì che il kernel trovi/apra una *Object Directory* e confronti stringhe Unicode. I collegamenti simbolici (es., lettere di unità) possono essere attraversati lungo il percorso.
* **UNICODE_STRING limit** – I percorsi OM sono contenuti in un `UNICODE_STRING` il cui `Length` è un valore a 16 bit. Il limite assoluto è 65 535 bytes (32 767 UTF-16 codepoints). Con prefissi come `\BaseNamedObjects\`, un attaccante controlla ancora ≈32 000 caratteri.
* **Attacker prerequisites** – Qualsiasi utente può creare oggetti sotto directory scrivibili come `\BaseNamedObjects`. Quando il codice vulnerabile usa un nome al loro interno, o segue un collegamento simbolico che porta lì, l'attaccante controlla le prestazioni della lookup senza privilegi speciali.

## Slowdown primitive #1 – Single maximal component

Il costo di risolvere un componente è approssimativamente lineare rispetto alla sua lunghezza perché il kernel deve eseguire un confronto Unicode contro ogni voce nella directory padre. Creare un event con un nome lungo 32 kB aumenta immediatamente la latenza di `NtOpenEvent` da ~2 µs a ~35 µs su Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Note pratiche*

- Puoi raggiungere il limite di lunghezza usando qualsiasi oggetto kernel nominato (events, sections, semaphores…).
- I collegamenti simbolici o i reparse points possono puntare un nome breve “victim” verso questo componente gigante, così il rallentamento viene applicato in modo trasparente.
- Poiché tutto risiede in namespace scrivibili dall'utente, il payload funziona da un livello di integrità utente standard.

## Primitiva di rallentamento #2 – Directory ricorsive profonde

Una variante più aggressiva alloca una catena di migliaia di directory (`\BaseNamedObjects\A\A\...\X`). Ogni passo attiva la logica di risoluzione delle directory (controlli ACL, ricerche di hash, conteggio dei riferimenti), quindi la latenza per livello è superiore rispetto a un singolo confronto di stringhe. Con ~16 000 livelli (limitati dalla stessa dimensione di `UNICODE_STRING`), i tempi empirici superano la barriera dei 35 µs raggiunta con componenti singoli lunghi.
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
Tips:

* Alterna il carattere per livello (`A/B/C/...`) se la parent directory inizia a rifiutare i duplicati.
* Mantieni un handle array così puoi cancellare la catena pulitamente dopo lo sfruttamento per evitare di inquinare lo namespace.

## Primitiva di rallentamento #3 – Shadow directories, hash collisions & symlink reparses (minuti invece di microsecondi)

Le Object directories supportano **shadow directories** (fallback lookups) e tabelle hash a bucket per le voci. Abusa di entrambi assieme al limite di 64 componenti per il symbolic-link reparse per moltiplicare il rallentamento senza superare la lunghezza di `UNICODE_STRING`:

1. Crea due directory sotto `\BaseNamedObjects`, es. `A` (shadow) e `A\A` (target). Crea la seconda usando la prima come shadow directory (`NtCreateDirectoryObjectEx`), così le lookup mancanti in `A` ricadono su `A\A`.
2. Riempi ogni directory con migliaia di **colliding names** che finiscono nello stesso hash bucket (es., variando le cifre terminali mantenendo lo stesso valore di `RtlHashUnicodeString`). Le lookup ora degradano a scansioni lineari O(n) all'interno di una singola directory.
3. Costruisci una catena di ~63 **object manager symbolic links** che ripetutamente reparseano nel lungo suffisso `A\A\…`, consumando il budget di reparse. Ogni reparse riavvia il parsing dall'inizio, moltiplicando il costo delle collisioni.
4. La lookup dell'ultimo componente (`...\\0`) ora richiede **minuti** su Windows 11 quando sono presenti 16 000 collisioni per directory, garantendo praticamente una vittoria di race per one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Perché è importante*: Un rallentamento di minuti trasforma gli LPEs race-based one-shot in exploit deterministici.

## Misurare la finestra di race

Integra un rapido harness all'interno del tuo exploit per misurare quanto diventa ampia la finestra sull'hardware della vittima. Lo snippet qui sotto apre l'oggetto target `iterations` volte e restituisce il costo medio per apertura usando `QueryPerformanceCounter`.
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
I risultati si riflettono direttamente sulla tua race orchestration strategy (e.g., numero di worker threads necessari, sleep intervals, quanto prima devi flip the shared state).

## Exploitation workflow

1. **Locate the vulnerable open** – Traccia il kernel path (via symbols, ETW, hypervisor tracing, or reversing) fino a trovare una chiamata `NtOpen*`/`ObOpenObjectByName` che percorre un attacker-controlled name o un symbolic link in una user-writable directory.
2. **Replace that name with a slow path**
- Crea il long component o la catena di directory sotto `\BaseNamedObjects` (o un altro writable OM root).
- Crea un symbolic link in modo che il nome che il kernel si aspetta ora risolva nello slow path. Puoi puntare il vulnerable driver’s directory lookup alla tua struttura senza toccare il target originale.
3. **Trigger the race**
- Thread A (victim) esegue il codice vulnerabile e si blocca all'interno della slow lookup.
- Thread B (attacker) flip the guarded state (e.g., swaps a file handle, rewrites a symbolic link, toggles object security) mentre Thread A è occupato.
- Quando Thread A riprende ed esegue l'azione privilegiata, osserva uno stale state e compie l'operazione controllata dall'attacker.
4. **Clean up** – Elimina la catena di directory e i symbolic link per evitare di lasciare artefatti sospetti o rompere utenti IPC legittimi.

## Considerazioni operative

- **Combine primitives** – Puoi usare un long name *per level* in una catena di directory per ottenere una latenza ancora maggiore fino a esaurire la dimensione di `UNICODE_STRING`.
- **One-shot bugs** – La finestra espansa (da decine di microsecondi a minuti) rende realistici i bug “single trigger” quando sono abbinati a CPU affinity pinning o hypervisor-assisted preemption.
- **Side effects** – Il slowdown riguarda solo il percorso malevolo, quindi le prestazioni complessive del sistema rimangono invariate; i defenders noteranno raramente a meno che non monitorino la crescita dello namespace.
- **Cleanup** – Mantieni handles per ogni directory/object che crei così potrai chiamare `NtMakeTemporaryObject`/`NtClose` in seguito. Altrimenti catene di directory non limitate possono persistere attraverso i reboot.

## Note difensive

- Il kernel code che si basa su named objects dovrebbe re-validate lo stato sensibile alla sicurezza *after* the open, o prendere un reference prima della check (chiudendo il TOCTOU gap).
- Imporre limiti superiori sulla profondità/length degli OM path prima di dereferenziare nomi controllati dall'utente. Rifiutare nomi eccessivamente lunghi costringe gli attacker nella finestra dei microsecondi.
- Monitora la crescita dello object manager namespace (ETW `Microsoft-Windows-Kernel-Object`) per rilevare catene sospette di migliaia di componenti sotto `\BaseNamedObjects`.

## Riferimenti

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
