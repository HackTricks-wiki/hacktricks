# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Perché allargare la finestra di race è importante

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. Su hardware moderno una cold `NtOpenEvent`/`NtOpenSection` risolve un nome corto in ~2 µs, lasciando quasi nessun tempo per cambiare lo stato controllato prima che l'azione privilegiata avvenga. Forzando deliberatamente la lookup dell'Object Manager Namespace (OMNS) nel passo 2 per farla durare decine di microsecondi, l'attaccante guadagna abbastanza tempo per vincere consistentemente race altrimenti instabili senza bisogno di migliaia di tentativi.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Nomi come `\BaseNamedObjects\Foo` vengono risolti directory per directory. Ogni componente fa sì che il kernel trovi/apra un *Object Directory* e confronti stringhe Unicode. I symbolic link (es., lettere di unità) possono essere attraversati lungo il percorso.
* **UNICODE_STRING limit** – I percorsi OM sono contenuti in un `UNICODE_STRING` il cui `Length` è un valore a 16 bit. Il limite assoluto è 65 535 byte (32 767 codepoint UTF-16). Con prefissi come `\BaseNamedObjects\`, un attaccante controlla ancora ≈32 000 caratteri.
* **Attacker prerequisites** – Qualsiasi utente può creare oggetti sotto directory scrivibili come `\BaseNamedObjects`. Quando il codice vulnerabile usa un nome al loro interno, o segue un symbolic link che lì porta, l'attaccante controlla le prestazioni della lookup senza privilegi speciali.

## Primitive di rallentamento #1 – Single maximal component

Il costo di risolvere un componente è approssimativamente lineare rispetto alla sua lunghezza perché il kernel deve eseguire un confronto Unicode contro ogni voce nella directory padre. Creare un event con un nome lungo 32 kB aumenta immediatamente la latenza di `NtOpenEvent` da ~2 µs a ~35 µs su Windows 11 24H2 (testbed Snapdragon X Elite).
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
- Symbolic links o reparse points possono puntare un breve nome “victim” a questo componente gigante in modo che il slowdown venga applicato in modo trasparente.
- Poiché tutto risiede in user-writable namespaces, il payload funziona da un standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Una variante più aggressiva alloca una catena di migliaia di directory (`\BaseNamedObjects\A\A\...\X`). Ogni hop triggers directory resolution logic (ACL checks, hash lookups, reference counting), quindi la latenza per livello è maggiore rispetto a un singolo confronto di stringhe. Con ~16 000 livelli (limitati dalla stessa dimensione `UNICODE_STRING`), i tempi empirici superano la barriera di 35 µs raggiunta da long single components.
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
* Tieni un array di handle in modo da poter eliminare la catena pulitamente dopo lo sfruttamento per evitare di inquinare lo spazio dei nomi.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuti invece di microsecondi)

Object directories supportano **shadow directories** (fallback lookups) e bucketed hash tables per le voci. Abusa di entrambi insieme al limite di reparse di 64 componenti dei symbolic-link per moltiplicare il rallentamento senza superare la lunghezza di `UNICODE_STRING`:

1. Crea due directory sotto `\BaseNamedObjects`, p.es. `A` (shadow) e `A\A` (target). Crea la seconda usando la prima come shadow directory (`NtCreateDirectoryObjectEx`), così le ricerche mancanti in `A` ricadono su `A\A`.
2. Riempi ciascuna directory con migliaia di **colliding names** che ricadono nello stesso hash bucket (p.es. variando le cifre finali mantenendo lo stesso valore `RtlHashUnicodeString`). Le ricerche ora degradano a scansioni lineari O(n) all'interno di una singola directory.
3. Costruisci una catena di ~63 **object manager symbolic links** che ripetutamente fanno reparse nel lungo suffisso `A\A\…`, consumando il budget di reparse. Ogni reparse riavvia il parsing dall'inizio, moltiplicando il costo delle collisioni.
4. La ricerca dell'ultimo componente (`...\\0`) ora richiede **minuti** su Windows 11 quando sono presenti 16 000 collisioni per directory, fornendo una vittoria di race praticamente garantita per one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Perché è importante*: Un rallentamento di minuti trasforma gli LPE basati su race one-shot in exploit deterministici.

### Note di retest 2025 e strumenti pronti all'uso

- James Forshaw ha ripubblicato la tecnica con tempi aggiornati su Windows 11 24H2 (ARM64). Le aperture di base rimangono ~2 µs; un componente da 32 kB le porta a ~35 µs, e shadow-dir + collision + 63-reparse chains raggiungono ancora ~3 minuti, confermando che le primitive sopravvivono alle build correnti. Il codice sorgente e il perf harness sono nel post aggiornato di Project Zero.
- Puoi automatizzare la configurazione usando il bundle pubblico `symboliclink-testing-tools`: `CreateObjectDirectory.exe` per creare la coppia shadow/target e `NativeSymlink.exe` in loop per generare la catena a 63 hop. Questo evita wrapper `NtCreate*` scritti a mano e mantiene gli ACL coerenti.

## Misurare la finestra di race

Inserisci un semplice harness all'interno del tuo exploit per misurare quanto si allarga la finestra sulla macchina vittima. Lo snippet qui sotto apre l'oggetto target `iterations` volte e restituisce il costo medio per apertura usando `QueryPerformanceCounter`.
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
I risultati si alimentano direttamente nella tua strategia di orchestrazione della race (p.es., numero di worker thread necessari, intervalli di sleep, quanto prima devi modificare lo stato condiviso).

## Flusso di sfruttamento

1. **Individua la open vulnerabile** – Traccia il percorso kernel (via symbols, ETW, hypervisor tracing, o reversing) finché non trovi una chiamata `NtOpen*`/`ObOpenObjectByName` che percorre un nome controllato dall'attaccante o un symbolic link in una directory scrivibile dall'utente.
2. **Sostituisci quel nome con un slow path**
- Crea il componente lungo o la catena di directory sotto `\BaseNamedObjects` (o un altro writable OM root).
- Crea un symbolic link in modo che il nome che il kernel si aspetta risolva ora nel slow path. Puoi indirizzare la directory lookup del driver vulnerabile alla tua struttura senza toccare il target originale.
3. **Innesca la race**
- Thread A (vittima) esegue il codice vulnerabile e resta bloccato all'interno della slow lookup.
- Thread B (attaccante) cambia lo stato protetto (p.es., scambia un file handle, riscrive un symbolic link, modifica la security dell'oggetto) mentre Thread A è occupato.
- Quando Thread A riprende ed esegue l'azione privilegiata, osserva uno stato obsoleto ed esegue l'operazione controllata dall'attaccante.
4. **Pulizia** – Elimina la catena di directory e i symbolic link per evitare di lasciare artefatti sospetti o interrompere utenti IPC legittimi.

## Considerazioni operative

- **Combine primitives** – Puoi usare un nome lungo per livello in una catena di directory per ottenere una latenza ancora maggiore fino a esaurire la dimensione di `UNICODE_STRING`.
- **One-shot bugs** – La finestra estesa (dalle decine di microsecondi ai minuti) rende realistici i bug “single trigger” se abbinati a CPU affinity pinning o preemption assistita da hypervisor.
- **Side effects** – Il rallentamento interessa solo il percorso malevolo, quindi le prestazioni complessive del sistema rimangono invariate; i difensori noteranno raramente a meno che non monitorino la crescita del namespace.
- **Cleanup** – Mantieni handle per ogni directory/oggetto che crei così potrai chiamare `NtMakeTemporaryObject`/`NtClose` in seguito. Altrimenti le catene di directory non limitate possono persistere attraverso i reboot.
- **File-system races** – Se il percorso vulnerabile alla fine si risolve tramite NTFS, puoi sovrapporre un Oplock (p.es., `SetOpLock.exe` dallo stesso toolkit) sul file di backing mentre il slowdown dell'OM è in corso, bloccando il consumer per alcuni millisecondi aggiuntivi senza alterare il grafo OM.

## Note difensive

- Il codice kernel che si basa su named objects dovrebbe rivalidare lo stato sensibile alla security *dopo* l'open, oppure prendere una reference prima del controllo (chiudendo la finestra TOCTOU).
- Imporre limiti superiori sulla profondità/lunghezza del path OM prima di dereferenziare nomi controllati dall'utente. Rifiutare nomi eccessivamente lunghi costringe gli attaccanti a rientrare nella finestra dei microsecondi.
- Strumentare la crescita del namespace dell'object manager (ETW `Microsoft-Windows-Kernel-Object`) per rilevare catene sospette con migliaia di componenti sotto `\BaseNamedObjects`.

## Riferimenti

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
