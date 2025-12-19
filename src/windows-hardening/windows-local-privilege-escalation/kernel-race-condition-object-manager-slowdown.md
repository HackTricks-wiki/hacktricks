# Sfruttamento di kernel race condition tramite Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Perché allargare la race window è importante

Molte LPE del kernel di Windows seguono il classico pattern `check_state(); NtOpenX("name"); privileged_action();`. Su hardware moderno una chiamata fredda a `NtOpenEvent`/`NtOpenSection` risolve un nome corto in ~2 µs, lasciando quasi nessun tempo per modificare lo stato verificato prima che l'azione sicura venga eseguita. Forzando deliberatamente la lookup nell'Object Manager Namespace (OMNS) al passo 2 a durare decine di microsecondi, l'attaccante ottiene abbastanza tempo per vincere in modo consistente race altrimenti instabili senza dover effettuare migliaia di tentativi.

## Panoramica interna del lookup dell'Object Manager

* **OMNS structure** – Nomi come `\BaseNamedObjects\Foo` vengono risolti directory per directory. Ogni componente fa sì che il kernel trovi/apra una *Object Directory* e confronti stringhe Unicode. Symbolic links (es. lettere di unità) possono essere attraversati lungo il percorso.
* **UNICODE_STRING limit** – I percorsi OM sono trasportati dentro un `UNICODE_STRING` il cui `Length` è un valore a 16 bit. Il limite assoluto è 65 535 bytes (32 767 codepoint UTF-16). Con prefissi come `\BaseNamedObjects\`, un attaccante controlla ancora ≈32 000 caratteri.
* **Attacker prerequisites** – Qualsiasi utente può creare oggetti sotto directory scrivibili come `\BaseNamedObjects`. Quando il codice vulnerabile usa un nome all'interno, o segue un symbolic link che vi porta, l'attaccante controlla le prestazioni della lookup senza privilegi speciali.

## Slowdown primitive #1 – Single maximal component

Il costo di risolvere un componente è grosso modo lineare rispetto alla sua lunghezza perché il kernel deve eseguire un confronto Unicode contro ogni voce nella directory padre. Creare un event con un nome lungo 32 kB aumenta immediatamente la latenza di `NtOpenEvent` da ~2 µs a ~35 µs su Windows 11 24H2 (testbed Snapdragon X Elite).
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
- Symbolic links o reparse points possono puntare un nome “vittima” corto a questo componente gigante così il rallentamento viene applicato in modo trasparente.
- Poiché tutto risiede in user-writable namespaces, il payload funziona da un livello di integrità utente standard.

## Primitive di rallentamento #2 – Directory ricorsive profonde

Una variante più aggressiva alloca una catena di migliaia di directory (`\BaseNamedObjects\A\A\...\X`). Ogni salto attiva la logica di risoluzione delle directory (ACL checks, hash lookups, reference counting), quindi la latenza per livello è maggiore rispetto a una singola comparazione di stringhe. Con ~16 000 livelli (limitati dalla stessa dimensione di `UNICODE_STRING`), i tempi empirici superano la barriera dei 35 µs raggiunta dai singoli componenti lunghi.
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

* Alterna il carattere per livello (`A/B/C/...`) se la directory padre comincia a rifiutare duplicati.
* Mantieni una handle array in modo da poter eliminare la chain in modo pulito dopo l'exploitation per evitare di inquinare la namespace.

## Misurare la race window

Incorpora un piccolo harness all'interno del tuo exploit per misurare quanto diventa ampia la race window sull'hardware della vittima. Lo snippet qui sotto apre l'oggetto target `iterations` volte e restituisce il costo medio per apertura usando `QueryPerformanceCounter`.
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
I risultati influiscono direttamente sulla tua strategia di orchestrazione delle race (es., numero di worker threads necessari, intervalli di sleep, quanto presto devi modificare lo stato condiviso).

## Exploitation workflow

1. **Locate the vulnerable open** – Traccia il percorso kernel (tramite simboli, ETW, hypervisor tracing, o reversing) fino a trovare una chiamata `NtOpen*`/`ObOpenObjectByName` che percorre un nome controllato dall'attaccante o un link simbolico in una directory scrivibile dall'utente.
2. **Replace that name with a slow path**
- Crea il componente lungo o la catena di directory sotto `\BaseNamedObjects` (o un'altra OM root scrivibile).
- Crea un link simbolico in modo che il nome che il kernel si aspetta risolva ora verso il percorso lento. Puoi indirizzare la directory lookup del driver vulnerabile alla tua struttura senza toccare il target originale.
3. **Trigger the race**
- Thread A (vittima) esegue il codice vulnerabile e si blocca nella lookup lenta.
- Thread B (attaccante) cambia lo stato protetto (es., scambia un file handle, riscrive un link simbolico, modifica la sicurezza dell'oggetto) mentre Thread A è occupato.
- Quando Thread A riprende e esegue l'azione privilegiata, osserva uno stato obsoleto e compie l'operazione controllata dall'attaccante.
4. **Clean up** – Elimina la catena di directory e i link simbolici per evitare di lasciare artefatti sospetti o di interrompere utenti IPC legittimi.

## Considerazioni operative

- **Combine primitives** – Puoi usare un nome lungo *per level* in una catena di directory per ottenere latenza ancora maggiore finché non esaurisci la dimensione di `UNICODE_STRING`.
- **One-shot bugs** – La finestra ampliata (decine di microsecondi) rende realistici i bug a “single trigger” se combinati con CPU affinity pinning o hypervisor-assisted preemption.
- **Side effects** – Il rallentamento interessa solo il percorso malevolo, quindi le prestazioni complessive del sistema restano invariate; i defender raramente noteranno a meno che non monitorino la crescita del namespace.
- **Cleanup** – Mantieni handle per ogni directory/oggetto che crei così da poter chiamare `NtMakeTemporaryObject`/`NtClose` in seguito. Altrimenti catene di directory illimitate potrebbero persistere attraverso i reboot.

## Note difensive

- Il codice kernel che si basa su named objects dovrebbe rivedere lo stato sensibile alla sicurezza *dopo* l'open, oppure prendere un reference prima del controllo (chiudendo la TOCTOU gap).
- Imporre limiti massimi sulla profondità/lunghezza del path OM prima di dereferenziare nomi controllati dall'utente. Rifiutare nomi eccessivamente lunghi costringe gli attaccanti di nuovo nella finestra dei microsecondi.
- Strumentare la crescita del namespace dell'object manager (ETW `Microsoft-Windows-Kernel-Object`) per rilevare catene sospette di migliaia di componenti sotto `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
