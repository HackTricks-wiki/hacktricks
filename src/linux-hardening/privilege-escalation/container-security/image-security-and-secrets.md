# Sicurezza delle immagini, firma e segreti

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

La sicurezza dei container inizia prima del lancio del carico di lavoro. L'immagine determina quali binari, interpreter, librerie, script di avvio e configurazioni incorporate arrivano in produzione. Se l'immagine è backdoored, obsoleta o costruita con segreti incorporati, l'hardening del runtime che segue sta già operando su un artefatto compromesso.

È per questo che la provenienza dell'immagine, la scansione delle vulnerabilità, la verifica delle firme e la gestione dei segreti devono far parte della stessa conversazione di namespaces e seccomp. Proteggono una fase diversa del ciclo di vita, ma i fallimenti qui spesso definiscono la superficie di attacco che il runtime dovrà poi contenere.

## Image Registries And Trust

Le immagini possono provenire da registry pubblici come Docker Hub o da registry privati gestiti da un'organizzazione. La domanda di sicurezza non è semplicemente dove risiede l'immagine, ma se il team è in grado di stabilire provenienza e integrità. Effettuare il pull di immagini non firmate o scarsamente tracciate da sorgenti pubbliche aumenta il rischio che contenuti dannosi o manomessi entrino in produzione. Anche i registry ospitati internamente necessitano di una proprietà chiara, di processi di revisione e di una politica di trust.

Docker Content Trust storicamente utilizzava i concetti di Notary e TUF per richiedere immagini firmate. L'ecosistema esatto si è evoluto, ma la lezione duratura rimane utile: l'identità e l'integrità dell'immagine dovrebbero essere verificabili piuttosto che assunte.

Esempio storico del flusso di lavoro di Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
The point of the example is not that every team must still use the same tooling, but that signing and key management are operational tasks, not abstract theory.

## Vulnerability Scanning

Image scanning aiuta a rispondere a due domande diverse. Primo, l'image contiene pacchetti o librerie noti per essere vulnerabili? Secondo, l'image contiene software non necessario che amplia l'attack surface? Un'image piena di debugging tools, shells, interpreters e stale packages è sia più facile da sfruttare sia più difficile da comprendere.

Esempi di scanner comunemente usati includono:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
I risultati di questi strumenti devono essere interpretati con attenzione. Una vulnerabilità in un pacchetto non utilizzato non comporta lo stesso rischio di un percorso RCE esposto, ma entrambi sono comunque rilevanti per le decisioni di hardening.

## Segreti in fase di build

Uno degli errori più vecchi nelle pipeline di build dei container è incorporare i segreti direttamente nell'immagine o passarli tramite variabili d'ambiente che in seguito diventano visibili attraverso `docker inspect`, i log di build, o i layer recuperati. I segreti in fase di build dovrebbero essere montati in modo effimero durante la build invece di essere copiati nel filesystem dell'immagine.

BuildKit ha migliorato questo modello permettendo una gestione dedicata dei segreti in fase di build. Invece di scrivere un segreto in un layer, lo step di build può consumarlo in modo transitorio:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Questo è importante perché i layer dell'immagine sono artefatti duraturi. Una volta che un segreto entra in un layer committato, cancellare successivamente il file in un altro layer non rimuove veramente la divulgazione originale dalla cronologia dell'immagine.

## Segreti a runtime

I segreti necessari a un workload in esecuzione dovrebbero anch'essi evitare pattern ad hoc come semplici variabili d'ambiente ogni volta che è possibile. Volumes, integrazioni dedicate per la gestione dei segreti, Docker secrets, e Kubernetes Secrets sono meccanismi comuni. Nessuno di questi elimina completamente il rischio, specialmente se l'attaccante ha già esecuzione di codice nel workload, ma sono comunque preferibili rispetto a memorizzare credenziali permanentemente nell'immagine o esporle in modo casuale tramite strumenti di ispezione.

Una semplice dichiarazione di secret in stile Docker Compose ha questo aspetto:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
In Kubernetes, Secret objects, projected volumes, service-account tokens e cloud workload identities creano un modello più ampio e potente, ma introducono anche maggiori opportunità di esposizione accidentale tramite host mounts, RBAC troppo permissive o una progettazione debole dei Pod.

## Abuso

Quando si esamina un target, l'obiettivo è scoprire se i secrets sono stati baked nell'image, leaked nei layers o mounted in posizioni runtime prevedibili:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Questi comandi aiutano a distinguere tra tre problemi diversi: leaks di configurazione dell'applicazione, image-layer leaks e file secret iniettati a runtime. Se un secret appare sotto `/run/secrets`, in un projected volume, o in un cloud identity token path, il passo successivo è capire se concede accesso solo al workload corrente o a un control plane molto più ampio.

### Esempio completo: Embedded Secret nel filesystem dell'immagine

Se una build pipeline ha copiato i file `.env` o le credenziali nell'immagine finale, post-exploitation diventa semplice:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impatto dipende dall'applicazione, ma chiavi di firma incorporate, segreti JWT o credenziali cloud possono facilmente trasformare la compromissione del container in una compromissione delle API, lateral movement o nella falsificazione di token di applicazioni attendibili.

### Esempio completo: Controllo della perdita di segreti durante la build

Se la preoccupazione è che lo storico dell'immagine abbia catturato uno strato contenente segreti:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Questo tipo di revisione è utile perché un secret potrebbe essere stato cancellato dalla vista finale del filesystem pur rimanendo in un layer precedente o nei build metadata.

## Checks

Questi controlli servono a stabilire se l'image e la secret-handling pipeline hanno probabilmente aumentato l'attack surface prima del runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
What is interesting here:

- Una storia di build sospetta può rivelare credenziali copiate, materiale SSH o passaggi di build non sicuri.
- Secrets presenti in percorsi di projected volume possono portare ad accesso al cluster o al cloud, non solo all'accesso locale dell'applicazione.
- Un gran numero di file di configurazione con credenziali in plaintext indica di solito che l'image o il modello di deployment sta trasportando più materiale fidato del necessario.

## Impostazioni predefinite di runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supporta mount sicuri di secret a build-time, ma non automaticamente | I Secrets possono essere montati in modo effimero durante `build`; la firma e la scansione dell'image richiedono scelte esplicite nel workflow | copiare Secrets nell'image, passare Secrets tramite `ARG` o `ENV`, disabilitare i controlli di provenance |
| Podman / Buildah | Supporta build nativi OCI e workflow consapevoli dei Secret | Sono disponibili workflow di build solidi, ma gli operatori devono comunque sceglierli intenzionalmente | incorporare Secret nei Containerfiles, contesti di build ampi, bind mount permissivi durante i build |
| Kubernetes | Oggetti Secret nativi e projected volumes | La consegna dei Secret a runtime è una funzionalità primaria, ma l'esposizione dipende da RBAC, dal design del pod e dai mount dell'host | mount di Secret troppo ampi, uso improprio di service-account token, `hostPath` accesso a volumi gestiti da kubelet |
| Registries | L'integrità è opzionale a meno che non sia applicata | Sia i registri pubblici che privati dipendono da policy, signing e decisioni di admission | scaricare liberamente immagini non firmate, controllo di admission debole, gestione delle chiavi scadente |
