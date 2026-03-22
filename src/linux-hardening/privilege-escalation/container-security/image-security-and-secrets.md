# Sicurezza delle immagini, firma e segreti

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

La sicurezza dei container inizia prima del lancio del workload. L'immagine determina quali binari, interpreti, librerie, script di avvio e configurazioni incorporate arrivano in produzione. Se l'immagine contiene una backdoor, è obsoleta o è costruita con segreti incorporati, l'hardening del runtime che segue opera già su un artefatto compromesso.

Per questo motivo image provenance, vulnerability scanning, signature verification e secret handling appartengono alla stessa conversazione di namespaces e seccomp. Proteggono una fase diversa del ciclo di vita, ma i fallimenti in questa fase spesso definiscono la superficie di attacco che il runtime dovrà poi contenere.

## Registri delle immagini e fiducia

Le immagini possono provenire da registri pubblici come Docker Hub o da registri privati gestiti da un'organizzazione. La questione di sicurezza non è semplicemente dove risiede l'immagine, ma se il team può stabilire provenienza e integrità. Scaricare immagini non firmate o con tracciamento insufficiente da fonti pubbliche aumenta il rischio che contenuti malevoli o manomessi entrino in produzione. Anche i registri ospitati internamente necessitano di chiare responsabilità, revisione e politiche di trust.

Docker Content Trust storicamente utilizzava i concetti di Notary e TUF per richiedere immagini firmate. L'ecosistema esatto si è evoluto, ma la lezione duratura rimane valida: l'identità e l'integrità dell'immagine dovrebbero essere verificabili piuttosto che presunte.

Esempio storico di workflow di Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Il punto dell'esempio non è che ogni team debba necessariamente usare gli stessi strumenti, ma che firma e gestione delle chiavi sono attività operative, non teoria astratta.

## Scansione delle vulnerabilità

La scansione delle immagini aiuta a rispondere a due domande distinte. Prima: l'immagine contiene package o librerie vulnerabili noti? Seconda: l'immagine include software non necessario che amplia la superficie di attacco? Un'immagine piena di strumenti di debugging, shell, interpreter e pacchetti obsoleti è sia più facile da sfruttare sia più difficile da analizzare.

Esempi di scanner comunemente usati includono:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
I risultati di questi strumenti vanno interpretati con attenzione. Una vulnerabilità in un pacchetto inutilizzato non comporta lo stesso rischio di un percorso RCE esposto, ma entrambi rimangono rilevanti per le decisioni di hardening.

## Segreti durante la build

Uno degli errori più antichi nelle pipeline di build dei container è incorporare i segreti direttamente nell'immagine o passarli tramite variabili d'ambiente che poi diventano visibili con `docker inspect`, nei log di build o nei layer recuperati. I segreti durante la build dovrebbero essere montati in modo effimero durante la build anziché copiati nel filesystem dell'immagine.

BuildKit ha migliorato questo modello permettendo una gestione dedicata dei segreti durante la build. Invece di scrivere un segreto in un layer, lo step di build può consumarlo in modo transitorio:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Questo è importante perché i livelli dell'immagine sono artefatti persistenti. Una volta che un segreto entra in un livello consolidato, cancellare successivamente il file in un altro livello non rimuove davvero la divulgazione originale dalla cronologia dell'immagine.

## Segreti a runtime

I segreti necessari a un carico di lavoro in esecuzione dovrebbero, per quanto possibile, evitare schemi ad hoc come le semplici variabili d'ambiente. Volumi, integrazioni dedicate per la gestione dei segreti, Docker secrets e Kubernetes Secrets sono meccanismi comuni. Nessuno di questi elimina completamente il rischio, soprattutto se l'attaccante ha già code execution nel carico di lavoro, ma sono comunque preferibili rispetto a memorizzare le credenziali permanentemente nell'immagine o a esporle casualmente tramite strumenti di ispezione.

Una semplice dichiarazione di secret in stile Docker Compose appare così:
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
In Kubernetes, Secret objects, projected volumes, service-account tokens e cloud workload identities creano un modello più ampio e potente, ma offrono anche maggiori opportunità di esposizione accidentale tramite host mounts, RBAC troppo permissivo o un design dei Pod debole.

## Abuso

Quando si esamina un target, l'obiettivo è scoprire se secrets sono stati baked into the image, leaked into layers, o mounted in posizioni di runtime prevedibili:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Questi comandi aiutano a distinguere tra tre diversi problemi: application configuration leaks, image-layer leaks e runtime-injected secret files. Se un segreto appare sotto `/run/secrets`, un projected volume, o un percorso di token di identità cloud, il passo successivo è capire se concede accesso solo al workload corrente o a un control plane molto più ampio.

### Esempio completo: Segreto incorporato nel filesystem dell'immagine

Se una build pipeline ha copiato file `.env` o credenziali nell'immagine finale, la post-exploitation diventa semplice:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impatto dipende dall'applicazione, ma chiavi di firma incorporate, JWT secrets o credenziali cloud possono facilmente trasformare un compromesso del container in un compromesso dell'API, lateral movement o nella falsificazione di token di applicazioni fidate.

### Esempio completo: Build-Time Secret Leakage Check

Se il timore è che la cronologia dell'immagine abbia catturato un layer contenente segreti:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Questo tipo di revisione è utile perché un secret potrebbe essere stato cancellato dalla vista finale del filesystem pur rimanendo in uno strato precedente o nei metadati di build.

## Checks

Questi controlli servono a stabilire se l'image e la secret-handling pipeline abbiano probabilmente aumentato l'attack surface prima del runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Quello che è interessante qui:

- Una cronologia di build sospetta può rivelare credenziali copiate, materiale SSH o passaggi di build non sicuri.
- Secrets sotto percorsi di projected volume possono portare all'accesso al cluster o al cloud, non solo all'accesso dell'applicazione locale.
- Un gran numero di file di configurazione con credenziali in chiaro di solito indica che l'image o il modello di deployment stanno trasportando più materiale di fiducia del necessario.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supporta montaggi sicuri di secret durante il build, ma non automaticamente | I secret possono essere montati in modo effimero durante `build`; image signing and scanning richiedono scelte di workflow esplicite | copiare secret nell'image, passare secret tramite `ARG` o `ENV`, disabilitare i controlli di provenance |
| Podman / Buildah | Supporta build native OCI e workflow consapevoli dei secret | Sono disponibili workflow di build robusti, ma gli operatori devono comunque sceglierli intenzionalmente | incorporare secret nei Containerfiles, contesti di build ampi, bind mount permissivi durante i build |
| Kubernetes | Oggetti Secret nativi e projected volumes | La consegna runtime di secret è di prima classe, ma l'esposizione dipende da RBAC, design del pod e mount dell'host | mount di Secret troppo ampi, abuso di service-account token, accesso `hostPath` a volumi gestiti da kubelet |
| Registries | L'integrità è opzionale a meno che non sia applicata | Registri pubblici e privati dipendono da policy, signing e decisioni di admission | scaricare liberamente immagini non firmate, controllo di admission debole, gestione delle chiavi scadente |
{{#include ../../../banners/hacktricks-training.md}}
