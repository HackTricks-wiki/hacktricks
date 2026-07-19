# Sicurezza delle immagini, firma e secrets

{{#include ../../../banners/hacktricks-training.md}}

## Registri delle immagini e trust

La sicurezza dei container inizia prima dell'avvio del workload. L'immagine determina quali binari, interpreti, librerie, script di avvio e configurazioni incorporate arrivano in produzione. Se l'immagine contiene una backdoor, è obsoleta o viene compilata con secrets incorporati, l'hardening del runtime successivo sta già operando su un artifact compromesso.

Per questo la provenienza delle immagini, la scansione delle vulnerabilità, la verifica delle firme e la gestione dei secrets appartengono alla stessa discussione di namespaces e seccomp. Proteggono una fase diversa del ciclo di vita, ma i problemi che si verificano qui spesso definiscono la superficie di attacco che il runtime dovrà poi contenere.

## Registri delle immagini e trust

Le immagini possono provenire da registri pubblici come Docker Hub o da registri privati gestiti da un'organizzazione. La questione di sicurezza non è semplicemente dove si trova l'immagine, ma se il team può stabilirne la provenienza e l'integrità. Il pull di immagini non firmate o tracciate in modo insufficiente da fonti pubbliche aumenta il rischio che contenuti malevoli o manomessi entrino in produzione. Anche i registri ospitati internamente necessitano di una titolarità, una revisione e una trust policy chiare.

Docker Content Trust utilizzava storicamente i concetti di Notary e TUF per richiedere immagini firmate. L'ecosistema preciso si è evoluto, ma la lezione fondamentale rimane utile: l'identità e l'integrità delle immagini dovrebbero essere verificabili anziché date per scontate.

Esempio di workflow storico di Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Il punto dell'esempio non è che ogni team debba continuare a usare gli stessi strumenti, ma che la firma e la gestione delle chiavi sono attività operative, non teoria astratta.

## Scansione delle Vulnerabilità

La scansione delle immagini aiuta a rispondere a due domande diverse. Primo, l'immagine contiene pacchetti o librerie noti per essere vulnerabili? Secondo, l'immagine include software non necessario che amplia la attack surface? Un'immagine piena di strumenti di debugging, shell, interpreti e pacchetti obsoleti è sia più facile da sfruttare sia più difficile da analizzare.

Esempi di scanner comunemente utilizzati includono:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
I risultati di questi tool devono essere interpretati con attenzione. Una vulnerabilità in un package inutilizzato non presenta lo stesso rischio di un percorso RCE esposto, ma entrambi sono comunque rilevanti per le decisioni di hardening.

## Secrets durante la build

Uno degli errori più vecchi nelle pipeline di build dei container consiste nell'inserire direttamente i secrets nell'immagine o nel passarli tramite variabili d'ambiente che in seguito diventano visibili attraverso `docker inspect`, i build log o i layer recuperati. I secrets durante la build devono essere montati temporaneamente durante la build, invece di essere copiati nel filesystem dell'immagine.

BuildKit ha migliorato questo modello consentendo una gestione dedicata dei secrets durante la build. Invece di scrivere un secret in un layer, lo step di build può utilizzarlo temporaneamente:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Questo è importante perché i livelli dell'immagine sono artefatti duraturi. Una volta che un secret entra in un livello sottoposto a commit, eliminare successivamente il file in un altro livello non rimuove realmente la divulgazione originale dalla cronologia dell'immagine.

## Secrets a runtime

I secrets necessari per un workload in esecuzione dovrebbero inoltre evitare, ove possibile, pattern ad hoc come le variabili d'ambiente in chiaro. I volumi, le integrazioni dedicate per la gestione dei secrets, Docker secrets e Kubernetes Secrets sono meccanismi comuni. Nessuno di questi elimina ogni rischio, soprattutto se l'attacker ha già ottenuto l'esecuzione di codice nel workload, ma sono comunque preferibili alla memorizzazione permanente delle credenziali nell'immagine o alla loro esposizione casuale tramite strumenti di inspection.

Una semplice dichiarazione di secret in stile Docker Compose è simile a:
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
In Kubernetes, gli oggetti Secret, i projected volumes, i token degli account di servizio e le cloud workload identities creano un modello più ampio e potente, ma anche più opportunità di esposizione accidentale attraverso host mounts, RBAC troppo permissivo o un design debole dei Pod.

## Abuso

Durante la revisione di un target, l'obiettivo è scoprire se i secrets sono stati incorporati nell'immagine, esposti nei layer o montati in posizioni runtime prevedibili:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Questi comandi aiutano a distinguere tra tre problemi diversi: leak di configurazione dell'applicazione, leak nei layer dell'immagine e file di secret iniettati a runtime. Se un secret appare sotto `/run/secrets`, in un volume proiettato o in un percorso del token di identità cloud, il passo successivo consiste nel capire se concede l'accesso solo al workload corrente o a un control plane molto più ampio.

### Esempio completo: Secret incorporato nel filesystem dell'immagine

Se una build pipeline ha copiato file `.env` o credenziali nell'immagine finale, il post-exploitation diventa semplice:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impatto dipende dall'applicazione, ma signing keys incorporate, JWT secrets o cloud credentials possono facilmente trasformare la compromissione del container in una compromissione dell'API, lateral movement o falsificazione di trusted application tokens.

### Esempio completo: controllo del Secret Leakage in fase di build

Se il problema è che la image history ha acquisito un layer contenente un secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Questo tipo di revisione è utile perché un secret potrebbe essere stato eliminato dalla vista finale del filesystem, pur rimanendo in un layer precedente o nei build metadata.

## Verifiche

Queste verifiche servono a stabilire se la pipeline di gestione dell'immagine e dei secret ha probabilmente aumentato la superficie d'attacco prima del runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Cosa c'è di interessante qui:

- Una cronologia di build sospetta può rivelare credenziali copiate, materiale SSH o passaggi di build non sicuri.
- I secret nei percorsi dei volumi projected possono portare all'accesso al cluster o al cloud, non soltanto all'accesso all'applicazione locale.
- Un numero elevato di file di configurazione con credenziali in chiaro indica solitamente che l'immagine o il modello di deployment trasporta più materiale di autenticazione del necessario.

## Impostazioni predefinite di Runtime

| Runtime / platform | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker / BuildKit | Supporta mount di secret sicuri durante la build, ma non automaticamente | I secret possono essere montati temporaneamente durante la `build`; la firma e la scansione delle immagini richiedono scelte esplicite nel workflow | copiare i secret nell'immagine, passare i secret tramite `ARG` o `ENV`, disabilitare i controlli di provenance |
| Podman / Buildah | Supporta build native OCI e workflow consapevoli dei secret | Sono disponibili workflow di build robusti, ma gli operatori devono comunque sceglierli intenzionalmente | incorporare i secret nei Containerfile, usare context di build ampi, mount bind permissivi durante le build |
| Kubernetes | Oggetti Secret nativi e volumi projected | La distribuzione dei secret a runtime è una funzionalità di prima classe, ma l'esposizione dipende da RBAC, progettazione dei pod e mount dell'host | mount di Secret troppo ampi, uso improprio dei token degli account di servizio, accesso `hostPath` ai volumi gestiti dal kubelet |
| Registries | L'integrità è opzionale, a meno che non venga applicata | I registries pubblici e privati dipendono entrambi da policy, signing e decisioni di admission | estrarre liberamente immagini non firmate, controlli di admission deboli, gestione inadeguata delle chiavi |
{{#include ../../../banners/hacktricks-training.md}}
