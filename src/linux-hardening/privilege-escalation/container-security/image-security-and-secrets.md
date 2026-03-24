# Sicurezza delle immagini, firma e segreti

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

La sicurezza dei container inizia prima che il carico di lavoro venga avviato. L'immagine determina quali binari, interpreti, librerie, script di avvio e configurazioni incorporate arrivano in produzione. Se l'immagine è manomessa, obsoleta o costruita con segreti incorporati, il hardening del runtime che segue sta già operando su un artefatto compromesso.

Per questo motivo la provenienza delle immagini, la scansione delle vulnerabilità, la verifica delle firme e la gestione dei segreti appartengono alla stessa conversazione di namespaces e seccomp. Proteggono una fase diversa del ciclo di vita, ma i fallimenti qui spesso determinano la superficie di attacco che il runtime dovrà poi contenere.

## Registry delle immagini e fiducia

Le immagini possono provenire da registry pubblici come Docker Hub o da registry privati gestiti da un'organizzazione. La questione di sicurezza non è semplicemente dove risiede l'immagine, ma se il team può stabilire provenienza e integrità. Recuperare immagini non firmate o poco tracciate da fonti pubbliche aumenta il rischio che contenuti malevoli o manomessi entrino in produzione. Anche i registry ospitati internamente richiedono una chiara proprietà, processi di revisione e una politica di fiducia.

Docker Content Trust storicamente utilizzava i concetti di Notary e TUF per richiedere immagini firmate. L'ecosistema preciso si è evoluto, ma la lezione duratura rimane utile: l'identità e l'integrità dell'immagine dovrebbero essere verificabili e non date per scontate.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Lo scopo dell'esempio non è che ogni team debba continuare a usare lo stesso tooling, ma che signing e key management sono attività operative, non teoria astratta.

## Scansione delle vulnerabilità

La scansione delle immagini aiuta a rispondere a due domande diverse. Prima, l'immagine contiene pacchetti o librerie con vulnerabilità note? Seconda, l'immagine include software non necessario che amplia la superficie d'attacco? Un'immagine piena di debugging tools, shells, interpreters e pacchetti obsoleti è sia più facile da sfruttare sia più difficile da comprendere.

Esempi di scanner comunemente usati includono:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Risultati di questi strumenti vanno interpretati con cautela. Una vulnerabilità in un pacchetto non utilizzato non è equivalente, in termini di rischio, a un percorso RCE esposto, ma entrambi sono comunque rilevanti per le decisioni di hardening.

## Segreti durante la build

Uno degli errori più antichi nelle pipeline di build dei container è incorporare segreti direttamente nell'immagine o passarli tramite variabili d'ambiente che poi diventano visibili tramite `docker inspect`, i log di build o layer recuperati. I segreti a build-time dovrebbero essere montati in modo effimero durante la build anziché copiati nel filesystem dell'immagine.

BuildKit ha migliorato questo modello permettendo una gestione dedicata dei segreti a build-time. Invece di scrivere un segreto in un layer, il passo di build può consumarlo transitoriamente:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Questo è importante perché i layer delle immagini sono artefatti durevoli. Una volta che un secret entra in un committed layer, eliminare successivamente il file in un altro layer non rimuove realmente la divulgazione originale dalla cronologia dell'immagine.

## Segreti di runtime

I secret necessari a un workload in esecuzione dovrebbero evitare schemi ad hoc come le semplici environment variables, quando possibile. Volumes, integrazioni dedicate di secret-management, Docker secrets e Kubernetes Secrets sono meccanismi comuni. Nessuno di questi elimina completamente il rischio, soprattutto se l'attacker ha già code execution nel workload, ma sono comunque preferibili rispetto a memorizzare credenziali permanentemente nell'immagine o esporle casualmente tramite tooling di inspection.

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
In Kubernetes, Secret objects, projected volumes, service-account tokens e cloud workload identities creano un modello più ampio e potente, ma creano anche maggiori opportunità di esposizione accidentale tramite host mounts, RBAC troppo ampio o un design debole dei Pod.

## Abuso

Quando si esamina un target, l'obiettivo è scoprire se secrets sono state incorporate nell'image, leaked into layers o montate in posizioni runtime prevedibili:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Questi comandi aiutano a distinguere tra tre problemi diversi: application configuration leaks, image-layer leaks e runtime-injected secret files. Se un secret appare sotto `/run/secrets`, in un projected volume o in un cloud identity token path, il passo successivo è capire se concede accesso solo al workload corrente o a un control plane molto più ampio.

### Esempio completo: secret incorporato nel filesystem dell'immagine

Se una build pipeline ha copiato file `.env` o credenziali nell'immagine finale, la post-exploitation diventa semplice:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impatto dipende dall'applicazione, ma chiavi di firma incorporate, JWT secrets o credenziali cloud possono facilmente trasformare la compromissione del container in compromissione delle API, movimento laterale o falsificazione di token di applicazioni attendibili.

### Esempio completo: Build-Time Secret Leakage Check

Se la preoccupazione è che lo storico dell'immagine abbia catturato un layer contenente segreti:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Questo tipo di revisione è utile perché un secret potrebbe essere stato eliminato dalla vista finale del filesystem pur rimanendo in uno strato precedente o nei metadati di build.

## Controlli

Questi controlli mirano a stabilire se l'immagine e la pipeline di gestione dei secret hanno probabilmente aumentato la superficie di attacco prima del runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Quello che è interessante qui:

- Una cronologia di build sospetta può rivelare credenziali copiate, materiale SSH o passaggi di build non sicuri.
- Secrets sotto projected volume paths possono portare ad accesso al cluster o al cloud, non solo all'applicazione locale.
- Un gran numero di file di configurazione con credenziali in plaintext indica di solito che l'immagine o il modello di deployment sta trasportando più materiale di fiducia del necessario.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Debolezze comuni introdotte manualmente |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | pulling unsigned images freely, weak admission control, poor key management |
{{#include ../../../banners/hacktricks-training.md}}
