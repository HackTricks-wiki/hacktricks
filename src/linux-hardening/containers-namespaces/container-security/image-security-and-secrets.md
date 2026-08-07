# Sicurezza delle immagini, signing e secrets

{{#include ../../../banners/hacktricks-training.md}}

## Registry delle immagini e trust

La sicurezza dei container inizia prima dell'avvio del workload. L'immagine determina quali binari, interpreti, librerie, script di avvio e configurazioni incorporate arrivano in produzione. Se l'immagine contiene una backdoor, è obsoleta o viene creata con secrets incorporati, l'hardening del runtime applicato successivamente sta già operando su un artifact compromesso.

Per questo la provenienza delle immagini, la scansione delle vulnerabilità, la verifica delle signature e la gestione dei secrets fanno parte della stessa discussione di namespaces e seccomp. Proteggono una fase diversa del ciclo di vita, ma i problemi in quest'area spesso definiscono l'attack surface che il runtime dovrà successivamente contenere.

Le immagini possono provenire da registry pubblici, come Docker Hub, oppure da registry privati gestiti da un'organizzazione. La questione di sicurezza non è semplicemente dove risiede l'immagine, ma se il team può stabilirne la provenienza e l'integrità. Effettuare il pull di immagini non firmate o tracciate in modo inadeguato da fonti pubbliche aumenta il rischio che contenuti malevoli o manomessi entrino in produzione. Anche i registry ospitati internamente necessitano di ownership chiara, review e una trust policy.

Docker Content Trust ha storicamente utilizzato i concetti di Notary e TUF per richiedere immagini firmate. L'ecosistema esatto si è evoluto, ma la lezione fondamentale rimane utile: l'identità e l'integrità dell'immagine dovrebbero essere verificabili anziché date per scontate.

Esempio di workflow storico di Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Il punto dell'esempio non è che ogni team debba continuare a utilizzare gli stessi strumenti, ma che la firma e la gestione delle chiavi sono attività operative, non teoria astratta.

## Scansione delle vulnerabilità

La scansione delle immagini aiuta a rispondere a due domande diverse. Innanzitutto, l'immagine contiene pacchetti o librerie con vulnerabilità note? In secondo luogo, l'immagine include software non necessario che amplia la attack surface? Un'immagine piena di strumenti di debug, shell, interpreti e pacchetti obsoleti è sia più facile da sfruttare sia più difficile da analizzare.

Esempi di scanner comunemente utilizzati includono:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
I risultati di questi strumenti devono essere interpretati con attenzione. Una vulnerabilità in un package inutilizzato non presenta lo stesso rischio di un percorso RCE esposto, ma entrambi sono comunque rilevanti per le decisioni di hardening.

## Build-Time Secrets

Uno degli errori più antichi nelle pipeline di build dei container consiste nell'includere direttamente i secrets nell'immagine o nel passarli tramite variabili d'ambiente che in seguito diventano visibili attraverso `docker inspect`, i log di build o i layer recuperati. I secrets di build devono essere montati temporaneamente durante la build, anziché essere copiati nel filesystem dell'immagine.

BuildKit ha migliorato questo modello consentendo una gestione dedicata dei secrets di build. Invece di scrivere un secret in un layer, lo step di build può utilizzarlo temporaneamente:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Questo è importante perché i livelli delle immagini sono artifact persistenti. Una volta che un secret entra in un layer sottoposto a commit, eliminare successivamente il file in un altro layer non rimuove realmente la disclosure originale dalla cronologia dell'immagine.

## Secret a runtime

I secret necessari a un workload in esecuzione dovrebbero inoltre evitare, quando possibile, pattern ad hoc come le variabili d'ambiente in chiaro. I volumi, le integrazioni dedicate per la gestione dei secret, Docker secrets e Kubernetes Secrets sono meccanismi comuni. Nessuno di questi elimina ogni rischio, soprattutto se l'attacker dispone già di code execution nel workload, ma sono comunque preferibili alla memorizzazione permanente delle credenziali nell'immagine o alla loro esposizione disinvolta tramite strumenti di ispezione.

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
In Kubernetes, gli oggetti Secret, i projected volumes, i service-account tokens e le cloud workload identities creano un modello più ampio e potente, ma anche più opportunità di esposizione accidentale attraverso host mounts, RBAC troppo permissivi o un design debole dei Pod.

## Abuso

Durante la revisione di un target, l'obiettivo è scoprire se i secrets sono stati incorporati nell'immagine, se sono trapelati nei layer o se sono stati montati in percorsi runtime prevedibili:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Questi comandi aiutano a distinguere tra tre problemi diversi: leak di configurazione dell’applicazione, leak nei layer dell’immagine e file di secret iniettati a runtime. Se un secret compare in `/run/secrets`, in un volume projected o in un percorso di token di identità cloud, il passaggio successivo consiste nel capire se concede accesso solo al workload corrente o a un control plane molto più ampio.

### Esempio completo: Secret incorporato nel filesystem dell’immagine

Se una build pipeline ha copiato file `.env` o credenziali nell’immagine finale, il post-exploitation diventa semplice:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impatto dipende dall'applicazione, ma signing keys incorporate, secret JWT o credenziali cloud possono facilmente trasformare la compromissione del container in una compromissione dell'API, lateral movement o falsificazione di token applicativi attendibili.

### Esempio completo: controllo del Secret Leakage in fase di build

Se il problema è che la history dell'immagine ha catturato un layer contenente un secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Questo tipo di revisione è utile perché un secret potrebbe essere stato eliminato dalla vista finale del filesystem pur rimanendo in un layer precedente o nei metadati della build.

## Controlli

Questi controlli servono a stabilire se l'immagine e la pipeline di gestione dei secret abbiano probabilmente aumentato la superficie di attacco prima del runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Cosa c'è di interessante qui:

- Una cronologia di build sospetta può rivelare credenziali copiate, materiale SSH o build steps non sicuri.
- I secrets nei percorsi dei projected volume possono portare all'accesso al cluster o al cloud, non soltanto all'accesso all'applicazione locale.
- Un numero elevato di file di configurazione con credenziali in plaintext indica solitamente che l'immagine o il modello di deployment stanno trasportando più materiale di trust del necessario.

## Default di runtime

| Runtime / platform | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker / BuildKit | Supporta secret mounts sicuri durante la build, ma non automaticamente | I secrets possono essere montati temporaneamente durante la `build`; image signing e scanning richiedono scelte esplicite nel workflow | copiare i secrets nell'immagine, passare i secrets tramite `ARG` o `ENV`, disabilitare i controlli sulla provenienza |
| Podman / Buildah | Supporta build OCI-native e workflow consapevoli dei secrets | Sono disponibili workflow di build sicuri, ma gli operatori devono comunque sceglierli intenzionalmente | incorporare i secrets nei Containerfile, contesti di build troppo ampi, bind mounts permissivi durante le build |
| Kubernetes | Oggetti Secret nativi e projected volumes | La distribuzione dei secrets a runtime è una funzionalità di primo livello, ma l'esposizione dipende da RBAC, dal design dei pod e dagli host mounts | Secret mounts troppo ampi, uso improprio dei service-account token, accesso `hostPath` ai volumi gestiti dal kubelet |
| Registries | L'integrità è opzionale, a meno che non venga applicata | I registries pubblici e privati dipendono entrambi da policy, signing e decisioni di admission | eseguire liberamente il pull di immagini non firmate, admission control debole, gestione inadeguata delle chiavi |

{{#include ../../../banners/hacktricks-training.md}}
