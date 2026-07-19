# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace UTS isola il **hostname** e il **NIS domain name** visualizzati dal processo. A prima vista può sembrare un aspetto trascurabile rispetto ai mount, PID o user namespaces, ma fa parte di ciò che permette a un container di apparire come il proprio host. All'interno del namespace, il workload può visualizzare e talvolta modificare un hostname locale a quel namespace, anziché globale per la macchina.

Da solo, questo di solito non è l'elemento centrale di una breakout story. Tuttavia, quando il namespace UTS dell'host è condiviso, un processo sufficientemente privilegiato può influenzare le impostazioni relative all'identità dell'host, cosa che può avere rilevanza operativa e occasionalmente anche per la sicurezza.

## Lab

Puoi creare un namespace UTS con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Il cambio del hostname rimane locale a quel namespace e non modifica il hostname globale dell'host. Questa è una dimostrazione semplice ma efficace della proprietà di isolamento.

## Utilizzo a runtime

I container normali ottengono un UTS namespace isolato. Docker e Podman possono entrare nel UTS namespace dell'host tramite `--uts=host`, e pattern simili di condivisione dell'host possono comparire in altri runtime e sistemi di orchestrazione. Tuttavia, nella maggior parte dei casi, l'isolamento UTS privato fa semplicemente parte della normale configurazione del container e richiede poca attenzione da parte dell'operatore.

## Impatto sulla sicurezza

Sebbene il UTS namespace non sia solitamente quello più pericoloso da condividere, contribuisce comunque all'integrità del confine del container. Se il UTS namespace dell'host è esposto e il processo dispone dei privilegi necessari, potrebbe essere in grado di modificare le informazioni relative all'hostname dell'host. Ciò potrebbe influire sul monitoring, sul logging, sulle assunzioni operative o sugli script che prendono decisioni di trust basate sui dati relativi all'identità dell'host.

## Abuso

Se il UTS namespace dell'host è condiviso, la domanda pratica è se il processo possa modificare le impostazioni relative all'identità dell'host invece di limitarsi a leggerle:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Se il container dispone anche del privilegio necessario, verifica se è possibile modificare l'hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Questo riguarda principalmente l'integrità e l'impatto operativo, piuttosto che un escape completo, ma dimostra comunque che il container può influenzare direttamente una proprietà globale dell'host.

Impatto:

- manomissione dell'identità dell'host
- confusione nei log, nel monitoring o nell'automazione che si affidano al hostname
- generalmente non consente un escape completo da solo, a meno che non venga combinato con altre vulnerabilità

Negli ambienti in stile Docker, un pattern utile per il rilevamento lato host è:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
I container che mostrano `UTSMode=host` condividono il namespace UTS dell'host e devono essere esaminati con maggiore attenzione se dispongono anche di capabilities che consentono loro di chiamare `sethostname()` o `setdomainname()`.

## Verifiche

Questi comandi sono sufficienti per verificare se il workload dispone di una propria vista del hostname o se condivide il namespace UTS dell'host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Cosa è interessante qui:

- La corrispondenza tra gli identificatori dei namespace e un processo host può indicare la condivisione del namespace UTS con l'host.
- Se la modifica dell'hostname influisce su qualcosa oltre al container stesso, il workload ha più influenza sull'identità dell'host di quanto dovrebbe.
- Questo di solito ha una priorità inferiore rispetto ai problemi relativi ai namespace PID, mount o user, ma conferma comunque quanto il processo sia realmente isolato.

Nella maggior parte degli ambienti, il namespace UTS va considerato come un livello di isolamento di supporto. Raramente è la prima cosa da esaminare durante un breakout, ma fa comunque parte della coerenza e della sicurezza complessive della vista del container.
{{#include ../../../../../banners/hacktricks-training.md}}
