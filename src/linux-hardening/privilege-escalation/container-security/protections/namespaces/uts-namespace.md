# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il UTS namespace isola il **hostname** e il **NIS domain name** visibili al processo. A prima vista questo può sembrare banale rispetto ai namespace mount, PID o user, ma è parte di ciò che fa sembrare un container il proprio host. All'interno del namespace, la workload può vedere e talvolta modificare un hostname che è locale a quel namespace anziché globale per la macchina.

Di per sé, questo di solito non è il fulcro di una storia di breakout. Tuttavia, una volta che l'host UTS namespace è condiviso, un processo sufficientemente privilegiato può influenzare impostazioni legate all'identità dell'host, che possono avere rilevanza operativa e talvolta di sicurezza.

## Laboratorio

Puoi creare un UTS namespace con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
La modifica del hostname rimane locale a quell'UTS namespace e non altera l'hostname globale dell'host. Questa è una dimostrazione semplice ma efficace della proprietà di isolamento.

## Uso a runtime

I container normali ottengono un UTS namespace isolato. Docker e Podman possono unirsi all'UTS namespace dell'host tramite `--uts=host`, e schemi simili di condivisione dell'host possono apparire in altri runtime e sistemi di orchestrazione. Tuttavia, nella maggior parte dei casi, l'isolamento UTS privato è semplicemente parte della normale configurazione del container e richiede poca attenzione da parte dell'operatore.

## Impatto sulla sicurezza

Anche se l'UTS namespace di solito non è il più pericoloso da condividere, contribuisce comunque all'integrità del confine del container. Se l'UTS namespace dell'host è esposto e il processo ha i privilegi necessari, potrebbe essere in grado di modificare informazioni relative all'hostname dell'host. Ciò può influire sul monitoring, sul logging, sulle assunzioni operative o su script che prendono decisioni di fiducia basate sui dati di identità dell'host.

## Abuso

Se l'UTS namespace dell'host è condiviso, la questione pratica è se il processo può modificare le impostazioni di identità dell'host invece di limitarsi a leggerle:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Se il container ha anche il privilegio necessario, verifica se l'hostname può essere cambiato:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Questo è principalmente un problema di integrità e di impatto operativo piuttosto che una escape completa, ma dimostra comunque che il container può influenzare direttamente una proprietà globale dell'host.

Impatto:

- manomissione dell'identità dell'host
- confusione nei log, nel monitoring o nelle automazioni che si basano sul hostname
- di solito non è una escape completa da sola a meno che non sia combinata con altre debolezze

Negli ambienti in stile Docker, un utile pattern di rilevamento lato host è:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
I container che mostrano `UTSMode=host` condividono il namespace UTS dell'host e dovrebbero essere esaminati con maggiore attenzione se dispongono anche di capabilities che permettono loro di chiamare `sethostname()` o `setdomainname()`.

## Controlli

Questi comandi sono sufficienti per vedere se il workload ha una propria vista dell'hostname o sta condividendo il namespace UTS dell'host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Cosa c'è di interessante:

- La corrispondenza degli identificatori di namespace con un processo host può indicare la condivisione dell'UTS namespace con l'host.
- Se la modifica del hostname influisce su più del solo container, il workload ha più influenza sull'identità dell'host di quanto dovrebbe.
- Si tratta di solito di un riscontro a bassa priorità rispetto a problemi relativi a PID, mount o user namespace, ma conferma comunque quanto il processo sia realmente isolato.

Nella maggior parte degli ambienti, l'UTS namespace va considerato come un livello di isolamento di supporto. Raramente è la prima cosa che si cerca in un breakout, ma resta parte della coerenza e della sicurezza complessiva della vista del container.
{{#include ../../../../../banners/hacktricks-training.md}}
