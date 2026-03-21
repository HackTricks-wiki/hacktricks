# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace UTS isola il **hostname** e il **NIS domain name** visti dal processo. A prima vista questo può sembrare banale rispetto a mount, PID, o user namespaces, ma fa parte di ciò che fa apparire un container come se fosse il proprio host. All'interno del namespace, il workload può vedere e talvolta modificare un hostname che è locale a quel namespace invece che globale per la macchina.

Da solo, questo di solito non è il nucleo di una storia di breakout. Tuttavia, una volta che il host UTS namespace è condiviso, un processo con privilegi sufficienti può influenzare le impostazioni relative all'identità dell'host, il che può avere rilevanza operativa e occasionalmente a livello di sicurezza.

## Lab

Puoi creare un UTS namespace con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
La modifica del nome host rimane locale a quel namespace e non altera il nome host globale dell'host. Questa è una dimostrazione semplice ma efficace della proprietà di isolamento.

## Uso a runtime

I container normali ottengono un UTS namespace isolato. Docker e Podman possono unirsi all'UTS namespace dell'host tramite `--uts=host`, e schemi simili di condivisione con l'host possono apparire in altri runtimes e sistemi di orchestrazione. Nella maggior parte dei casi, comunque, l'isolamento UTS privato fa semplicemente parte della normale configurazione del container e richiede poca attenzione da parte dell'operatore.

## Impatto sulla sicurezza

Anche se l'UTS namespace di solito non è il più pericoloso da condividere, contribuisce comunque all'integrità del confine del container. Se l'UTS namespace dell'host è esposto e il processo dispone dei privilegi necessari, può essere in grado di modificare le informazioni relative al hostname dell'host. Ciò può influenzare il monitoring, il logging, le ipotesi operative o script che prendono decisioni di fiducia basate sui dati di identità dell'host.

## Abuso

Se l'UTS namespace dell'host è condiviso, la domanda pratica è se il processo può modificare le impostazioni di identità dell'host invece di limitarsi a leggerle:
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
Si tratta principalmente di un problema di integrità e di impatto operativo più che di un escape completo, ma mostra comunque che il container può influenzare direttamente una proprietà globale dell'host.

Impatto:

- manomissione dell'identità dell'host
- confondere i log, il monitoring o le automazioni che si fidano dell'hostname
- di solito non è un escape completo da solo a meno che non sia combinato con altre debolezze

Negli ambienti in stile Docker, un pattern di rilevamento lato host utile è:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
I container che mostrano `UTSMode=host` condividono il namespace UTS dell'host e dovrebbero essere esaminati con maggiore attenzione se possiedono anche delle capability che consentono loro di chiamare `sethostname()` o `setdomainname()`.

## Controlli

Questi comandi sono sufficienti per verificare se il carico di lavoro ha la propria vista del nome host o sta condividendo il namespace UTS dell'host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- La corrispondenza degli identificatori di namespace con un processo host può indicare host UTS sharing.
- Se cambiare l'hostname influisce su più del solo container, il workload ha più influenza sull'identità dell'host di quanto dovrebbe.
- Questo di solito è un riscontro di priorità inferiore rispetto ai problemi di PID, mount o user namespace, ma conferma comunque quanto un processo sia effettivamente isolato.

Nella maggior parte degli ambienti, l'UTS namespace va considerato come uno strato di isolamento di supporto. Raramente è la prima cosa che insegui in un breakout, ma fa comunque parte della coerenza complessiva e della sicurezza della container view.
