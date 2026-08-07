# Namespace UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace UTS isola il **hostname** e il **nome di dominio NIS** visualizzati dal processo. A prima vista, questo può sembrare banale rispetto ai namespace mount, PID o user, ma fa parte di ciò che consente a un container di apparire come il proprio host. All'interno del namespace, il workload può visualizzare e talvolta modificare un hostname locale a quel namespace anziché globale per la macchina.

Da solo, questo di solito non è l'elemento centrale di uno scenario di breakout. Tuttavia, quando il namespace UTS dell'host è condiviso, un processo sufficientemente privilegiato può influenzare le impostazioni relative all'identità dell'host, cosa che può avere rilevanza operativa e, occasionalmente, anche per la sicurezza.

## Lab

È possibile creare un namespace UTS con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
La modifica dell'hostname rimane locale a quel namespace e non altera l'hostname globale dell'host. Questa è una dimostrazione semplice ma efficace della proprietà di isolamento.

## Utilizzo a runtime

I container normali ricevono un namespace UTS isolato. Docker e Podman possono unirsi al namespace UTS dell'host tramite `--uts=host`, e pattern simili di condivisione dell'host possono comparire in altri runtime e sistemi di orchestrazione. Nella maggior parte dei casi, tuttavia, l'isolamento UTS privato fa semplicemente parte della normale configurazione del container e richiede poca attenzione da parte dell'operatore.

## Impatto sulla sicurezza

Anche se il namespace UTS non è solitamente quello più pericoloso da condividere, contribuisce comunque all'integrità del confine del container. Se il namespace UTS dell'host è esposto e il processo dispone dei privilegi necessari, potrebbe essere in grado di modificare le informazioni relative all'hostname dell'host. Ciò può influire sul monitoring, sul logging, sulle ipotesi operative o sugli script che prendono decisioni di trust basandosi sui dati relativi all'identità dell'host.

## Abuse

Se il namespace UTS dell'host è condiviso, la questione pratica è stabilire se il processo può modificare le impostazioni relative all'identità dell'host, anziché limitarsi a leggerle:
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
Si tratta principalmente di un problema di integrità e di impatto operativo, piuttosto che di un full escape, ma dimostra comunque che il container può influenzare direttamente una proprietà globale dell'host.

Impatto:

- manomissione dell'identità dell'host
- log, monitoraggio o automazione fuorvianti che si fidano dell'hostname
- di solito non è un full escape autonomamente, a meno che non venga combinato con altre vulnerabilità

Negli ambienti in stile Docker, un pattern utile per il rilevamento lato host è:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
I container che mostrano `UTSMode=host` condividono il namespace UTS dell'host e dovrebbero essere esaminati con maggiore attenzione se dispongono anche di capabilities che consentono di chiamare `sethostname()` o `setdomainname()`.

## Verifiche

Questi comandi sono sufficienti per verificare se il workload dispone di una propria visualizzazione dell'hostname o condivide il namespace UTS dell'host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Cosa è interessante qui:

- La corrispondenza tra gli identificatori del namespace e quelli di un processo host può indicare la condivisione del namespace UTS con l'host.
- Se la modifica del hostname influisce su qualcosa oltre al container stesso, il workload ha più influenza sull'identità dell'host di quanta dovrebbe.
- Questa è generalmente una finding con priorità inferiore rispetto ai problemi relativi ai namespace PID, mount o user, ma conferma comunque quanto il processo sia realmente isolato.

Nella maggior parte degli ambienti, il namespace UTS va considerato soprattutto come un layer di isolamento di supporto. Raramente è la prima cosa da analizzare durante un breakout, ma fa comunque parte della coerenza e della sicurezza complessive della vista del container.

{{#include ../../../../../banners/hacktricks-training.md}}
