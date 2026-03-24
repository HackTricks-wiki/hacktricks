# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Lo UTS namespace isola l'**hostname** e il **NIS domain name** visibili al processo. A prima vista questo può sembrare banale rispetto a mount, PID o user namespaces, ma è parte di ciò che fa apparire un container come un host a sé stante. All'interno del namespace, il workload può vedere e talvolta modificare un hostname che è locale a quel namespace piuttosto che globale per la macchina.

Di per sé, questo di solito non è il fulcro di una storia di breakout. Tuttavia, una volta che l'UTS namespace dell'host viene condiviso, un processo con privilegi sufficienti può influenzare le impostazioni relative all'identità dell'host, cosa che può avere rilevanza operativa e, occasionalmente, anche dal punto di vista della sicurezza.

## Lab

Puoi creare un UTS namespace con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
La modifica del hostname rimane locale a quel namespace e non altera il hostname globale dell'host. Questa è una semplice ma efficace dimostrazione della proprietà di isolamento.

## Utilizzo a runtime

I container normali ottengono un UTS namespace isolato. Docker e Podman possono unirsi all'UTS namespace dell'host tramite `--uts=host`, e schemi simili di condivisione con l'host possono apparire in altri runtime e sistemi di orchestrazione. Nella maggior parte dei casi, comunque, l'isolamento UTS privato fa semplicemente parte della normale configurazione dei container e richiede poca attenzione da parte dell'operatore.

## Impatto sulla sicurezza

Anche se l'UTS namespace di solito non è il più pericoloso da condividere, contribuisce comunque all'integrità del confine del container. Se l'UTS namespace dell'host è esposto e il processo dispone dei privilegi necessari, potrebbe essere in grado di alterare le informazioni legate al hostname dell'host. Ciò può influenzare il monitoraggio, la registrazione, le ipotesi operative o script che prendono decisioni di fiducia basate sui dati di identità dell'host.

## Abuso

Se l'UTS namespace dell'host è condiviso, la domanda pratica è se il processo possa modificare le impostazioni di identità dell'host invece di limitarsi a leggerle:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Se il container ha anche il privilegio necessario, verifica se il nome host può essere cambiato:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Questo è principalmente un problema di integrità e di impatto operativo piuttosto che una full escape, ma dimostra comunque che il container può influenzare direttamente una proprietà globale dell'host.

Impatto:

- manomissione dell'identità dell'host
- confondere logs, monitoring o automation che si affidano allo hostname
- di solito non è una full escape di per sé, a meno che non sia combinata con altre debolezze

Negli ambienti in stile Docker, un utile pattern di rilevamento lato host è:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
I container che mostrano `UTSMode=host` condividono lo UTS namespace dell'host e dovrebbero essere esaminati più attentamente se possiedono anche capabilities che consentono loro di chiamare `sethostname()` o `setdomainname()`.

## Controlli

Questi comandi sono sufficienti per vedere se il workload ha la propria vista del hostname o sta condividendo lo UTS namespace dell'host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Cosa c'è di interessante qui:

- La corrispondenza degli identificatori di namespace con un processo host può indicare una condivisione dell'UTS con l'host.
- Se la modifica dell'hostname influisce su più del solo container, il carico di lavoro ha più influenza sull'identità dell'host di quanto dovrebbe.
- Questo è di solito un riscontro a bassa priorità rispetto a problemi di PID, mount o user namespace, ma conferma comunque quanto il processo sia realmente isolato.

Nella maggior parte degli ambienti, l'UTS namespace va considerato soprattutto come un livello di isolamento di supporto. Raramente è la prima cosa che si insegue in un breakout, ma rimane comunque parte della coerenza e della sicurezza complessiva della vista del container.
{{#include ../../../../../banners/hacktricks-training.md}}
