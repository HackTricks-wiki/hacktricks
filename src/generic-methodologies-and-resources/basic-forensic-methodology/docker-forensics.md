# Analisi forense Docker

{{#include ../../banners/hacktricks-training.md}}


## Modifica del container

Si sospetta che un container Docker sia stato compromesso:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Puoi facilmente **trovare le modifiche apportate a questo container rispetto all'immagine** con:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
Nel comando precedente **C** significa **Changed** e **A,** **Added**.\
Se trovi che qualche file interessante, come `/etc/shadow`, è stato modificato, puoi scaricarlo dal container per verificare la presenza di attività malevole con:
```bash
docker cp wordpress:/etc/shadow.
```
Puoi anche **confrontarlo con quello originale** avviando un nuovo container ed estraendo il file da esso:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Se rilevi che **è stato aggiunto qualche file sospetto**, puoi accedere al container e controllarlo:
```bash
docker exec -it wordpress bash
```
## Modifiche alle immagini

Quando ti viene fornita un'immagine docker esportata (probabilmente in formato `.tar`), puoi usare [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) per **estrarre un riepilogo delle modifiche**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Quindi, puoi **decomprimere** l'immagine e **accedere ai blobs** per cercare file sospetti che potresti aver trovato nella cronologia delle modifiche:
```bash
tar -xf image.tar
```
### Analisi di base

Puoi ottenere **informazioni di base** dall'immagine eseguendo:
```bash
docker inspect <image>
```
Puoi anche ottenere un riepilogo della **cronologia delle modifiche** con:
```bash
docker history --no-trunc <image>
```
Puoi anche generare un **dockerfile** da un'immagine con:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Per trovare i file aggiunti/modificati nelle immagini docker puoi anche usare l'utility [**dive**](https://github.com/wagoodman/dive) (scaricala dalle [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Questo permette di **navigare tra i diversi blob delle docker images** e verificare quali file sono stati modificati/aggiunti. **Rosso** indica gli elementi aggiunti e **giallo** quelli modificati. Usa **tab** per passare all'altra vista e **space** per comprimere/espandere le cartelle.

Con die non potrai accedere al contenuto dei diversi stage dell'immagine. Per farlo dovrai **decomprimere ogni layer e accedervi**.\
Puoi decomprimere tutti i layer di un'immagine dalla directory in cui l'immagine è stata decompressa, eseguendo:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenziali dalla memoria

Nota che quando esegui un container docker all'interno di un host **puoi vedere i processi in esecuzione nel container dall'host** eseguendo semplicemente `ps -ef`

Pertanto (come root) puoi **eseguire il dump della memoria dei processi** dall'host e cercare le **credenziali** proprio [**come nell'esempio seguente**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
