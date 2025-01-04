# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Modifica del contenitore

Ci sono sospetti che alcuni contenitori docker siano stati compromessi:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Puoi facilmente **trovare le modifiche apportate a questo contenitore rispetto all'immagine** con:
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
Nel comando precedente, **C** significa **Cambiato** e **A** significa **Aggiunto**.\
Se scopri che un file interessante come `/etc/shadow` è stato modificato, puoi scaricarlo dal container per controllare attività malevole con:
```bash
docker cp wordpress:/etc/shadow.
```
Puoi anche **confrontarlo con l'originale** eseguendo un nuovo container ed estraendo il file da esso:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Se scopri che **è stato aggiunto un file sospetto** puoi accedere al container e controllarlo:
```bash
docker exec -it wordpress bash
```
## Modifiche alle immagini

Quando ti viene fornita un'immagine docker esportata (probabilmente in formato `.tar`), puoi utilizzare [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) per **estrarre un riepilogo delle modifiche**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Poi, puoi **decomprimere** l'immagine e **accedere ai blob** per cercare file sospetti che potresti aver trovato nella cronologia delle modifiche:
```bash
tar -xf image.tar
```
### Analisi di Base

Puoi ottenere **informazioni di base** dall'immagine eseguendo:
```bash
docker inspect <image>
```
Puoi anche ottenere un riepilogo **storia delle modifiche** con:
```bash
docker history --no-trunc <image>
```
Puoi anche generare un **dockerfile da un'immagine** con:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Per trovare file aggiunti/modificati nelle immagini docker puoi anche utilizzare il [**dive**](https://github.com/wagoodman/dive) (scaricalo da [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Questo ti consente di **navigare attraverso i diversi blob delle immagini docker** e controllare quali file sono stati modificati/aggiunti. **Rosso** significa aggiunto e **giallo** significa modificato. Usa **tab** per passare alla vista successiva e **space** per comprimere/aprire le cartelle.

Con die non sarai in grado di accedere al contenuto dei diversi stadi dell'immagine. Per farlo, dovrai **decomprimere ogni strato e accedervi**.\
Puoi decomprimere tutti gli strati di un'immagine dalla directory in cui l'immagine è stata decompressa eseguendo:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenziali dalla memoria

Nota che quando esegui un container docker all'interno di un host **puoi vedere i processi in esecuzione sul container dall'host** semplicemente eseguendo `ps -ef`

Pertanto (come root) puoi **estrarre la memoria dei processi** dall'host e cercare **credenziali** proprio [**come nel seguente esempio**](../../linux-hardening/privilege-escalation/index.html#process-memory).

{{#include ../../banners/hacktricks-training.md}}
