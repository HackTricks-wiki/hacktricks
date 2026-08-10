# Docker Forensics

## Modifica del container

Si sospetta che un container Docker sia stato compromesso:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Puoi facilmente **individuare le modifiche apportate al filesystem di questo container dalla sua creazione** con:<sup>[[1]](#references)</sup>
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
Nel comando precedente **C** significa **Changed** e **A** significa **Added**.<sup>[[1]](#references)</sup>\
Se scopri che un file interessante come `/etc/shadow` è stato modificato, puoi scaricarlo dal container per verificare la presenza di attività malevole con:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Puoi anche **confrontarlo con quello originale** eseguendo un nuovo container ed estraendo il file da esso:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Se rilevi che è stato aggiunto **un file sospetto**, puoi accedere al container e controllarlo:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Modifiche alle immagini

Quando ti viene fornita un'immagine docker esportata (probabilmente in formato `.tar`), puoi usare [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) per **estrarre un riepilogo delle modifiche**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Quindi, puoi **decomprimere** l'immagine e **accedere ai blob** per cercare file sospetti che potresti aver trovato nella cronologia delle modifiche:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Analisi di base

È possibile ottenere **informazioni di base** dall'immagine eseguendo:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Puoi anche ottenere una **cronologia riepilogativa delle modifiche** con:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Puoi anche generare un **dockerfile da un'immagine** con:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Per individuare i file aggiunti/modificati nelle immagini Docker puoi anche usare l'utilità [**dive**](https://github.com/wagoodman/dive) (scaricala dalle [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0):<sup>[[11]](#references)[[12]](#references)</sup>

Carica l'archivio salvato in Docker prima di aprire il relativo image tag con dive:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Questo ti permette di **navigare tra i diversi blob delle docker images** e verificare quali file sono stati modificati/aggiunti/rimossi. Usa **tab** per passare all'altra vista e **space** per comprimere/espandere le cartelle.<sup>[[11]](#references)</sup>

Con dive non potrai accedere al contenuto dei diversi stage dell'immagine. Per farlo dovrai **decomprimere ogni layer e accedervi**.\
Puoi decomprimere tutti i layer di un'immagine dalla directory in cui l'immagine è stata decompressa eseguendo:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenziali dalla memoria

Su Linux, il PID namespace antenato dell'host può vedere i processi nel PID namespace figlio di un container, quindi un elenco dei processi dell'host come `ps -ef` può mostrarli.<sup>[[14]](#references)</sup>

Quando le credenziali dell'host, le capabilities e la policy LSM/ptrace lo consentono, un investigatore dell'host con privilegi appropriati può **dumpare la memoria dei processi** e cercare **credenziali** proprio [**come nell'esempio seguente**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [diff del container Docker](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [cp del container Docker](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [run del container Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [exec del container Docker](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [definizioni degli analyzer di container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [save dell'immagine Docker](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [inspect dell'immagine Docker](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [history dell'immagine Docker](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [README di Dive v0.10.0](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [release di Dive v0.10.0](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [load dell'immagine Docker](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
