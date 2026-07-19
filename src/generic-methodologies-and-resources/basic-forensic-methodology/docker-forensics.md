# Docker-Forensik

{{#include ../../banners/hacktricks-training.md}}


## Änderung des Containers

Es besteht der Verdacht, dass ein Docker-Container kompromittiert wurde:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Du kannst die am Container vorgenommenen Änderungen im Vergleich zum Image problemlos **finden** mit:
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
Im vorherigen Befehl steht **C** für **Changed** und **A** für **Added**.\
Wenn du feststellst, dass eine interessante Datei wie `/etc/shadow` verändert wurde, kannst du sie aus dem Container herunterladen, um sie auf bösartige Aktivitäten zu überprüfen:
```bash
docker cp wordpress:/etc/shadow.
```
Du kannst es auch **mit dem ursprünglichen vergleichen**, indem du einen neuen Container startest und die Datei daraus extrahierst:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Wenn du feststellst, dass **eine verdächtige Datei hinzugefügt wurde**, kannst du auf den Container zugreifen und sie überprüfen:
```bash
docker exec -it wordpress bash
```
## Änderungen an Images

Wenn Sie ein exportiertes Docker-Image (wahrscheinlich im `.tar`-Format) erhalten, können Sie [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) verwenden, um **eine Zusammenfassung der Änderungen zu extrahieren**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Anschließend können Sie das **Image dekomprimieren** und auf die **Blobs zugreifen**, um nach verdächtigen Dateien zu suchen, die Sie möglicherweise in der Änderungshistorie gefunden haben:
```bash
tar -xf image.tar
```
### Grundlegende Analyse

Du kannst **grundlegende Informationen** aus dem Image abrufen, indem du Folgendes ausführst:
```bash
docker inspect <image>
```
Du kannst außerdem eine zusammenfassende **Änderungshistorie** abrufen mit:
```bash
docker history --no-trunc <image>
```
Du kannst auch ein **dockerfile aus einem Image** generieren mit:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Um hinzugefügte/geänderte Dateien in Docker images zu finden, kannst du auch das Dienstprogramm [**dive**](https://github.com/wagoodman/dive) verwenden (lade es aus den [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) herunter):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dies ermöglicht es dir, **durch die verschiedenen Blobs von Docker images zu navigieren** und zu überprüfen, welche Dateien geändert oder hinzugefügt wurden. **Rot** bedeutet hinzugefügt und **gelb** bedeutet geändert. Verwende **tab**, um zur anderen Ansicht zu wechseln, und **space**, um Ordner zu reduzieren/zu öffnen.

Mit die kannst du nicht auf den Inhalt der verschiedenen stages des Images zugreifen. Dazu musst du **jede Ebene dekomprimieren und darauf zugreifen**.\
Du kannst alle Ebenen eines Images aus dem Verzeichnis dekomprimieren, in dem das Image dekomprimiert wurde, indem du Folgendes ausführst:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials aus dem Speicher

Beachte, dass du, wenn du einen Docker-Container innerhalb eines Hosts ausführst, **die im Container laufenden Prozesse vom Host aus sehen kannst**, indem du einfach `ps -ef` ausführst.

Daher kannst du (als root) den **Speicher der Prozesse** vom Host aus **dumpen** und nach **Credentials** suchen, genau [**wie im folgenden Beispiel**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
