# Docker-Forensik

{{#include ../../banners/hacktricks-training.md}}

## Änderung des Containers

Es besteht der Verdacht, dass ein Docker-Container kompromittiert wurde:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Du kannst ganz einfach **Änderungen am Dateisystem dieses Containers seit seiner Erstellung finden** mit:<sup>[[1]](#references)</sup>
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
Im vorherigen Befehl steht **C** für **Geändert** und **A** für **Hinzugefügt**.<sup>[[1]](#references)</sup>\
Wenn Sie feststellen, dass eine interessante Datei wie `/etc/shadow` geändert wurde, können Sie sie aus dem Container herunterladen, um sie mit Folgendem auf bösartige Aktivitäten zu überprüfen:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Du kannst es auch mit dem Original vergleichen, indem du einen neuen Container startest und die Datei daraus extrahierst:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Wenn du feststellst, dass **eine verdächtige Datei hinzugefügt wurde**, kannst du auf den Container zugreifen und sie überprüfen:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Änderungen an Images

Wenn dir ein exportiertes Docker-Image (wahrscheinlich im `.tar`-Format) vorliegt, kannst du [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) verwenden, um **eine Zusammenfassung der Änderungen zu extrahieren**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dann kannst du das **Image dekomprimieren** und auf die **Blobs** zugreifen, um nach verdächtigen Dateien zu suchen, die du möglicherweise in der Änderungshistorie gefunden hast:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Grundlegende Analyse

Du kannst **grundlegende Informationen** aus dem Image erhalten, indem du Folgendes ausführst:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Sie können außerdem eine zusammengefasste **Änderungshistorie** abrufen mit:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
You can also generate a **dockerfile from an image** with:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Um hinzugefügte/geänderte Dateien in Docker-Images zu finden, kannst du auch das Dienstprogramm [**dive**](https://github.com/wagoodman/dive) verwenden (lade es aus den [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) herunter):<sup>[[11]](#references)[[12]](#references)</sup>

Lade das gespeicherte Archiv in Docker, bevor du dessen Image-Tag mit dive öffnest:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Damit kannst du **durch die verschiedenen Blobs von Docker-Images navigieren** und überprüfen, welche Dateien geändert, hinzugefügt oder entfernt wurden. Verwende **Tab**, um zur anderen Ansicht zu wechseln, und **Leertaste**, um Ordner ein- oder auszuklappen.<sup>[[11]](#references)</sup>

Mit dive kannst du nicht auf den Inhalt der verschiedenen Stages des Images zugreifen. Dazu musst du **jede Layer dekomprimieren und darauf zugreifen**.\
Du kannst alle Layer eines Images aus dem Verzeichnis dekomprimieren, in dem das Image dekomprimiert wurde, indem du Folgendes ausführst:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials aus dem Speicher

Unter Linux kann der übergeordnete PID-Namensraum des Hosts Prozesse im untergeordneten PID-Namensraum eines Containers sehen, sodass eine Prozessauflistung des Hosts wie `ps -ef` diese anzeigen kann.<sup>[[14]](#references)</sup>

Wenn die Host-Credentials, Capabilities und die LSM-/ptrace-Richtlinie dies erlauben, kann ein entsprechend privilegierter Host-Untersucher den **Prozessspeicher auslesen** und nach **Credentials** suchen, genau [**wie im folgenden Beispiel**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Docker-Container-Diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker-Container kopieren](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker-Container ausführen](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker-Container ausführen](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Analyzer-Definitionen von container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker-Image speichern](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker-Image untersuchen](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker-Image-Verlauf](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 Release](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker-Image laden](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
