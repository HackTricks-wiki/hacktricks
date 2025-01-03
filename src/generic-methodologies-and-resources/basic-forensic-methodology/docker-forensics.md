# Docker Forensik

{{#include ../../banners/hacktricks-training.md}}


## Containeränderung

Es gibt Verdachtsmomente, dass ein bestimmter Docker-Container kompromittiert wurde:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Sie können die **Änderungen, die an diesem Container im Hinblick auf das Image vorgenommen wurden**, leicht mit folgendem Befehl finden:
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
Im vorherigen Befehl bedeutet **C** **Geändert** und **A,** **Hinzugefügt**.\
Wenn Sie feststellen, dass eine interessante Datei wie `/etc/shadow` geändert wurde, können Sie sie aus dem Container herunterladen, um nach bösartiger Aktivität zu suchen mit:
```bash
docker cp wordpress:/etc/shadow.
```
Sie können es auch **mit dem Original vergleichen**, indem Sie einen neuen Container ausführen und die Datei daraus extrahieren:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Wenn Sie feststellen, dass **eine verdächtige Datei hinzugefügt wurde**, können Sie auf den Container zugreifen und ihn überprüfen:
```bash
docker exec -it wordpress bash
```
## Bildermodifikationen

Wenn Ihnen ein exportiertes Docker-Image (wahrscheinlich im `.tar`-Format) gegeben wird, können Sie [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) verwenden, um **eine Zusammenfassung der Modifikationen** zu **extrahieren**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dann können Sie das Image **dekomprimieren** und die **Blobs** zugreifen, um nach verdächtigen Dateien zu suchen, die Sie möglicherweise in der Änderungsverlauf gefunden haben:
```bash
tar -xf image.tar
```
### Grundlegende Analyse

Sie können **grundlegende Informationen** aus dem Image erhalten, indem Sie Folgendes ausführen:
```bash
docker inspect <image>
```
Sie können auch eine Zusammenfassung **der Änderungen** mit folgendem Befehl erhalten:
```bash
docker history --no-trunc <image>
```
Sie können auch ein **dockerfile aus einem Image** mit folgendem Befehl generieren:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Um hinzugefügte/ändernde Dateien in Docker-Images zu finden, können Sie auch das [**dive**](https://github.com/wagoodman/dive) (laden Sie es von [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0))-Dienstprogramm verwenden:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dies ermöglicht es Ihnen, **durch die verschiedenen Blobs von Docker-Images zu navigieren** und zu überprüfen, welche Dateien geändert/hinzugefügt wurden. **Rot** bedeutet hinzugefügt und **gelb** bedeutet geändert. Verwenden Sie **Tab**, um zur anderen Ansicht zu wechseln, und **Leertaste**, um Ordner zu minimieren/öffnen.

Mit dies können Sie nicht auf den Inhalt der verschiedenen Stufen des Images zugreifen. Um dies zu tun, müssen Sie **jede Schicht dekomprimieren und darauf zugreifen**.\
Sie können alle Schichten eines Images aus dem Verzeichnis, in dem das Image dekomprimiert wurde, dekomprimieren, indem Sie Folgendes ausführen:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Anmeldeinformationen aus dem Speicher

Beachten Sie, dass Sie, wenn Sie einen Docker-Container auf einem Host ausführen, **die auf dem Container laufenden Prozesse vom Host aus sehen können**, indem Sie einfach `ps -ef` ausführen.

Daher können Sie (als root) **den Speicher der Prozesse** vom Host aus dumpen und nach **Anmeldeinformationen** suchen, **genau wie im folgenden Beispiel** [**dargestellt**](../../linux-hardening/privilege-escalation/#process-memory). 

{{#include ../../banners/hacktricks-training.md}}
