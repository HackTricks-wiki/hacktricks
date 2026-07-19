# Docker Forensika

{{#include ../../banners/hacktricks-training.md}}


## Wysiging van container

Daar is vermoedens dat een Docker-container gekompromitteer is:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Jy kan maklik **die wysigings wat aan hierdie container in verhouding tot die image aangebring is, vind** met:
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
In die vorige opdrag beteken **C** **Changed** en **A,** **Added**.\
As jy vind dat ’n interessante lêer soos `/etc/shadow` gewysig is, kan jy dit vanaf die container aflaai om vir kwaadwillige aktiwiteit te kontroleer met:
```bash
docker cp wordpress:/etc/shadow.
```
Jy kan dit ook **met die oorspronklike vergelyk** deur ’n nuwe container te begin en die lêer daaruit te onttrek:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
As jy vind dat **’n verdagte lêer bygevoeg is**, kan jy toegang tot die container verkry en dit nagaan:
```bash
docker exec -it wordpress bash
```
## Wysigings aan Images

Wanneer jy ’n geëksporteerde docker image (waarskynlik in `.tar`-formaat) kry, kan jy [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) gebruik om **’n opsomming van die wysigings te onttrek**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dan kan jy die **image dekomprimeer** en **toegang tot die blobs verkry** om te soek na verdagte lêers wat jy moontlik in die veranderingsgeskiedenis gevind het:
```bash
tar -xf image.tar
```
### Basiese Analise

Jy kan **basiese inligting** uit die image verkry deur die volgende uit te voer:
```bash
docker inspect <image>
```
Jy kan ook ’n opsomming van die **veranderingsgeskiedenis** kry met:
```bash
docker history --no-trunc <image>
```
Jy kan ook ’n **dockerfile** vanaf ’n image genereer met:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Om bygevoegde/gewysigde lêers in Docker images te vind, kan jy ook die [**dive**](https://github.com/wagoodman/dive) [(laai dit van **releases** af)](https://github.com/wagoodman/dive/releases/tag/v0.10.0)-hulpmiddel gebruik:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dit stel jou in staat om **deur die verskillende blobs van Docker images te navigeer** en te kontroleer watter lêers gewysig/bygevoeg is. **Rooi** beteken bygevoeg en **geel** beteken gewysig. Gebruik **tab** om na die ander aansig te beweeg en **space** om vouers toe te vou/oop te maak.

Met die kan jy nie toegang tot die inhoud van die verskillende stadiums van die image kry nie. Om dit te doen, moet jy **elke layer dekomprimeer en toegang daartoe verkry**.\
Jy kan al die layers van ’n image dekomprimeer vanuit die gids waar die image gedekomprimeer is deur die volgende uit te voer:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials uit geheue

Let daarop dat wanneer jy ’n docker container binne ’n host uitvoer **jy die prosesse wat in die container loop vanaf die host kan sien** deur eenvoudig `ps -ef` uit te voer.

Daarom kan jy (as root) **die geheue van die prosesse** vanaf die host **dump** en vir **credentials** soek, [**soos in die volgende voorbeeld**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
