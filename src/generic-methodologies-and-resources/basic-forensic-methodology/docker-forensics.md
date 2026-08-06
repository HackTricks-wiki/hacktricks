# Docker Forensiese Ondersoek

{{#include ../../banners/hacktricks-training.md}}

## Wysiging van container

Daar bestaan vermoedens dat ’n Docker-container gekompromitteer is:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Jy kan maklik **die wysigings wat aan hierdie container met betrekking tot die image aangebring is** vind met:
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
In die vorige opdrag beteken **C** **Gewysig** en **A,** **Bygevoeg**.\
As jy vind dat ’n interessante lêer soos `/etc/shadow` gewysig is, kan jy dit vanaf die container aflaai om dit vir kwaadwillige aktiwiteit na te gaan met:
```bash
docker cp wordpress:/etc/shadow.
```
Jy kan dit ook **met die oorspronklike een vergelyk** deur ’n nuwe container te laat loop en die lêer daaruit te onttrek:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
As jy vind dat **’n verdagte lêer bygevoeg is**, kan jy toegang tot die container verkry en dit nagaan:
```bash
docker exec -it wordpress bash
```
## Wysigings aan Docker images

Wanneer jy ’n uitgevoerde Docker image kry (waarskynlik in `.tar`-formaat), kan jy [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) gebruik om **’n opsomming van die wysigings te onttrek**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Daarna kan jy die image **decompress** en **toegang tot die blobs verkry** om na verdagte lêers te soek wat jy moontlik in die change history gevind het:
```bash
tar -xf image.tar
```
### Basiese Analise

Jy kan **basiese inligting** uit die image verkry deur die volgende uit te voer:
```bash
docker inspect <image>
```
Jy kan ook ’n opsomming van die **geskiedenis van veranderinge** kry met:
```bash
docker history --no-trunc <image>
```
Jy kan ook ’n **dockerfile uit ’n image** genereer met:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Om bygevoegde/gewysigde lêers in Docker images te vind, kan jy ook die [**dive**](https://github.com/wagoodman/dive) (laai dit af vanaf [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0))-utility gebruik:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dit laat jou toe om **deur die verskillende blobs van Docker images te navigeer** en te kontroleer watter lêers gewysig/bygevoeg is. **Rooi** beteken bygevoeg en **geel** beteken gewysig. Gebruik **tab** om na die ander aansig te beweeg en **spasie** om vouers in te vou/oop te maak.

Met die kan jy nie toegang tot die inhoud van die verskillende stadiums van die image kry nie. Om dit te doen, sal jy **elke layer moet decomprimeer en toegang daartoe kry**.\
Jy kan al die layers van ’n image decomprimeer vanuit die gids waar die image gedecomprimeer is deur die volgende uit te voer:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials uit geheue

Let daarop dat wanneer jy 'n docker container binne 'n host laat loop, **jy die prosesse wat in die container loop vanaf die host kan sien** deur net `ps -ef` uit te voer.

Daarom kan jy (as root) **die geheue van die prosesse** vanaf die host **dump** en vir **credentials** soek, net [**soos in die volgende voorbeeld**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).

{{#include ../../banners/hacktricks-training.md}}
