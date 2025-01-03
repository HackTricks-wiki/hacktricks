# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Container modificasie

Daar is vermoedens dat 'n paar docker houers gecompromitteer is:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
U kan maklik **die wysigings wat aan hierdie houer gemaak is met betrekking tot die beeld** vind met:
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
In die vorige opdrag beteken **C** **Verander** en **A,** **Bygevoeg**.\
As jy vind dat 'n interessante lêer soos `/etc/shadow` gewysig is, kan jy dit van die houer aflaai om vir kwaadwillige aktiwiteit te kyk met:
```bash
docker cp wordpress:/etc/shadow.
```
U kan dit ook **vergelyk met die oorspronklike een** deur 'n nuwe houer te laat loop en die lêer daaruit te onttrek:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
As jy vind dat **'n paar verdagte lêer bygevoeg is** kan jy die houer toegang en dit nagaan:
```bash
docker exec -it wordpress bash
```
## Beeldwysigings

Wanneer jy 'n uitgevoerde docker-beeld ontvang (waarskynlik in `.tar` formaat), kan jy [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) gebruik om **'n opsomming van die wysigings** te **onttrek**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dan kan jy die **dekomprimeer** die beeld en **toegang tot die blobs** verkry om te soek na verdagte lêers wat jy in die veranderinge geskiedenis mag gevind het:
```bash
tar -xf image.tar
```
### Basiese Analise

Jy kan **basiese inligting** van die beeld verkry deur:
```bash
docker inspect <image>
```
U kan ook 'n opsomming **geskiedenis van veranderinge** kry met:
```bash
docker history --no-trunc <image>
```
Jy kan ook 'n **dockerfile uit 'n beeld** genereer met:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Om bygevoegde/gewijzigde lêers in docker beelde te vind, kan jy ook die [**dive**](https://github.com/wagoodman/dive) (aflaai dit van [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) nut gebruik:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dit stel jou in staat om **deur die verskillende blobs van docker prente te navigeer** en te kyk watter lêers gewysig/gevoeg is. **Rooi** beteken gevoeg en **geel** beteken gewysig. Gebruik **tab** om na die ander weergawe te beweeg en **spasie** om vouers in te klap/open.

Met dit sal jy nie toegang hê tot die inhoud van die verskillende fases van die prent nie. Om dit te doen, sal jy **elke laag moet dekomprimeer en toegang daartoe kry**.\
Jy kan al die lae van 'n prent dekomprimeer vanaf die gids waar die prent gedecomprimeer is deur die volgende uit te voer:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Kredensiale uit geheue

Let daarop dat wanneer jy 'n docker-container binne 'n gasheer uitvoer, **kan jy die prosesse wat op die container loop vanaf die gasheer sien** deur net `ps -ef` te loop.

Daarom (as root) kan jy **die geheue van die prosesse** vanaf die gasheer dump en soek na **kredensiale** net [**soos in die volgende voorbeeld**](../../linux-hardening/privilege-escalation/#process-memory). 

{{#include ../../banners/hacktricks-training.md}}
