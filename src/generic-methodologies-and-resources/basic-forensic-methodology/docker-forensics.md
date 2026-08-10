# Docker-forensika

## Wysiging van container

Daar is vermoedens dat een of ander Docker-container gekompromitteer is:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Jy kan maklik **veranderinge wat sedert die skepping daarvan aan hierdie container se lêerstelsel gemaak is, vind** met:<sup>[[1]](#references)</sup>
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
In die vorige opdrag beteken **C** **Gewysig** en **A** **Bygevoeg**.<sup>[[1]](#references)</sup>\
As jy vind dat een of ander interessante lêer soos `/etc/shadow` gewysig is, kan jy dit vanaf die container aflaai om vir kwaadwillige aktiwiteit te kontroleer met:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Jy kan dit ook **met die oorspronklike een vergelyk** deur ’n nuwe container te laat loop en die lêer daaruit te onttrek:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
As jy vind dat **’n verdagte lêer bygevoeg is**, kan jy toegang tot die container verkry en dit nagaan:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Image-wysigings

Wanneer jy 'n geëksporteerde Docker image (waarskynlik in `.tar`-formaat) kry, kan jy [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) gebruik om **'n opsomming van die wysigings te onttrek**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dan kan jy die **image** **decompress** en **access the blobs** om na verdagte lêers te soek wat jy moontlik in die changes history gevind het:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Basiese Analise

Jy kan **basiese inligting** uit die image verkry deur die volgende uit te voer:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Jy kan ook ’n opsommende **geskiedenis van veranderinge** verkry met:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Jy kan ook ’n **dockerfile vanaf ’n image genereer met:<sup>[[10]](#references)</sup>**
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Om bygevoegde/gewysigde lêers in Docker-images te vind, kan jy ook die [**dive**](https://github.com/wagoodman/dive) utility gebruik (laai dit van [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) af):<sup>[[11]](#references)[[12]](#references)</sup>

Laai die gestoorde argief in Docker voordat jy die image tag met dive oopmaak:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dit laat jou toe om **deur die verskillende blobs van Docker images te navigeer** en te kontroleer watter lêers gewysig/bygevoeg/verwyder is. Gebruik **tab** om na die ander aansig te beweeg en **spasie** om vouers toe te vou/oop te maak.<sup>[[11]](#references)</sup>

Met dive sal jy nie toegang tot die inhoud van die verskillende stages van die image hê nie. Om dit te doen, sal jy **elke layer moet dekomprimeer en toegang daartoe moet verkry**.\
Jy kan al die layers van ’n image dekomprimeer vanuit die gids waar die image gedekomprimeer is deur die volgende uit te voer:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Aanmeldbesonderhede uit geheue

Op Linux kan die gasheer se voorouer-PID-namespace prosesse in ’n houer se kind-PID-namespace sien, sodat ’n gasheerproseslys soos `ps -ef` dit kan vertoon.<sup>[[14]](#references)</sup>

Wanneer gasheer-aanmeldbesonderhede, capabilities en LSM/ptrace-beleid dit toelaat, kan ’n toepaslik bevoorregte gasheernavorser **prosesgeheue dump** en vir **aanmeldbesonderhede** soek [**soos in die volgende voorbeeld**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diff-ontlederdefinisies](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0-vrystelling](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
