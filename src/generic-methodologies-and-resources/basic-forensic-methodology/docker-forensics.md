# Uchunguzi wa Docker

{{#include ../../banners/hacktricks-training.md}}

## Marekebisho ya container

Kuna tuhuma kwamba container fulani ya Docker iliathiriwa:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Unaweza kwa urahisi **kupata mabadiliko yaliyofanywa kwenye filesystem ya container hii tangu ilipoundwa** kwa:<sup>[[1]](#references)</sup>
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
Katika amri iliyotangulia **C** inamaanisha **Changed** na **A** inamaanisha **Added**.<sup>[[1]](#references)</sup>\
Ukigundua kuwa faili fulani ya kuvutia kama `/etc/shadow` imebadilishwa, unaweza kuipakua kutoka kwenye container ili kuangalia shughuli hasidi kwa:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Unaweza pia **kuilinganisha na ya awali** kwa kuendesha container mpya na kutoa file kutoka humo:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ukigundua kuwa **faili fulani ya kutiliwa shaka imeongezwa**, unaweza kufikia container na kuikagua:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Marekebisho ya image

Unapopewa docker image iliyotolewa (huenda ikiwa katika muundo wa `.tar`), unaweza kutumia [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) **kutoa muhtasari wa marekebisho**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Kisha, unaweza **decompress** image na **access the blobs** ili kutafuta faili zinazotiliwa shaka ambazo huenda ulizipata katika historia ya mabadiliko:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Uchambuzi wa Msingi

Unaweza kupata **maelezo ya msingi** kutoka kwenye image kwa kuendesha:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Unaweza pia kupata muhtasari wa **historia ya mabadiliko** kwa kutumia:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Unaweza pia kutengeneza **dockerfile kutoka kwenye image** kwa:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Ili kupata faili zilizoongezwa/kubadilishwa katika docker images, unaweza pia kutumia utility ya [**dive**](https://github.com/wagoodman/dive) (ipakue kutoka kwenye [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0):<sup>[[11]](#references)[[12]](#references)</sup>

Pakia archive iliyohifadhiwa kwenye Docker kabla ya kufungua image tag yake kwa kutumia dive:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Hii hukuwezesha **kuvinjari blobs tofauti za docker images** na kuangalia ni files zipi zilibadilishwa/kuongezwa/kuondolewa. Tumia **tab** kuhamia kwenye mwonekano mwingine na **space** kukunja/kufungua folda.<sup>[[11]](#references)</sup>

Kwa kutumia dive hutaweza kufikia maudhui ya stages tofauti za image. Ili kufanya hivyo utahitaji **decompress kila layer na kuifikia**.\
Unaweza ku-decompress layers zote kutoka kwenye image ukiwa kwenye directory ambako image ilidecompressiwa, kwa kutekeleza:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Vitambulisho kutoka kwenye kumbukumbu

Kwenye Linux, namespace ya PID ya mzazi wa host inaweza kuona processes katika namespace ya PID ya mtoto wa container, hivyo orodha ya processes ya host kama `ps -ef` inaweza kuwaonyesha.<sup>[[14]](#references)</sup>

Wakati credentials, capabilities na sera za LSM/ptrace za host zinaruhusu, mchunguzi wa host mwenye privileges zinazofaa anaweza **dump process memory** na kutafuta **credentials** [**kama katika mfano ufuatao**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diff analyzer definitions](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 release](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
