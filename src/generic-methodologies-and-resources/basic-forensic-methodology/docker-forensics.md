# Uchunguzi wa Docker

{{#include ../../banners/hacktricks-training.md}}


## Marekebisho ya container

Kuna mashaka kwamba container fulani ya Docker iliingiliwa:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Unaweza kwa urahisi **kupata marekebisho yaliyofanywa kwenye container hii ikilinganishwa na image** kwa:
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
Katika amri iliyotangulia, **C** inamaanisha **Changed** na **A,** **Added**.\
Ukigundua kuwa faili fulani ya kuvutia kama `/etc/shadow` imebadilishwa, unaweza kuipakua kutoka kwenye container ili kuangalia shughuli hasidi kwa:
```bash
docker cp wordpress:/etc/shadow.
```
Unaweza pia **kuilinganisha na ya awali** kwa kuendesha container mpya na kutoa faili kutoka humo:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ukigundua kuwa **faili fulani yenye kutia shaka iliongezwa** unaweza kufikia container na kuiangalia:
```bash
docker exec -it wordpress bash
```
## Marekebisho ya Images

Unapopewa Docker image iliyosafirishwa (huenda ikiwa katika muundo wa `.tar`), unaweza kutumia [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) ili **kutoa muhtasari wa marekebisho**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Kisha, unaweza **ku-decompress** image na **ku-access blobs** ili kutafuta files zinazotiliwa shaka ambazo huenda ulizipata katika historia ya mabadiliko:
```bash
tar -xf image.tar
```
### Uchambuzi wa Msingi

Unaweza kupata **taarifa za msingi** kutoka kwenye image kwa kuendesha:
```bash
docker inspect <image>
```
Unaweza pia kupata muhtasari wa **historia ya mabadiliko** kwa:
```bash
docker history --no-trunc <image>
```
Unaweza pia kutengeneza **dockerfile kutoka kwenye image** kwa:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Ili kupata faili zilizoongezwa/kubadilishwa katika Docker images, unaweza pia kutumia zana ya [**dive**](https://github.com/wagoodman/dive) (ipakue kutoka kwenye [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Hii inakuruhusu **kuvinjari blobs tofauti za docker images** na kukagua ni mafaili yapi yamebadilishwa/kuongezwa. **Red** inamaanisha yameongezwa na **yellow** inamaanisha yamebadilishwa. Tumia **tab** kuhamia kwenye mwonekano mwingine na **space** kukunja/kufungua folda.

Ukitumia die hutaweza kufikia maudhui ya stages tofauti za image. Ili kufanya hivyo utahitaji **kudecompress kila layer na kuifikia**.\
Unaweza kudecompress layers zote kutoka kwenye image ukiwa kwenye directory ambako image ilidecompressiwa, kwa kutekeleza:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials kutoka kwenye memory

Kumbuka kwamba unapoendesha docker container ndani ya host, **unaweza kuona processes zinazoendesha kwenye container kutoka kwa host** kwa kuendesha tu `ps -ef`

Kwa hiyo, (ukiwa root) unaweza **ku-dump memory ya processes** kutoka kwa host na kutafuta **credentials** [**kama ilivyo kwenye mfano ufuatao**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
