# Forensics za Docker

{{#include ../../banners/hacktricks-training.md}}

## Marekebisho ya Container

Kuna mashaka kwamba container fulani ya Docker imevamiwa:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Unaweza kwa urahisi **kupata marekebisho yaliyofanywa kwenye container hii kuhusiana na image** kwa kutumia:
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
Unaweza pia **kuilinganisha na ya awali** kwa kuendesha container mpya na kutoa file kutoka humo:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ikiwa utagundua kuwa **faili fulani la kutiliwa shaka liliongezwa**, unaweza kufikia container na kulikagua:
```bash
docker exec -it wordpress bash
```
## Marekebisho ya Images

Unapopewa Docker image iliyotolewa (huenda ikiwa katika umbizo la `.tar`), unaweza kutumia [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) ili **kutoa muhtasari wa marekebisho**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Kisha, unaweza **decompress** image na **access the blobs** ili kutafuta faili zinazotiliwa shaka ambazo huenda ulizipata katika historia ya mabadiliko:
```bash
tar -xf image.tar
```
### Uchambuzi wa Msingi

Unaweza kupata **maelezo ya msingi** kutoka kwenye image kwa kuendesha:
```bash
docker inspect <image>
```
Unaweza pia kupata muhtasari wa **historia ya mabadiliko** kupitia:
```bash
docker history --no-trunc <image>
```
Unaweza pia kuzalisha **dockerfile kutoka kwenye image** kwa kutumia:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Ili kupata faili zilizoongezwa/kubadilishwa katika docker images, unaweza pia kutumia utility ya [**dive**](https://github.com/wagoodman/dive) (ipakue kutoka [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Hii inakuruhusu **kuvinjari blobs tofauti za docker images** na kuangalia ni faili zipi zilibadilishwa/kuongezwa. **Nyekundu** inamaanisha imeongezwa na **njano** inamaanisha imebadilishwa. Tumia **tab** kuhamia kwenye mwonekano mwingine na **space** kukunja/kufungua folders.

Ukitumia die hutaweza kufikia maudhui ya stages tofauti za image. Ili kufanya hivyo, utahitaji **decompress kila layer na kuifikia**.\
Unaweza ku-decompress layers zote kutoka kwenye image ukiwa kwenye directory ambako image ilidecompressiwa, kwa kutekeleza:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials kutoka kwenye memory

Kumbuka kwamba unapoendesha docker container ndani ya host **unaweza kuona processes zinazoendesha kwenye container kutoka kwenye host** kwa kuendesha tu `ps -ef`

Kwa hivyo (kama root) unaweza **kudump memory ya processes** kutoka kwenye host na kutafuta **credentials** [**kama ilivyo kwenye mfano ufuatao**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).

{{#include ../../banners/hacktricks-training.md}}
