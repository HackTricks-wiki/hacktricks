# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Container modification

Kuna shaka kwamba baadhi ya kontena za docker zilipatikana na kuathiriwa:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Unaweza kwa urahisi **kupata marekebisho yaliyofanywa kwa kontena hili kuhusiana na picha** kwa kutumia:
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
Katika amri iliyopita, **C** inamaanisha **Changed** na **A** inamaanisha **Added**.\
Ikiwa utagundua kuwa faili ya kuvutia kama `/etc/shadow` imebadilishwa, unaweza kuipakua kutoka kwenye kontena ili kuangalia shughuli za uhalifu kwa:
```bash
docker cp wordpress:/etc/shadow.
```
Unaweza pia **kuilinganisha na ile ya asili** kwa kuendesha kontena mpya na kutoa faili kutoka kwake:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ikiwa utagundua kwamba **faili fulani ya kushuku imeongezwa** unaweza kufikia kontena na kuangalia:
```bash
docker exec -it wordpress bash
```
## Mabadiliko ya picha

Unapopewa picha ya docker iliyosafirishwa (labda katika muundo wa `.tar`) unaweza kutumia [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) **kuondoa muhtasari wa mabadiliko**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Kisha, unaweza **kufungua** picha na **kufikia blobs** kutafuta faili za kushangaza ambazo huenda umepata katika historia ya mabadiliko:
```bash
tar -xf image.tar
```
### Uchambuzi wa Msingi

Unaweza kupata **taarifa za msingi** kutoka kwa picha ukifanya:
```bash
docker inspect <image>
```
Unaweza pia kupata muhtasari wa **historia ya mabadiliko** kwa:
```bash
docker history --no-trunc <image>
```
Unaweza pia kuunda **dockerfile kutoka kwa picha** kwa:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Ili kupata faili zilizoongezwa/zilizobadilishwa katika picha za docker unaweza pia kutumia [**dive**](https://github.com/wagoodman/dive) (ipakue kutoka [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) utility:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Hii inakuwezesha **kuvinjari kupitia blobs tofauti za picha za docker** na kuangalia faili zipi zilirekebishwa/zimeongezwa. **Nyekundu** inamaanisha zimeongezwa na **njano** inamaanisha zimebadilishwa. Tumia **tab** kuhamia kwenye mtazamo mwingine na **space** kufunga/kufungua folda.

Kwa die huwezi kufikia maudhui ya hatua tofauti za picha. Ili kufanya hivyo, utahitaji **kufungua kila safu na kuifikia**.\
Unaweza kufungua safu zote kutoka kwa picha kutoka kwenye saraka ambapo picha ilifunguliwa ukitekeleza:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Akreditivu kutoka kwa kumbukumbu

Kumbuka kwamba unapokimbia kontena la docker ndani ya mwenyeji **unaweza kuona michakato inayokimbia kwenye kontena kutoka kwa mwenyeji** kwa kukimbia tu `ps -ef`

Hivyo (kama root) unaweza **kutoa kumbukumbu ya michakato** kutoka kwa mwenyeji na kutafuta **akreditivu** kama [**ilivyo katika mfano ufuatao**](../../linux-hardening/privilege-escalation/#process-memory).


{{#include ../../banners/hacktricks-training.md}}
