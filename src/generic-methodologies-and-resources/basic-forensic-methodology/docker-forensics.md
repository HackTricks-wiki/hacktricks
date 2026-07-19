# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Container संशोधन

संदेह है कि किसी Docker container से छेड़छाड़ की गई है:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
आप आसानी से **image के संबंध में इस container में किए गए modifications को खोज सकते हैं**:
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
पिछली command में **C** का अर्थ **Changed** और **A,** का अर्थ **Added** है।\
यदि आपको `/etc/shadow` जैसी कोई interesting file modified मिलती है, तो malicious activity की जांच करने के लिए आप उसे container से download कर सकते हैं:
```bash
docker cp wordpress:/etc/shadow.
```
आप इसे **मूल वाले से भी compare कर सकते हैं**, एक नया container चलाकर और उसमें से file extract करके:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
यदि आपको पता चलता है कि **कोई संदिग्ध file जोड़ी गई है**, तो आप container को access करके उसकी जाँच कर सकते हैं:
```bash
docker exec -it wordpress bash
```
## Images modifications

जब आपको एक exported docker image (संभवतः `.tar` format में) दी जाती है, तो आप [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) का उपयोग **modifications का summary extract करने** के लिए कर सकते हैं:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
इसके बाद, आप image को **decompress** कर सकते हैं और **blobs** को **access** करके उन suspicious files को खोज सकते हैं जिन्हें आपने changes history में पाया हो:
```bash
tar -xf image.tar
```
### बुनियादी विश्लेषण

आप image को चलाकर **बुनियादी जानकारी** प्राप्त कर सकते हैं:
```bash
docker inspect <image>
```
आप **परिवर्तनों का संक्षिप्त इतिहास** भी प्राप्त कर सकते हैं:
```bash
docker history --no-trunc <image>
```
आप **image से dockerfile** भी बना सकते हैं:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Docker images में जोड़ी या संशोधित की गई फ़ाइलों को खोजने के लिए आप [**dive**](https://github.com/wagoodman/dive) utility का भी उपयोग कर सकते हैं (इसे [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) से download करें):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
यह आपको **docker images के अलग-अलग blobs में navigate करने** और यह जाँचने की सुविधा देता है कि कौन-सी files modified/added हुई हैं। **Red** का अर्थ added और **yellow** का अर्थ modified है। दूसरे view पर जाने के लिए **tab** और folders को collapse/open करने के लिए **space** का उपयोग करें।

die के साथ आप image के अलग-अलग stages के content तक access नहीं कर पाएँगे। ऐसा करने के लिए आपको **प्रत्येक layer को decompress करके उस तक access करना** होगा।\
आप image की सभी layers को उस directory से decompress कर सकते हैं जहाँ image को decompress किया गया था, यह execute करके:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Memory से Credentials

ध्यान दें कि जब आप किसी host के अंदर docker container चलाते हैं, तो **आप host से container पर चल रहे processes देख सकते हैं** केवल `ps -ef` चलाकर।

इसलिए (root के रूप में) आप host से **processes की memory dump कर सकते हैं** और **credentials** खोज सकते हैं, बिल्कुल [**निम्नलिखित उदाहरण की तरह**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory)।

{{#include ../../banners/hacktricks-training.md}}
