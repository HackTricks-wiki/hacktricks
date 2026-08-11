# Docker फॉरेंसिक्स

{{#include ../../banners/hacktricks-training.md}}

## Container में संशोधन

संदेह है कि किसी Docker Container से छेड़छाड़ की गई है:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
आप आसानी से **इस container के filesystem में इसके बनाए जाने के बाद किए गए बदलावों को खोज सकते हैं**:<sup>[[1]](#references)</sup>
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
पिछले command में **C** का अर्थ **Changed** और **A** का अर्थ **Added** है।<sup>[[1]](#references)</sup>\
यदि आपको `/etc/shadow` जैसी कोई रोचक file modified मिलती है, तो malicious activity की जांच करने के लिए उसे container से download कर सकते हैं:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
आप इसे **एक नया container चलाकर और उसमें से file extract करके original वाले से compare भी कर सकते हैं**:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
यदि आपको पता चलता है कि **कोई संदिग्ध फ़ाइल जोड़ी गई है**, तो आप container को access करके उसकी जाँच कर सकते हैं:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Images में modifications

जब आपको एक exported docker image (संभवतः `.tar` format में) दी जाती है, तो आप [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) का उपयोग **modifications का summary extract करने** के लिए कर सकते हैं:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
फिर, आप image को **decompress** करके **blobs को access** कर सकते हैं और changes history में मिली संदिग्ध फ़ाइलों को खोज सकते हैं:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### मूलभूत विश्लेषण

आप image चलाकर **मूलभूत जानकारी** प्राप्त कर सकते हैं:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
आप इससे **परिवर्तनों का संक्षिप्त इतिहास** भी प्राप्त कर सकते हैं:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
आप <sup>[[10]](#references)</sup> की मदद से **dockerfile from an image** भी generate कर सकते हैं:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Docker images में जोड़ी गई/संशोधित files खोजने के लिए आप [**dive**](https://github.com/wagoodman/dive) ([**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) से download करें) utility का भी उपयोग कर सकते हैं:<sup>[[11]](#references)[[12]](#references)</sup>

dive के साथ उसका image tag खोलने से पहले saved archive को Docker में load करें:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
यह आपको **docker images के अलग-अलग blobs में navigate करने** और यह जाँचने की अनुमति देता है कि कौन-सी फ़ाइलें modified/added/removed की गई हैं। दूसरे view पर जाने के लिए **tab** और folders को collapse/open करने के लिए **space** का उपयोग करें।<sup>[[11]](#references)</sup>

dive के साथ आप image के अलग-अलग stages के content तक access नहीं कर पाएँगे। ऐसा करने के लिए आपको **प्रत्येक layer को decompress करके उसे access करना** होगा।\
आप image की सभी layers को उस directory से decompress कर सकते हैं जहाँ image को decompress किया गया था, इसे execute करके:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## मेमोरी से Credentials

Linux पर, host का ancestor PID namespace किसी container के child PID namespace में मौजूद processes को देख सकता है, इसलिए `ps -ef` जैसी host process listing उन्हें दिखा सकती है।<sup>[[14]](#references)</sup>

जब host credentials, capabilities और LSM/ptrace policy इसकी अनुमति देते हैं, तो उचित privileges वाला host investigator **process memory dump** कर सकता है और **credentials** खोज सकता है, ठीक [**निम्न उदाहरण की तरह**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory)।<sup>[[15]](#references)</sup>

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
