# Docker Adli İncelemesi

## Container değişikliği

Bir Docker container'ının ele geçirildiğine dair şüpheler var:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Bu container'ın filesystem'ında, oluşturulduğundan bu yana yapılan değişiklikleri kolayca **bulabilirsiniz**:<sup>[[1]](#references)</sup>
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
Önceki komutta **C**, **Changed** (Değiştirildi) ve **A**, **Added** (Eklendi) anlamına gelir.<sup>[[1]](#references)</sup>\
`/etc/shadow` gibi ilginç bir dosyanın değiştirildiğini fark ederseniz kötü amaçlı etkinlikleri kontrol etmek için dosyayı container'dan şu komutla indirebilirsiniz:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Yeni bir container çalıştırıp dosyayı ondan çıkararak **orijinaliyle karşılaştırabilirsiniz**:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**Herhangi bir şüpheli dosyanın eklendiğini tespit ederseniz**, container'a erişip dosyayı kontrol edebilirsiniz:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Image değişiklikleri

Size dışa aktarılmış bir Docker image (muhtemelen `.tar` formatında) verildiğinde, **değişikliklerin özetini çıkarmak** için [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) kullanabilirsiniz:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ardından, image'ı **decompress** edebilir ve değişiklik geçmişinde bulmuş olabileceğiniz şüpheli dosyaları aramak için **blob**'lara **access** sağlayabilirsiniz:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Temel Analiz

Görüntü üzerinde şu işlemi çalıştırarak **temel bilgileri** edinebilirsiniz:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Ayrıca şu şekilde **değişiklik geçmişinin** bir özetini de alabilirsiniz:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Bir **dockerfile**'ı bir **image**'dan da oluşturabilirsiniz:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Docker images içindeki eklenmiş/değiştirilmiş dosyaları bulmak için [**dive**](https://github.com/wagoodman/dive) ([**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) üzerinden indirin) aracını da kullanabilirsiniz:<sup>[[11]](#references)[[12]](#references)</sup>

Image tag'ini dive ile açmadan önce kaydedilmiş arşivi Docker'a yükleyin:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Bu, **docker image'larının farklı blob'ları arasında gezinmenize** ve hangi dosyaların değiştirildiğini/eklendiğini/kaldırıldığını kontrol etmenize olanak tanır. Diğer görünüme geçmek için **tab** tuşunu, klasörleri daraltmak/açmak için **space** tuşunu kullanın.<sup>[[11]](#references)</sup>

dive ile image'ın farklı aşamalarının içeriğine erişemezsiniz. Bunun için **her layer'ı decompress etmeniz ve bunlara erişmeniz** gerekir.\
Bir image'daki tüm layer'ları, image'ın decompress edildiği dizinden şu komutu çalıştırarak decompress edebilirsiniz:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Bellekten kimlik bilgileri

Linux'ta, host'un ancestor PID namespace'i bir container'ın child PID namespace'indeki süreçleri görebilir; bu nedenle `ps -ef` gibi bir host süreç listesi bunları gösterebilir.<sup>[[14]](#references)</sup>

Host credentials, capabilities ve LSM/ptrace policy buna izin verdiğinde, uygun şekilde yetkilendirilmiş bir host investigator **process memory dökümü alabilir** ve **credentials** arayabilir; tıpkı [**aşağıdaki örnekte olduğu gibi**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

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
