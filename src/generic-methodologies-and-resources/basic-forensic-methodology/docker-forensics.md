# Docker Adli İncelemesi

{{#include ../../banners/hacktricks-training.md}}

## Container Değişikliği

Bir Docker container'ının ele geçirildiğine dair şüpheler var:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Bu **container**'ın dosya sisteminde oluşturulmasından bu yana yapılan değişiklikleri şu komutla kolayca **bulabilirsiniz**:<sup>[[1]](#references)</sup>
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
`/etc/shadow` gibi ilgi çekici bir dosyanın değiştirildiğini fark ederseniz kötü amaçlı etkinlikleri kontrol etmek için dosyayı container'dan şu komutla indirebilirsiniz:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Ayrıca yeni bir container çalıştırıp dosyayı ondan çıkararak **orijinaliyle karşılaştırabilirsiniz**:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**Herhangi bir şüpheli dosyanın eklendiğini fark ederseniz**, container'a erişip kontrol edebilirsiniz:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## İmaj değişiklikleri

Size bir Docker image'ı (muhtemelen `.tar` formatında) verildiğinde, **değişikliklerin özetini çıkarmak** için [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) kullanabilirsiniz:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ardından, image'ı **decompress** edebilir ve değişiklik geçmişinde bulmuş olabileceğiniz şüpheli dosyaları aramak için **blob'lara erişebilirsiniz**:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Temel Analiz

Görüntüyü çalıştırarak **temel bilgileri** edinebilirsiniz:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Ayrıca şunlarla kısa bir **değişiklik geçmişi** özeti de alabilirsiniz:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Ayrıca bir **image'dan Dockerfile** da oluşturabilirsiniz:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Docker images içindeki eklenen/değiştirilen dosyaları bulmak için [**dive**](https://github.com/wagoodman/dive) ([**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) üzerinden indirin) aracını da kullanabilirsiniz:<sup>[[11]](#references)[[12]](#references)</sup>

Kaydedilen arşivi Docker'a yükledikten sonra dive ile image tag'ini açın:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Bu, **docker image'larının farklı blob'ları arasında gezinmenize** ve hangi dosyaların değiştirildiğini/eklendiğini/kaldırıldığını kontrol etmenize olanak tanır. Diğer görünüme geçmek için **tab**, klasörleri daraltmak/açmak için **space** kullanın.<sup>[[11]](#references)</sup>

dive ile image'ın farklı aşamalarının içeriğine erişemezsiniz. Bunu yapmak için **her layer'ı decompress edip ona erişmeniz** gerekir.\
Bir image'daki tüm layer'ları, image'ın decompress edildiği dizinden aşağıdaki komutu çalıştırarak decompress edebilirsiniz:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Bellekten kimlik bilgileri

Linux'ta, host'un ancestor PID namespace'i bir container'ın child PID namespace'indeki işlemleri görebilir; bu nedenle `ps -ef` gibi bir host işlem listeleme komutu bunları gösterebilir.<sup>[[14]](#references)</sup>

Host credentials, capabilities ve LSM/ptrace policy izin verdiğinde, yeterli ayrıcalıklara sahip bir host investigator **process memory dökümü alabilir** ve **credentials** arayabilir; tıpkı [**aşağıdaki örnekte olduğu gibi**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Docker container farkı](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container kopyalama](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container çalıştırma](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container içinde komut çalıştırma](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diff analyzer tanımları](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image kaydetme](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inceleme](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image geçmişi](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 sürümü](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image yükleme](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
