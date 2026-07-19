# Docker Adli İncelemesi

{{#include ../../banners/hacktricks-training.md}}


## Container modification

Bazı Docker container'larının ele geçirildiğine dair şüpheler var:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Bu container'da image'a göre yapılan değişiklikleri şu şekilde kolayca **bulabilirsiniz**:
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
Önceki komutta **C**, **Changed** (Değiştirildi) ve **A,** **Added** (Eklendi) anlamına gelir.\
`/etc/shadow` gibi ilginç bir dosyanın değiştirildiğini fark ederseniz kötü amaçlı etkinlikleri kontrol etmek için dosyayı container'dan şu komutla indirebilirsiniz:
```bash
docker cp wordpress:/etc/shadow.
```
Ayrıca yeni bir container çalıştırıp dosyayı ondan çıkararak **orijinaliyle karşılaştırabilirsiniz**:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**Şüpheli bir dosyanın eklendiğini** fark ederseniz, container'a erişip onu kontrol edebilirsiniz:
```bash
docker exec -it wordpress bash
```
## Image değişiklikleri

Size dışa aktarılmış bir Docker image'ı (muhtemelen `.tar` formatında) verildiğinde, **değişikliklerin özetini çıkarmak** için [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) kullanabilirsiniz:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ardından, image'ı **decompress** edebilir ve değişiklik geçmişinde bulmuş olabileceğiniz şüpheli dosyaları aramak için **blob'lara erişebilirsiniz**:
```bash
tar -xf image.tar
```
### Temel Analiz

**Temel bilgiler**i image'i çalıştırarak edinebilirsiniz:
```bash
docker inspect <image>
```
Şunlarla ayrıca **değişiklik geçmişi** özeti elde edebilirsiniz:
```bash
docker history --no-trunc <image>
```
Bir **image**'dan **dockerfile** da oluşturabilirsiniz:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Docker imajlarına eklenen/değiştirilen dosyaları bulmak için [**dive**](https://github.com/wagoodman/dive) aracını da kullanabilirsiniz ([**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) üzerinden indirin):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Bu, **docker image'larının farklı blob'ları arasında gezinmenize** ve hangi dosyaların değiştirildiğini/eklendiğini kontrol etmenize olanak tanır. **Kırmızı**, eklenenleri; **sarı** ise değiştirilenleri belirtir. Diğer görünüme geçmek için **tab**, klasörleri daraltmak/açmak için **space** tuşunu kullanın.

die ile image'ın farklı aşamalarının içeriğine erişemezsiniz. Bunun için **her layer'ı decompress edip bunlara erişmeniz** gerekir.\
Bir image'daki tüm layer'ları, image'ın decompress edildiği dizinden aşağıdaki komutu çalıştırarak decompress edebilirsiniz:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Bellekten kimlik bilgileri

Bir host içinde Docker container çalıştırdığınızda, yalnızca `ps -ef` komutunu çalıştırarak **host üzerinden container'da çalışan process'leri görebileceğinizi** unutmayın.

Bu nedenle (root olarak) host üzerinden **process'lerin belleğini dökebilir** ve **kimlik bilgilerini** [**aşağıdaki örnekte olduğu gibi**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory) arayabilirsiniz.


{{#include ../../banners/hacktricks-training.md}}
