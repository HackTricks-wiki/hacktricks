# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Container modification

Bazı docker konteynerlerinin tehlikeye atıldığına dair şüpheler var:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Bu konteynerdeki **görüntü ile ilgili yapılan değişiklikleri kolayca bulabilirsiniz**:
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
Önceki komutta **C** **Değiştirildi** ve **A,** **Eklendi** anlamına gelir.\
Eğer `/etc/shadow` gibi ilginç bir dosyanın değiştirildiğini bulursanız, kötü niyetli etkinlikleri kontrol etmek için dosyayı konteynerden indirmek için:
```bash
docker cp wordpress:/etc/shadow.
```
Aynı zamanda **bunu orijinal ile karşılaştırabilirsiniz** yeni bir konteyner çalıştırarak ve içinden dosyayı çıkararak:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Eğer **şüpheli bir dosyanın eklendiğini** bulursanız, konteynıra erişip kontrol edebilirsiniz:
```bash
docker exec -it wordpress bash
```
## Görüntü Modifikasyonları

Bir dışa aktarılmış docker görüntüsü (muhtemelen `.tar` formatında) verildiğinde, **değişikliklerin bir özetini çıkarmak için** [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) kullanabilirsiniz:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Sonra, görüntüyü **açabilir** ve **blob'lara erişebilir** ve değişiklik geçmişinde bulmuş olabileceğiniz şüpheli dosyaları arayabilirsiniz:
```bash
tar -xf image.tar
```
### Temel Analiz

Görüntüden **temel bilgiler** alabilirsiniz:
```bash
docker inspect <image>
```
Ayrıca **değişiklikler tarihi** özeti alabilirsiniz:
```bash
docker history --no-trunc <image>
```
Bir **görüntüden dockerfile oluşturabilirsiniz**:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Docker görüntülerinde eklenmiş/değiştirilmiş dosyaları bulmak için [**dive**](https://github.com/wagoodman/dive) (bunu [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) üzerinden indirin) aracını da kullanabilirsiniz:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Bu, **docker görüntülerinin farklı blob'ları arasında gezinmenizi** ve hangi dosyaların değiştirildiğini/eklendiğini kontrol etmenizi sağlar. **Kırmızı** eklenmiş anlamına gelir ve **sarı** değiştirilmiş anlamına gelir. Diğer görünüme geçmek için **tab** tuşunu ve klasörleri daraltmak/açmak için **space** tuşunu kullanın.

Die ile görüntünün farklı aşamalarının içeriğine erişemezsiniz. Bunu yapmak için **her katmanı sıkıştırmanız ve erişmeniz** gerekecek.\
Bir görüntüden tüm katmanları, görüntünün sıkıştırıldığı dizinden şu komutu çalıştırarak sıkıştırabilirsiniz:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Bellekten Kimlik Bilgileri

Bir docker konteynerini bir ana bilgisayar içinde çalıştırdığınızda **ana bilgisayardan konteynerde çalışan süreçleri görebileceğinizi** unutmayın, sadece `ps -ef` komutunu çalıştırarak.

Bu nedenle (root olarak) **ana bilgisayardan süreçlerin belleğini dökebilir** ve **kimlik bilgilerini** arayabilirsiniz, tıpkı [**aşağıdaki örnekteki gibi**](../../linux-hardening/privilege-escalation/#process-memory). 

{{#include ../../banners/hacktricks-training.md}}
