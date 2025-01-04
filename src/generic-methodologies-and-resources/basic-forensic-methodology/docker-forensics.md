# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Container modification

일부 도커 컨테이너가 손상되었다는 의혹이 있습니다:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
이 컨테이너에 대해 **이미지와 관련된 수정 사항을 쉽게 찾을 수 있습니다**:
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
이전 명령에서 **C**는 **Changed**를 의미하고 **A**는 **Added**를 의미합니다.\
`/etc/shadow`와 같은 흥미로운 파일이 수정된 것을 발견하면, 악의적인 활동을 확인하기 위해 컨테이너에서 파일을 다운로드할 수 있습니다:
```bash
docker cp wordpress:/etc/shadow.
```
원본과 **비교할 수 있습니다** 새 컨테이너를 실행하고 그 안에서 파일을 추출하여:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**의심스러운 파일이 추가된 것을 발견한 경우** 컨테이너에 접근하여 확인할 수 있습니다:
```bash
docker exec -it wordpress bash
```
## 이미지 수정

내보낸 도커 이미지(아마도 `.tar` 형식)를 받으면 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)를 사용하여 **수정 사항의 요약을 추출**할 수 있습니다:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
그런 다음 이미지를 **압축 해제**하고 **블롭에 접근**하여 변경 이력에서 발견한 의심스러운 파일을 검색할 수 있습니다:
```bash
tar -xf image.tar
```
### 기본 분석

이미지에서 **기본 정보**를 얻으려면 다음을 실행하세요:
```bash
docker inspect <image>
```
변경 사항 **이력 요약**을 다음과 같이 얻을 수 있습니다:
```bash
docker history --no-trunc <image>
```
이미지에서 **dockerfile을 생성할 수 있습니다**:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

docker 이미지에서 추가되거나 수정된 파일을 찾기 위해 [**dive**](https://github.com/wagoodman/dive) (다운로드는 [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)에서) 유틸리티를 사용할 수 있습니다:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
이것은 **docker 이미지의 다양한 블롭을 탐색하고 어떤 파일이 수정되었거나 추가되었는지 확인할 수 있게 해줍니다**. **빨간색**은 추가된 것을 의미하고 **노란색**은 수정된 것을 의미합니다. **탭**을 사용하여 다른 보기로 이동하고 **스페이스**를 사용하여 폴더를 축소/열 수 있습니다.

die를 사용하면 이미지의 다양한 단계의 콘텐츠에 접근할 수 없습니다. 그렇게 하려면 **각 레이어를 압축 해제하고 접근해야 합니다**.\
이미지가 압축 해제된 디렉토리에서 다음을 실행하여 이미지의 모든 레이어를 압축 해제할 수 있습니다:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 메모리에서의 자격 증명

호스트 내에서 도커 컨테이너를 실행할 때 **호스트에서 컨테이너에서 실행 중인 프로세스를 볼 수 있습니다** `ps -ef`를 실행하기만 하면 됩니다.

따라서 (루트로) **호스트에서 프로세스의 메모리를 덤프하고** **자격 증명**을 검색할 수 있습니다 [**다음 예제와 같이**](../../linux-hardening/privilege-escalation/index.html#process-memory).

{{#include ../../banners/hacktricks-training.md}}
