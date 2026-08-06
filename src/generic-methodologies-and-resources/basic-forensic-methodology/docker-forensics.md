# Docker 포렌식

{{#include ../../banners/hacktricks-training.md}}

## Container 수정

일부 Docker container가 침해되었다는 의심이 있습니다:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
다음을 사용하면 이 **컨테이너에서 이미지에 대해 수행된 변경 사항을 쉽게 확인할 수 있습니다**:
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
이전 명령에서 **C**는 **변경됨**을, **A,** **추가됨**을 의미합니다.\
`/etc/shadow`와 같은 흥미로운 파일이 수정된 것을 발견하면, 악성 활동을 확인하기 위해 해당 파일을 컨테이너에서 다운로드할 수 있습니다:
```bash
docker cp wordpress:/etc/shadow.
```
새 container를 실행하고 그 안에서 파일을 추출하여 **원본과 비교할 수도 있습니다**:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**의심스러운 파일이 추가된 것을 발견한 경우**, container에 액세스하여 확인할 수 있습니다:
```bash
docker exec -it wordpress bash
```
## 이미지 수정 사항

export된 docker image(일반적으로 `.tar` 형식)가 주어진 경우, [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)를 사용하여 **수정 사항 요약을 추출**할 수 있습니다:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
그러면 이미지를 **압축 해제**하고 **blobs에 액세스**하여 변경 기록에서 발견했을 수 있는 의심스러운 파일을 검색할 수 있습니다:
```bash
tar -xf image.tar
```
### 기본 분석

이미지에서 다음을 실행하여 **기본 정보**를 얻을 수 있습니다:
```bash
docker inspect <image>
```
다음 명령으로 **변경 이력** 요약도 확인할 수 있습니다:
```bash
docker history --no-trunc <image>
```
다음 명령으로 **image에서 dockerfile을** 생성할 수도 있습니다:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Docker image에서 추가/수정된 파일을 찾으려면 [**dive**](https://github.com/wagoodman/dive) ([**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)에서 다운로드) utility를 사용할 수도 있습니다:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
이를 통해 **docker images의 다양한 blob을 탐색**하고 어떤 파일이 수정되거나 추가되었는지 확인할 수 있습니다. **빨간색**은 추가된 파일을, **노란색**은 수정된 파일을 의미합니다. **tab**을 사용해 다른 뷰로 이동하고 **space**를 사용해 폴더를 접거나 펼칠 수 있습니다.

die를 사용하면 image의 각 stage 콘텐츠에 액세스할 수 없습니다. 그러려면 **각 layer를 decompress하고 해당 layer에 액세스해야 합니다**.\
image가 decompress된 디렉터리에서 다음을 실행하면 image의 모든 layer를 decompress할 수 있습니다:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 메모리에서 Credentials

Docker container를 host 내부에서 실행하면 **host에서 실행 중인 container의 프로세스를 볼 수 있다**는 점에 유의해야 한다. `ps -ef`만 실행하면 된다.

따라서 (root 권한으로) host에서 **프로세스의 메모리를 덤프하고** **Credentials**를 검색할 수 있다. [**다음 예제와 동일한 방식으로**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).

{{#include ../../banners/hacktricks-training.md}}
