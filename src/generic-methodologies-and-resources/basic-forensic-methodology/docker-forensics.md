# Docker 포렌식

{{#include ../../banners/hacktricks-training.md}}


## Container 수정

일부 Docker container가 compromised되었다는 의심이 있습니다:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
다음을 사용하면 **이 container에서 image에 비해 변경된 사항을 쉽게 확인할 수 있습니다**:
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
이전 명령에서 **C**는 **변경됨(Changed)**, **A**는 **추가됨(Added)**을 의미합니다.\
`/etc/shadow`와 같은 흥미로운 파일이 수정된 것을 발견하면, 다음 명령을 사용하여 container에서 해당 파일을 download한 후 악의적인 활동이 있었는지 확인할 수 있습니다:
```bash
docker cp wordpress:/etc/shadow.
```
또한 새 컨테이너를 실행하고 그 컨테이너에서 파일을 추출하여 **원본과 비교할** 수도 있습니다:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**의심스러운 파일이 추가된 것을 발견하면** 컨테이너에 액세스하여 확인할 수 있습니다:
```bash
docker exec -it wordpress bash
```
## 이미지 변경 사항

export된 docker image(대개 `.tar` 형식)가 주어지면 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)를 사용하여 **변경 사항 요약을 추출**할 수 있습니다:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
그런 다음 image를 **decompress**하고 **blobs에 access**하여 변경 history에서 발견했을 수 있는 의심스러운 파일을 검색할 수 있습니다:
```bash
tar -xf image.tar
```
### 기본 분석

다음 명령을 실행하여 이미지에서 **기본 정보**를 확인할 수 있습니다:
```bash
docker inspect <image>
```
다음 명령어로 **변경 내역 요약**도 확인할 수 있습니다:
```bash
docker history --no-trunc <image>
```
다음 명령으로 **image에서 dockerfile을 생성**할 수도 있습니다:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

docker image에서 추가/수정된 파일을 찾으려면 [**dive**](https://github.com/wagoodman/dive) ( [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) 에서 다운로드) utility를 사용할 수도 있습니다:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
이를 통해 **Docker images의 다양한 blob을 탐색**하고 어떤 파일이 수정되거나 추가되었는지 확인할 수 있습니다. **Red**는 추가됨을, **yellow**는 수정됨을 의미합니다. **tab**을 사용해 다른 뷰로 이동하고 **space**를 사용해 폴더를 접거나 펼칠 수 있습니다.

die를 사용하면 image의 각 stage 콘텐츠에 액세스할 수 없습니다. 그러려면 **각 layer를 압축 해제한 후 액세스해야 합니다**.\
image가 압축 해제된 디렉터리에서 다음을 실행하면 image의 모든 layer를 압축 해제할 수 있습니다:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 메모리에서 Credentials 가져오기

호스트 내부에서 docker container를 실행하면 **호스트에서 container에서 실행 중인 processes를 볼 수 있습니다**. `ps -ef`만 실행하면 됩니다.

따라서 (root 권한으로) 호스트에서 processes의 **memory를 dump하고**, [**다음 예시와 같이**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory) **credentials**를 검색할 수 있습니다.


{{#include ../../banners/hacktricks-training.md}}
