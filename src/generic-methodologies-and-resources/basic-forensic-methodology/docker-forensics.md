# Docker 포렌식

{{#include ../../banners/hacktricks-training.md}}

## 컨테이너 수정

일부 Docker 컨테이너가 침해되었다는 의심이 있습니다:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
생성된 이후 **이 컨테이너의 파일 시스템에 적용된 변경 사항을 쉽게 찾을 수 있습니다**:<sup>[[1]](#references)</sup>
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
이전 명령에서 **C**는 **변경됨**을, **A**는 **추가됨**을 의미합니다.<sup>[[1]](#references)</sup>\
`/etc/shadow`와 같은 중요한 파일이 수정된 것을 발견하면 다음 명령을 사용하여 컨테이너에서 파일을 다운로드한 후 악성 활동이 있었는지 확인할 수 있습니다.<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
새 container를 실행하고 그 안에서 파일을 추출하여 **원본과 비교**할 수도 있습니다:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**의심스러운 파일이 추가된 것을 발견한 경우** 컨테이너에 액세스하여 확인할 수 있습니다:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## 이미지 수정

내보낸 docker image(대개 `.tar` 형식)가 주어지면 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)를 사용하여 **수정 사항 요약을 추출**할 수 있습니다:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
그런 다음, 이미지를 **decompress**하고 **access the blobs**하여 변경 이력에서 발견했을 수 있는 의심스러운 파일을 검색할 수 있습니다:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### 기본 분석

다음을 실행하여 이미지에서 **기본 정보**를 확인할 수 있습니다:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
다음 명령어로 **변경 이력 요약**도 확인할 수 있습니다:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
**image에서 dockerfile도 생성할 수 있습니다**:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Docker images에서 추가/수정된 파일을 찾으려면 [**dive**](https://github.com/wagoodman/dive) ([**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)에서 다운로드) utility를 사용할 수도 있습니다:<sup>[[11]](#references)[[12]](#references)</sup>

dive로 image tag를 열기 전에 저장된 archive를 Docker에 load하세요:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
이를 통해 **Docker 이미지의 여러 blob을 탐색**하고 어떤 파일이 수정/추가/삭제되었는지 확인할 수 있습니다. **tab**을 사용하여 다른 보기로 이동하고 **space**를 사용하여 폴더를 접거나 펼칠 수 있습니다.<sup>[[11]](#references)</sup>

dive를 사용하면 이미지의 여러 stage 콘텐츠에 액세스할 수 없습니다. 이를 위해서는 **각 layer를 압축 해제하고 해당 layer에 액세스해야 합니다**.\
이미지의 압축을 해제한 디렉터리에서 다음을 실행하면 이미지의 모든 layer를 압축 해제할 수 있습니다:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 메모리에서 Credentials

Linux에서는 호스트의 상위 PID namespace가 container의 하위 PID namespace에 있는 프로세스를 볼 수 있으므로, `ps -ef`와 같은 호스트 프로세스 목록에 해당 프로세스가 표시될 수 있습니다.<sup>[[14]](#references)</sup>

호스트의 credentials, capabilities 및 LSM/ptrace 정책이 허용하는 경우, 적절한 권한을 가진 호스트 조사자는 **프로세스 메모리를 덤프**하고 [**다음 예제와 같이**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory) **credentials**를 검색할 수 있습니다.<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diff analyzer definitions](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 release](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
