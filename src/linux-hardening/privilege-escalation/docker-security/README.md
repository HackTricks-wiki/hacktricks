# Docker 보안

{{#include ../../../banners/hacktricks-training.md}}

## **기본 Docker 엔진 보안**

**Docker 엔진**은 Linux 커널의 **네임스페이스**와 **Cgroups**를 사용하여 컨테이너를 격리하여 기본적인 보안 계층을 제공합니다. 추가적인 보호는 **Capabilities dropping**, **Seccomp**, 및 **SELinux/AppArmor**를 통해 제공되어 컨테이너 격리를 강화합니다. **auth 플러그인**은 사용자 행동을 추가로 제한할 수 있습니다.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Docker 엔진에 대한 안전한 접근

Docker 엔진은 Unix 소켓을 통해 로컬에서 또는 HTTP를 사용하여 원격으로 접근할 수 있습니다. 원격 접근을 위해서는 HTTPS와 **TLS**를 사용하여 기밀성, 무결성 및 인증을 보장하는 것이 필수적입니다.

Docker 엔진은 기본적으로 `unix:///var/run/docker.sock`에서 Unix 소켓을 통해 수신 대기합니다. Ubuntu 시스템에서 Docker의 시작 옵션은 `/etc/default/docker`에 정의되어 있습니다. Docker API 및 클라이언트에 대한 원격 접근을 활성화하려면 다음 설정을 추가하여 Docker 데몬을 HTTP 소켓을 통해 노출하십시오:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
그러나 Docker 데몬을 HTTP로 노출하는 것은 보안 문제로 인해 권장되지 않습니다. HTTPS를 사용하여 연결을 보호하는 것이 좋습니다. 연결을 보호하는 두 가지 주요 접근 방식이 있습니다:

1. 클라이언트가 서버의 신원을 확인합니다.
2. 클라이언트와 서버가 서로의 신원을 상호 인증합니다.

서버의 신원을 확인하기 위해 인증서가 사용됩니다. 두 방법에 대한 자세한 예는 [**이 가이드**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)를 참조하십시오.

### 컨테이너 이미지의 보안

컨테이너 이미지는 개인 또는 공용 저장소에 저장될 수 있습니다. Docker는 컨테이너 이미지를 위한 여러 저장 옵션을 제공합니다:

- [**Docker Hub**](https://hub.docker.com): Docker의 공용 레지스트리 서비스입니다.
- [**Docker Registry**](https://github.com/docker/distribution): 사용자가 자신의 레지스트리를 호스팅할 수 있도록 하는 오픈 소스 프로젝트입니다.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): 역할 기반 사용자 인증 및 LDAP 디렉토리 서비스와의 통합 기능을 갖춘 Docker의 상업적 레지스트리 제공입니다.

### 이미지 스캔

컨테이너는 기본 이미지 또는 기본 이미지 위에 설치된 소프트웨어로 인해 **보안 취약점**이 있을 수 있습니다. Docker는 컨테이너의 보안 스캔을 수행하고 취약점을 나열하는 **Nautilus**라는 프로젝트를 진행 중입니다. Nautilus는 각 컨테이너 이미지 레이어를 취약점 저장소와 비교하여 보안 구멍을 식별합니다.

자세한 [**정보는 여기에서 읽어보세요**](https://docs.docker.com/engine/scan/) .

- **`docker scan`**

**`docker scan`** 명령은 이미지 이름 또는 ID를 사용하여 기존 Docker 이미지를 스캔할 수 있게 해줍니다. 예를 들어, hello-world 이미지를 스캔하려면 다음 명령을 실행하십시오:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker 이미지 서명

Docker 이미지 서명은 컨테이너에서 사용되는 이미지의 보안성과 무결성을 보장합니다. 간략한 설명은 다음과 같습니다:

- **Docker Content Trust**는 이미지 서명을 관리하기 위해 The Update Framework (TUF)를 기반으로 한 Notary 프로젝트를 활용합니다. 자세한 내용은 [Notary](https://github.com/docker/notary) 및 [TUF](https://theupdateframework.github.io)를 참조하세요.
- Docker 콘텐츠 신뢰를 활성화하려면 `export DOCKER_CONTENT_TRUST=1`을 설정합니다. 이 기능은 Docker 버전 1.10 이상에서 기본적으로 꺼져 있습니다.
- 이 기능이 활성화되면 서명된 이미지만 다운로드할 수 있습니다. 초기 이미지 푸시에는 루트 및 태깅 키에 대한 비밀번호를 설정해야 하며, Docker는 보안을 강화하기 위해 Yubikey도 지원합니다. 더 많은 세부정보는 [여기](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)에서 확인할 수 있습니다.
- 콘텐츠 신뢰가 활성화된 상태에서 서명되지 않은 이미지를 가져오려고 하면 "No trust data for latest" 오류가 발생합니다.
- 첫 번째 이후의 이미지 푸시를 위해 Docker는 이미지를 서명하기 위해 리포지토리 키의 비밀번호를 요청합니다.

개인 키를 백업하려면 다음 명령을 사용하세요:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Docker 호스트를 전환할 때, 운영을 유지하기 위해 루트 및 리포지토리 키를 이동하는 것이 필요합니다.

## 컨테이너 보안 기능

<details>

<summary>컨테이너 보안 기능 요약</summary>

**주요 프로세스 격리 기능**

컨테이너화된 환경에서 프로젝트와 그 프로세스를 격리하는 것은 보안 및 자원 관리에 있어 매우 중요합니다. 주요 개념에 대한 간단한 설명은 다음과 같습니다:

**네임스페이스**

- **목적**: 프로세스, 네트워크 및 파일 시스템과 같은 자원의 격리를 보장합니다. 특히 Docker에서는 네임스페이스가 컨테이너의 프로세스를 호스트 및 다른 컨테이너와 분리합니다.
- **`unshare`의 사용**: `unshare` 명령(또는 기본 syscall)은 새로운 네임스페이스를 생성하는 데 사용되어 추가적인 격리 계층을 제공합니다. 그러나 Kubernetes는 본질적으로 이를 차단하지 않지만, Docker는 차단합니다.
- **제한 사항**: 새로운 네임스페이스를 생성하는 것은 프로세스가 호스트의 기본 네임스페이스로 되돌아가는 것을 허용하지 않습니다. 호스트 네임스페이스에 침투하려면 일반적으로 호스트의 `/proc` 디렉토리에 접근해야 하며, `nsenter`를 사용하여 진입합니다.

**제어 그룹 (CGroups)**

- **기능**: 주로 프로세스 간 자원을 할당하는 데 사용됩니다.
- **보안 측면**: CGroups 자체는 격리 보안을 제공하지 않지만, 잘못 구성된 경우 무단 접근을 위해 악용될 수 있는 `release_agent` 기능이 있습니다.

**능력 드롭**

- **중요성**: 프로세스 격리를 위한 중요한 보안 기능입니다.
- **기능**: 특정 능력을 드롭하여 루트 프로세스가 수행할 수 있는 작업을 제한합니다. 프로세스가 루트 권한으로 실행되더라도 필요한 능력이 부족하면 특권 작업을 실행할 수 없으며, 이는 권한 부족으로 인해 syscall이 실패합니다.

이것은 프로세스가 다른 능력을 드롭한 후의 **남은 능력**입니다:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

Docker에서 기본적으로 활성화되어 있습니다. 이는 프로세스가 호출할 수 있는 **syscalls를 더욱 제한하는 데 도움을 줍니다**.\
**기본 Docker Seccomp 프로파일**은 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)에서 찾을 수 있습니다.

**AppArmor**

Docker에는 활성화할 수 있는 템플릿이 있습니다: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

이것은 기능, syscalls, 파일 및 폴더에 대한 접근을 줄이는 데 도움이 됩니다...

</details>

### Namespaces

**Namespaces**는 **커널 리소스를 분할하는** Linux 커널의 기능으로, 한 집합의 **프로세스**가 한 집합의 **리소스**를 **보고**, **다른** 집합의 **프로세스**가 **다른** 집합의 리소스를 보는 방식으로 작동합니다. 이 기능은 리소스와 프로세스의 집합에 대해 동일한 네임스페이스를 가지지만, 그 네임스페이스는 서로 다른 리소스를 참조합니다. 리소스는 여러 공간에 존재할 수 있습니다.

Docker는 컨테이너 격리를 달성하기 위해 다음 Linux 커널 네임스페이스를 사용합니다:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

**네임스페이스에 대한 더 많은 정보**는 다음 페이지를 확인하세요:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

Linux 커널 기능 **cgroups**는 **cpu, memory, io, network bandwidth와 같은 리소스를** 프로세스 집합에 대해 **제한할 수 있는 기능**을 제공합니다. Docker는 특정 컨테이너에 대한 리소스 제어를 허용하는 cgroup 기능을 사용하여 컨테이너를 생성할 수 있습니다.\
다음은 사용자 공간 메모리가 500m로 제한되고, 커널 메모리가 50m로 제한되며, cpu share가 512, blkioweight가 400인 컨테이너입니다. CPU share는 컨테이너의 CPU 사용량을 제어하는 비율입니다. 기본값은 1024이며 0에서 1024 사이의 범위를 가집니다. 세 개의 컨테이너가 동일한 CPU share 1024를 가지면, 각 컨테이너는 CPU 리소스 경합 시 최대 33%의 CPU를 사용할 수 있습니다. blkio-weight는 컨테이너의 IO를 제어하는 비율입니다. 기본값은 500이며 10에서 1000 사이의 범위를 가집니다.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
컨테이너의 cgroup을 얻으려면 다음을 수행할 수 있습니다:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
더 많은 정보는 다음을 확인하세요:

{{#ref}}
cgroups.md
{{#endref}}

### 권한

권한은 **루트 사용자에게 허용될 수 있는 권한에 대한 더 세밀한 제어를 허용**합니다. Docker는 Linux 커널 권한 기능을 사용하여 **사용자 유형에 관계없이 컨테이너 내에서 수행할 수 있는 작업을 제한**합니다.

Docker 컨테이너가 실행될 때, **프로세스는 격리에서 탈출하는 데 사용할 수 있는 민감한 권한을 포기합니다**. 이는 프로세스가 민감한 작업을 수행하고 탈출할 수 없도록 보장하려는 시도입니다:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Docker의 Seccomp

이것은 Docker가 **컨테이너 내에서 사용할 수 있는 시스템 호출을 제한**할 수 있도록 하는 보안 기능입니다:

{{#ref}}
seccomp.md
{{#endref}}

### Docker의 AppArmor

**AppArmor**는 **컨테이너**를 **제한된** **자원** 집합에 **프로그램별 프로필**로 제한하는 커널 향상 기능입니다.:

{{#ref}}
apparmor.md
{{#endref}}

### Docker의 SELinux

- **레이블링 시스템**: SELinux는 모든 프로세스와 파일 시스템 객체에 고유한 레이블을 할당합니다.
- **정책 집행**: 프로세스 레이블이 시스템 내 다른 레이블에서 수행할 수 있는 작업을 정의하는 보안 정책을 집행합니다.
- **컨테이너 프로세스 레이블**: 컨테이너 엔진이 컨테이너 프로세스를 시작할 때, 일반적으로 제한된 SELinux 레이블인 `container_t`가 할당됩니다.
- **컨테이너 내 파일 레이블링**: 컨테이너 내의 파일은 일반적으로 `container_file_t`로 레이블이 지정됩니다.
- **정책 규칙**: SELinux 정책은 주로 `container_t` 레이블이 있는 프로세스가 `container_file_t`로 레이블이 지정된 파일과만 상호작용(읽기, 쓰기, 실행)할 수 있도록 보장합니다.

이 메커니즘은 컨테이너 내의 프로세스가 손상되더라도 해당 레이블이 있는 객체와만 상호작용하도록 제한되어, 그러한 손상으로 인한 잠재적 피해를 크게 제한합니다.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ 및 AuthN

Docker에서 권한 부여 플러그인은 Docker 데몬에 대한 요청을 허용하거나 차단할지를 결정하는 데 중요한 역할을 합니다. 이 결정은 두 가지 주요 컨텍스트를 검토하여 이루어집니다:

- **인증 컨텍스트**: 여기에는 사용자에 대한 포괄적인 정보가 포함되며, 사용자가 누구인지와 어떻게 인증했는지를 포함합니다.
- **명령 컨텍스트**: 이는 요청과 관련된 모든 관련 데이터를 포함합니다.

이러한 컨텍스트는 인증된 사용자로부터의 합법적인 요청만 처리되도록 보장하여 Docker 작업의 보안을 강화합니다.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## 컨테이너에서의 DoS

컨테이너가 사용할 수 있는 자원을 적절히 제한하지 않으면, 손상된 컨테이너가 실행 중인 호스트에 DoS를 일으킬 수 있습니다.

- CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- 대역폭 DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## 흥미로운 Docker 플래그

### --privileged 플래그

다음 페이지에서 **`--privileged` 플래그가 의미하는 바**를 배울 수 있습니다:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

공격자가 낮은 권한 사용자로 접근할 수 있는 컨테이너를 실행하는 경우, **잘못 구성된 suid 바이너리**가 있다면 공격자가 이를 악용하여 **컨테이너 내에서 권한을 상승시킬 수** 있습니다. 이는 그가 컨테이너에서 탈출할 수 있게 할 수 있습니다.

**`no-new-privileges`** 옵션을 활성화하여 컨테이너를 실행하면 **이러한 종류의 권한 상승을 방지할 수** 있습니다.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### 기타
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
더 많은 **`--security-opt`** 옵션은 다음을 확인하세요: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## 기타 보안 고려사항

### 비밀 관리: 모범 사례

비밀을 Docker 이미지에 직접 포함시키거나 환경 변수를 사용하는 것은 피하는 것이 중요합니다. 이러한 방법은 `docker inspect` 또는 `exec`와 같은 명령을 통해 컨테이너에 접근할 수 있는 모든 사람에게 민감한 정보를 노출합니다.

**Docker 볼륨**은 민감한 정보에 접근하기 위한 더 안전한 대안으로 권장됩니다. 이는 메모리 내의 임시 파일 시스템으로 활용될 수 있어 `docker inspect` 및 로깅과 관련된 위험을 완화합니다. 그러나 루트 사용자와 컨테이너에 `exec` 접근 권한이 있는 사용자는 여전히 비밀에 접근할 수 있습니다.

**Docker 비밀**은 민감한 정보를 처리하기 위한 더욱 안전한 방법을 제공합니다. 이미지 빌드 단계에서 비밀이 필요한 인스턴스의 경우, **BuildKit**은 빌드 시간 비밀을 지원하여 빌드 속도를 향상시키고 추가 기능을 제공합니다.

BuildKit을 활용하려면 세 가지 방법으로 활성화할 수 있습니다:

1. 환경 변수를 통해: `export DOCKER_BUILDKIT=1`
2. 명령어에 접두사를 붙여: `DOCKER_BUILDKIT=1 docker build .`
3. Docker 구성에서 기본적으로 활성화: `{ "features": { "buildkit": true } }`, 이후 Docker를 재시작합니다.

BuildKit은 `--secret` 옵션을 사용하여 빌드 시간 비밀을 사용할 수 있게 하여, 이러한 비밀이 이미지 빌드 캐시나 최종 이미지에 포함되지 않도록 합니다.
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
실행 중인 컨테이너에서 필요한 비밀에 대해, **Docker Compose와 Kubernetes**는 강력한 솔루션을 제공합니다. Docker Compose는 비밀 파일을 지정하기 위해 서비스 정의에서 `secrets` 키를 사용합니다. 다음은 `docker-compose.yml` 예제입니다:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
이 구성은 Docker Compose로 서비스를 시작할 때 비밀을 사용할 수 있도록 허용합니다.

Kubernetes 환경에서는 비밀이 기본적으로 지원되며 [Helm-Secrets](https://github.com/futuresimple/helm-secrets)와 같은 도구로 추가 관리할 수 있습니다. Kubernetes의 역할 기반 접근 제어(RBAC)는 Docker Enterprise와 유사하게 비밀 관리 보안을 강화합니다.

### gVisor

**gVisor**는 Go로 작성된 애플리케이션 커널로, Linux 시스템 표면의 상당 부분을 구현합니다. 이는 애플리케이션과 호스트 커널 간의 **격리 경계를 제공하는** `runsc`라는 [Open Container Initiative (OCI)](https://www.opencontainers.org) 런타임을 포함합니다. `runsc` 런타임은 Docker 및 Kubernetes와 통합되어 샌드박스화된 컨테이너를 쉽게 실행할 수 있게 합니다.

{{#ref}}
https://github.com/google/gvisor
{{#endref}}

### Kata Containers

**Kata Containers**는 경량 가상 머신을 사용하여 안전한 컨테이너 런타임을 구축하기 위해 노력하는 오픈 소스 커뮤니티입니다. 이들은 컨테이너처럼 느껴지고 작동하지만, **하드웨어 가상화** 기술을 사용하여 더 강력한 작업 부하 격리를 제공합니다.

{{#ref}}
https://katacontainers.io/
{{#endref}}

### 요약 팁

- **`--privileged` 플래그를 사용하지 않거나** [**Docker 소켓을 컨테이너 내부에 마운트하지 마십시오**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Docker 소켓은 컨테이너를 생성할 수 있게 하므로, 예를 들어 `--privileged` 플래그로 다른 컨테이너를 실행하여 호스트를 완전히 제어할 수 있는 쉬운 방법입니다.
- **컨테이너 내부에서 root로 실행하지 마십시오.** [**다른 사용자**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **를 사용하고** [**사용자 네임스페이스**](https://docs.docker.com/engine/security/userns-remap/) **를 사용하십시오.** 컨테이너의 root는 사용자 네임스페이스로 재매핑되지 않는 한 호스트의 root와 동일합니다. 이는 주로 Linux 네임스페이스, 기능 및 cgroups에 의해 약간 제한됩니다.
- [**모든 기능을 제거하십시오**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) 및 필요한 기능만 활성화하십시오** (`--cap-add=...`). 많은 작업 부하에는 기능이 필요하지 않으며, 이를 추가하면 잠재적인 공격 범위가 증가합니다.
- [**“no-new-privileges” 보안 옵션을 사용하십시오**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) **.** 이는 프로세스가 더 많은 권한을 얻지 못하도록 방지합니다. 예를 들어 suid 바이너리를 통해서입니다.
- [**컨테이너에 사용할 수 있는 리소스를 제한하십시오**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** 리소스 제한은 서비스 거부 공격으로부터 머신을 보호할 수 있습니다.
- **seccomp** [**조정하십시오**](https://docs.docker.com/engine/security/seccomp/), **AppArmor** [**(또는 SELinux)**](https://docs.docker.com/engine/security/apparmor/) 프로파일을 조정하여 컨테이너에 필요한 최소한의 작업 및 시스템 호출만 허용하십시오.
- **공식 Docker 이미지를 사용하고** [**서명을 요구하십시오**](https://docs.docker.com/docker-hub/official_images/) **또는 이를 기반으로 직접 빌드하십시오.** 백도어가 있는 이미지를 상속하거나 사용하지 마십시오. 또한 루트 키와 비밀번호를 안전한 장소에 보관하십시오. Docker는 UCP로 키를 관리할 계획이 있습니다.
- **정기적으로** **이미지를 재빌드하여 호스트와 이미지에 보안 패치를 적용하십시오.**
- **비밀을 현명하게 관리하여 공격자가 접근하기 어렵게 하십시오.**
- Docker 데몬을 **노출하는 경우 HTTPS를 사용하십시오** 클라이언트 및 서버 인증과 함께.
- Dockerfile에서 **ADD 대신 COPY를 선호하십시오.** ADD는 자동으로 압축된 파일을 추출하고 URL에서 파일을 복사할 수 있습니다. COPY는 이러한 기능이 없습니다. 가능한 경우 ADD 사용을 피하여 원격 URL 및 Zip 파일을 통한 공격에 취약하지 않도록 하십시오.
- **각 마이크로 서비스에 대해 별도의 컨테이너를 가지십시오.**
- **컨테이너 내부에 ssh를 두지 마십시오.** “docker exec”를 사용하여 컨테이너에 ssh할 수 있습니다.
- **더 작은** 컨테이너 **이미지를 가지십시오.**

## Docker 탈출 / 권한 상승

당신이 **docker 컨테이너 내부에 있거나** **docker 그룹의 사용자에 접근할 수 있다면**, **탈출하고 권한을 상승시키려고 시도할 수 있습니다**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Docker 인증 플러그인 우회

Docker 소켓에 접근하거나 **docker 그룹의 사용자에 접근할 수 있지만** Docker 인증 플러그인에 의해 행동이 제한되고 있다면, **우회할 수 있는지 확인하십시오**:

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Docker 강화

- 도구 [**docker-bench-security**](https://github.com/docker/docker-bench-security)는 프로덕션에서 Docker 컨테이너를 배포할 때의 일반적인 모범 사례를 확인하는 스크립트입니다. 테스트는 모두 자동화되어 있으며, [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/)을 기반으로 합니다.\
Docker를 실행하는 호스트 또는 충분한 권한이 있는 컨테이너에서 도구를 실행해야 합니다. **README에서 실행 방법을 확인하십시오:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## 참고자료

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

{{#include ../../../banners/hacktricks-training.md}}
