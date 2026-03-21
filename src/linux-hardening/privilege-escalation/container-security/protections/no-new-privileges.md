# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` はプロセスが `execve()` によってより高い権限を得るのを防ぐカーネルのハードニング機能です。実務的には、このフラグが設定されると、setuid バイナリ、setgid バイナリ、または Linux file capabilities を持つファイルを実行しても、プロセスが既に持っている権限を超える追加の権限は与えられません。コンテナ化された環境では、イメージ内の実行可能ファイルが起動時に権限を変えることを前提とした多くの privilege-escalation チェーンが存在するため、これは重要です。

防御の観点から、`no_new_privs` は namespaces、seccomp、または capability dropping の代替にはなりません。補強のレイヤーです。コード実行をすでに奪われた後の特定の種類の追撃的エスカレーションをブロックします。そのため、イメージに helper binaries、package-manager artifacts、または部分的な妥協と組み合わせると危険になるレガシーツールが含まれている環境では特に有用です。

## 動作

この挙動の背後にあるカーネルフラグは `PR_SET_NO_NEW_PRIVS` です。一度プロセスに設定されると、その後の `execve()` 呼び出しは権限を増加させることができません。重要な点は、プロセスが依然としてバイナリを実行できることですが、それらのバイナリを使ってカーネルが通常許容するような権限の境界を越えることはできない、ということです。

Kubernetes 指向の環境では、`allowPrivilegeEscalation: false` がコンテナプロセスに対してこの挙動に対応します。Docker や Podman スタイルのランタイムでは、同等の設定は通常セキュリティオプションを通じて明示的に有効化されます。

## ラボ

現在のプロセス状態を確認する:
```bash
grep NoNewPrivs /proc/self/status
```
ランタイムが flag を有効にしているコンテナと比較してください:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
ハードニングされたワークロードでは、結果は `NoNewPrivs: 1` を示すべきです。

## Security Impact

`no_new_privs` が存在しない場合、コンテナ内の足場は setuid ヘルパーや file capabilities を持つバイナリを通じて昇格される可能性があります。`no_new_privs` が設定されていると、それらの post-exec の権限変更は遮断されます。この効果は、アプリケーションがそもそも必要としない多くのユーティリティを含む汎用のベースイメージで特に重要です。

## Misconfigurations

最も一般的な問題は、対応可能な環境で単にこの制御を有効にしていないことです。Kubernetes では `allowPrivilegeEscalation` を有効のままにしておくことがしばしば運用上の誤りです。Docker や Podman では、関連するセキュリティオプションを省略すると同じ効果になります。別の繰り返し起こる誤りは、コンテナが "not privileged" であるために exec-time の権限遷移が自動的に無関係だと想定することです。

## Abuse

`no_new_privs` が設定されていない場合、最初に確認すべきはイメージ内にまだ権限を引き上げられるバイナリが含まれているかどうかです:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
興味深い結果には次のものが含まれます:

- `NoNewPrivs: 0`
- setuid ヘルパー（`su`、`mount`、`passwd`、またはディストリビューション固有の管理ツールなど）
- ネットワークやファイルシステムの特権を付与する file capabilities を持つ binaries

実際の評価では、これらの発見だけで実際にエスカレーションできることを証明するわけではありませんが、次にテストすべき binaries を正確に特定します。

### 完全な例: In-Container Privilege Escalation Through setuid

この制御は通常、ホストエスケープを直接防ぐというよりも、**in-container privilege escalation** を防ぎます。`NoNewPrivs` が `0` で setuid ヘルパーが存在する場合は、明示的にテストしてください:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
既知の setuid バイナリが存在して正常に動作する場合は、特権遷移を維持する方法で起動してみてください：
```bash
/bin/su -c id 2>/dev/null
```
これはそれ自体でコンテナから脱出するわけではありませんが、コンテナ内の low-privilege foothold を container-root に変えることができ、これがしばしば mounts、runtime sockets、または kernel-facing interfaces 経由での後続のホスト脱出の前提条件になります。

## Checks

これらのチェックの目的は、exec-time privilege gain がブロックされているかどうか、そしてブロックされていない場合に影響する helpers がイメージにまだ含まれているかどうかを確認することです。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
ここで注目すべき点:

- `NoNewPrivs: 1` は通常、より安全な結果です。
- `NoNewPrivs: 0` は setuid および file-cap に基づく権限昇格パスが依然として有効であることを意味します。
- setuid/file-cap バイナリがほとんどない、または存在しない最小イメージは、`no_new_privs` が無効であっても攻撃者に対する post-exploitation の選択肢を減らします。

## ランタイムのデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | 一般的によくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効になっていない | 明示的に `--security-opt no-new-privileges=true` で有効化される | フラグを省略する、`--privileged` |
| Podman | デフォルトでは有効になっていない | 明示的に `--security-opt no-new-privileges` または同等のセキュリティ設定で有効化される | オプションを省略する、`--privileged` |
| Kubernetes | ワークロードポリシーで制御される | `allowPrivilegeEscalation: false` を設定すると効果が有効になる；多くのワークロードは依然として有効のままにしている | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes のワークロード設定に従う | 通常、Pod のセキュリティコンテキストから継承される | Kubernetes 行と同様 |

この保護が欠如しているのは、多くの場合ランタイムがサポートしていないからではなく、誰もそれを有効にしていないためです。
