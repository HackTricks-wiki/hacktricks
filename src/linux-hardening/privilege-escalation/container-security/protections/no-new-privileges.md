# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` はカーネルのハードニング機能で、プロセスが `execve()` を跨いで追加の権限を得ることを防ぎます。実務的には、このフラグがセットされると、setuid バイナリや setgid バイナリ、あるいは Linux file capabilities を持つファイルを実行しても、プロセスが元々持っていた権限を超える追加の権限は与えられません。コンテナ化された環境では、イメージ内の実行ファイルを起動することで権限が変わるような多くの privilege-escalation chains に依存するため、これは重要です。

防御の観点からは、`no_new_privs` は namespaces、seccomp、または capability dropping の代替にはなりません。強化の一層です。コード実行が既に得られた後に起こる、特定の種類の追従的な昇格を阻止します。したがって、イメージに helper binaries、package-manager artifacts、あるいは部分的な妥協と組み合わされた場合に危険となるようなレガシーツールが含まれている環境では特に有用です。

## Operation

この挙動の背後にあるカーネルフラグは `PR_SET_NO_NEW_PRIVS` です。一度プロセスにセットされると、以降の `execve()` 呼び出しで権限を増すことはできません。重要な点は、プロセスは引き続きバイナリを実行できるが、それらのバイナリを使ってカーネルが通常許可するような権限境界を越えることはできない、ということです。

Kubernetes 応用の環境では、コンテナプロセスに対して `allowPrivilegeEscalation: false` がこの挙動に対応します。Docker や Podman スタイルのランタイムでは、同等の設定は通常セキュリティオプションを通じて明示的に有効化されます。

## Lab

現在のプロセス状態を確認する:
```bash
grep NoNewPrivs /proc/self/status
```
ランタイムが flag を有効にしたコンテナと比較すると:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
On a hardened workload, the result should show `NoNewPrivs: 1`.

## セキュリティへの影響

もし `no_new_privs` が設定されていない場合、コンテナ内部で得た足場は setuid helpers や file capabilities を持つバイナリを通じて権限昇格され得ます。`no_new_privs` が設定されていると、そのような実行後の権限変更は遮断されます。この効果は、アプリケーションが本来不要な多数のユーティリティを含むような汎用のベースイメージで特に重要です。

## 誤設定

最も一般的な問題は、単にその制御が適用可能な環境で有効にしていないことです。Kubernetes では `allowPrivilegeEscalation` を有効のままにすることがしばしば運用上の典型的なミスです。Docker と Podman では、関連するセキュリティオプションを省略することが同じ結果になります。別の繰り返し発生する失敗モードは、コンテナが "not privileged" だからといって、実行時の権限遷移が自動的に無関係だと想定することです。

## 悪用

もし `no_new_privs` が設定されていない場合、まず確認すべきはイメージにまだ権限を上げられるバイナリが含まれているかどうかです：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
興味深い結果には以下が含まれます:

- `NoNewPrivs: 0`
- setuid ヘルパー（例: `su`, `mount`, `passwd`）またはディストリビューション固有の管理ツール
- ネットワークやファイルシステムの権限を付与する file capabilities を持つバイナリ

実際の評価では、これらの所見だけで実際に権限昇格が可能であることは証明されませんが、次にテストすべきバイナリを正確に特定します。

### 完全な例: In-Container Privilege Escalation Through setuid

この制御は通常、直接的なホストエスケープよりも**in-container privilege escalation**を防止します。`NoNewPrivs` が `0` で setuid ヘルパーが存在する場合は、それを明示的にテストしてください：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
既知の setuid binary が存在して機能している場合は、privilege transition を維持する方法でそれを起動してみてください:
```bash
/bin/su -c id 2>/dev/null
```
これはそれ自体でcontainerを脱出するものではありませんが、container内の低権限の足がかりをcontainer-rootに変えることができ、これはしばしばmounts、runtime sockets、またはkernel-facing interfacesを通じた後のhost escapeの前提条件になります。

## チェック

これらのチェックの目的は、exec-time privilege gainがブロックされているかどうかを確認し、ブロックされていない場合に重要となるhelpersがimageにまだ含まれているかどうかを判断することです。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
What is interesting here:

- `NoNewPrivs: 1` は通常より安全な結果です。
- `NoNewPrivs: 0` は setuid や file-cap に基づくエスカレーション経路が依然として有効であることを意味します。
- setuid/file-cap バイナリがほとんどない、またはまったくない最小限のイメージは、`no_new_privs` が設定されていない場合でも攻撃者に対する post-exploitation の選択肢を減らします。

## ランタイムのデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの挙動 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは有効になっていない | 明示的に `--security-opt no-new-privileges=true` を付けて有効化される | フラグを省略する、`--privileged` |
| Podman | デフォルトでは有効になっていない | 明示的に `--security-opt no-new-privileges` または同等のセキュリティ設定で有効化される | オプションを省略する、`--privileged` |
| Kubernetes | ワークロードポリシーによって制御される | `allowPrivilegeEscalation: false` が効果を有効にする; 多くのワークロードは依然としてそれを有効にしたままにしている | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes ワークロード設定に従う | 通常は Pod security context から継承される | Kubernetes の行と同じ |

この保護は、ランタイムがそれをサポートしていないためではなく、単に誰も有効にしていないために欠けていることが多い。
{{#include ../../../../banners/hacktricks-training.md}}
