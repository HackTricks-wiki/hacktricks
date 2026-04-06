# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinuxは**ラベルベースの Mandatory Access Control (MAC)**システムです。

実際には、これはたとえDAC permissions、groups、またはLinux capabilitiesがその操作に対して十分に見えても、カーネルが要求されたクラス/permissionで**source context**が**target context**にアクセスすることを許可していないため、アクセスを拒否することがある、ということを意味します。

コンテキストは通常次のようになります:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privesc の観点では、`type`（プロセスのドメイン、オブジェクトのタイプ）は通常最も重要なフィールドです:

- プロセスは、`unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t` のような**ドメイン**で実行されます
- ファイルやソケットは、`admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t` のような**タイプ**を持ちます
- ポリシーは、あるドメインが別のドメインを読み取り/書き込み/実行/遷移できるかを決定します

## 迅速な列挙

SELinux が有効な場合は、早い段階で列挙してください。これは、一般的な Linux privesc の経路が失敗する理由や、特権を持つラッパーが "harmless" と見なされる SELinux ツールの周りにある場合に実は重要である理由を説明してくれます:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
フォローアップで確認すべき有用な項目:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
Interesting findings:

- `Disabled` or `Permissive` mode removes most of the value of SELinux as a boundary.
- `unconfined_t` usually means SELinux is present but not meaningfully constraining that process.
- `default_t`, `file_t`, or obviously wrong labels on custom paths often indicate mislabeling or incomplete deployment.
- Local overrides in `file_contexts.local` take precedence over policy defaults, so review them carefully.

## ポリシー解析

SELinux は次の2つの問いに答えられると、攻撃やバイパスがはるかに容易になる:

1. **現在のドメインがアクセスできるものは何か？**
2. **どのドメインに遷移できるか？**

これを調べるために最も有用なツールは `sepolicy` と **SETools** (`seinfo`, `sesearch`, `sedta`):
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
これは、ホストが全員を `unconfined_u` にマッピングするのではなく、**confined users** を使用している場合に特に有用です。その場合、次を確認してください：

- ユーザマッピング：`semanage login -l`
- 許可されたロール：`semanage user -l`
- 到達可能な管理ドメイン（例：`sysadm_t`, `secadm_t`, `webadm_t`）
- `sudoers` のエントリで `ROLE=` や `TYPE=` を使用しているもの

もし `sudo -l` にこのようなエントリが含まれている場合、SELinux は権限境界の一部です：
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
また、`newrole` が利用可能かどうかも確認してください:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` and `newrole` は自動的に悪用可能になるわけではありませんが、特権付きのラッパーや `sudoers` ルールでより良い role/type を選択できるようになると、重要な権限昇格プリミティブになります。

## Files, Relabeling, and High-Value Misconfigurations

一般的な SELinux ツール間で最も重要な運用上の違いは次の通りです：

- `chcon`: 特定パスの一時的なラベル変更
- `semanage fcontext`: 永続的なパス→ラベルのルール
- `restorecon` / `setfiles`: ポリシー／デフォルトラベルを再適用

これは privesc 中に非常に重要です。なぜなら **リラベリングは単なる見た目の変更ではない** からです。ファイルを「blocked by policy」から「readable/executable by a privileged confined service」に変えることができます。

ローカルのリラベルルールとリラベルのドリフトを確認する：
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
`sudo -l`、root wrappers、automation scripts、または file capabilities の中で探すべき高価値コマンド:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
特に注目すべき点:

- `semanage fcontext`: パスが受けるべきラベルを永続的に変更する
- `restorecon` / `setfiles`: それらの変更を大規模に再適用する
- `semodule -i`: カスタムポリシーモジュールをロードする
- `semanage permissive -a <domain_t>`: ホスト全体を切り替えずに特定の domain を permissive にする
- `setsebool -P`: ポリシーのブール値を恒久的に変更する
- `load_policy`: アクティブなポリシーをリロードする

これらはしばしば **helper primitives** であり、単独の root exploits ではありません。これらの利点は次を可能にする点です:

- ターゲット domain を permissive にする
- 自分の domain と保護された type の間のアクセスを拡大する
- 攻撃者が制御するファイルのラベルを変更して、特権サービスがそれらを読み取ったり実行したりできるようにする
- confined service を十分に弱体化させて、既存のローカルバグが exploitable になるようにする

チェック例:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
もし root として policy module をロードできるなら、通常は SELinux の境界を制御できます:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
だからこそ、`audit2allow`、`semodule`、および `semanage permissive` は post-exploitation 時に機密性の高い管理インターフェースとして扱うべきだ。これらは、従来の UNIX 権限を変更せずに、ブロックされたチェーンを静かに動作するものへと変えることができる。

## 監査の手がかり

AVC denials はしばしば攻撃のシグナルであり、単なる防御側のノイズではない。次のことを示してくれる：

- どのターゲットオブジェクト/タイプに当たっているか
- どの権限が拒否されたか
- どのドメインを現在制御しているか
- 小さなポリシー変更でチェーンが動作するかどうか
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
If a local exploit or persistence attempt keeps failing with `EACCES` or strange "permission denied" errors despite root-looking DAC permissions, SELinux is usually worth checking before discarding the vector.

## SELinux ユーザー

通常の Linux ユーザーに加えて SELinux ユーザーが存在します。各 Linux ユーザーはポリシーの一部として SELinux ユーザーにマッピングされており、これによりシステムはアカウントごとに異なる許可されたロールやドメインを課すことができます。

簡単なチェック:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
多くの一般的なシステムでは、ユーザーは `unconfined_u` にマッピングされており、ユーザーの拘束の実際的影響は小さくなっています。しかしハードニングされたデプロイでは、拘束されたユーザーが `sudo`、`su`、`newrole`、`runcon` をより興味深いものにすることがあります。なぜなら **エスカレーション経路は UID 0 になることだけでなく、より良い SELinux role/type に入ることに依存する場合がある** からです。

## コンテナにおける SELinux

コンテナランタイムは一般に、`container_t` のような制限されたドメインでワークロードを起動し、コンテナの内容に `container_file_t` というラベルを付けます。コンテナプロセスが脱出してもコンテナラベルで実行され続ける場合、ラベル境界が保たれたままなのでホストへの書き込みは依然として失敗することがあります。

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
現代のコンテナ運用で注目すべき点:

- `--security-opt label=disable` は、ワークロードを `spc_t` のような制限されていないコンテナ関連タイプに実質的に移すことができる
- `:z` / `:Z` を使ったバインドマウントは、ホストパスをコンテナの共有/専用利用向けに再ラベル付けする
- ホストのコンテンツを広範囲に再ラベル付けすること自体がセキュリティ上の問題になり得る

このページでは重複を避けるためにコンテナに関する内容は短くまとめています。コンテナ固有の悪用ケースやランタイムの例については、次を参照してください:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## 参考資料

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
