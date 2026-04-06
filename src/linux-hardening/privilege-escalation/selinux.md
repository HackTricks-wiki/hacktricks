# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinuxは**ラベルベースの Mandatory Access Control (MAC)**システムです。実際には、たとえ DAC permissions、groups、または Linux capabilities がある操作に対して十分に見えても、kernel は要求された class/permission によって **source context** が **target context** にアクセスすることを許可していないため、それを拒否することがあります。

コンテキストは通常次のようになります:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privescの観点から、`type`（プロセスのドメイン、オブジェクトのタイプ）は通常最も重要なフィールドです:

- プロセスは **ドメイン**（例: `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`）で実行される
- ファイルやソケットには **型**（例: `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`）がある
- ポリシーは、あるドメインが別のドメインを読み取り/書き込み/実行/遷移できるかを決定する

## 早期の列挙

If SELinux is enabled, enumerate it early because it can explain why common Linux privesc paths fail or why a privileged wrapper around a "harmless" SELinux tool is actually critical:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
役立つフォローアップチェック:
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
興味深い所見:

- `Disabled` または `Permissive` モードでは、SELinuxが境界として持つ価値のほとんどが失われる。
- `unconfined_t` は通常、SELinuxは存在するが、そのプロセスを実質的に制限していないことを意味する。
- `default_t`, `file_t`, またはカスタムパスに対する明らかに誤ったラベルは、しばしばラベル付けミスや展開の不備を示す。
- `file_contexts.local` のローカルオーバーライドはポリシーのデフォルトより優先されるため、注意深く確認すること。

## ポリシー解析

次の2つの質問に答えられると、SELinuxを攻撃またはバイパスするのはずっと容易になる:

1. **現在のドメインは何にアクセスできるか？**
2. **どのドメインに遷移できるか？**

これを調べるのに最も有用なツールは `sepolicy` と **SETools**（`seinfo`, `sesearch`, `sedta`）である:
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
これは、ホストが全員を `unconfined_u` にマッピングするのではなく**confined users**を使用している場合に特に有用です。その場合、次を確認してください:

- `semanage login -l` によるユーザーのマッピング
- `semanage user -l` による許可されたロール
- 例えば `sysadm_t`、`secadm_t`、`webadm_t` のような到達可能な管理ドメイン
- `ROLE=` または `TYPE=` を使用する `sudoers` エントリ

もし `sudo -l` がこのようなエントリを含んでいる場合、SELinux は権限境界の一部です:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
また、`newrole` が利用可能か確認してください:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` と `newrole` は自動的に悪用可能というわけではありませんが、特権を持つラッパーや `sudoers` ルールでより有利なロール/タイプを選択できるようになると、高価値な権限昇格プリミティブになります。

## ファイル、再ラベリング、および高価値な誤設定

一般的な SELinux ツール間での最も重要な運用上の違いは次のとおりです:

- `chcon`: 特定パス上での一時的なラベル変更
- `semanage fcontext`: パス→ラベルの永続的ルール
- `restorecon` / `setfiles`: ポリシー/デフォルトのラベルを再適用する

これは privesc の際に非常に重要です。**再ラベリングは単なる見た目だけの変更ではありません。** ファイルを「ポリシーによってブロックされている」状態から「特権を持つ隔離されたサービスが読み取り/実行できる」状態に変えることがあり得ます。

ローカルの再ラベルルールとラベルのドリフトを確認する:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
`sudo -l`、root wrappers、automation scripts、またはfile capabilitiesで探すべき重要なコマンド:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Especially interesting:

- `semanage fcontext`: パスが受け取るべきラベルを永続的に変更する
- `restorecon` / `setfiles`: それらの変更を大規模に再適用する
- `semodule -i`: カスタムポリシーモジュールを読み込む
- `semanage permissive -a <domain_t>`: ホスト全体を切り替えずに特定のドメインをpermissiveにする
- `setsebool -P`: ポリシーのブール値を永続的に変更する
- `load_policy`: 有効なポリシーを再読み込みする

These are often **補助的なプリミティブ**, not standalone root exploits. Their value is that they let you:

- 対象ドメインをpermissiveにする
- 自分のドメインと保護されたタイプ間のアクセスを拡大する
- 攻撃者が制御するファイルのラベルを変更して、特権サービスがそれらを読み取ったり実行したりできるようにする
- 既存のローカルバグが悪用可能になる程度に、制限されたサービスを弱体化させる

Example checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
rootとしてポリシーモジュールを読み込める場合、通常はSELinuxの境界を制御できます：
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
That is why `audit2allow`, `semodule`, and `semanage permissive` should be treated as sensitive admin surfaces during post-exploitation. They can silently convert a blocked chain into a working one without changing classic UNIX permissions.

## 監査の手がかり

AVC denials は単なる防御ノイズではなく、しばしば攻撃の手掛かりである。これらは次のことを教えてくれる：

- どのターゲットオブジェクト／タイプに当たったか
- どの権限が拒否されたか
- 現在どのドメインを制御しているか
- 小さなポリシー変更でチェーンが動作するかどうか
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
もしローカル exploit や persistence の試みが、root に見える DAC 権限があるにもかかわらず `EACCES` や奇妙な "permission denied" エラーで失敗し続ける場合、ベクターを諦める前に SELinux を確認する価値がある。

## SELinuxユーザー

通常の Linux ユーザーに加えて SELinux ユーザーが存在する。各 Linux ユーザーはポリシーの一部として SELinux ユーザーにマップされており、これによりシステムはアカウントごとに異なる許可されたロールやドメインを課すことができる。

簡易チェック:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
多くの主流システムでは、ユーザーは `unconfined_u` にマップされており、ユーザーの隔離の実際的な影響は小さくなる。とはいえ、ハードニングされた環境では、隔離されたユーザーが `sudo`、`su`、`newrole`、`runcon` をより興味深いものにし得る。**昇格パスは UID 0 になることだけでなく、より良い SELinux ロール/タイプに入ることに依存する場合がある**。

## コンテナ内の SELinux

コンテナランタイムは一般的に `container_t` のような隔離されたドメインでワークロードを起動し、コンテナのコンテンツに `container_file_t` とラベル付けする。コンテナプロセスが脱出してもコンテナのラベルで実行され続ける場合、ラベル境界が維持されているためホストへの書き込みは依然として失敗する可能性がある。

簡単な例:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
注目すべきモダンなコンテナ操作:

- `--security-opt label=disable` は、ワークロードを `spc_t` のような制約されていないコンテナ関連の type に実質的に移すことができる
- `:z` / `:Z` を伴う bind mounts は、共有/プライベートなコンテナ利用のためにホストパスの再ラベリングを引き起こす
- ホストコンテンツの広範な再ラベリングは、それ自体でセキュリティ上の問題になり得る

このページでは重複を避けるためコンテナ関連の内容は短めにしています。コンテナ固有の悪用ケースやランタイムの例については、次を参照してください：

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## 参考資料

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
