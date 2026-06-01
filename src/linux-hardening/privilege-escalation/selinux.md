# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux は **ラベルベースの Mandatory Access Control (MAC)** システムです。実際には、DAC 権限、グループ、または Linux capabilities だけで操作が可能に見えても、カーネルは **source context** が要求された class/permission で **target context** にアクセスすることを許可されていないため、依然としてそれを拒否できます。

コンテキストは通常、次のようになります:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privescの観点では、`type`（プロセスにはdomain、オブジェクトにはtype）が通常、最も重要な項目です:

- プロセスは `unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t` などの **domain** で動作する
- ファイルとソケットは `admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t` などの **type** を持つ
- policy は、ある domain が別のものを read/write/execute/transition できるかを決める

## Fast Enumeration

SELinux が有効なら、早い段階で列挙するべきです。なぜなら、一般的な Linux privesc の経路が失敗する理由や、"harmless" な SELinux tool を囲む privileged wrapper が実際には重要である理由を説明できるからです:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
有用な追加確認事項:
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
興味深い点:

- `Disabled` または `Permissive` モードでは、境界としての SELinux の価値の大部分が失われる。
- `unconfined_t` は通常、SELinux は存在するが、そのプロセスを実質的には制限していないことを意味する。
- `default_t`、`file_t`、またはカスタムパス上の明らかに誤ったラベルは、しばしば mislabeling か不完全なデプロイを示す。
- `file_contexts.local` のローカル上書きは policy のデフォルトより優先されるため、注意して確認する。

## Policy Analysis

SELinux は、次の 2 つの質問に答えられると、はるかに攻撃しやすく、または bypass しやすくなる。

1. **現在の domain は何にアクセスできるか?**
2. **どの domain に transition できるか?**

これらに最も役立つツールは `sepolicy` と **SETools** (`seinfo`, `sesearch`, `sedta`):
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
これは、ホストが全員を `unconfined_u` に割り当てるのではなく、**confined users** を使っている場合に特に有用です。その場合は、次を確認してください:

- `semanage login -l` による user mappings
- `semanage user -l` による許可された roles
- `sysadm_t`、`secadm_t`、`webadm_t` など到達可能な admin domains
- `ROLE=` または `TYPE=` を使う `sudoers` エントリ

`sudo -l` にこのようなエントリが含まれている場合、SELinux は privilege boundary の一部です:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
また、`newrole` が利用可能か確認してください:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` と `newrole` は自動的には悪用できませんが、特権付きラッパーや `sudoers` ルールによってより良い role/type を選べるなら、高価値な権限昇格プリミティブになります。

## Files, Relabeling, and High-Value Misconfigurations

一般的な SELinux ツールの最も重要な運用上の違いは次のとおりです:

- `chcon`: 特定の path に対する一時的な label 変更
- `semanage fcontext`: 永続的な path-to-label ルール
- `restorecon` / `setfiles`: policy/default label を再適用する

これは privesc の間に非常に重要です。なぜなら、**relabeling は単なる見た目の変更ではない**からです。ファイルを「policy によって blocked」な状態から、特権付きの confined service が「readable/executable」にできる状態へ変えられます。

ローカルの relabel ルールと relabel drift を確認してください:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
1 つの微妙ですが役立つ詳細として、通常の `restorecon` は **必ずしも怪しいラベルを完全に元に戻すとは限りません**。対象の type が `customizable_types` に含まれている場合、完全にリセットするために `-F` が必要になることがあります。攻撃側の視点では、これは、通常とは異なる `chcon` が、軽い「もう `restorecon` は実行済みだ」という後片付けをすり抜けて残ることがある理由を説明しています。
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrappers, automation scripts, or file capabilities で探すべき高価値コマンド:`
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
MAC capability のどちらかが出てきたら、[Linux capabilities page](linux-capabilities.md) もあわせて確認すること; `cap_mac_admin` と `cap_mac_override` は珍しいが、SELinux が境界の一部にある場合には直接関連する。

特に注目すべきもの:

- `semanage fcontext`: パスが受けるべきラベルを永続的に変更する
- `restorecon` / `setfiles`: それらの変更を大規模に再適用する
- `semodule -i`: カスタム policy module を読み込む
- `semanage permissive -a <domain_t>`: ホスト全体を切り替えずに、1つの domain を permissive にする
- `setsebool -P`: policy booleans を永続的に変更する
- `load_policy`: アクティブな policy を再読み込みする

これらはしばしば **helper primitives** であり、単独の root exploit ではない。価値は次のことを可能にする点にある:

- 対象の domain を permissive にする
- 自分の domain と保護された type の間のアクセスを広げる
- attacker-controlled files のラベルを付け替えて、特権サービスがそれらを読み取ったり実行したりできるようにする
- 制限されたサービスを十分に弱めて、既存のローカル bug を exploit 可能にする

Example checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
root として policy module を load できるなら、通常は SELinux boundary を制御できます:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
だからこそ、`audit2allow`、`semodule`、そして `semanage permissive` は、post-exploitation 中の機微な管理者向け操作面として扱うべきです。これらは、従来の UNIX 権限を変更せずに、ブロックされていたチェーンを静かに動作するものへ変えられます。

## Hidden Denials and Module Extraction

非常に一般的な offensive のフラストレーションは、期待される AVC denial が一切出ず、単に `EACCES` だけでチェーンが失敗することです。`dontaudit` ルールが、必要な権限そのものを隠している可能性があります。`sudo` や他の特権付きラッパー経由で `semodule` を実行できるなら、一時的に `dontaudit` を無効化することで、静かな失敗を正確な policy の手がかりに変えられます：
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
これは、ローカル管理者がすでに何を変更したかを確認するのにも役立ちます。小さなカスタム module や、1つの domain に対する permissive rule が、target service が base policy よりもはるかに緩く振る舞う原因であることがよくあります。

## Audit Clues

AVC denials は、単なる防御側のノイズではなく、しばしば攻撃側のシグナルです。そこから次が分かります:

- どの target object/type に当たったか
- どの permission が denied されたか
- 現在どの domain を control しているか
- 小さな policy change で chain が成立するかどうか
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
ローカル exploit や persistence の試みが `EACCES` や、root のように見える DAC 権限があるのに奇妙な "permission denied" エラーで失敗し続ける場合、そのベクターを諦める前に SELinux を確認する価値が通常あります。

## SELinux Users

通常の Linux users に加えて SELinux users があります。各 Linux user は policy の一部として SELinux user にマッピングされ、これにより system は異なる account に異なる許可された roles と domains を適用できます。

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
多くの一般的なシステムでは、ユーザーは `unconfined_u` にマップされるため、user confinement の実際の影響は小さくなります。  
しかし、hardened なデプロイメントでは、confined users は `sudo`、`su`、`newrole`、`runcon` をかなり興味深いものにします。なぜなら、**escalation path は UID 0 になることだけでなく、より適切な SELinux role/type に入ることに依存する場合がある**からです。  
また、policy が基盤となる setuid transition を明示的に許可していない限り、一部の confined users は `sudo`/`su` をまったく呼び出せないことも忘れないでください。そのため、`staff_u` + `sysadm_r` を使う host では、一見すると小さな `sudo ROLE=` / `TYPE=` ルールが、実際の privilege boundary になることがあります。

## SELinux in Containers

Container runtimes は通常、workloads を `container_t` のような confined domain で起動し、container content に `container_file_t` をラベル付けします。container process が escape しても、container label のまま実行されている場合、label boundary がそのまま維持されているため host への書き込みは依然として失敗することがあります。

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` の部分は装飾ではありません。多くのコンテナ環境では、runtime が MCS categories を動的に割り当てるため、`container_t` として動作する 2 つの process は互いに分離されたままになります。escape によって host namespace に入っても元の category set が維持されている場合、category の不一致が、なぜ一部の host path が今でも unreadable または unwritable のままなのかを説明できることがあります。

注目すべき modern container operations:

- `--security-opt label=disable` は、workload を `spc_t` のような unconfined の container-related type に事実上移せる
- `:z` / `:Z` を使った bind mounts は、shared/private container 用に host path の relabeling を引き起こす
- host content の広範な relabeling は、それ自体が security issue になり得る

このページでは重複を避けるため、container の内容は短くしています。container-specific な abuse cases と runtime の例については、次を確認してください:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
