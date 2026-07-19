# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux は **label-based Mandatory Access Control (MAC)** システムです。実際には、DAC permissions、groups、Linux capabilities がある action に十分に見える場合でも、**source context** が要求された class/permission で **target context** に access することを許可されていなければ、kernel はその access を deny できます。

context は通常、次のようになります:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
権限昇格の観点では、`type`（プロセスの場合は domain、オブジェクトの場合は type）が通常、最も重要なフィールドです。

- プロセスは、`unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t` などの **domain** で実行されます
- ファイルとソケットには、`admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t` などの **type** があります
- ポリシーによって、ある domain が別の domain に対して読み取り、書き込み、実行、または transition できるかどうかが決まります

## 高速な列挙

SELinux が有効な場合は、一般的な Linux privesc の経路が失敗する理由や、「無害な」SELinux tool をラップした privileged wrapper が実際には重要である理由を説明できるため、早い段階で列挙します：
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
興味深い発見:

- `Disabled` または `Permissive` モードでは、境界としての SELinux の価値の大部分が失われます。
- `unconfined_t` は通常、SELinux は存在しているものの、そのプロセスを実質的に制約していないことを意味します。
- カスタムパスに `default_t`、`file_t`、または明らかに不適切なラベルが付いている場合、誤ったラベリングや不完全な導入を示していることがよくあります。
- `file_contexts.local` のローカルオーバーライドはポリシーのデフォルトよりも優先されるため、注意深く確認してください。

## ポリシー分析

SELinux は、次の2つの質問に答えられる場合、より簡単に攻撃またはバイパスできます。

1. **現在のドメインは何にアクセスできるか?**
2. **どのドメインへ遷移できるか?**

このために最も役立つツールは `sepolicy` と **SETools** (`seinfo`、`sesearch`、`sedta`) です:
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
これは、ホストが全員を `unconfined_u` にマッピングするのではなく、**confined users** を使用している場合に特に有用です。その場合は、次を確認します。

- `semanage login -l` による user mappings
- `semanage user -l` による許可された roles
- `sysadm_t`、`secadm_t`、`webadm_t` などの到達可能な admin domains
- `ROLE=` または `TYPE=` を使用する `sudoers` entries

`sudo -l` に次のような entries が含まれている場合、SELinux は privilege boundary の一部です。
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
また、`newrole` が利用可能かどうかも確認します：
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` と `newrole` は自動的に exploit 可能になるわけではありませんが、特権ラッパーまたは `sudoers` ルールによって、より適切な role/type を選択できる場合、高価値な権限昇格プリミティブになります。

## ファイル、ラベル変更、高価値な設定ミス

一般的な SELinux ツールの最も重要な運用上の違いは次のとおりです。

- `chcon`: 特定のパスに対する一時的なラベル変更
- `semanage fcontext`: 永続的なパスとラベルのルール
- `restorecon` / `setfiles`: policy/default label を再適用

これは privesc で非常に重要です。**ラベル変更は単なる外観上の変更ではありません**。ファイルを「policy によってブロックされている」状態から「特権を持つ confined service によって読み取り／実行可能」な状態へ変えることができます。

ローカルの relabel ルールと relabel drift を確認します。
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
微妙ですが有用な点が1つあります。通常の `restorecon` では、疑わしいラベルが**必ずしも完全には元に戻りません**。対象の type が `customizable_types` に含まれている場合、完全なリセットを強制するには `-F` が必要になることがあります。攻撃者の視点では、これは通常とは異なる `chcon` が、「すでに restorecon を実行した」とする簡単なクリーンアップ後にも残ることがある理由を説明します。
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`、root wrappers、automation scripts、または file capabilities 内で探す価値の高いコマンド:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
いずれかの MAC capability が表示された場合は、[Linux capabilities page](linux-capabilities.md) も確認してください。`cap_mac_admin` と `cap_mac_override` は珍しいものですが、SELinux が境界に含まれる場合には直接関係します。

特に注目すべきもの:

- `semanage fcontext`: パスが受け取るべき label を永続的に変更する
- `restorecon` / `setfiles`: それらの変更を大規模に再適用する
- `semodule -i`: カスタム policy module を読み込む
- `semanage permissive -a <domain_t>`: ホスト全体を切り替えずに、1 つの domain を permissive にする
- `setsebool -P`: policy boolean を永続的に変更する
- `load_policy`: active policy を再読み込みする

これらは多くの場合、単独で root exploit になるものではなく、**helper primitive** です。価値があるのは、次のことを可能にする点です:

- target domain を permissive にする
- 自分の domain と保護された type の間の access を広げる
- attacker-controlled files に relabel を行い、privileged service がそれらを読み込む、または実行できるようにする
- confined service を十分に弱め、既存の local bug を exploit 可能にする

チェック例:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
rootとしてポリシーモジュールをロードできる場合、通常はSELinuxの境界を掌握できます：
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
そのため、`audit2allow`、`semodule`、`semanage permissive` は、post-exploitation 中の機密性の高い管理者向けサーフェスとして扱うべきです。これらは、従来の UNIX permissions を変更せずに、ブロックされていた chain を機能するものへと、気付かれないまま変換できます。

## Hidden Denials and Module Extraction

攻撃側で非常によくある苛立ちは、想定していた AVC denial が一切表示されないまま、単純な `EACCES` で chain が失敗することです。`dontaudit` rules によって、必要な正確な permission が隠されている可能性があります。`sudo` や別の privileged wrapper 経由で `semodule` を実行できる場合、`dontaudit` を一時的に無効化することで、silent failure を正確な policy の手掛かりに変えられます。
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
これは、local adminsがすでに変更した内容を確認する際にも役立ちます。小規模な custom module や、1つの domain に対する permissive rule が、target serviceの動作を base policy から想定されるよりもはるかに緩くしていることがよくあります。

## 監査の手がかり

AVC denials は、単なる防御側のノイズではなく、攻撃側のシグナルであることがよくあります。次の情報が分かります。

- ヒットした target object/type
- 拒否された permission
- 現在 control している domain
- 小さな policy change によって chain が動作するようになるかどうか
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
ローカル exploit や persistence の試行が `EACCES` または奇妙な「permission denied」エラーで繰り返し失敗し、DAC permissions が root に見えるにもかかわらず解決しない場合は、その vector を破棄する前に SELinux を確認する価値があります。

## SELinux Users

通常の Linux users に加えて SELinux users も存在します。各 Linux user は policy の一部として SELinux user にマッピングされ、システムはアカウントごとに異なる許可された roles と domains を適用できます。

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
多くの主流システムでは、ユーザーは `unconfined_u` にマッピングされるため、ユーザーの confinement による実際の影響は小さくなります。しかし、hardening された環境では、confined user にとって `sudo`、`su`、`newrole`、`runcon` がより興味深いものになります。これは、**escalation path が UID 0 になることだけでなく、より有利な SELinux role/type に入ることに依存する場合があるためです**。また、一部の confined user は、policy が基盤となる setuid transition を明示的に許可しない限り、`sudo`/`su` 自体を実行できない点にも注意してください。そのため、`staff_u` + `sysadm_r` を使用するホストでは、一見すると軽微な `sudo ROLE=` / `TYPE=` ルールが、実際の privilege boundary になる可能性があります。

## Containers における SELinux

Container runtime は通常、workload を `container_t` のような confined domain で起動し、container の内容に `container_file_t` のラベルを付けます。Container process が escape しても container label のまま実行されている場合、label boundary が維持されているため、host への書き込みは依然として失敗する可能性があります。

簡単な例:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` の部分は装飾ではありません。多くのコンテナデプロイメントでは、ランタイムが MCS カテゴリを動的に割り当てるため、`container_t` として実行されている 2 つのプロセスも、互いに分離された状態になります。escape によってホスト namespace に入った場合でも、元のカテゴリセットが維持されていると、いくつかのホストパスが読み取り不能または書き込み不能なままである理由を、カテゴリの不一致によって説明できることがあります。

注目すべき現代のコンテナ運用:

- `--security-opt label=disable` は、ワークロードを `spc_t` などの制限されていないコンテナ関連 type に実質的に移動させる可能性があります
- `:z` / `:Z` を使用した bind mount は、共有またはプライベートなコンテナ利用に合わせてホストパスの relabeling をトリガーします
- ホストコンテンツに対する広範な relabeling は、それ自体が security issue になる可能性があります

このページでは、重複を避けるためコンテナに関する内容を短くしています。コンテナ固有の abuse cases と runtime の例については、以下を確認してください。

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## 参考資料

- [Red Hat docs: SELinux の使用](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: SELinux の policy analysis tools](https://github.com/SELinuxProject/setools)
- [制限付きユーザーと制限なしユーザーの管理 - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
