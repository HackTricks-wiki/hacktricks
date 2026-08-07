# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinuxは**ラベルベースのMandatory Access Control（MAC）**システムです。実際には、DACの権限、グループ、Linux capabilitiesがあるアクションに十分に見えても、要求されたclass/permissionにおいて、**source context**から**target context**へのアクセスが許可されていない場合、kernelはそのアクションを拒否できます。

contextは通常、次のようになります：
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privescの観点では、`type`（プロセスではdomain、オブジェクトではtype）が通常、最も重要なフィールドです。

- プロセスは、`unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t`などの**domain**で実行される
- ファイルとソケットには、`admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t`などの**type**が設定される
- Policyによって、一方のdomainが他方に対してread/write/execute/transitionできるかどうかが決まる

## Fast Enumeration

SELinuxが有効な場合は、早い段階でenumerateしてください。一般的なLinux privescの経路が失敗する理由や、「無害な」SELinux toolをラップしたprivileged wrapperが実際にはcriticalである理由を説明できるためです。
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Useful follow-up checks:
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

- `Disabled` または `Permissive` モードでは、境界としての SELinux の価値の大部分が失われます。
- `unconfined_t` は通常、SELinux が存在していても、そのプロセスを実質的に制限していないことを意味します。
- カスタムパス上の `default_t`、`file_t`、または明らかに誤ったラベルは、ラベル付けの誤りや不完全な deployment を示していることがよくあります。
- `file_contexts.local` のローカル override は policy のデフォルトより優先されるため、慎重に確認してください。

## Policy Analysis

SELinux は、次の2つの質問に答えられる場合、より簡単に attack または bypass できます。

1. **現在の domain から何にアクセスできますか？**
2. **どの domain に transition できますか？**

これらを調べるための最も有用なツールは、`sepolicy` と **SETools**（`seinfo`、`sesearch`、`sedta`）です:<sup>[[2]](#references)</sup>
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
これは、ホストが全員を `unconfined_u` にマッピングするのではなく、**confined users** を使用している場合に特に有用です。その場合は、次を確認します:<sup>[[3]](#references)</sup>

- `semanage login -l` による user mappings
- `semanage user -l` による許可された roles
- `sysadm_t`、`secadm_t`、`webadm_t` などの到達可能な admin domains
- `ROLE=` または `TYPE=` を使用する `sudoers` entries

`sudo -l` に次のような entries が含まれている場合、SELinux は privilege boundary の一部です:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
また、`newrole` が利用可能かどうかも確認してください。
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` と `newrole` は自動的に exploit 可能なわけではありませんが、privileged wrapper や `sudoers` ルールによって、より適切な role/type を選択できる場合、高価値な escalation primitive になります。

## Files、Relabeling、High-Value Misconfigurations

一般的な SELinux tools の最も重要な運用上の違いは次のとおりです。<sup>[[1]](#references)</sup>

- `chcon`: 特定の path の一時的な label 変更
- `semanage fcontext`: 永続的な path-to-label rule
- `restorecon` / `setfiles`: policy/default label を再度適用

これは privesc の際に非常に重要です。なぜなら **relabeling は単なる見た目の変更ではない** からです。これにより、ある file を「policy によって blocked」な状態から、「privileged な confined service によって readable/executable」な状態へ変更できます。

local relabel rules と relabel drift を確認します。
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
微妙ですが有用な点が1つあります。通常の `restorecon` では、疑わしい label が常に完全に元へ戻るとは限りません。対象の type が `customizable_types` に含まれている場合、完全にリセットするには `-F` が必要になることがあります。攻撃者の視点では、これは、変則的な `chcon` が「すでに restorecon を実行した」とする簡易的なクリーンアップ後も、ときどき残存する理由を説明します。
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`、root wrappers、automation scripts、または file capabilities で探す価値の高いコマンド:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
いずれかの MAC capability が表示された場合は、[Linux capabilities page](linux-capabilities.md) も照合してください。`cap_mac_admin` と `cap_mac_override` は通常とは異なりますが、SELinux が境界の一部となっている場合には直接関係します。

特に興味深いもの:

- `semanage fcontext`: パスが受け取るべき label を永続的に変更する
- `restorecon` / `setfiles`: それらの変更を大規模に再適用する
- `semodule -i`: custom policy module をロードする
- `semanage permissive -a <domain_t>`: ホスト全体を切り替えずに、1つの domain を permissive にする
- `setsebool -P`: policy boolean を永続的に変更する
- `load_policy`: active policy を再ロードする

これらは standalone root exploit ではなく、**helper primitives** であることが多いです。価値があるのは、次のことを可能にする点です:

- target domain を permissive にする
- 自分の domain と保護された type 間の access を広げる
- attacker-controlled files を relabel し、privileged service がそれらを読み取ったり execute したりできるようにする
- confined service を十分に弱体化し、既存の local bug を exploitable にする

確認例:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
rootとしてpolicy moduleをロードできる場合、通常はSELinuxの境界を制御できます：
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
そのため、`audit2allow`、`semodule`、`semanage permissive` は、post-exploitation 中の機密性の高い admin surface として扱うべきです。これらを使うと、従来の UNIX permissions を変更せずに、ブロックされていた chain を silently に機能する状態へ変えられる可能性があります。

## 隠れた Denials と Module Extraction

攻撃側が非常によく直面する厄介な問題は、期待される AVC denial が表示されないまま、単純な `EACCES` で chain が失敗することです。`dontaudit` rules によって、必要な正確な permission が隠されている可能性があります。`sudo` または別の privileged wrapper 経由で `semodule` を実行できる場合、一時的に `dontaudit` を無効化することで、silent failure を正確な policy の手掛かりに変えられます:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
これは、local admins がすでに変更した内容を確認する際にも役立ちます。小さな custom module や、特定の1つの domain に対する permissive rule が、base policy から想定されるよりも target service の動作をはるかに緩くしている原因であることがよくあります。

## Audit Clues

AVC denials は、単なる防御側のノイズではなく、offensive signal であることがよくあります。次の情報が分かります。

- ヒットした target object/type
- 拒否された permission
- 現在 control している domain
- 小さな policy change によって chain が機能するようになるかどうか
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
ローカル exploit や persistence の試行が `EACCES` または奇妙な「permission denied」エラーで繰り返し失敗し、root に見える DAC permissions が設定されている場合は、その vector を破棄する前に SELinux を確認する価値があります。

## SELinux ユーザー

通常の Linux ユーザーに加えて、SELinux ユーザーが存在します。各 Linux ユーザーは policy の一部として SELinux ユーザーにマッピングされ、アカウントごとに異なる role と domain を許可するようシステムに適用させることができます。<sup>[[3]](#references)</sup>

簡単な確認方法:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
多くの主流システムでは、ユーザーは `unconfined_u` にマッピングされているため、ユーザー隔離による実際の影響は小さくなります。しかし、hardening された環境では、隔離されたユーザーにとって `sudo`、`su`、`newrole`、`runcon` がはるかに興味深いものになる可能性があります。これは、**escalation path が UID 0 になることだけでなく、より適切な SELinux role/type への移行に依存する可能性があるためです**。また、一部の隔離されたユーザーは、policy が基盤となる setuid transition を明示的に許可しない限り、`sudo`/`su` をまったく実行できない点にも注意してください。そのため、`staff_u` + `sysadm_r` を使用するホストでは、一見すると小さな `sudo ROLE=` / `TYPE=` ルールが、実際の privilege boundary になる可能性があります。<sup>[[3]](#references)</sup>

## SELinux のコンテナ

Container runtime は通常、`container_t` のような隔離された domain で workload を起動し、container content に `container_file_t` のラベルを付けます。Container process が escape しても、container label が維持されていれば、host への writes は依然として失敗する可能性があります。

簡単な例:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` の部分は装飾ではありません。多くの container deployment では、runtime が MCS category を動的に割り当てるため、`container_t` として実行されている 2 つの process も相互に分離されます。escape によって host namespace に入り、元の category set が維持されている場合、category の不一致によって、一部の host path が読み取り不可または書き込み不可のままとなる理由を説明できる場合があります。

注目すべき modern container operation:

- `--security-opt label=disable` は、workload を `spc_t` のような unconfined な container 関連 type に実質的に移行させる可能性がある
- `:z` / `:Z` を指定した bind mount は、shared/private container use のために host path の relabeling をトリガーする
- host content の広範な relabeling 自体が security issue になる可能性がある

このページでは、重複を避けるため container content を短くまとめています。container 固有の abuse case と runtime example については、以下を確認してください。

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [3] [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
